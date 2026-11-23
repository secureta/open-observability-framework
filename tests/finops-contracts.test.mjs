import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_CLOUDFLARE_PRICING,
  buildCloudflareGraphqlQuery,
  classifyR2Action,
  normalizeCloudflareAnalyticsToFocus,
  normalizeGitHubBillingUsageToFocus,
  resolveUtcDayWindow,
  runFinopsCollection,
  sendFocusToBasin,
} from "../adapters/collect/finops-billing/collect-focus.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const FOCUS_SCHEMA_PATH = path.join(REPO_ROOT, "contracts/focus/cost-and-usage.basin.json");
const FOCUS_PIPELINE_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/focus_pipeline.sql");
const FINOPS_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/finops_monitoring.sql");
const FINOPS_BASIN_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/finops_monitoring.basin.sql");
const TERRAFORM_DIR = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/terraform");
const PULUMI_DIR = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pulumi");
const STACK_SCHEMA_PATH = path.join(REPO_ROOT, "manifest/stack.schema.json");

const OFFICIAL_FOCUS_V1_0_COLUMNS = new Set([
  "AvailabilityZone",
  "BilledCost",
  "BillingAccountId",
  "BillingAccountName",
  "BillingCurrency",
  "BillingPeriodEnd",
  "BillingPeriodStart",
  "ChargeCategory",
  "ChargeClass",
  "ChargeDescription",
  "ChargeFrequency",
  "ChargePeriodEnd",
  "ChargePeriodStart",
  "CommitmentDiscountCategory",
  "CommitmentDiscountId",
  "CommitmentDiscountName",
  "CommitmentDiscountStatus",
  "CommitmentDiscountType",
  "ConsumedQuantity",
  "ConsumedUnit",
  "ContractedCost",
  "ContractedUnitPrice",
  "EffectiveCost",
  "InvoiceIssuerName",
  "ListCost",
  "ListUnitPrice",
  "PricingCategory",
  "PricingQuantity",
  "PricingUnit",
  "ProviderName",
  "PublisherName",
  "RegionId",
  "RegionName",
  "ResourceId",
  "ResourceName",
  "ResourceType",
  "ServiceCategory",
  "ServiceName",
  "SkuId",
  "SkuPriceId",
  "SubAccountId",
  "SubAccountName",
  "Tags",
]);

const ALLOWED_BASIN_TYPES = new Set([
  "string",
  "int32",
  "int64",
  "float32",
  "float64",
  "bool",
  "timestamp",
  "json",
  "bytes",
  "struct",
  "list",
]);

function assertFocusRecordMatchesSchema(record, schemaFields) {
  assert.equal(typeof record, "object");
  assert.ok(record !== null && !Array.isArray(record), "FOCUS record must be a plain object");

  const fieldMap = new Map(schemaFields.map((f) => [f.name, f]));

  for (const key of Object.keys(record)) {
    assert.ok(fieldMap.has(key), `Record contains non-FOCUS / unknown top-level field '${key}'`);
  }

  for (const field of schemaFields) {
    const val = record[field.name];
    if (val === undefined || val === null) {
      assert.equal(field.required, false, `Missing required FOCUS field '${field.name}'`);
      continue;
    }
    switch (field.type) {
      case "string":
        assert.equal(typeof val, "string", `Field '${field.name}' must be string`);
        break;
      case "float64":
        assert.ok(typeof val === "number" && Number.isFinite(val), `Field '${field.name}' must be finite number`);
        break;
      case "timestamp":
        assert.equal(typeof val, "string", `Timestamp field '${field.name}' must be RFC3339 string`);
        assert.ok(!Number.isNaN(Date.parse(val)), `Timestamp field '${field.name}' must parse as ISO date`);
        break;
      case "json":
        assert.ok(typeof val === "object" && !Array.isArray(val), `JSON field '${field.name}' must be an object`);
        break;
      default:
        assert.fail(`Unexpected Basin type '${field.type}' for '${field.name}'`);
    }
  }
}

test("FOCUS v1.0 Basin schema contract uses only official FOCUS v1.0 columns and valid Basin types", () => {
  const schema = JSON.parse(fs.readFileSync(FOCUS_SCHEMA_PATH, "utf8"));
  assert.ok(Array.isArray(schema.fields) && schema.fields.length === OFFICIAL_FOCUS_V1_0_COLUMNS.size);

  const seen = new Set();
  for (const field of schema.fields) {
    assert.ok(OFFICIAL_FOCUS_V1_0_COLUMNS.has(field.name), `Non-standard FOCUS column: ${field.name}`);
    assert.ok(!seen.has(field.name), `Duplicate FOCUS column: ${field.name}`);
    seen.add(field.name);
    assert.ok(ALLOWED_BASIN_TYPES.has(field.type), `Invalid Basin type '${field.type}' on ${field.name}`);
    assert.equal(typeof field.required, "boolean", `Field '${field.name}' missing boolean required`);
    if (field.type === "timestamp") {
      assert.equal(field.unit, "millisecond");
    }
  }
});

test("focus_pipeline.sql SELECT columns match FOCUS v1.0 Basin schema 1:1", () => {
  const schema = JSON.parse(fs.readFileSync(FOCUS_SCHEMA_PATH, "utf8"));
  const sql = fs.readFileSync(FOCUS_PIPELINE_SQL_PATH, "utf8");

  assert.match(sql, /INSERT INTO __SINK_NAME__/);
  assert.match(sql, /FROM __STREAM_NAME__;/);

  const selectMatch = sql.match(/SELECT\s+([\s\S]*?)\s+FROM __STREAM_NAME__;/);
  assert.ok(selectMatch, "Could not parse SELECT column list from focus_pipeline.sql");

  const sqlColumns = selectMatch[1]
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const schemaColumns = schema.fields.map((f) => f.name);

  assert.deepEqual(sqlColumns, schemaColumns);
});

test("FinOps monitoring SQL queries (DuckDB & Basin SQL dialects) deduplicate snapshots, separate cost_basis, avoid mixed-unit sums, and use strict 7-calendar-day baselines", () => {
  const duckdbSql = fs.readFileSync(FINOPS_SQL_PATH, "utf8");
  const basinSql = fs.readFileSync(FINOPS_BASIN_SQL_PATH, "utf8");

  for (const sql of [duckdbSql, basinSql]) {
    assert.match(sql, /FROM siem\.ocsf_event_log_activity/);
    assert.match(sql, /FROM finops\.focus_cost_and_usage/);
    assert.match(sql, /estimated_usd/);
    assert.match(sql, /estimated_waste_usd/);
    assert.match(sql, /approx_payload_mib/);
    assert.match(sql, /max_snapshot_ts_ms/);
    assert.match(sql, /GROUP BY ProviderName, BillingAccountId, dataset, charge_day/);
    assert.match(sql, /cost_basis = 'billed_usage'/);
    assert.match(sql, /INTERVAL '7' DAY/);
    assert.match(sql, /spike_ratio/);
    assert.doesNotMatch(sql, /ROWS BETWEEN 7 PRECEDING/);

    // Query 6 (resource cost ranking) must not sum ConsumedQuantity across incompatible units
    const q6Match = sql.match(/-- 6\. Top cost-bearing resources[\s\S]*?-- 7\./);
    assert.ok(q6Match, "Could not locate Query 6 block");
    assert.doesNotMatch(q6Match[0], /SUM\(ConsumedQuantity\)/);
  }

  assert.match(duckdbSql, /json_extract_string\(/);
  assert.doesNotMatch(duckdbSql, /json_get_str\(/);

  assert.match(basinSql, /json_get_str\(/);
  assert.match(basinSql, /json_get_int\(/);
  assert.doesNotMatch(basinSql, /json_extract\(/);
  assert.doesNotMatch(basinSql, /TRY_CAST\(/);
});

test("Terraform and Pulumi IaC modules expose matching opt-in FinOps FOCUS resources without conditional type coercion", () => {
  const tfMain = fs.readFileSync(path.join(TERRAFORM_DIR, "main.tf"), "utf8");
  const tfVars = fs.readFileSync(path.join(TERRAFORM_DIR, "variables.tf"), "utf8");
  const tfOuts = fs.readFileSync(path.join(TERRAFORM_DIR, "outputs.tf"), "utf8");

  assert.match(tfVars, /variable "enable_finops"/);
  assert.match(tfMain, /focus_schema\s*=\s*var\.enable_finops\s*\?\s*jsondecode\(file\(local\.focus_schema_path\)\)\s*:\s*null/);
  assert.doesNotMatch(tfMain, /focus_schema\s*=.*\{\s*fields\s*=\s*\[\s*\]\s*\}/);
  assert.match(tfMain, /resource "restful_resource" "focus_stream"/);
  assert.match(tfMain, /resource "cloudflare_pipeline_sink" "focus"/);
  assert.match(tfMain, /resource "cloudflare_pipeline" "focus"/);
  assert.match(tfMain, /contracts\/focus\/cost-and-usage\.basin\.json/);
  assert.match(tfMain, /focus_pipeline\.sql/);
  assert.match(tfOuts, /output "focus_stream_endpoint"/);

  const pulumiIndex = fs.readFileSync(path.join(PULUMI_DIR, "index.ts"), "utf8");
  const pulumiCore = fs.readFileSync(path.join(PULUMI_DIR, "basin-core.ts"), "utf8");

  assert.match(pulumiCore, /contracts\/focus\/cost-and-usage\.basin\.json/);
  assert.match(pulumiCore, /focus_pipeline\.sql/);
  assert.match(pulumiIndex, /enableFinops/);
  assert.match(pulumiIndex, /oof-focus-stream/);
  assert.match(pulumiIndex, /oof-focus-sink/);
  assert.match(pulumiIndex, /oof-focus-pipeline/);
  assert.match(pulumiIndex, /export const focusStreamEndpoint/);
});

test("stack.schema.json supports focus schema profile and optional finops slot", () => {
  const stackSchema = JSON.parse(fs.readFileSync(STACK_SCHEMA_PATH, "utf8"));
  assert.ok(stackSchema.properties.schema.properties.profile.enum.includes("focus"));
  assert.ok(stackSchema.properties.finops, "stack.schema.json must define optional finops slot");
  assert.equal(stackSchema.properties.finops.properties.schema_profile.const, "focus");
  assert.deepEqual(stackSchema.properties.finops.properties.providers.items.enum, ["cloudflare", "github"]);
});

test("Cloudflare and GitHub FOCUS normalizers classify R2 free/unknown ops safely, separate list estimates from billed spend, and tag snapshots", () => {
  const schema = JSON.parse(fs.readFileSync(FOCUS_SCHEMA_PATH, "utf8"));
  const window = resolveUtcDayWindow("2026-11-22");
  const snapshotTsMs = 1795305600000;

  assert.equal(classifyR2Action("PutObject"), "A");
  assert.equal(classifyR2Action("GetObject"), "B");
  assert.equal(classifyR2Action("DeleteObject"), "free");
  assert.equal(classifyR2Action("DeleteBucket"), "free");
  assert.equal(classifyR2Action("AbortMultipartUpload"), "free");
  assert.equal(classifyR2Action("SomeFutureAction"), "unknown");

  const defaultQuery = buildCloudflareGraphqlQuery({ includePipelines: false });
  assert.match(defaultQuery, /r2StorageAdaptiveGroups/);
  assert.match(defaultQuery, /r2OperationsAdaptiveGroups/);
  assert.doesNotMatch(defaultQuery, /pipelinesOperatorAdaptiveGroups/);

  const withPipelinesQuery = buildCloudflareGraphqlQuery({ includePipelines: true });
  assert.match(withPipelinesQuery, /pipelinesOperatorAdaptiveGroups/);
  assert.match(withPipelinesQuery, /streamId_neq:\s*""/);
  assert.match(withPipelinesQuery, /pipelineId/);
  assert.match(withPipelinesQuery, /bytesIn/);

  const cfRecords = normalizeCloudflareAnalyticsToFocus(
    {
      data: {
        viewer: {
          accounts: [
            {
              r2StorageAdaptiveGroups: [
                {
                  dimensions: { bucketName: "oof-telemetry" },
                  max: { payloadSize: 30_000_000_000, metadataSize: 0 },
                },
              ],
              r2OperationsAdaptiveGroups: [
                { dimensions: { bucketName: "oof-telemetry", actionType: "PutObject" }, sum: { requests: 1_000_000 } },
                { dimensions: { bucketName: "oof-telemetry", actionType: "GetObject" }, sum: { requests: 2_000_000 } },
                { dimensions: { bucketName: "oof-telemetry", actionType: "DeleteObject" }, sum: { requests: 100_000 } },
                { dimensions: { bucketName: "oof-telemetry", actionType: "FutureUnknownAction" }, sum: { requests: 50_000 } },
              ],
              pipelinesOperatorAdaptiveGroups: [
                { dimensions: { pipelineId: "ocsf_event_log_to_iceberg" }, sum: { bytesIn: 4_000_000_000 } },
              ],
            },
          ],
        },
      },
    },
    {
      accountId: "0123456789abcdef0123456789abcdef",
      accountName: "oof-prod",
      window,
      pricing: DEFAULT_CLOUDFLARE_PRICING,
      snapshotTsMs,
    }
  );

  assert.equal(cfRecords.length, 6);
  for (const r of cfRecords) {
    assertFocusRecordMatchesSchema(r, schema.fields);
    // Analytics-derived Cloudflare rows must never report positive BilledCost / EffectiveCost
    assert.equal(r.BilledCost, 0);
    assert.equal(r.EffectiveCost, 0);
    assert.equal(r.Tags.cost_basis, "list_price_estimate");
    assert.equal(r.Tags.snapshot_ts_ms, snapshotTsMs);
  }

  const storageRec = cfRecords.find((r) => r.SkuId === "r2_storage_standard");
  const classARec = cfRecords.find((r) => r.SkuId === "r2_class_a_ops");
  const classBRec = cfRecords.find((r) => r.SkuId === "r2_class_b_ops");
  const freeRec = cfRecords.find((r) => r.SkuId === "r2_free_ops");
  const unknownRec = cfRecords.find((r) => r.SkuId === "r2_unclassified_ops");
  const pipeRec = cfRecords.find((r) => r.SkuId === "pipelines_stream_ingress_gb");

  assert.equal(storageRec.ListCost, 0.015);
  assert.equal(storageRec.ContractedCost, 0.015);
  assert.equal(storageRec.Tags.dataset, "cloudflare_r2");
  assert.equal(classARec.ListCost, 4.5);
  assert.equal(classARec.ContractedCost, 4.5);
  assert.equal(classBRec.ListCost, 0.72);
  assert.equal(classBRec.ContractedCost, 0.72);
  assert.equal(freeRec.ListCost, 0);
  assert.equal(freeRec.ContractedCost, 0);
  assert.equal(freeRec.ConsumedQuantity, 100_000);
  assert.equal(unknownRec.ListCost, 0);
  assert.equal(unknownRec.ContractedCost, 0);
  assert.equal(unknownRec.ConsumedQuantity, 50_000);
  // Pipelines stream ingress is free ($0) under Cloudflare Pipelines pricing
  assert.equal(pipeRec.ListCost, 0);
  assert.equal(pipeRec.ContractedCost, 0);
  assert.equal(pipeRec.ConsumedQuantity, 4);
  assert.equal(pipeRec.Tags.dataset, "cloudflare_pipelines");

  // Regression: R2-only rerun must not hide earlier Pipelines snapshot when deduplicating per dataset
  const r2OnlyRerun = normalizeCloudflareAnalyticsToFocus(
    {
      data: {
        viewer: {
          accounts: [
            {
              r2StorageAdaptiveGroups: [
                { dimensions: { bucketName: "oof-telemetry" }, max: { payloadSize: 60_000_000_000, metadataSize: 0 } },
              ],
              r2OperationsAdaptiveGroups: [],
            },
          ],
        },
      },
    },
    {
      accountId: "0123456789abcdef0123456789abcdef",
      accountName: "oof-prod",
      window,
      pricing: DEFAULT_CLOUDFLARE_PRICING,
      snapshotTsMs: snapshotTsMs + 60_000,
    }
  );
  const combined = [...cfRecords, ...r2OnlyRerun];
  const latestByDataset = new Map();
  for (const r of combined) {
    const key = `${r.ProviderName}::${r.BillingAccountId}::${r.Tags.dataset}::${r.ChargePeriodStart}`;
    const prev = latestByDataset.get(key) ?? -1;
    if (r.Tags.snapshot_ts_ms > prev) latestByDataset.set(key, r.Tags.snapshot_ts_ms);
  }
  const deduped = combined.filter((r) => {
    const key = `${r.ProviderName}::${r.BillingAccountId}::${r.Tags.dataset}::${r.ChargePeriodStart}`;
    return r.Tags.snapshot_ts_ms === latestByDataset.get(key);
  });
  assert.equal(deduped.filter((r) => r.Tags.dataset === "cloudflare_r2").length, 1);
  assert.equal(deduped.find((r) => r.Tags.dataset === "cloudflare_r2").ListCost, 0.03);
  assert.equal(deduped.filter((r) => r.Tags.dataset === "cloudflare_pipelines").length, 1);

  const ghRecords = normalizeGitHubBillingUsageToFocus(
    {
      usageItems: [
        {
          date: "2026-11-22T00:00:00Z",
          product: "actions",
          sku: "actions_linux",
          quantity: 120,
          unitType: "Minutes",
          pricePerUnit: 0.008,
          grossAmount: 0.96,
          discountAmount: 0.96,
          netAmount: 0.0,
          organizationName: "acme-org",
          repositoryName: "open-observability-framework",
        },
        {
          date: "2026-11-22T00:00:00Z",
          product: "actions",
          sku: "actions_macos",
          quantity: 10,
          unitType: "Minutes",
          pricePerUnit: 0.08,
          grossAmount: 0.8,
          discountAmount: 0,
          netAmount: 0.8,
          organizationName: "acme-org",
          repositoryName: "open-observability-framework",
        },
      ],
    },
    { billingAccountId: "acme-org", billingAccountName: "acme-org", window, snapshotTsMs }
  );

  assert.equal(ghRecords.length, 2);
  for (const r of ghRecords) {
    assertFocusRecordMatchesSchema(r, schema.fields);
    assert.equal(r.Tags.cost_basis, "billed_usage");
    assert.equal(r.Tags.snapshot_ts_ms, snapshotTsMs);
  }
  assert.equal(ghRecords[0].ListCost, 0.96);
  assert.equal(ghRecords[0].EffectiveCost, 0);
  assert.equal(ghRecords[1].EffectiveCost, 0.8);
  assert.equal(ghRecords[1].ServiceName, "GitHub Actions");
});

test("E2E FinOps collector fetches Cloudflare R2+Pipelines + GitHub APIs, gzips FOCUS v1.0 batch to Basin HTTP, and enforces HTTPS + secret hygiene", async () => {
  const schema = JSON.parse(fs.readFileSync(FOCUS_SCHEMA_PATH, "utf8"));
  const cfToken = "test-cf-token-0123456789abcdef0123456789";
  const ghToken = "test-github-token-0123456789abcdef";
  const basinToken = "test-basin-token-0123456789abcdef";

  let receivedGraphqlQuery = null;
  let receivedBasinAuth = null;
  let receivedBasinEncoding = null;
  let receivedBasinRecords = null;

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);

    if (req.method === "POST" && req.url === "/client/v4/graphql") {
      assert.equal(req.headers.authorization, `Bearer ${cfToken}`);
      const gqlBody = JSON.parse(rawBody.toString("utf8"));
      receivedGraphqlQuery = gqlBody.query;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          data: {
            viewer: {
              accounts: [
                {
                  r2StorageAdaptiveGroups: [
                    { dimensions: { bucketName: "oof-telemetry" }, max: { payloadSize: 15_000_000_000, metadataSize: 0 } },
                  ],
                  r2OperationsAdaptiveGroups: [
                    { dimensions: { bucketName: "oof-telemetry", actionType: "PutObject" }, sum: { requests: 500_000 } },
                    { dimensions: { bucketName: "oof-telemetry", actionType: "DeleteObject" }, sum: { requests: 100_000 } },
                  ],
                  pipelinesOperatorAdaptiveGroups: [
                    { dimensions: { pipelineId: "pipe-123" }, sum: { bytesIn: 2_000_000_000 } },
                  ],
                },
              ],
            },
          },
        })
      );
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/organizations/acme-org/settings/billing/usage?")) {
      assert.equal(req.headers.authorization, `Bearer ${ghToken}`);
      assert.match(req.url, /year=2026&month=11&day=22/);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          usageItems: [
            {
              date: "2026-11-22T00:00:00Z",
              product: "actions",
              sku: "actions_windows",
              quantity: 50,
              unitType: "Minutes",
              pricePerUnit: 0.016,
              grossAmount: 0.8,
              discountAmount: 0,
              netAmount: 0.8,
              organizationName: "acme-org",
              repositoryName: "oof-repo",
            },
          ],
        })
      );
      return;
    }

    if (req.method === "POST" && req.url === "/basin-focus") {
      receivedBasinAuth = req.headers.authorization;
      receivedBasinEncoding = req.headers["content-encoding"];
      const unzipped = zlib.gunzipSync(rawBody).toString("utf8");
      receivedBasinRecords = JSON.parse(unzipped);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. HTTPS must be enforced by default
    await assert.rejects(
      sendFocusToBasin([{ ProviderName: "Cloudflare" }], {
        endpoint: `${baseUrl}/basin-focus`,
        token: basinToken,
      }),
      /must use https:\/\//
    );

    // 2. Full E2E collection & ingest with Pipelines enabled
    const result = await runFinopsCollection({
      env: {
        OOF_FINOPS_DATE: "2026-11-22",
        OOF_CF_INCLUDE_PIPELINES: "true",
        CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
        CLOUDFLARE_API_TOKEN: cfToken,
        CLOUDFLARE_API_BASE_URL: `${baseUrl}/client/v4`,
        GITHUB_ORG: "acme-org",
        GITHUB_TOKEN: ghToken,
        GITHUB_API_BASE_URL: baseUrl,
        OOF_FOCUS_BASIN_ENDPOINT: `${baseUrl}/basin-focus`,
        OOF_INGEST_TOKEN: basinToken,
      },
      snapshotTsMs: 1795305600123,
      allowInsecureHttp: true,
    });

    assert.match(receivedGraphqlQuery, /pipelinesOperatorAdaptiveGroups/);
    assert.match(receivedGraphqlQuery, /streamId_neq:\s*""/);
    assert.match(receivedGraphqlQuery, /bytesIn/);
    assert.equal(result.status, 200);
    assert.equal(result.count, 5);
    assert.equal(receivedBasinAuth, `Bearer ${basinToken}`);
    assert.equal(receivedBasinEncoding, "gzip");
    assert.equal(receivedBasinRecords.length, 5);

    for (const rec of receivedBasinRecords) {
      assertFocusRecordMatchesSchema(rec, schema.fields);
      assert.equal(rec.Tags.snapshot_ts_ms, 1795305600123);
      assert.equal(typeof rec.ContractedCost, "number");
    }

    const providers = new Set(receivedBasinRecords.map((r) => r.ProviderName));
    assert.deepEqual(providers, new Set(["Cloudflare", "GitHub"]));
    assert.ok(
      receivedBasinRecords.some(
        (r) =>
          r.ServiceName === "Cloudflare Pipelines" &&
          r.SkuId === "pipelines_stream_ingress_gb" &&
          r.ConsumedQuantity === 2 &&
          r.ListCost === 0 &&
          r.ContractedCost === 0
      )
    );
    assert.ok(receivedBasinRecords.some((r) => r.SkuId === "r2_free_ops" && r.ListCost === 0));

    // 3. Error messages must never leak tokens
    await assert.rejects(
      async () => {
        await sendFocusToBasin(receivedBasinRecords, {
          endpoint: `${baseUrl}/nonexistent-404`,
          token: basinToken,
          allowInsecureHttp: true,
        });
      },
      (err) => {
        assert.ok(!err.message.includes(basinToken), "Ingest token leaked in error message");
        return /HTTP 404/.test(err.message);
      }
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
