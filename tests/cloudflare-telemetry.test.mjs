import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import zlib from "node:zlib";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const BASIN_SCHEMA_PATH = path.join(REPO_ROOT, "contracts/ocsf/event-log-activity.basin.json");
const VECTOR_CF_AUDIT_PATH = path.join(REPO_ROOT, "adapters/collect/vector-cloudflare-audit-logs/vector.yaml");
const VECTOR_CF_LOGPUSH_PATH = path.join(REPO_ROOT, "adapters/collect/vector-cloudflare-logpush/vector.yaml");
const CF_EXPORTER_PATH = path.join(REPO_ROOT, "adapters/collect/cloudflare-graphql-exporter/exporter.mjs");
const CF_SQL_DUCKDB_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/cloudflare_monitoring.sql");
const CF_SQL_BASIN_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/cloudflare_monitoring.basin.sql");
const TF_MAIN_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/terraform/main.tf");
const PULUMI_INDEX_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pulumi/index.ts");

function requireBinary(name) {
  const pathEntries = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathEntries) {
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // continue
    }
  }
  throw new Error(`Required test runtime binary '${name}' is not in PATH`);
}

async function getFreeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
}

async function waitForCondition(fn, { timeoutMs = 15000, intervalMs = 150, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const val = await fn();
      if (val) return val;
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  const detail = lastError ? ` (last error: ${lastError.message})` : "";
  throw new Error(`Timed out waiting for ${label} after ${timeoutMs}ms${detail}`);
}

function validateOcsfRecordAgainstBasinSchema(record, schemaFields) {
  assert.equal(typeof record, "object");
  assert.ok(record !== null && !Array.isArray(record));
  const allowedTop = new Set(schemaFields.map((f) => f.name));
  for (const key of Object.keys(record)) {
    assert.ok(allowedTop.has(key), `Unexpected non-OCSF top-level field '${key}'`);
  }
  for (const field of schemaFields) {
    if (field.required) {
      assert.ok(record[field.name] !== undefined && record[field.name] !== null, `Missing required OCSF field '${field.name}'`);
    }
  }
  assert.equal(record.category_uid, 1);
  assert.equal(record.class_uid, 1008);
  assert.equal(record.activity_id, 99);
  assert.equal(record.type_uid, 100899);
  assert.equal(record.metadata.version, "1.3.0");
  assert.equal(typeof record.time, "number");
  assert.match(record.time_dt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
}

function startMockBasinServer(expectedToken) {
  const receivedEvents = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        assert.equal(req.headers.authorization, `Bearer ${expectedToken}`);
        let raw = Buffer.concat(chunks);
        if ((req.headers["content-encoding"] || "").toLowerCase() === "gzip") {
          raw = zlib.gunzipSync(raw);
        }
        const parsed = JSON.parse(raw.toString("utf8"));
        const batch = Array.isArray(parsed) ? parsed : [parsed];
        receivedEvents.push(...batch);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
  });
  return { server, receivedEvents };
}

test("Static contracts: Cloudflare SQL queries and IaC Logpush definitions", () => {
  const duckdbSql = fs.readFileSync(CF_SQL_DUCKDB_PATH, "utf8");
  const basinSql = fs.readFileSync(CF_SQL_BASIN_PATH, "utf8");
  for (const [label, sql] of [
    ["DuckDB", duckdbSql],
    ["Basin SQL", basinSql],
  ]) {
    assert.match(sql, /log_provider = 'cloudflare-audit-logs'/, `${label} query must filter cloudflare-audit-logs`);
    assert.match(sql, /log_provider = 'cloudflare-logpush'/, `${label} query must filter cloudflare-logpush`);
    assert.match(sql, /ROW_NUMBER\(\)\s+OVER\s*\(\s*PARTITION BY metadata\.original_event_uid/i, `${label} query must deduplicate audit logs`);
  }
  assert.match(basinSql, /json_get_str\(/, "Basin SQL must use json_get_str");
  assert.match(duckdbSql, /json_extract_string\(/, "DuckDB SQL must use json_extract_string");

  const tfMain = fs.readFileSync(TF_MAIN_PATH, "utf8");
  assert.match(tfMain, /resource\s+"cloudflare_logpush_job"\s+"telemetry"/, "Terraform must define cloudflare_logpush_job.telemetry");

  const pulumiIndex = fs.readFileSync(PULUMI_INDEX_PATH, "utf8");
  assert.match(pulumiIndex, /new\s+cloudflare\.LogpushJob\(/, "Pulumi must define cloudflare.LogpushJob");
});

test("Vector Cloudflare Audit Logs: validate + built-in VRL unit tests", () => {
  const vectorBin = requireBinary("vector");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vec-cf-audit-"));
  try {
    const env = {
      ...process.env,
      VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
      OOF_VECTOR_DATA_DIR: tmpDir,
      OOF_BASIN_ENDPOINT: "https://example.ingest.cloudflare.com",
      OOF_INGEST_TOKEN: "dummy-ingest-token",
      OOF_CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
      OOF_CLOUDFLARE_API_TOKEN: "dummy-cf-api-token",
    };

    const val = spawnSync(vectorBin, ["validate", "--no-environment", VECTOR_CF_AUDIT_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(val.status, 0, `vector validate failed:\n${val.stdout}\n${val.stderr}`);

    const tst = spawnSync(vectorBin, ["test", VECTOR_CF_AUDIT_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(tst.status, 0, `vector test failed:\n${tst.stdout}\n${tst.stderr}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Vector Cloudflare Logpush: validate + built-in VRL unit tests", () => {
  const vectorBin = requireBinary("vector");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vec-cf-logpush-"));
  try {
    const env = {
      ...process.env,
      VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
      OOF_VECTOR_DATA_DIR: tmpDir,
      OOF_BASIN_ENDPOINT: "https://example.ingest.cloudflare.com",
      OOF_INGEST_TOKEN: "dummy-ingest-token",
      OOF_CLOUDFLARE_LOGPUSH_TOKEN: "test-logpush-secret",
      OOF_CF_LOGPUSH_LISTEN: "127.0.0.1:8089",
    };

    const val = spawnSync(vectorBin, ["validate", "--no-environment", VECTOR_CF_LOGPUSH_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(val.status, 0, `vector validate failed:\n${val.stdout}\n${val.stderr}`);

    const tst = spawnSync(vectorBin, ["test", VECTOR_CF_LOGPUSH_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(tst.status, 0, `vector test failed:\n${tst.stdout}\n${tst.stderr}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Live E2E: Vector Cloudflare Logpush auth filter + gzipped NDJSON -> OCSF v1.3.0 -> Basin HTTP", async () => {
  const vectorBin = requireBinary("vector");
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8")).fields;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-e2e-cf-logpush-"));

  const basinToken = "e2e-basin-token-lp";
  const logpushToken = "e2e-logpush-secret-xyz";
  const basinPort = await getFreeLoopbackPort();
  const logpushPort = await getFreeLoopbackPort();

  const { server: basinServer, receivedEvents } = startMockBasinServer(basinToken);
  await new Promise((resolve) => basinServer.listen(basinPort, "127.0.0.1", resolve));

  // Speed up batch timeout for E2E
  const rawYaml = fs.readFileSync(VECTOR_CF_LOGPUSH_PATH, "utf8").replace("timeout_secs: 5", "timeout_secs: 1");
  const tmpCfg = path.join(tmpDir, "vector.yaml");
  fs.writeFileSync(tmpCfg, rawYaml, "utf8");

  const vecProc = spawn(vectorBin, ["--config", tmpCfg], {
    env: {
      ...process.env,
      VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
      OOF_VECTOR_DATA_DIR: path.join(tmpDir, "data"),
      OOF_BASIN_ENDPOINT: `http://127.0.0.1:${basinPort}/ingest`,
      OOF_INGEST_TOKEN: basinToken,
      OOF_CLOUDFLARE_LOGPUSH_TOKEN: logpushToken,
      OOF_CF_LOGPUSH_LISTEN: `127.0.0.1:${logpushPort}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    // Wait for Vector HTTP server to accept connections
    await waitForCondition(
      async () => {
        try {
          const res = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
            method: "POST",
            headers: { "content-type": "application/x-ndjson", "x-oof-logpush-token": "wrong-token" },
            body: JSON.stringify({ RayID: "rejected-ray", EdgeResponseStatus: 200 }) + "\n",
          });
          return res.status === 200;
        } catch {
          return false;
        }
      },
      { timeoutMs: 12000, label: "Vector Logpush HTTP server readiness" }
    );

    // Send gzipped NDJSON batch with valid token (includes ownership probe + 2 real events)
    const ndjsonLines = [
      JSON.stringify({ content: "test" }),
      JSON.stringify({
        RayID: "e2e-ray-http-500",
        ClientIP: "198.51.100.77",
        ClientRequestHost: "api.example.com",
        ClientRequestMethod: "GET",
        ClientRequestURI: "/health",
        EdgeResponseStatus: 503,
        CacheCacheStatus: "miss",
        EdgeColoCode: "NRT",
        EdgeStartTimestamp: "2026-03-01T15:00:00.000Z",
      }),
      JSON.stringify({
        RayID: "e2e-ray-waf-block",
        Action: "block",
        RuleID: "rule-999",
        Source: "firewallCustom",
        ClientIP: "203.0.113.55",
        ClientRequestHost: "app.example.com",
        Datetime: "2026-03-01T15:00:05.000Z",
      }),
    ].join("\n") + "\n";

    const gzBody = zlib.gzipSync(Buffer.from(ndjsonLines, "utf8"));
    const postRes = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
      method: "POST",
      headers: {
        "content-type": "application/x-ndjson",
        "content-encoding": "gzip",
        "x-oof-logpush-token": logpushToken,
      },
      body: gzBody,
    });
    assert.equal(postRes.status, 200);

    await waitForCondition(() => receivedEvents.length >= 2, {
      timeoutMs: 12000,
      label: "Basin receiving 2 normalized Cloudflare Logpush OCSF events",
    });

    assert.equal(receivedEvents.length, 2, "Probe and unauthenticated events must be dropped");
    for (const ev of receivedEvents) {
      validateOcsfRecordAgainstBasinSchema(ev, basinSchema);
      assert.equal(ev.log_provider, "cloudflare-logpush");
      assert.ok(!JSON.stringify(ev).includes(logpushToken), "Auth token must never leak into OCSF event");
    }
    const rayIds = new Set(receivedEvents.map((e) => e.metadata.original_event_uid));
    assert.ok(rayIds.has("e2e-ray-http-500"));
    assert.ok(rayIds.has("e2e-ray-waf-block"));
    assert.ok(!rayIds.has("rejected-ray"));
  } finally {
    vecProc.kill("SIGTERM");
    await new Promise((resolve) => basinServer.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Cloudflare GraphQL Analytics Exporter: unit + live HTTP /metrics scrape", async () => {
  const mod = await import(pathToFileURL(CF_EXPORTER_PATH).href);
  const zones = mod.parseZoneSpecs("prod=0123456789abcdef0123456789abcdef,fedcba9876543210fedcba9876543210");
  assert.equal(zones.length, 2);
  assert.equal(zones[0].alias, "prod");
  assert.equal(zones[1].alias, "fedcba9876543210fedcba9876543210");

  const payload = mod.buildGraphqlPayload(zones, { nowMs: Date.parse("2026-03-01T12:05:30Z"), windowMinutes: 5 });
  assert.deepEqual(payload.variables.zoneTags, [
    "0123456789abcdef0123456789abcdef",
    "fedcba9876543210fedcba9876543210",
  ]);
  assert.equal(payload.variables.since, "2026-03-01T12:00:00.000Z");
  assert.equal(payload.variables.until, "2026-03-01T12:05:00.000Z");

  // Mock Cloudflare GraphQL server
  let failUpstream = false;
  const gqlPort = await getFreeLoopbackPort();
  const gqlServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (failUpstream) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ errors: [{ message: "simulated outage" }] }));
        return;
      }
      assert.equal(req.headers.authorization, "Bearer mock-gql-token");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          data: {
            viewer: {
              zones: [
                {
                  zoneTag: "0123456789abcdef0123456789abcdef",
                  httpRequests1mGroups: [
                    {
                      sum: {
                        requests: 120,
                        cachedRequests: 90,
                        encryptedRequests: 118,
                        threats: 3,
                        bytes: 500000,
                        cachedBytes: 400000,
                        responseStatusMap: [
                          { edgeResponseStatus: 200, requests: 110 },
                          { edgeResponseStatus: 404, requests: 7 },
                          { edgeResponseStatus: 502, requests: 3 },
                        ],
                      },
                    },
                  ],
                },
              ],
            },
          },
        })
      );
    });
  });
  await new Promise((resolve) => gqlServer.listen(gqlPort, "127.0.0.1", resolve));

  const expPort = await getFreeLoopbackPort();
  const exporterServer = mod.createExporterServer({
    apiToken: "mock-gql-token",
    zoneEntries: [zones[0]],
    graphqlEndpoint: `http://127.0.0.1:${gqlPort}/graphql`,
    windowMinutes: 5,
    cacheTtlSecs: 0,
  });
  await new Promise((resolve) => exporterServer.listen(expPort, "127.0.0.1", resolve));

  try {
    const healthRes = await fetch(`http://127.0.0.1:${expPort}/healthz`);
    assert.equal(healthRes.status, 200);

    const okRes = await fetch(`http://127.0.0.1:${expPort}/metrics`);
    assert.equal(okRes.status, 200);
    const okBody = await okRes.text();
    assert.match(okBody, /cloudflare_zone_requests_total\{zone="prod"\} 120/);
    assert.match(okBody, /cloudflare_zone_requests_cached\{zone="prod"\} 90/);
    assert.match(okBody, /cloudflare_zone_threats_total\{zone="prod"\} 3/);
    assert.match(okBody, /cloudflare_zone_requests_status_2xx\{zone="prod"\} 110/);
    assert.match(okBody, /cloudflare_zone_requests_status_4xx\{zone="prod"\} 7/);
    assert.match(okBody, /cloudflare_zone_requests_status_5xx\{zone="prod"\} 3/);
    assert.match(okBody, /cloudflare_graphql_scrape_success 1/);

    // Simulate upstream failure
    failUpstream = true;
    const errRes = await fetch(`http://127.0.0.1:${expPort}/metrics`);
    assert.equal(errRes.status, 200);
    const errBody = await errRes.text();
    assert.match(errBody, /cloudflare_graphql_scrape_success 0/);
    assert.doesNotMatch(errBody, /cloudflare_zone_requests_total\{zone="prod"\}/);
  } finally {
    await new Promise((resolve) => exporterServer.close(resolve));
    await new Promise((resolve) => gqlServer.close(resolve));
  }
});
