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
const CF_AUDIT_POLLER_PATH = path.join(REPO_ROOT, "adapters/collect/cloudflare-audit-logs/poller.mjs");
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
  let failNext = false;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (failNext) {
        failNext = false;
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "simulated basin outage" }));
        return;
      }
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
  return {
    server,
    receivedEvents,
    setFailNext: (v) => {
      failNext = v;
    },
  };
}

test("Static contracts: Cloudflare SQL queries (explicit WAF actions) and IaC Logpush definitions", () => {
  const duckdbSql = fs.readFileSync(CF_SQL_DUCKDB_PATH, "utf8");
  const basinSql = fs.readFileSync(CF_SQL_BASIN_PATH, "utf8");
  for (const [label, sql] of [
    ["DuckDB", duckdbSql],
    ["Basin SQL", basinSql],
  ]) {
    assert.match(sql, /log_provider = 'cloudflare-audit-logs'/, `${label} query must filter cloudflare-audit-logs`);
    assert.match(sql, /log_provider = 'cloudflare-logpush'/, `${label} query must filter cloudflare-logpush`);
    assert.match(sql, /ROW_NUMBER\(\)\s+OVER\s*\(\s*PARTITION BY metadata\.original_event_uid/i, `${label} query must deduplicate audit logs`);
    assert.match(sql, /'managedchallenge'/, `${label} WAF report must explicitly include managedchallenge`);
    assert.match(sql, /'connectionclose'/, `${label} WAF report must explicitly include connectionclose`);
    assert.doesNotMatch(sql, /'log'/, `${label} enforced WAF report must not include log-only actions`);
  }
  assert.match(basinSql, /json_get_str\(/, "Basin SQL must use json_get_str");
  assert.match(duckdbSql, /json_extract_string\(/, "DuckDB SQL must use json_extract_string");

  const tfMain = fs.readFileSync(TF_MAIN_PATH, "utf8");
  assert.match(tfMain, /resource\s+"cloudflare_logpush_job"\s+"telemetry"/, "Terraform must define cloudflare_logpush_job.telemetry");

  const pulumiIndex = fs.readFileSync(PULUMI_INDEX_PATH, "utf8");
  assert.match(pulumiIndex, /new\s+cloudflare\.LogpushJob\(/, "Pulumi must define cloudflare.LogpushJob");
});

test("Cloudflare Audit Logs poller: multi-page burst pagination, checkpoint preservation on failure, and restart dedup", async () => {
  const mod = await import(pathToFileURL(CF_AUDIT_POLLER_PATH).href);
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8")).fields;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-cf-audit-poller-"));
  const checkpointPath = path.join(tmpDir, "checkpoint.json");

  const accountId = "0123456789abcdef0123456789abcdef";
  const basinToken = "e2e-basin-audit-token";
  const cfToken = "e2e-cf-audit-api-token";

  const basinPort = await getFreeLoopbackPort();
  const cfPort = await getFreeLoopbackPort();
  const { server: basinServer, receivedEvents, setFailNext } = startMockBasinServer(basinToken);
  await new Promise((resolve) => basinServer.listen(basinPort, "127.0.0.1", resolve));

  // 5 audit records across 3 pages (per_page=2), including one in the oldest minute of initial lookback (11:55:30Z)
  const allRecords = [
    { id: "audit-001", when: "2026-03-01T11:55:30Z", interface: "API", action: { type: "rec_add", result: true }, actor: { id: "u1", email: "alice@example.com", ip: "198.51.100.1", type: "user" }, owner: { id: accountId }, resource: { id: "r1", type: "DNS_record" } },
    { id: "audit-002", when: "2026-03-01T11:58:02Z", interface: "API", action: { type: "rec_add", result: true }, actor: { id: "u1", email: "alice@example.com", ip: "198.51.100.1", type: "user" }, owner: { id: accountId }, resource: { id: "r2", type: "DNS_record" } },
    { id: "audit-003", when: "2026-03-01T11:59:03Z", interface: "UI", action: { type: "delete", result: true }, actor: { id: "u2", email: "secops@example.com", ip: "198.51.100.2", type: "user" }, owner: { id: accountId }, resource: { id: "w1", type: "firewall_rule" } },
    { id: "audit-004", when: "2026-03-01T11:59:30Z", interface: "API", action: { type: "token_create", result: false }, actor: { id: "u3", email: "bob@example.com", ip: "203.0.113.5", type: "user" }, owner: { id: accountId }, resource: { id: "t1", type: "api_token" } },
    { id: "audit-005", when: "2026-03-01T12:01:58Z", interface: "API", action: { type: "rec_add", result: true }, actor: { id: "u1", email: "alice@example.com", ip: "198.51.100.1", type: "user" }, owner: { id: accountId }, resource: { id: "r5", type: "DNS_record" } },
  ];

  const cfServer = http.createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${cfToken}`);
    const u = new URL(req.url, `http://127.0.0.1:${cfPort}`);
    const page = Number(u.searchParams.get("page") || "1");
    const perPage = Number(u.searchParams.get("per_page") || "100");
    const sinceMs = Date.parse(u.searchParams.get("since"));
    const beforeMs = Date.parse(u.searchParams.get("before"));

    // Enforce Cloudflare's strict open-interval timestamp bounds (since < when < before)
    const filtered = allRecords.filter((r) => {
      const t = Date.parse(r.when);
      return t > sinceMs && t < beforeMs;
    });
    const totalPages = Math.ceil(filtered.length / perPage);
    const slice = filtered.slice((page - 1) * perPage, page * perPage);

    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        success: true,
        result: slice,
        result_info: { page, per_page: perPage, total_pages: totalPages, total_count: filtered.length },
      })
    );
  });
  await new Promise((resolve) => cfServer.listen(cfPort, "127.0.0.1", resolve));

  try {
    // 1. Startup Basin failure persists initialSince (11:55:00Z) without advancing lastBefore
    setFailNext(true);
    await assert.rejects(
      () =>
        mod.pollOnce({
          accountId,
          apiToken: cfToken,
          basinEndpoint: `http://127.0.0.1:${basinPort}/ingest`,
          ingestToken: basinToken,
          checkpointPath,
          apiBaseUrl: `http://127.0.0.1:${cfPort}/client/v4`,
          perPage: 2,
          initialLookbackSecs: 300,
          nowMs: Date.parse("2026-03-01T12:00:00.000Z"),
        }),
      /Basin HTTP ingest failed/
    );
    const failedCp = mod.loadCheckpoint(checkpointPath);
    assert.equal(failedCp.lastBefore, null, "lastBefore must remain null when startup upload fails");
    assert.equal(failedCp.initialSince, "2026-03-01T11:55:00.000Z", "initialSince must be persisted before first upload");

    // 2. Retry with advanced nowMs (12:02:00Z): reuses persisted initialSince so 11:55:30Z is NOT lost
    const res1 = await mod.pollOnce({
      accountId,
      apiToken: cfToken,
      basinEndpoint: `http://127.0.0.1:${basinPort}/ingest`,
      ingestToken: basinToken,
      checkpointPath,
      apiBaseUrl: `http://127.0.0.1:${cfPort}/client/v4`,
      perPage: 2,
      initialLookbackSecs: 300,
      nowMs: Date.parse("2026-03-01T12:02:00.000Z"),
    });
    assert.equal(res1.since, "2026-03-01T11:55:00.000Z");
    assert.equal(res1.pagesFetched, 3);
    assert.equal(res1.shipped, 5);
    assert.equal(receivedEvents.length, 5);
    for (const ev of receivedEvents) {
      validateOcsfRecordAgainstBasinSchema(ev, basinSchema);
      assert.equal(ev.log_provider, "cloudflare-audit-logs");
    }
    const ids1 = new Set(receivedEvents.map((e) => e.metadata.original_event_uid));
    assert.deepEqual(ids1, new Set(["audit-001", "audit-002", "audit-003", "audit-004", "audit-005"]));

    // 3. Strict boundary cutoff test: unseen record timestamped EXACTLY at previous cutoff (12:02:00.000Z)
    //    must be captured by overlap while already-seen audit-005 (12:01:58Z) is deduplicated.
    allRecords.push(
      { id: "audit-boundary", when: "2026-03-01T12:02:00.000Z", interface: "API", action: { type: "rec_add", result: true }, actor: { id: "u1", email: "alice@example.com", type: "user" }, owner: { id: accountId }, resource: { id: "r-bnd", type: "DNS_record" } },
      { id: "audit-006", when: "2026-03-01T12:02:30Z", interface: "API", action: { type: "rec_add", result: true }, actor: { id: "u1", email: "alice@example.com", type: "user" }, owner: { id: accountId }, resource: { id: "r6", type: "DNS_record" } }
    );
    const res2 = await mod.pollOnce({
      accountId,
      apiToken: cfToken,
      basinEndpoint: `http://127.0.0.1:${basinPort}/ingest`,
      ingestToken: basinToken,
      checkpointPath,
      apiBaseUrl: `http://127.0.0.1:${cfPort}/client/v4`,
      perPage: 2,
      nowMs: Date.parse("2026-03-01T12:03:00.000Z"),
    });
    assert.equal(res2.since, "2026-03-01T12:01:55.000Z", "Next window must overlap previous cutoff by 5s");
    assert.equal(res2.shipped, 2, "Must ship exact-boundary audit-boundary + audit-006 and skip duplicate audit-005");
    assert.equal(receivedEvents.length, 7);
    const ids2 = new Set(receivedEvents.map((e) => e.metadata.original_event_uid));
    assert.ok(ids2.has("audit-boundary"));
    assert.ok(ids2.has("audit-006"));

    // 4. High-volume burst (>2,000 events) inside the 5s overlap window across multiple pages:
    //    every overlap ID must be retained regardless of count so the next poll ships zero duplicates,
    //    and expired IDs outside the next overlap window are pruned.
    for (let i = 0; i < 2050; i += 1) {
      allRecords.push({
        id: `burst-${i}`,
        when: "2026-03-01T12:03:57.000Z",
        interface: "API",
        action: { type: "rec_add", result: true },
        actor: { id: "u1", email: "alice@example.com", type: "user" },
        owner: { id: accountId },
        resource: { id: `rb-${i}`, type: "DNS_record" },
      });
    }
    const resBurst = await mod.pollOnce({
      accountId,
      apiToken: cfToken,
      basinEndpoint: `http://127.0.0.1:${basinPort}/ingest`,
      ingestToken: basinToken,
      checkpointPath,
      apiBaseUrl: `http://127.0.0.1:${cfPort}/client/v4`,
      perPage: 1000,
      nowMs: Date.parse("2026-03-01T12:04:00.000Z"),
    });
    assert.equal(resBurst.pagesFetched, 3);
    assert.equal(resBurst.shipped, 2050);

    const cpAfterBurst = mod.loadCheckpoint(checkpointPath);
    assert.equal(cpAfterBurst.recentEntries.length, 2050, "All 2050 overlap-window IDs must be retained without 2000-item cap");

    // Next poll at 12:05:00Z overlaps back to 12:03:55Z (which includes all 2050 burst records at 12:03:57Z)
    const resAfterBurst = await mod.pollOnce({
      accountId,
      apiToken: cfToken,
      basinEndpoint: `http://127.0.0.1:${basinPort}/ingest`,
      ingestToken: basinToken,
      checkpointPath,
      apiBaseUrl: `http://127.0.0.1:${cfPort}/client/v4`,
      perPage: 1000,
      nowMs: Date.parse("2026-03-01T12:05:00.000Z"),
    });
    assert.equal(resAfterBurst.shipped, 0, "Zero duplicates must be re-uploaded from the 2050-event overlap burst");

    const cpAfterExpire = mod.loadCheckpoint(checkpointPath);
    assert.equal(cpAfterExpire.recentEntries.length, 0, "IDs older than the next overlap window must be expired");
  } finally {
    await new Promise((resolve) => cfServer.close(resolve));
    await new Promise((resolve) => basinServer.close(resolve));
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

    // Empty OOF_CLOUDFLARE_LOGPUSH_TOKEN must be rejected so Vector never boots with a blank Basic password
    const emptyPassVal = spawnSync(vectorBin, ["validate", "--no-environment", VECTOR_CF_LOGPUSH_PATH], {
      env: { ...env, OOF_CLOUDFLARE_LOGPUSH_TOKEN: "" },
      encoding: "utf8",
    });
    assert.notEqual(emptyPassVal.status, 0, "Empty OOF_CLOUDFLARE_LOGPUSH_TOKEN must fail Vector config validation");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Live E2E: Vector Cloudflare Logpush HTTP 401 auth boundary, compressed 'tests' probe drop, and OCSF v1.3.0 delivery", async () => {
  const vectorBin = requireBinary("vector");
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8")).fields;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-e2e-cf-logpush-"));

  const basinToken = "e2e-basin-token-lp";
  const logpushUser = "logpush";
  const logpushToken = "e2e-logpush-secret-xyz";
  const validAuthHeader = `Basic ${Buffer.from(`${logpushUser}:${logpushToken}`).toString("base64")}`;
  const wrongAuthHeader = `Basic ${Buffer.from(`${logpushUser}:wrong-token`).toString("base64")}`;

  const basinPort = await getFreeLoopbackPort();
  const logpushPort = await getFreeLoopbackPort();

  const { server: basinServer, receivedEvents } = startMockBasinServer(basinToken);
  await new Promise((resolve) => basinServer.listen(basinPort, "127.0.0.1", resolve));

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
      OOF_CLOUDFLARE_LOGPUSH_USER: logpushUser,
      OOF_CLOUDFLARE_LOGPUSH_TOKEN: logpushToken,
      OOF_CF_LOGPUSH_LISTEN: `127.0.0.1:${logpushPort}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    // 1. Missing or wrong credentials MUST return HTTP 401 at the HTTP boundary (so Cloudflare retries)
    await waitForCondition(
      async () => {
        try {
          const res = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
            method: "POST",
            headers: { "content-type": "application/x-ndjson" },
            body: JSON.stringify({ RayID: "no-auth-ray", EdgeResponseStatus: 200 }) + "\n",
          });
          return res.status === 401;
        } catch {
          return false;
        }
      },
      { timeoutMs: 12000, label: "Vector Logpush HTTP server returning 401 for missing credentials" }
    );

    const wrongRes = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
      method: "POST",
      headers: { "content-type": "application/x-ndjson", authorization: wrongAuthHeader },
      body: JSON.stringify({ RayID: "wrong-auth-ray", EdgeResponseStatus: 200 }) + "\n",
    });
    assert.equal(wrongRes.status, 401, "Wrong credentials must return HTTP 401");

    // 2. Documented compressed Cloudflare ownership probe `{"content":"tests"}` WITH dataset header
    //    must return HTTP 200 but emit ZERO records to Basin.
    const probeGz = zlib.gzipSync(Buffer.from('{"content":"tests"}\n', "utf8"));
    const probeRes = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
      method: "POST",
      headers: {
        "content-type": "application/x-ndjson",
        "content-encoding": "gzip",
        authorization: validAuthHeader,
        "x-cloudflare-dataset": "http_requests",
      },
      body: probeGz,
    });
    assert.equal(probeRes.status, 200, "Valid ownership probe must return HTTP 200");

    // 3. Valid gzipped NDJSON batch with HTTP, Firewall, Access, and Gateway DNS events
    const ndjsonLines =
      [
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
          RayID: "e2e-ray-waf-mc",
          Action: "managedchallenge",
          RuleID: "rule-999",
          Source: "firewallCustom",
          ClientIP: "203.0.113.55",
          ClientRequestHost: "app.example.com",
          Datetime: "2026-03-01T15:00:05.000Z",
        }),
        JSON.stringify({
          AppUUID: "app-uuid-99",
          AppDomain: "admin.example.com",
          Allowed: false,
          UserEmail: "intruder@example.org",
          IPAddress: "198.51.100.99",
          Country: "JP",
          CreatedAt: "2026-03-01T15:00:10.000Z",
        }),
      ].join("\n") + "\n";

    const gzBody = zlib.gzipSync(Buffer.from(ndjsonLines, "utf8"));
    const postRes = await fetch(`http://127.0.0.1:${logpushPort}/logpush/cloudflare`, {
      method: "POST",
      headers: {
        "content-type": "application/x-ndjson",
        "content-encoding": "gzip",
        authorization: validAuthHeader,
      },
      body: gzBody,
    });
    assert.equal(postRes.status, 200);

    await waitForCondition(() => receivedEvents.length >= 3, {
      timeoutMs: 12000,
      label: "Basin receiving 3 normalized Cloudflare Logpush OCSF events",
    });

    assert.equal(receivedEvents.length, 3, "Ownership probe and 401 requests must not reach Basin");
    for (const ev of receivedEvents) {
      validateOcsfRecordAgainstBasinSchema(ev, basinSchema);
      assert.equal(ev.log_provider, "cloudflare-logpush");
      assert.ok(!JSON.stringify(ev).includes(logpushToken), "Auth token must never leak into OCSF event");
    }

    const accessEv = receivedEvents.find((e) => e.unmapped.cloudflare_dataset === "access_requests");
    assert.ok(accessEv, "Access event must be present");
    assert.equal(accessEv.device.hostname, "admin.example.com");
    assert.equal(accessEv.unmapped.access_app_uid, "app-uuid-99");
    assert.equal(accessEv.unmapped.client_ip, "198.51.100.99");
    assert.equal(accessEv.unmapped.client_country, "JP");
  } finally {
    vecProc.kill("SIGTERM");
    await new Promise((resolve) => basinServer.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Cloudflare GraphQL Analytics Exporter: 11-zone batching (<=10/query), loopback enforcement, and live /metrics scrape", async () => {
  const mod = await import(pathToFileURL(CF_EXPORTER_PATH).href);

  // Enforce loopback-only listener by default
  assert.throws(() => mod.parseListenAddress("0.0.0.0:9199"), /loopback/);
  assert.throws(() => mod.parseListenAddress("[::]:9199"), /loopback/);
  assert.throws(() => mod.parseListenAddress("192.168.1.10:9199"), /loopback/);
  assert.deepEqual(mod.parseListenAddress("127.0.0.1:9199"), { host: "127.0.0.1", port: 9199 });
  assert.deepEqual(mod.parseListenAddress("[::1]:9199"), { host: "::1", port: 9199 });

  // Build 11 valid zones to exercise Cloudflare's 10-zone per-query limit
  const elevenSpec = Array.from({ length: 11 }, (_, i) => {
    const hex = i.toString(16).padStart(32, "0");
    return `zone${i + 1}=${hex}`;
  }).join(",");
  const zones = mod.parseZoneSpecs(elevenSpec);
  assert.equal(zones.length, 11);

  // Verify hourly dataset support for Cloudflare Free plans (httpRequests1hGroups)
  const hourlyPayload = mod.buildGraphqlPayload(zones.slice(0, 1), {
    nowMs: Date.UTC(2026, 10, 27, 1, 34, 56),
    windowMinutes: 60,
    dataset: "httpRequests1hGroups",
  });
  assert.match(hourlyPayload.query, /\bhttpRequests1hGroups\(/);
  assert.equal(hourlyPayload.variables.since, "2026-11-27T00:00:00.000Z");
  assert.equal(hourlyPayload.variables.until, "2026-11-27T01:00:00.000Z");

  const hourlyAgg = mod.aggregateZoneAnalytics(
    {
      data: {
        viewer: {
          zones: [
            {
              zoneTag: zones[0].zoneId,
              httpRequests1hGroups: [
                {
                  sum: {
                    requests: 42,
                    cachedRequests: 10,
                    encryptedRequests: 40,
                    threats: 1,
                    bytes: 12345,
                    cachedBytes: 2345,
                    responseStatusMap: [{ edgeResponseStatus: 200, requests: 42 }],
                  },
                },
              ],
            },
          ],
        },
      },
    },
    zones.slice(0, 1)
  );
  assert.equal(hourlyAgg[0].requests, 42);
  assert.equal(hourlyAgg[0].status2xx, 42);

  assert.throws(
    () => mod.buildGraphqlPayload(zones.slice(0, 1), { dataset: "httpRequests1dGroups" }),
    /Unsupported OOF_CF_EXPORTER_DATASET/
  );
  assert.throws(
    () =>
      mod.createExporterServer({
        apiToken: "mock-gql-token",
        zoneEntries: zones.slice(0, 1),
        dataset: "httpRequests1HGroups",
      }),
    /Unsupported OOF_CF_EXPORTER_DATASET/
  );

  const gqlRequests = [];
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
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const tags = body.variables.zoneTags;
      gqlRequests.push({ count: tags.length, since: body.variables.since, until: body.variables.until });

      // Enforce Cloudflare global limit of at most 10 zones per GraphQL query
      if (tags.length > 10) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ errors: [{ message: "cannot query more than 10 zones at once" }] }));
        return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          data: {
            viewer: {
              zones: tags.map((tag, idx) => ({
                zoneTag: tag,
                httpRequests1mGroups: [
                  {
                    sum: {
                      requests: 100 + idx,
                      cachedRequests: 80,
                      encryptedRequests: 100,
                      threats: 2,
                      bytes: 50000,
                      cachedBytes: 40000,
                      responseStatusMap: [
                        { edgeResponseStatus: 200, requests: 95 },
                        { edgeResponseStatus: 404, requests: 3 },
                        { edgeResponseStatus: 502, requests: 2 },
                      ],
                    },
                  },
                ],
              })),
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
    zoneEntries: zones,
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

    assert.equal(gqlRequests.length, 2, "11 zones must be batched into 2 GraphQL requests (10 + 1)");
    assert.equal(gqlRequests[0].count, 10);
    assert.equal(gqlRequests[1].count, 1);
    assert.equal(gqlRequests[0].since, gqlRequests[1].since, "Batches must share identical since timestamp");
    assert.equal(gqlRequests[0].until, gqlRequests[1].until, "Batches must share identical until timestamp");

    assert.match(okBody, /cloudflare_zone_requests_total\{zone="zone1"\} 100/);
    assert.match(okBody, /cloudflare_zone_requests_total\{zone="zone11"\} 100/);
    assert.match(okBody, /cloudflare_graphql_scrape_success 1/);

    failUpstream = true;
    const errRes = await fetch(`http://127.0.0.1:${expPort}/metrics`);
    assert.equal(errRes.status, 200);
    const errBody = await errRes.text();
    assert.match(errBody, /cloudflare_graphql_scrape_success 0/);
    assert.doesNotMatch(errBody, /cloudflare_zone_requests_total\{zone="zone1"\}/);
  } finally {
    await new Promise((resolve) => exporterServer.close(resolve));
    await new Promise((resolve) => gqlServer.close(resolve));
  }
});
