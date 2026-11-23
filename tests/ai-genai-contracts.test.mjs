import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import zlib from "node:zlib";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const AI_SCHEMA_PATH = path.join(REPO_ROOT, "contracts/otel-genai/genai-usage.basin.json");
const AI_PIPELINE_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pipeline_ai_usage.sql");
const AI_QUERIES_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/ai_coding_agents.sql");
const STACK_SCHEMA_PATH = path.join(REPO_ROOT, "manifest/stack.schema.json");
const AI_MANIFEST_EXAMPLE_PATH = path.join(REPO_ROOT, "manifest/examples/cloudflare-basin-ai-coding-agents.yaml");
const VECTOR_AI_CONFIG_PATH = path.join(REPO_ROOT, "adapters/collect/vector-ai-coding-agents/vector.yaml");

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
const ALLOWED_TIMESTAMP_UNITS = new Set(["second", "millisecond", "microsecond", "nanosecond"]);

function validateBasinFields(fields, depth = 0) {
  assert.ok(Array.isArray(fields) && fields.length > 0, `fields at depth ${depth} must be non-empty array`);
  const seen = new Set();
  for (const field of fields) {
    assert.equal(typeof field.name, "string");
    assert.ok(field.name.length > 0);
    assert.ok(!seen.has(field.name), `duplicate field '${field.name}' at depth ${depth}`);
    seen.add(field.name);
    assert.equal(typeof field.required, "boolean", `field '${field.name}' must specify boolean required`);
    assert.ok(ALLOWED_BASIN_TYPES.has(field.type), `field '${field.name}' has invalid Basin type '${field.type}'`);
    if (field.type === "timestamp") {
      assert.ok(ALLOWED_TIMESTAMP_UNITS.has(field.unit), `timestamp field '${field.name}' requires valid unit`);
    }
    if (field.type === "struct") {
      assert.ok(depth < 2, `struct field '${field.name}' exceeds Basin max nesting depth <= 2`);
      validateBasinFields(field.fields, depth + 1);
    }
  }
}

function findBinary(name) {
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
  return null;
}

test("OTel GenAI Basin schema conforms to Basin field and nesting rules", () => {
  const schema = JSON.parse(fs.readFileSync(AI_SCHEMA_PATH, "utf8"));
  validateBasinFields(schema.fields);
  const topNames = schema.fields.map((f) => f.name);
  for (const req of ["time", "event_name", "operation_name", "status", "service", "host", "gen_ai"]) {
    assert.ok(topNames.includes(req), `missing required top-level field '${req}'`);
  }
});

test("pipeline_ai_usage.sql SELECT columns match genai-usage.basin.json in strict lockstep", () => {
  const schema = JSON.parse(fs.readFileSync(AI_SCHEMA_PATH, "utf8"));
  const expectedCols = schema.fields.map((f) => f.name);
  const sql = fs.readFileSync(AI_PIPELINE_SQL_PATH, "utf8");
  const m = sql.match(/INSERT\s+INTO\s+__SINK_NAME__\s+SELECT\s+([\s\S]+?)\s+FROM\s+__STREAM_NAME__\s*;/i);
  assert.ok(m, "pipeline_ai_usage.sql must contain INSERT INTO __SINK_NAME__ SELECT ... FROM __STREAM_NAME__;");
  const sqlCols = m[1]
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);
  assert.deepEqual(sqlCols, expectedCols);
});

test("ai_coding_agents.sql references ai.genai_usage and OCSF correlation join", () => {
  const sql = fs.readFileSync(AI_QUERIES_SQL_PATH, "utf8");
  assert.ok(sql.includes("FROM ai.genai_usage"), "queries must target ai.genai_usage");
  assert.ok(sql.includes("codex.websocket_request"), "daily rollup must count Codex WebSocket requests");
  assert.ok(
    sql.includes("siem.ocsf_event_log_activity"),
    "queries must include SIEM correlation query against siem.ocsf_event_log_activity"
  );
});

test("stack.schema.json defines optional ai slot and example manifest references valid paths", () => {
  const stackSchema = JSON.parse(fs.readFileSync(STACK_SCHEMA_PATH, "utf8"));
  assert.ok(stackSchema.properties.ai, "stack.schema.json must define ai slot");
  assert.ok(!stackSchema.required.includes("ai"), "ai slot must remain optional for backwards compatibility");

  const manifestYaml = fs.readFileSync(AI_MANIFEST_EXAMPLE_PATH, "utf8");
  assert.match(manifestYaml, /schema_profile:\s*otel-genai/);
  assert.match(manifestYaml, /capture_content:\s*none/);
  assert.match(manifestYaml, /contract_path:\s*contracts\/otel-genai\/genai-usage\.basin\.json/);
  assert.match(manifestYaml, /collector_adapter:\s*vector-ai-coding-agents/);
});

test("vector-ai-coding-agents config obeys comment interpolation safety and passes vector validate/test when available", (t) => {
  const raw = fs.readFileSync(VECTOR_AI_CONFIG_PATH, "utf8");
  for (const [idx, line] of raw.split("\n").entries()) {
    if (line.trimStart().startsWith("#")) {
      assert.ok(
        !/\$\{[^}]+\}/.test(line),
        `vector-ai-coding-agents/vector.yaml:${idx + 1} must not contain raw braced env placeholder in comment`
      );
    }
  }

  const vectorBin = findBinary("vector");
  if (!vectorBin) {
    t.skip("vector binary not in PATH; run inside `nix develop` to execute live vector validate/test");
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vector-ai-"));
  const env = {
    ...process.env,
    VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
    OOF_VECTOR_AI_DATA_DIR: tmpDir,
    OOF_AI_BASIN_ENDPOINT: "https://example.ingest.cloudflare.com",
    OOF_AI_INGEST_TOKEN: "dummy-token-for-validation",
    OOF_AI_OTLP_AUTH_TOKEN: "dummy-local-otlp-auth-token",
  };
  try {
    const val = spawnSync(vectorBin, ["validate", "--no-environment", VECTOR_AI_CONFIG_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(val.status, 0, `vector validate failed:\n${val.stdout}\n${val.stderr}`);

    const tst = spawnSync(vectorBin, ["test", VECTOR_AI_CONFIG_PATH], {
      env,
      encoding: "utf8",
    });
    assert.equal(tst.status, 0, `vector test (capture_content=none) failed:\n${tst.stdout}\n${tst.stderr}`);

    // Also verify opt-in OOF_AI_CAPTURE_CONTENT=redacted redacts secrets/emails and preserves thinking/arg stripping
    const baseWithoutTests = raw.split(/\ntests:\n/)[0];
    const redactedTestConfig = `${baseWithoutTests}
tests:
  - name: redacted_mode_masks_secrets_in_claude_prompt
    inputs:
      - insert_at: genai_otlp_logs
        type: log
        log_fields:
          timestamp: "2026-11-23T03:10:00Z"
          resources:
            service.name: "claude-code"
          attributes:
            event.name: "claude_code.user_prompt"
            session.id: "sess-redact-1"
            prompt: "Use Bearer mySuperSecretToken123 and sk-1234567890abcdef123456 for dev@example.com"
    outputs:
      - extract_from: genai_content_policy
        conditions:
          - type: vrl
            source: |
              assert_eq!(.attributes.capture_content, "redacted")
              p = string!(.attributes.prompt)
              assert!(contains(p, "Bearer [REDACTED]"))
              assert!(contains(p, "[REDACTED_SECRET]"))
              assert!(contains(p, "[REDACTED_EMAIL]"))
              assert!(!contains(p, "mySuperSecretToken123"))
              assert!(!contains(p, "sk-1234567890abcdef123456"))
              assert!(!contains(p, "dev@example.com"))
              assert!(!exists(._raw_prompt))

  - name: redacted_mode_captures_pi_user_prompt_and_strips_thinking
    inputs:
      - insert_at: genai_pi_parse
        type: log
        log_fields:
          host: "dev-workstation"
          file: "/home/dev/.pi/agent/sessions/--repo--/2026-11-23T03-10-00_def67890.jsonl"
          message: '{"type":"message","timestamp":"2026-11-23T03:10:00Z","message":{"role":"user","content":"Fix login for alice@example.com with ghp_1234567890abcdefghij1234"}}'
    outputs:
      - extract_from: genai_content_policy
        conditions:
          - type: vrl
            source: |
              assert_eq!(.event_name, "pi.user_message")
              assert_eq!(.attributes.capture_content, "redacted")
              p = string!(.attributes.prompt)
              assert!(contains(p, "[REDACTED_EMAIL]"))
              assert!(contains(p, "[REDACTED_SECRET]"))
              assert!(!contains(p, "alice@example.com"))
              assert!(!contains(p, "ghp_1234567890abcdefghij1234"))

  - name: redacted_mode_captures_codex_agent_response
    inputs:
      - insert_at: genai_otlp_logs
        type: log
        log_fields:
          timestamp: "2026-11-23T03:11:00Z"
          resources:
            service.name: "codex-cli"
          attributes:
            event.name: "codex.agent_response"
            conversation.id: "conv-redact-1"
            response: "Done! Contact bob@example.com with Bearer topSecretToken999"
    outputs:
      - extract_from: genai_content_policy
        conditions:
          - type: vrl
            source: |
              assert_eq!(.operation_name, "chat")
              assert_eq!(.attributes.capture_content, "redacted")
              c = string!(.attributes.completion)
              assert!(contains(c, "[REDACTED_EMAIL]"))
              assert!(contains(c, "Bearer [REDACTED]"))
              assert!(!contains(c, "bob@example.com"))
              assert!(!contains(c, "topSecretToken999"))
`;
    const redactedCfgPath = path.join(tmpDir, "vector-redacted-test.yaml");
    fs.writeFileSync(redactedCfgPath, redactedTestConfig, "utf8");
    const tstRedacted = spawnSync(vectorBin, ["test", redactedCfgPath], {
      env: { ...env, OOF_AI_CAPTURE_CONTENT: "redacted" },
      encoding: "utf8",
    });
    assert.equal(
      tstRedacted.status,
      0,
      `vector test (capture_content=redacted) failed:\n${tstRedacted.stdout}\n${tstRedacted.stderr}`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
  });
}

async function waitForPort(port, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const sock = net.connect({ host: "127.0.0.1", port }, () => {
        sock.destroy();
        resolve(true);
      });
      sock.on("error", () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Timed out waiting for 127.0.0.1:${port}`);
}

test("live wire-level OTLP HTTP auth returns 401 on invalid token and delivers valid batch to Basin", async (t) => {
  const vectorBin = findBinary("vector");
  if (!vectorBin) {
    t.skip("vector binary not in PATH; run inside `nix develop` to execute live wire-level auth test");
    return;
  }

  const otlpPort = await getFreePort();
  const receivedBatches = [];
  const basinServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      const body = req.headers["content-encoding"] === "gzip" ? zlib.gunzipSync(buf).toString("utf8") : buf.toString("utf8");
      receivedBatches.push({
        auth: req.headers.authorization,
        events: JSON.parse(body),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => basinServer.listen(0, "127.0.0.1", resolve));
  const basinPort = basinServer.address().port;

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vector-ai-wire-"));
  const localToken = "wire-local-secret-token-0123456789";
  const basinToken = "wire-basin-secret-token-9876543210";

  // Reduce batch timeout to 1s for fast deterministic wire test
  const wireCfg = fs
    .readFileSync(VECTOR_AI_CONFIG_PATH, "utf8")
    .split(/\ntests:\n/)[0]
    .replace("timeout_secs: 5", "timeout_secs: 1");
  const wireCfgPath = path.join(tmpDir, "vector-wire.yaml");
  fs.writeFileSync(wireCfgPath, wireCfg, "utf8");

  const proc = spawn(vectorBin, ["--config-yaml", wireCfgPath], {
    env: {
      ...process.env,
      VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
      OOF_VECTOR_AI_DATA_DIR: tmpDir,
      OOF_AI_OTLP_HTTP_LISTEN: `127.0.0.1:${otlpPort}`,
      OOF_AI_BASIN_ENDPOINT: `http://127.0.0.1:${basinPort}/ingest`,
      OOF_AI_INGEST_TOKEN: basinToken,
      OOF_AI_OTLP_AUTH_TOKEN: localToken,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForPort(otlpPort);

    const payload = JSON.stringify({
      resourceLogs: [
        {
          resource: {
            attributes: [{ key: "service.name", value: { stringValue: "claude-code" } }],
          },
          scopeLogs: [
            {
              logRecords: [
                {
                  timeUnixNano: "1795402902000000000",
                  eventName: "api_request",
                  attributes: [
                    { key: "model", value: { stringValue: "claude-sonnet-4-6" } },
                    { key: "input_tokens", value: { intValue: "100" } },
                    { key: "output_tokens", value: { intValue: "50" } },
                    { key: "session.id", value: { stringValue: "sess-wire-ok" } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });

    const postOtlp = (headers = {}) =>
      new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: "127.0.0.1",
            port: otlpPort,
            path: "/v1/logs",
            method: "POST",
            headers: { "content-type": "application/json", ...headers },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode));
          }
        );
        req.on("error", reject);
        req.end(payload);
      });

    // 1. Missing auth -> HTTP 401
    assert.equal(await postOtlp(), 401, "unauthenticated OTLP POST must return HTTP 401");
    // 2. Wrong bearer token -> HTTP 401
    assert.equal(
      await postOtlp({ authorization: "Bearer wrong-token" }),
      401,
      "mismatched bearer token must return HTTP 401"
    );
    // 3. Valid bearer token -> HTTP 200
    assert.equal(
      await postOtlp({ authorization: `Bearer ${localToken}` }),
      200,
      "valid bearer token must return HTTP 200"
    );

    const deadline = Date.now() + 8000;
    while (receivedBatches.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 150));
    }

    assert.equal(receivedBatches.length, 1, "expected exactly 1 delivered batch");
    assert.equal(receivedBatches[0].auth, `Bearer ${basinToken}`);
    assert.equal(receivedBatches[0].events.length, 1, "rejected 401 requests must not reach Basin");
    const ev = receivedBatches[0].events[0];
    assert.equal(ev.service.name, "claude-code");
    assert.equal(ev.event_name, "claude_code.api_request");
    assert.equal(ev.gen_ai.usage.total_tokens, 150);
    assert.equal(ev.session_id, "sess-wire-ok");
    assert.ok(!JSON.stringify(ev).includes(localToken), "local OTLP auth token must never leak to Basin");
  } finally {
    proc.kill("SIGTERM");
    await new Promise((resolve) => proc.once("exit", resolve));
    await new Promise((resolve) => basinServer.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
