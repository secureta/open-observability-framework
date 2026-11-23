import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
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
