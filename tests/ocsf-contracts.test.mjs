import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const BASIN_SCHEMA_PATH = path.join(REPO_ROOT, "contracts/ocsf/event-log-activity.basin.json");
const PIPELINE_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pipeline.sql");
const HUNTING_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql");
const TERRAFORM_DIR = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/terraform");
const PULUMI_DIR = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pulumi");
const PULUMI_CORE_PATH = path.join(PULUMI_DIR, "basin-core.ts");
const FLAKE_NIX_PATH = path.join(REPO_ROOT, "flake.nix");
const STACK_SCHEMA_PATH = path.join(REPO_ROOT, "manifest/stack.schema.json");
const STACK_EXAMPLE_PATH = path.join(REPO_ROOT, "manifest/examples/cloudflare-basin-ocsf.yaml");
const VECTOR_CONFIG_PATH = path.join(REPO_ROOT, "adapters/collect/vector-journald/vector.yaml");
const VECTOR_GHA_CONFIG_PATH = path.join(REPO_ROOT, "adapters/collect/vector-github-actions/vector.yaml");
const GHA_DIRECT_MODULE_PATH = path.join(REPO_ROOT, "adapters/collect/github-actions-direct/emit-ocsf.mjs");
const GHA_DIRECT_ACTION_PATH = path.join(REPO_ROOT, "adapters/collect/github-actions-direct/action.yml");
const GHA_MONITORING_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/github_actions_monitoring.sql");
const FLUENT_BIT_CONF_PATH = path.join(REPO_ROOT, "adapters/collect/fluent-bit-journald/fluent-bit.conf");
const FLUENT_BIT_LUA_PATH = path.join(REPO_ROOT, "adapters/collect/fluent-bit-journald/ocsf.lua");
const OTELCOL_CONF_PATH = path.join(REPO_ROOT, "adapters/collect/otel-collector-journald/otelcol.yaml");

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

function requireBinary(name) {
  const pathEntries = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathEntries) {
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // Continue searching PATH
    }
  }
  throw new Error(`Required test runtime binary '${name}' is not in PATH`);
}

function validateBasinFields(fields, depth = 0) {
  assert.ok(Array.isArray(fields) && fields.length > 0, `fields at depth ${depth} must be non-empty array`);
  const seenNames = new Set();
  for (const field of fields) {
    assert.equal(typeof field.name, "string", "field.name must be a string");
    assert.ok(field.name.length > 0, "field.name must be non-empty");
    assert.ok(!seenNames.has(field.name), `duplicate field '${field.name}' at depth ${depth}`);
    seenNames.add(field.name);

    assert.equal(typeof field.required, "boolean", `field '${field.name}' must specify boolean required`);
    assert.ok(ALLOWED_BASIN_TYPES.has(field.type), `field '${field.name}' has invalid Basin type '${field.type}'`);

    if (field.type === "timestamp") {
      assert.ok(
        ALLOWED_TIMESTAMP_UNITS.has(field.unit),
        `timestamp field '${field.name}' must specify valid unit`
      );
    }

    if (field.type === "struct") {
      assert.ok(depth < 2, `struct field '${field.name}' exceeds Basin max nesting depth <= 2`);
      validateBasinFields(field.fields, depth + 1);
    }

    if (field.type === "list") {
      assert.ok(depth < 2, `list field '${field.name}' exceeds Basin max nesting depth <= 2`);
      assert.ok(field.items && typeof field.items === "object", `list field '${field.name}' requires items`);
      validateBasinFields([{ name: `${field.name}[]`, required: true, ...field.items }], depth + 1);
    }
  }
}

function assertIsPlainObject(val, label) {
  assert.ok(
    typeof val === "object" && val !== null && !Array.isArray(val),
    `${label} must be a plain JSON object, got ${Array.isArray(val) ? "array" : typeof val}`
  );
}

function assertValueMatchesField(val, field, pathLabel) {
  switch (field.type) {
    case "string":
      assert.equal(typeof val, "string", `${pathLabel} must be string`);
      break;
    case "int32":
      assert.ok(
        typeof val === "number" && Number.isInteger(val) && val >= -2147483648 && val <= 2147483647,
        `${pathLabel} must be int32, got ${JSON.stringify(val)}`
      );
      break;
    case "int64":
      assert.ok(
        typeof val === "number" && Number.isInteger(val) && Number.isSafeInteger(val),
        `${pathLabel} must be safe int64 integer, got ${JSON.stringify(val)}`
      );
      break;
    case "float32":
    case "float64":
      assert.ok(typeof val === "number" && Number.isFinite(val), `${pathLabel} must be finite number`);
      break;
    case "bool":
      assert.equal(typeof val, "boolean", `${pathLabel} must be bool`);
      break;
    case "timestamp":
      assert.equal(typeof val, "string", `${pathLabel} must be RFC3339 timestamp string`);
      assert.match(
        val,
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/,
        `${pathLabel} must be UTC millisecond RFC3339 timestamp`
      );
      assert.ok(!Number.isNaN(Date.parse(val)), `${pathLabel} must parse as valid date`);
      break;
    case "json":
      assertIsPlainObject(val, pathLabel);
      break;
    case "struct":
      assertConformsToFields(val, field.fields, pathLabel);
      break;
    case "list":
      assert.ok(Array.isArray(val), `${pathLabel} must be list array`);
      for (let i = 0; i < val.length; i++) {
        assertValueMatchesField(val[i], field.items, `${pathLabel}[${i}]`);
      }
      break;
    default:
      throw new Error(`Unsupported field type '${field.type}' at ${pathLabel}`);
  }
}

function assertConformsToFields(obj, fields, pathLabel = "record") {
  assertIsPlainObject(obj, pathLabel);
  const byName = new Map(fields.map((f) => [f.name, f]));

  for (const field of fields) {
    const val = obj[field.name];
    if (field.required) {
      assert.ok(val !== undefined && val !== null, `${pathLabel}.${field.name} is required`);
    }
    if (val !== undefined && val !== null) {
      assertValueMatchesField(val, field, `${pathLabel}.${field.name}`);
    }
  }

  for (const key of Object.keys(obj)) {
    assert.ok(byName.has(key), `Unexpected non-OCSF key '${pathLabel}.${key}'`);
  }
}

function assertConformsToOcsfContract(record, basinSchema) {
  assertConformsToFields(record, basinSchema.fields, "ocsf");
  assert.equal(record.category_uid, 1);
  assert.equal(record.class_uid, 1008);
  assert.equal(record.activity_id, 99, "normal logged events must use activity_id = 99 (Other)");
  assert.equal(record.type_uid, 100899);
  assert.equal(record.metadata.version, "1.3.0");
  assert.ok(Number.isInteger(record.time) && record.time > 0, "ocsf.time must be positive epoch ms");

  if (record.metadata?.correlation_uid !== undefined && record.metadata?.correlation_uid !== null) {
    assert.ok(
      !/^0+$/.test(record.metadata.correlation_uid),
      "metadata.correlation_uid must not be all zeros"
    );
  }
  if (record.actor?.user?.uid_numeric !== undefined) {
    assert.equal(
      typeof record.actor.user.uid,
      "string",
      "actor.user.uid (string) must be populated whenever uid_numeric is set"
    );
  }
}

// Minimal indentation-aware YAML parser covering cloudflare-basin-ocsf.yaml structure (no external deps).
function parseSimpleYaml(text) {
  const root = {};
  const stack = [{ indent: -1, container: root }];
  const lines = text.split(/\r?\n/);

  const parseScalar = (raw) => {
    const s = raw.trim();
    if (s === "true") return true;
    if (s === "false") return false;
    if (/^-?\d+$/.test(s)) return Number(s);
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      return s.slice(1, -1);
    }
    return s;
  };

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const indent = rawLine.search(/\S/);
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    const parent = stack[stack.length - 1].container;

    if (trimmed.startsWith("- ")) {
      assert.ok(Array.isArray(parent), `Unexpected list item on line ${i + 1}: ${rawLine}`);
      parent.push(parseScalar(trimmed.slice(2)));
      continue;
    }

    const colonIdx = trimmed.indexOf(":");
    assert.ok(colonIdx > 0, `Malformed YAML line ${i + 1}: ${rawLine}`);
    const key = trimmed.slice(0, colonIdx).trim();
    const rest = trimmed.slice(colonIdx + 1).trim();

    if (rest === "") {
      let nextVal = {};
      for (let j = i + 1; j < lines.length; j++) {
        const nt = lines[j].trim();
        if (!nt || nt.startsWith("#")) continue;
        if (nt.startsWith("- ")) nextVal = [];
        break;
      }
      parent[key] = nextVal;
      stack.push({ indent, container: nextVal });
    } else {
      parent[key] = parseScalar(rest);
    }
  }
  return root;
}

// Subset JSON Schema Draft 2020-12 validator sufficient for manifest/stack.schema.json.
function validateAgainstJsonSchema(data, schema, ptr = "$") {
  const errors = [];
  if (schema.const !== undefined && data !== schema.const) {
    errors.push(`${ptr}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(data)}`);
    return errors;
  }
  if (schema.enum && !schema.enum.includes(data)) {
    errors.push(`${ptr}: value ${JSON.stringify(data)} not in enum ${JSON.stringify(schema.enum)}`);
  }
  if (
    schema.type === "object" ||
    schema.properties ||
    schema.required ||
    schema.if ||
    schema.additionalProperties !== undefined ||
    schema.minProperties !== undefined
  ) {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      errors.push(`${ptr}: expected object`);
      return errors;
    }
    if (Array.isArray(schema.required)) {
      for (const req of schema.required) {
        if (data[req] === undefined) errors.push(`${ptr}.${req}: missing required property`);
      }
    }
    const keys = Object.keys(data);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) {
      errors.push(`${ptr}: expected at least ${schema.minProperties} properties`);
    }
    const props = schema.properties || {};
    for (const k of keys) {
      if (props[k]) {
        errors.push(...validateAgainstJsonSchema(data[k], props[k], `${ptr}.${k}`));
      } else if (schema.additionalProperties === false) {
        errors.push(`${ptr}.${k}: additional property not allowed`);
      } else if (typeof schema.additionalProperties === "object") {
        errors.push(...validateAgainstJsonSchema(data[k], schema.additionalProperties, `${ptr}.${k}`));
      }
    }
    if (schema.if && schema.then) {
      const ifErrors = validateAgainstJsonSchema(data, schema.if, ptr);
      if (ifErrors.length === 0) {
        errors.push(...validateAgainstJsonSchema(data, schema.then, ptr));
      }
    }
  } else if (schema.type === "array") {
    if (!Array.isArray(data)) {
      errors.push(`${ptr}: expected array`);
      return errors;
    }
    if (schema.minItems !== undefined && data.length < schema.minItems) {
      errors.push(`${ptr}: expected at least ${schema.minItems} items`);
    }
    if (schema.items) {
      data.forEach((item, idx) => {
        errors.push(...validateAgainstJsonSchema(item, schema.items, `${ptr}[${idx}]`));
      });
    }
  } else if (schema.type === "string") {
    if (typeof data !== "string") {
      errors.push(`${ptr}: expected string`);
      return errors;
    }
    if (schema.minLength !== undefined && data.length < schema.minLength) {
      errors.push(`${ptr}: string shorter than minLength ${schema.minLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(data)) {
      errors.push(`${ptr}: does not match pattern ${schema.pattern}`);
    }
  } else if (schema.type === "integer") {
    if (typeof data !== "number" || !Number.isInteger(data)) {
      errors.push(`${ptr}: expected integer`);
      return errors;
    }
    if (schema.minimum !== undefined && data < schema.minimum) {
      errors.push(`${ptr}: below minimum ${schema.minimum}`);
    }
  } else if (schema.type === "boolean") {
    if (typeof data !== "boolean") {
      errors.push(`${ptr}: expected boolean`);
    }
  }
  return errors;
}

// Extract top-level VRL script blocks and sink config from vector.yaml without external YAML libs.
function extractVectorTransformVrl(vectorYamlText, transformName) {
  const lines = vectorYamlText.split(/\r?\n/);
  const headerRe = new RegExp(`^  ${transformName}:\\s*$`);
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (headerRe.test(lines[i])) {
      start = i;
      break;
    }
  }
  assert.ok(start >= 0, `Could not find transform '${transformName}' in vector.yaml`);

  let sourceLineIdx = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^    source:\s*\|\s*$/.test(lines[i])) {
      sourceLineIdx = i;
      break;
    }
  }
  assert.ok(sourceLineIdx >= 0, `Could not find 'source: |' in transform '${transformName}'`);

  const vrlLines = [];
  for (let i = sourceLineIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") {
      vrlLines.push("");
      continue;
    }
    if (!line.startsWith("      ")) {
      break;
    }
    vrlLines.push(line.slice(6));
  }
  return vrlLines.join("\n");
}

// Minimal OTLP ExportLogsServiceRequest protobuf encoder (no external protobuf packages).
function pbVarint(num) {
  let n = BigInt(num);
  const bytes = [];
  while (n >= 0x80n) {
    bytes.push(Number((n & 0x7fn) | 0x80n));
    n >>= 7n;
  }
  bytes.push(Number(n));
  return Buffer.from(bytes);
}

function pbTag(fieldNumber, wireType) {
  return pbVarint((fieldNumber << 3) | wireType);
}

function pbBytes(fieldNumber, buf) {
  return Buffer.concat([pbTag(fieldNumber, 2), pbVarint(buf.length), buf]);
}

function pbString(fieldNumber, str) {
  return pbBytes(fieldNumber, Buffer.from(str, "utf8"));
}

function pbFixed64(fieldNumber, bigVal) {
  const b = Buffer.allocUnsafe(8);
  b.writeBigUInt64LE(BigInt(bigVal), 0);
  return Buffer.concat([pbTag(fieldNumber, 1), b]);
}

function pbAnyValue(val) {
  if (typeof val === "string") {
    return pbString(1, val);
  }
  if (typeof val === "boolean") {
    return Buffer.concat([pbTag(2, 0), pbVarint(val ? 1 : 0)]);
  }
  if (typeof val === "number" && Number.isInteger(val)) {
    return Buffer.concat([pbTag(3, 0), pbVarint(BigInt.asUintN(64, BigInt(val)))]);
  }
  if (typeof val === "object" && val !== null && !Array.isArray(val)) {
    const kvList = Buffer.concat(Object.entries(val).map(([k, v]) => pbKeyValue(1, k, v)));
    return pbBytes(6, kvList);
  }
  return pbString(1, String(val));
}

function pbKeyValue(fieldNumber, key, val) {
  return pbBytes(fieldNumber, Buffer.concat([pbString(1, key), pbBytes(2, pbAnyValue(val))]));
}

function encodeOtlpLogsRequest({ resourceAttrs = {}, scopeName = "", logRecords = [] }) {
  const resAttrsBuf = Buffer.concat(Object.entries(resourceAttrs).map(([k, v]) => pbKeyValue(1, k, v)));
  const resourceBuf = resAttrsBuf;

  const scopeBuf = scopeName ? pbString(1, scopeName) : Buffer.alloc(0);

  const recordBuffers = logRecords.map((rec) => {
    const parts = [];
    if (rec.timeUnixNano !== undefined) {
      parts.push(pbFixed64(1, rec.timeUnixNano));
    }
    if (rec.severityNumber !== undefined) {
      parts.push(pbTag(2, 0), pbVarint(rec.severityNumber));
    }
    if (rec.severityText !== undefined) {
      parts.push(pbString(3, rec.severityText));
    }
    if (rec.body !== undefined) {
      parts.push(pbBytes(5, pbAnyValue(rec.body)));
    }
    if (rec.attributes) {
      for (const [k, v] of Object.entries(rec.attributes)) {
        parts.push(pbKeyValue(6, k, v));
      }
    }
    if (rec.traceIdHex !== undefined) {
      parts.push(pbBytes(9, Buffer.from(rec.traceIdHex, "hex")));
    }
    if (rec.spanIdHex !== undefined) {
      parts.push(pbBytes(10, Buffer.from(rec.spanIdHex, "hex")));
    }
    if (rec.observedTimeUnixNano !== undefined) {
      parts.push(pbFixed64(11, rec.observedTimeUnixNano));
    }
    return pbBytes(2, Buffer.concat(parts));
  });

  const scopeLogsBuf = Buffer.concat([pbBytes(1, scopeBuf), ...recordBuffers]);
  const resourceLogsBuf = Buffer.concat([pbBytes(1, resourceBuf), pbBytes(2, scopeLogsBuf)]);
  return pbBytes(1, resourceLogsBuf);
}

function startMockBasinServer(expectedToken) {
  const requests = [];
  const records = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks);
      const isGzip = (req.headers["content-encoding"] || "").toLowerCase() === "gzip";
      const decodedBuf = isGzip ? zlib.gunzipSync(rawBody) : rawBody;
      const parsed = JSON.parse(decodedBuf.toString("utf8"));
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        isGzip,
        batchLength: Array.isArray(parsed) ? parsed.length : -1,
      });

      if (req.headers.authorization !== `Bearer ${expectedToken}`) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }

      assert.ok(Array.isArray(parsed), "Basin HTTP endpoint requires top-level JSON array batch");
      for (const item of parsed) {
        records.push(item);
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        requests,
        records,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

async function getFreePorts(count) {
  const servers = [];
  const ports = [];
  for (let i = 0; i < count; i++) {
    const srv = http.createServer();
    await new Promise((res) => srv.listen(0, "127.0.0.1", res));
    ports.push(srv.address().port);
    servers.push(srv);
  }
  await Promise.all(servers.map((s) => new Promise((res) => s.close(res))));
  return ports;
}

async function waitForCondition(fn, timeoutMs = 15000, stepMs = 100) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const res = await fn();
      if (res) return res;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, stepMs));
  }
  throw lastErr || new Error(`Timed out after ${timeoutMs}ms waiting for condition`);
}

async function waitForTcpReady(port, timeoutMs = 10000) {
  return waitForCondition(
    () =>
      new Promise((resolve) => {
        const sock = net.connect({ host: "127.0.0.1", port }, () => {
          sock.destroy();
          resolve(true);
        });
        sock.on("error", () => {
          sock.destroy();
          resolve(false);
        });
      }),
    timeoutMs,
    80
  );
}

async function terminateProcess(proc) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise((resolve) => proc.once("exit", resolve));
  proc.kill("SIGTERM");
  const timer = setTimeout(() => {
    if (proc.exitCode === null && proc.signalCode === null) {
      proc.kill("SIGKILL");
    }
  }, 3000);
  await exited;
  clearTimeout(timer);
}

test("1. OCSF v1.3.0 Basin stream schema conforms to Basin SchemaField limits and OCSF invariants", () => {
  const schema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8"));
  validateBasinFields(schema.fields, 0);

  const byName = new Map(schema.fields.map((f) => [f.name, f]));
  assert.equal(schema.fields.length, 19);
  assert.equal(byName.get("category_uid")?.type, "int32");
  assert.equal(byName.get("class_uid")?.type, "int32");
  assert.equal(byName.get("type_uid")?.type, "int64");
  assert.equal(byName.get("activity_id")?.type, "int32");
  assert.equal(byName.get("severity_id")?.type, "int32");
  assert.equal(byName.get("time")?.type, "int64");
  assert.equal(byName.get("time_dt")?.type, "timestamp");
  assert.equal(byName.get("time_dt")?.unit, "millisecond");
  assert.equal(byName.get("unmapped")?.type, "json");

  const metaFields = new Map(byName.get("metadata").fields.map((f) => [f.name, f]));
  assert.equal(metaFields.get("version")?.required, true);
  assert.equal(metaFields.get("product")?.type, "struct");
  assert.equal(metaFields.get("product")?.required, true);

  const deviceFields = new Map(byName.get("device").fields.map((f) => [f.name, f]));
  assert.equal(deviceFields.get("type_id")?.required, true);
  const osFields = new Map(deviceFields.get("os").fields.map((f) => [f.name, f]));
  assert.equal(osFields.get("name")?.required, true);
  assert.equal(osFields.get("type_id")?.required, true);

  const actorFields = new Map(byName.get("actor").fields.map((f) => [f.name, f]));
  const userFields = new Map(actorFields.get("user").fields.map((f) => [f.name, f]));
  assert.equal(userFields.get("uid")?.type, "string");
  assert.equal(userFields.get("uid_numeric")?.type, "int64");
});

test("2. Basin pipeline.sql matches OCSF schema top-level columns 1:1 in order and hunting SQL targets OCSF table", () => {
  const schema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8"));
  const expectedColumns = schema.fields.map((f) => f.name);

  const sqlText = fs.readFileSync(PIPELINE_SQL_PATH, "utf8");
  const match = sqlText.match(/INSERT\s+INTO\s+__SINK_NAME__\s+SELECT\s+([\s\S]+?)\s+FROM\s+__STREAM_NAME__/i);
  assert.ok(match, "pipeline.sql must contain INSERT INTO __SINK_NAME__ SELECT ... FROM __STREAM_NAME__");

  const sqlColumns = match[1]
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  assert.deepEqual(sqlColumns, expectedColumns);

  const huntingSql = fs.readFileSync(HUNTING_SQL_PATH, "utf8");
  assert.ok(huntingSql.includes("siem.ocsf_event_log_activity"));
  assert.ok(huntingSql.includes("metadata.correlation_uid"));

  const tfVarsText = fs.readFileSync(path.join(TERRAFORM_DIR, "variables.tf"), "utf8");
  assert.match(tfVarsText, /variable\s+"bucket_name"[\s\S]*?default\s*=\s*"oof-telemetry"/);
  assert.match(tfVarsText, /variable\s+"namespace"[\s\S]*?default\s*=\s*"siem"/);
  assert.match(tfVarsText, /variable\s+"table_name"[\s\S]*?default\s*=\s*"ocsf_event_log_activity"/);

  const pulumiIndexText = fs.readFileSync(path.join(PULUMI_DIR, "index.ts"), "utf8");
  assert.match(pulumiIndexText, /config\.get\("bucketName"\)\s*\?\?\s*"oof-telemetry"/);
  assert.match(pulumiIndexText, /config\.get\("namespace"\)\s*\?\?\s*"siem"/);
  assert.match(pulumiIndexText, /config\.get\("tableName"\)\s*\?\?\s*"ocsf_event_log_activity"/);
  assert.match(pulumiIndexText, /replaceOnChanges:\s*\[\s*"sql"\s*\]/);
});

test("3. Stack manifest schema validates cloudflare-basin-ocsf.yaml and rejects invalid profiles/configs", () => {
  const stackSchema = JSON.parse(fs.readFileSync(STACK_SCHEMA_PATH, "utf8"));
  const exampleManifest = parseSimpleYaml(fs.readFileSync(STACK_EXAMPLE_PATH, "utf8"));

  assert.deepEqual(validateAgainstJsonSchema(exampleManifest, stackSchema), []);
  assert.equal(exampleManifest.schema.profile, "ocsf");
  assert.equal(exampleManifest.schema.class_uid, 1008);
  assert.equal(exampleManifest.detect.enabled, false);
  assert.equal(exampleManifest.ingest.adapter, "direct-basin-http");
  assert.equal(exampleManifest.ingest.auth, "basin-api-token");

  // Negative 1: custom proprietary profile rejected
  const badProfile = structuredClone(exampleManifest);
  badProfile.schema.profile = "custom";
  assert.ok(validateAgainstJsonSchema(badProfile, stackSchema).length > 0);

  // Negative 2: ocsf profile missing class_uid rejected
  const missingClass = structuredClone(exampleManifest);
  delete missingClass.schema.class_uid;
  assert.ok(validateAgainstJsonSchema(missingClass, stackSchema).length > 0);

  // Negative 3: detect.enabled=true missing placement/engine rejected
  const incompleteDetect = structuredClone(exampleManifest);
  incompleteDetect.detect = { enabled: true };
  assert.ok(validateAgainstJsonSchema(incompleteDetect, stackSchema).length > 0);
});

function listRepoFiles(rootDir) {
  if (fs.existsSync(path.join(rootDir, ".git"))) {
    const gitList = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
      cwd: rootDir,
      encoding: "utf8",
    });
    if (gitList.status === 0) {
      return gitList.stdout.trim().split("\n").filter(Boolean);
    }
  }

  const out = [];
  const skipDirs = new Set([".git", "node_modules", ".terraform", ".pulumi"]);
  const walk = (relDir) => {
    const absDir = relDir ? path.join(rootDir, relDir) : rootDir;
    for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
      if (skipDirs.has(entry.name) || entry.name === "result" || entry.name.startsWith("result-")) {
        continue;
      }
      const relPath = relDir ? path.posix.join(relDir, entry.name) : entry.name;
      if (entry.isDirectory()) {
        walk(relPath);
      } else if (entry.isFile()) {
        out.push(relPath);
      }
    }
  };
  walk("");
  return out;
}

function spawnAsync(bin, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { ...opts, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ status: code ?? -1, stdout, stderr });
    });
  });
}

function startMockCloudflareApiServer(expectedAccountId, expectedToken) {
  const buckets = new Map();
  const catalogs = new Map();
  const streams = new Map();
  const sinks = new Map();
  const pipelines = new Map();
  const tokens = new Map();
  const ops = [];
  let seq = 0;
  let nextOverride = null;

  const cfOk = (result, extra = {}) => JSON.stringify({ success: true, errors: [], messages: [], result, ...extra });
  const cfErr = (message) => JSON.stringify({ success: false, errors: [{ code: 10000, message }], messages: [] });

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks).toString("utf8");
      const parsedBody = rawBody.trim() ? JSON.parse(rawBody) : null;
      const reqUrl = new URL(req.url, "http://127.0.0.1");
      const pathname = reqUrl.pathname;

      if (nextOverride && (!nextOverride.method || nextOverride.method === req.method)) {
        const ov = nextOverride;
        nextOverride = null;
        res.writeHead(ov.status, { "content-type": ov.contentType || "text/plain" });
        res.end(ov.rawBody);
        return;
      }

      if (req.headers.authorization !== `Bearer ${expectedToken}`) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(cfErr("unauthorized"));
        return;
      }

      const prefix = `/client/v4/accounts/${expectedAccountId}`;
      if (!pathname.startsWith(prefix)) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(cfErr(`unexpected account prefix for ${pathname}`));
        return;
      }

      const rel = pathname.slice(prefix.length);
      ops.push({ method: req.method, path: rel, body: parsedBody });

      const sendJson = (statusCode, payload) => {
        res.writeHead(statusCode, { "content-type": "application/json" });
        res.end(payload);
      };

      // R2 Buckets: /r2/buckets and /r2/buckets/:name
      if (rel === "/r2/buckets" && req.method === "POST") {
        const name = parsedBody?.name;
        const rec = {
          name,
          creation_date: "2026-01-01T00:00:00Z",
          location: parsedBody?.location ?? "wnam",
          storage_class: parsedBody?.storage_class ?? "Standard",
          jurisdiction: parsedBody?.jurisdiction ?? "default",
        };
        buckets.set(name, rec);
        return sendJson(200, cfOk(rec));
      }
      const bucketMatch = /^\/r2\/buckets\/([^/]+)$/.exec(rel);
      if (bucketMatch) {
        const bName = decodeURIComponent(bucketMatch[1]);
        if (req.method === "GET") {
          const rec = buckets.get(bName);
          return rec ? sendJson(200, cfOk(rec)) : sendJson(404, cfErr("bucket not found"));
        }
        if (req.method === "DELETE") {
          if (!buckets.has(bName)) return sendJson(404, cfErr("bucket not found"));
          buckets.delete(bName);
          return sendJson(200, cfOk({}));
        }
      }

      // R2 Data Catalog: /r2-catalog/:name(/enable|/disable) and /r2/buckets/:name/catalog(/enable|/disable)
      const catalogMatch =
        /^\/r2-catalog\/([^/]+)(?:\/(enable|disable))?$/.exec(rel) ??
        /^\/r2\/buckets\/([^/]+)\/catalog(?:\/(enable|disable))?$/.exec(rel);
      if (catalogMatch) {
        const bName = decodeURIComponent(catalogMatch[1]);
        const action = catalogMatch[2];
        if ((req.method === "POST" || req.method === "PUT") && (!action || action === "enable")) {
          const rec = {
            id: `cat-${++seq}`,
            bucket: bName,
            name: `${expectedAccountId}_${bName}`,
            status: "active",
            credential_status: "present",
            maintenance_config: {
              compaction: { state: "enabled", target_size_mb: "128" },
              interval: "1h",
              snapshot_expiration: { max_snapshot_age: "7d", min_snapshots_to_keep: 100, state: "enabled" },
            },
          };
          catalogs.set(bName, rec);
          return sendJson(200, cfOk(rec));
        }
        if (req.method === "GET" && !action) {
          const rec = catalogs.get(bName);
          return rec ? sendJson(200, cfOk(rec)) : sendJson(404, cfErr("catalog not found"));
        }
        if (req.method === "DELETE" || (req.method === "POST" && action === "disable")) {
          if (!catalogs.has(bName)) return sendJson(404, cfErr("catalog not found"));
          catalogs.delete(bName);
          return sendJson(200, cfOk({}));
        }
      }

      // Basin Streams: /pipelines/v1/streams and /pipelines/v1/streams/:id
      if (rel === "/pipelines/v1/streams" && req.method === "POST") {
        const id = `stream0000${++seq}`.slice(0, 16);
        const rec = {
          id,
          name: parsedBody.name,
          endpoint: `https://${id}.ingest.cloudflare.com`,
          version: 1,
          created_at: "2026-01-01T00:00:00Z",
          modified_at: "2026-01-01T00:00:00Z",
          format: {
            ...parsedBody.format,
            unstructured: parsedBody.format?.unstructured ?? false,
          },
          http: {
            enabled: parsedBody.http?.enabled ?? true,
            authentication: parsedBody.http?.authentication ?? true,
            cors: { origins: parsedBody.http?.cors?.origins ?? [] },
          },
          worker_binding: { enabled: parsedBody.worker_binding?.enabled ?? false },
          schema: {
            fields: parsedBody.schema?.fields ?? [],
            inferred: parsedBody.schema?.inferred ?? false,
          },
        };
        streams.set(id, rec);
        return sendJson(200, cfOk(rec));
      }
      const streamMatch = /^\/pipelines\/v1\/streams\/([^/]+)$/.exec(rel);
      if (streamMatch) {
        const id = decodeURIComponent(streamMatch[1]);
        const existing = streams.get(id);
        if (!existing) return sendJson(404, cfErr("stream not found"));
        if (req.method === "GET") return sendJson(200, cfOk(existing));
        if (req.method === "PATCH") {
          if (!parsedBody || typeof parsedBody !== "object" || Array.isArray(parsedBody)) {
            return sendJson(400, cfErr("PATCH body must be a JSON object"));
          }
          const disallowed = Object.keys(parsedBody).filter((k) => k !== "http" && k !== "worker_binding");
          if (disallowed.length > 0) {
            return sendJson(400, cfErr(`Immutable stream fields rejected in PATCH: ${disallowed.join(", ")}`));
          }
          const nextHttp = parsedBody.http
            ? {
                enabled: parsedBody.http.enabled ?? existing.http.enabled,
                authentication: parsedBody.http.authentication ?? existing.http.authentication,
                cors: parsedBody.http.cors
                  ? { origins: parsedBody.http.cors.origins ?? existing.http.cors.origins }
                  : existing.http.cors,
              }
            : existing.http;
          const nextWb = parsedBody?.worker_binding
            ? { ...existing.worker_binding, ...parsedBody.worker_binding }
            : existing.worker_binding;
          const updated = {
            ...existing,
            http: nextHttp,
            worker_binding: nextWb,
            version: existing.version + 1,
            modified_at: "2026-01-01T00:01:00Z",
          };
          streams.set(id, updated);
          return sendJson(200, cfOk(updated));
        }
        if (req.method === "DELETE") {
          streams.delete(id);
          return sendJson(200, cfOk({}));
        }
      }

      // Basin Sinks: /pipelines/v1/sinks and /pipelines/v1/sinks/:id
      if (rel === "/pipelines/v1/sinks" && req.method === "POST") {
        const id = `sink-${++seq}`;
        const rec = {
          id,
          name: parsedBody.name,
          type: parsedBody.type,
          format: parsedBody.format,
          config: parsedBody.config,
          created_at: "2026-01-01T00:00:00Z",
          modified_at: "2026-01-01T00:00:00Z",
        };
        sinks.set(id, rec);
        return sendJson(200, cfOk(rec));
      }
      const sinkMatch = /^\/pipelines\/v1\/sinks\/([^/]+)$/.exec(rel);
      if (sinkMatch) {
        const id = decodeURIComponent(sinkMatch[1]);
        const existing = sinks.get(id);
        if (!existing) return sendJson(404, cfErr("sink not found"));
        if (req.method === "GET") return sendJson(200, cfOk(existing));
        if (req.method === "DELETE") {
          sinks.delete(id);
          return sendJson(200, cfOk({}));
        }
      }

      // Basin Pipelines: /pipelines/v1/pipelines and /pipelines/v1/pipelines/:id
      if (rel === "/pipelines/v1/pipelines" && req.method === "POST") {
        const id = `pipe-${++seq}`;
        const rec = {
          id,
          name: parsedBody.name,
          sql: parsedBody.sql,
          status: "active",
          tables: [],
          created_at: "2026-01-01T00:00:00Z",
          modified_at: "2026-01-01T00:00:00Z",
        };
        pipelines.set(id, rec);
        return sendJson(200, cfOk(rec));
      }
      const pipeMatch = /^\/pipelines\/v1\/pipelines\/([^/]+)$/.exec(rel);
      if (pipeMatch) {
        const id = decodeURIComponent(pipeMatch[1]);
        const existing = pipelines.get(id);
        if (!existing) return sendJson(404, cfErr("pipeline not found"));
        if (req.method === "GET") return sendJson(200, cfOk(existing));
        if (req.method === "PUT" || req.method === "PATCH") {
          const updated = { ...existing, ...parsedBody, modified_at: "2026-01-01T00:01:00Z" };
          pipelines.set(id, updated);
          return sendJson(200, cfOk(updated));
        }
        if (req.method === "DELETE") {
          pipelines.delete(id);
          return sendJson(200, cfOk({}));
        }
      }

      // Account API Token permission groups + tokens
      if (rel === "/tokens/permission_groups" && req.method === "GET") {
        return sendJson(
          200,
          cfOk(
            [
              {
                id: "pg-pipelines-send",
                name: "Pipelines Send",
                category: "analytics_and_logs",
                is_selectable: true,
                scopes: ["com.cloudflare.api.account"],
              },
            ],
            { result_info: { page: 1, per_page: 100, count: 1, total_count: 1, total_pages: 1 } }
          )
        );
      }
      if (rel === "/tokens" && req.method === "POST") {
        const id = `tok-${++seq}`;
        const rec = {
          id,
          name: parsedBody.name,
          status: "active",
          policies: parsedBody.policies,
          issued_on: "2026-01-01T00:00:00Z",
          modified_on: "2026-01-01T00:00:00Z",
        };
        tokens.set(id, rec);
        return sendJson(200, cfOk({ ...rec, value: "cf-mock-ingest-token-value-0123456789abcdef" }));
      }
      const tokMatch = /^\/tokens\/([^/]+)$/.exec(rel);
      if (tokMatch) {
        const id = decodeURIComponent(tokMatch[1]);
        const existing = tokens.get(id);
        if (!existing) return sendJson(404, cfErr("token not found"));
        if (req.method === "GET") return sendJson(200, cfOk(existing));
        if (req.method === "DELETE") {
          tokens.delete(id);
          return sendJson(200, cfOk({ id }));
        }
      }

      return sendJson(404, cfErr(`unmatched mock route: ${req.method} ${rel}`));
    });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        baseUrl: `http://127.0.0.1:${addr.port}/client/v4`,
        ops,
        streams,
        setNextResponse: (ov) => {
          nextOverride = ov;
        },
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test("4. Repository link integrity, zero shell scripts, and zero stale references", () => {
  const trackedFiles = listRepoFiles(REPO_ROOT);
  assert.ok(trackedFiles.length > 0, "Repository file list must not be empty");
  assert.ok(fs.existsSync(FLAKE_NIX_PATH), "flake.nix must exist at repository root");

  for (const relPath of trackedFiles) {
    assert.ok(!relPath.endsWith(".sh"), `Shell scripts are forbidden in repository: '${relPath}'`);
  }

  // Construct forbidden tokens dynamically so this test file never triggers self-matches even if checked
  const staleTerms = [
    ["cloudflare", "worker", "basin"].join("-"),
    ["yara", "wasm"].join("-"),
    ["journal", "logs.basin.json"].join("-"),
    ["telemetry", "envelope.md"].join("-"),
    ["pipeline", "fanout.sql"].join("-"),
    ["cloudflare", "basin", "siem.yaml"].join("-"),
    ["manage", "yara", "detection"].join("-"),
    ["INGEST", "AUTH", "TOKEN"].join("_"),
    ["yara", "matched"].join("_"),
    ["provision", "basin.sh"].join("-"),
    ["wrangler", "pipelines"].join(" "),
    ["wrangler", "r2"].join(" "),
    ["wrangler", "basin"].join(" "),
    ["npx", "wrangler"].join(" "),
  ];

  for (const relPath of trackedFiles) {
    if (relPath === "tests/ocsf-contracts.test.mjs") continue;
    const fullPath = path.join(REPO_ROOT, relPath);
    if (!fs.existsSync(fullPath)) continue;
    const content = fs.readFileSync(fullPath, "utf8");
    for (const term of staleTerms) {
      assert.ok(!content.includes(term), `Stale reference '${term}' found in '${relPath}'`);
    }
  }

  // Verify every relative adapter/contract/manifest path mentioned in key docs/manifests exists on disk
  const docFiles = [
    "README.md",
    "AGENTS.md",
    "contracts/ocsf/README.md",
    "manifest/examples/cloudflare-basin-ocsf.yaml",
    "adapters/storage/cloudflare-basin-iceberg/terraform/README.md",
    "adapters/storage/cloudflare-basin-iceberg/pulumi/README.md",
    "skills/compose-observability-stack/SKILL.md",
    "skills/compose-observability-stack/references/component-catalog.md",
    "skills/setup-cloudflare-basin-iceberg/SKILL.md",
    "skills/setup-cloudflare-basin-iceberg/references/basin-troubleshooting.md",
  ];
  const pathRefRe =
    /\b(?:adapters|contracts|manifest|skills|tests)\/[a-zA-Z0-9._\/-]+\.(?:yaml|yml|json|sql|sh|lua|conf|md|mjs|tf|ts|nix)\b/g;
  for (const doc of docFiles) {
    const text = fs.readFileSync(path.join(REPO_ROOT, doc), "utf8");
    for (const match of text.matchAll(pathRefRe)) {
      const refPath = path.join(REPO_ROOT, match[0]);
      assert.ok(fs.existsSync(refPath), `Missing referenced path '${match[0]}' in '${doc}'`);
    }
  }
});

test("5. Cloud IaC (Terraform/OpenTofu + Pulumi) CRUD lifecycle, struct schema preservation, secret hygiene, and validation", async () => {
  const tofuBin = requireBinary("tofu");
  const accountId = "0123456789abcdef0123456789abcdef";
  const adminToken = "cf_admin_mock_token_0123456789abcdef01234567";
  const catalogToken = "secret-catalog-token-do-not-leak-987654";
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8"));
  const pipelineSqlRaw = fs.readFileSync(PIPELINE_SQL_PATH, "utf8");

  const mockCf = await startMockCloudflareApiServer(accountId, adminToken);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-iac-test-"));
  const hadEnvToken = Object.hasOwn(process.env, "CLOUDFLARE_API_TOKEN");
  const prevEnvToken = process.env.CLOUDFLARE_API_TOKEN;

  try {
    // --- Part A: Real OpenTofu E2E against mock Cloudflare v4 API ---
    const stagedContractsDir = path.join(tmpDir, "contracts/ocsf");
    const stagedStorageDir = path.join(tmpDir, "adapters/storage/cloudflare-basin-iceberg");
    const stagedTfDir = path.join(stagedStorageDir, "terraform");
    fs.mkdirSync(stagedContractsDir, { recursive: true });
    fs.mkdirSync(stagedTfDir, { recursive: true });
    fs.copyFileSync(BASIN_SCHEMA_PATH, path.join(stagedContractsDir, "event-log-activity.basin.json"));
    fs.copyFileSync(PIPELINE_SQL_PATH, path.join(stagedStorageDir, "pipeline.sql"));
    for (const entry of fs.readdirSync(TERRAFORM_DIR)) {
      if (entry.endsWith(".tf") || entry.endsWith(".tfvars.example")) {
        fs.copyFileSync(path.join(TERRAFORM_DIR, entry), path.join(stagedTfDir, entry));
      }
    }

    const tfHome = path.join(tmpDir, "tf-home");
    fs.mkdirSync(tfHome, { recursive: true });
    const tfEnv = {
      ...process.env,
      HOME: tfHome,
      TF_VAR_cloudflare_account_id: accountId,
      TF_VAR_cloudflare_api_token: adminToken,
      TF_VAR_catalog_token: catalogToken,
      TF_VAR_cloudflare_api_base_url: mockCf.baseUrl,
    };

    const tfvarsPath = path.join(stagedTfDir, "test.tfvars.json");
    const writeTfvars = (extra = {}) => {
      // Exercise variables.tf defaults (oof-telemetry, siem.ocsf_event_log_activity) without overriding them.
      fs.writeFileSync(
        tfvarsPath,
        JSON.stringify(
          {
            roll_interval_seconds: 120,
            create_ingest_token: true,
            ...extra,
          },
          null,
          2
        )
      );
    };
    writeTfvars();

    const initRes = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "init", "-backend=false", "-input=false"],
      { env: tfEnv }
    );
    assert.equal(initRes.status, 0, `${initRes.stdout}\n${initRes.stderr}`);

    const valRes = await spawnAsync(tofuBin, [`-chdir=${stagedTfDir}`, "validate"], { env: tfEnv });
    assert.equal(valRes.status, 0, `${valRes.stdout}\n${valRes.stderr}`);

    // Negative variable validations before apply (input validation runs without mutating state)
    const invalidCases = [
      ["bad table_name SQLi", ["-var=table_name=foo; DROP TABLE bar"]],
      ["bad bucket_name", ["-var=bucket_name=Bad_Bucket"]],
      ["bad roll_interval_seconds", ["-var=roll_interval_seconds=30"]],
      ["bad non-HTTPS remote URL", ["-var=cloudflare_api_base_url=http://api.cloudflare.com/client/v4"]],
      ["stream_name equals sink_name", ["-var=stream_name=same_ident", "-var=sink_name=same_ident"]],
    ];
    for (const [label, extraFlags] of invalidCases) {
      const badPlan = await spawnAsync(
        tofuBin,
        [`-chdir=${stagedTfDir}`, "plan", "-input=false", "-refresh=false", `-var-file=${tfvarsPath}`, ...extraFlags],
        { env: tfEnv }
      );
      assert.notEqual(badPlan.status, 0, `Expected OpenTofu validation failure for: ${label}`);
    }

    const applyRes = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "apply", "-auto-approve", "-input=false", `-var-file=${tfvarsPath}`],
      { env: tfEnv }
    );
    assert.equal(applyRes.status, 0, `${applyRes.stdout}\n${applyRes.stderr}`);
    assert.ok(!applyRes.stdout.includes(adminToken), "apply output must never echo cloudflare_api_token");
    assert.ok(!applyRes.stdout.includes(catalogToken), "apply output must never echo catalog_token");

    // Verify zero-diff plan right after apply
    const zeroDiffPlan = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "plan", "-detailed-exitcode", "-input=false", `-var-file=${tfvarsPath}`],
      { env: tfEnv }
    );
    assert.equal(zeroDiffPlan.status, 0, `Expected zero-diff plan, got:\n${zeroDiffPlan.stdout}\n${zeroDiffPlan.stderr}`);

    // Inspect recorded HTTP operations from apply
    const isCatalogPath = (p) => p.startsWith("/r2-catalog/oof-telemetry") || p.startsWith("/r2/buckets/oof-telemetry/catalog");
    const createOps = mockCf.ops.filter((o) => o.method === "POST" || o.method === "PUT");
    const streamCreateIdx = createOps.findIndex((o) => o.path === "/pipelines/v1/streams");
    const bucketCreateIdx = createOps.findIndex((o) => o.path === "/r2/buckets");
    const catalogCreateIdx = createOps.findIndex((o) => isCatalogPath(o.path));
    const sinkCreateIdx = createOps.findIndex((o) => o.path === "/pipelines/v1/sinks");
    const pipeCreateIdx = createOps.findIndex((o) => o.path === "/pipelines/v1/pipelines");

    assert.ok(bucketCreateIdx >= 0 && catalogCreateIdx > bucketCreateIdx, "catalog must be enabled after bucket");
    assert.ok(sinkCreateIdx > catalogCreateIdx, "sink must be created after bucket and catalog");
    assert.ok(pipeCreateIdx > streamCreateIdx && pipeCreateIdx > sinkCreateIdx, "pipeline must be created after stream & sink");

    const streamCreateBody = createOps[streamCreateIdx].body;
    assert.equal(streamCreateBody.http?.enabled, true);
    assert.equal(streamCreateBody.http?.authentication, true);
    assert.equal(streamCreateBody.schema?.fields?.length, basinSchema.fields.length);
    const createdMeta = streamCreateBody.schema.fields.find((f) => f.name === "metadata");
    const createdDevice = streamCreateBody.schema.fields.find((f) => f.name === "device");
    const createdActor = streamCreateBody.schema.fields.find((f) => f.name === "actor");
    assert.equal(createdMeta?.type, "struct", "metadata struct type must be preserved verbatim");
    assert.equal(createdDevice?.type, "struct", "device struct type must be preserved verbatim");
    assert.equal(createdActor?.type, "struct", "actor struct type must be preserved verbatim");

    const sinkCreateBody = createOps[sinkCreateIdx].body;
    assert.equal(sinkCreateBody.type, "r2_data_catalog");
    assert.equal(sinkCreateBody.config?.namespace, "siem");
    assert.equal(sinkCreateBody.config?.table_name, "ocsf_event_log_activity");

    const expectedSql = pipelineSqlRaw
      .replaceAll("__SINK_NAME__", "ocsf_event_log_sink")
      .replaceAll("__STREAM_NAME__", "ocsf_event_log_stream");
    assert.equal(createOps[pipeCreateIdx].body.sql, expectedSql);

    // Check outputs
    const outRes = await spawnAsync(tofuBin, [`-chdir=${stagedTfDir}`, "output", "-json"], { env: tfEnv });
    assert.equal(outRes.status, 0, outRes.stderr);
    const outputs = JSON.parse(outRes.stdout);
    assert.equal(outputs.bucket_name.value, "oof-telemetry");
    assert.match(outputs.stream_endpoint.value, /^https:\/\/stream[0-9]+\.ingest\.cloudflare\.com$/);
    assert.match(outputs.stream_host.value, /^stream[0-9]+\.ingest\.cloudflare\.com$/);
    assert.equal(outputs.ingest_token.sensitive, true);
    assert.ok(typeof outputs.ingest_token.value === "string" && outputs.ingest_token.value.length > 0);

    // Update CORS origins -> must use PATCH in-place without replacing stream
    const opCountBeforePatch = mockCf.ops.length;
    writeTfvars({ stream_cors_origins: ["https://siem.example.com"] });
    const patchRes = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "apply", "-auto-approve", "-input=false", `-var-file=${tfvarsPath}`],
      { env: tfEnv }
    );
    assert.equal(patchRes.status, 0, `${patchRes.stdout}\n${patchRes.stderr}`);
    const patchOps = mockCf.ops.slice(opCountBeforePatch);
    const tfPatchCall = patchOps.find((o) => o.method === "PATCH" && o.path.startsWith("/pipelines/v1/streams/"));
    assert.ok(tfPatchCall, "stream CORS update must use PATCH");
    assert.deepEqual(Object.keys(tfPatchCall.body), ["http"]);
    assert.ok(!patchOps.some((o) => o.method === "POST" && o.path === "/pipelines/v1/streams"));

    const zeroDiffAfterPatch = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "plan", "-detailed-exitcode", "-input=false", `-var-file=${tfvarsPath}`],
      { env: tfEnv }
    );
    assert.equal(zeroDiffAfterPatch.status, 0, zeroDiffAfterPatch.stdout + zeroDiffAfterPatch.stderr);

    // Destroy ordering: pipeline before stream & sink, and sink before catalog & bucket
    const opCountBeforeDestroy = mockCf.ops.length;
    const destroyRes = await spawnAsync(
      tofuBin,
      [`-chdir=${stagedTfDir}`, "destroy", "-auto-approve", "-input=false", `-var-file=${tfvarsPath}`],
      { env: tfEnv }
    );
    assert.equal(destroyRes.status, 0, `${destroyRes.stdout}\n${destroyRes.stderr}`);
    const destroyOps = mockCf.ops
      .slice(opCountBeforeDestroy)
      .filter((o) => o.method === "DELETE" || (o.method === "POST" && o.path.endsWith("/disable")));
    const delPipeIdx = destroyOps.findIndex((o) => o.path.startsWith("/pipelines/v1/pipelines/"));
    const delStreamIdx = destroyOps.findIndex((o) => o.path.startsWith("/pipelines/v1/streams/"));
    const delSinkIdx = destroyOps.findIndex((o) => o.path.startsWith("/pipelines/v1/sinks/"));
    const delCatIdx = destroyOps.findIndex((o) => isCatalogPath(o.path));
    const delBucketIdx = destroyOps.findIndex((o) => o.path === "/r2/buckets/oof-telemetry");
    assert.ok(delPipeIdx >= 0 && delStreamIdx > delPipeIdx && delSinkIdx > delPipeIdx);
    assert.ok(delCatIdx > delSinkIdx && delBucketIdx > delSinkIdx);

    // --- Part B: Pulumi basin-core.ts runtime validation & BasinStructuredStreamProvider CRUD ---
    const basinCore = await import(pathToFileURL(PULUMI_CORE_PATH).href);
    const loadedFields = basinCore.loadBasinSchemaFields(BASIN_SCHEMA_PATH);
    assert.equal(loadedFields.length, basinSchema.fields.length);
    assert.equal(loadedFields.find((f) => f.name === "metadata")?.type, "struct");
    assert.equal(
      basinCore.renderPipelineSql(PIPELINE_SQL_PATH, "ocsf_event_log_sink", "ocsf_event_log_stream"),
      expectedSql
    );
    assert.equal(
      basinCore.extractHostFromEndpoint("https://abc123.ingest.cloudflare.com"),
      "abc123.ingest.cloudflare.com"
    );

    const validSettings = {
      accountId,
      catalogToken,
      apiBaseUrl: mockCf.baseUrl,
      bucketName: "oof-telemetry",
      namespace: "siem",
      tableName: "ocsf_event_log_activity",
      streamName: "ocsf_event_log_stream",
      sinkName: "ocsf_event_log_sink",
      pipelineName: "ocsf_event_log_to_iceberg",
      rollIntervalSeconds: 300,
      ingestTokenName: "oof-ingest",
    };
    basinCore.validateBasinSettings(validSettings);
    for (const badOverride of [
      { accountId: "not-hex" },
      { catalogToken: "   " },
      { apiBaseUrl: "http://api.cloudflare.com/client/v4" },
      { bucketName: "Bad_Bucket" },
      { tableName: "foo; DROP TABLE bar" },
      { streamName: "dup", sinkName: "dup" },
      { rollIntervalSeconds: 30 },
    ]) {
      assert.throws(() => basinCore.validateBasinSettings({ ...validSettings, ...badOverride }));
    }

    const provider = new basinCore.BasinStructuredStreamProvider();
    const baseStreamInputs = {
      accountId,
      apiBaseUrl: mockCf.baseUrl,
      name: "pulumi_ocsf_stream",
      format: { type: "json" },
      http: { enabled: true, authentication: true, cors: { origins: [] } },
      workerBinding: { enabled: false },
      schema: { fields: loadedFields },
    };

    // Without CLOUDFLARE_API_TOKEN, check/create must reject rather than permitting partial lifecycle.
    delete process.env.CLOUDFLARE_API_TOKEN;
    const checkNoToken = await provider.check(undefined, baseStreamInputs);
    assert.ok(checkNoToken.failures?.some((f) => f.property === "CLOUDFLARE_API_TOKEN"));
    await assert.rejects(() => provider.create(checkNoToken.inputs), /CLOUDFLARE_API_TOKEN/);

    process.env.CLOUDFLARE_API_TOKEN = adminToken;
    const checkGood = await provider.check(undefined, baseStreamInputs);
    assert.equal(checkGood.failures, undefined);
    const checkBad = await provider.check(undefined, {
      ...baseStreamInputs,
      accountId: "bad",
      name: "bad;name",
      schema: { fields: [] },
    });
    assert.equal(checkBad.failures?.length, 3);

    const created = await provider.create(checkGood.inputs);
    assert.ok(!Object.hasOwn(created.outs, "apiToken"), "Pulumi dynamic state outs must NEVER persist apiToken");
    assert.equal(created.outs.name, "pulumi_ocsf_stream");
    assert.equal(created.outs.schema.fields.find((f) => f.name === "device")?.type, "struct");

    // Passing `created.outs` directly (no manual apiToken injection) proves refresh/destroy work from CLOUDFLARE_API_TOKEN.
    const readBack = await provider.read(created.id, created.outs);
    assert.equal(readBack.id, created.id);
    // Server injects format.unstructured=false & schema.inferred=false; diff must stay clean (changes: false)
    const cleanDiff = await provider.diff(created.id, readBack.props, checkGood.inputs);
    assert.equal(cleanDiff.changes, false);

    // Missing CLOUDFLARE_API_TOKEN must fail loudly during read and delete as well.
    delete process.env.CLOUDFLARE_API_TOKEN;
    await assert.rejects(() => provider.read(created.id, created.outs), /CLOUDFLARE_API_TOKEN/);
    await assert.rejects(() => provider.delete(created.id, created.outs), /CLOUDFLARE_API_TOKEN/);
    process.env.CLOUDFLARE_API_TOKEN = adminToken;

    // Malformed upstream HTTP 200 / 404 HTML or missing result envelopes must reject loudly (Finding #2).
    mockCf.setNextResponse({ method: "GET", status: 200, rawBody: "<html>upstream temporarily unavailable</html>" });
    await assert.rejects(() => provider.read(created.id, created.outs), /non-JSON/);

    mockCf.setNextResponse({ method: "GET", status: 200, rawBody: JSON.stringify({ success: true, result: null }) });
    await assert.rejects(() => provider.read(created.id, created.outs), /missing result/);

    mockCf.setNextResponse({ method: "PATCH", status: 200, rawBody: "<html>bad gateway</html>" });
    await assert.rejects(() => provider.update(created.id, readBack.props, checkGood.inputs), /non-JSON/);

    mockCf.setNextResponse({ method: "PATCH", status: 200, rawBody: JSON.stringify({ success: true, result: null }) });
    await assert.rejects(() => provider.update(created.id, readBack.props, checkGood.inputs), /missing result/);

    mockCf.setNextResponse({ method: "POST", status: 200, rawBody: JSON.stringify({ success: true, result: null }) });
    await assert.rejects(() => provider.create(checkGood.inputs), /missing result/);

    mockCf.setNextResponse({ method: "GET", status: 404, rawBody: "<html>proxy 404</html>" });
    await assert.rejects(() => provider.read(created.id, created.outs), /non-JSON 404/);

    mockCf.setNextResponse({ method: "DELETE", status: 404, rawBody: "<html>proxy 404</html>" });
    await assert.rejects(() => provider.delete(created.id, created.outs), /non-JSON 404/);

    const corsUpdateInputs = {
      ...checkGood.inputs,
      http: { enabled: true, authentication: true, cors: { origins: ["https://siem.example.com"] } },
    };
    const patchDiff = await provider.diff(created.id, readBack.props, corsUpdateInputs);
    assert.equal(patchDiff.changes, true);
    assert.equal(patchDiff.replaces, undefined);

    const pulumiOpsBeforePatch = mockCf.ops.length;
    const updated = await provider.update(created.id, readBack.props, corsUpdateInputs);
    assert.ok(!Object.hasOwn(updated.outs, "apiToken"), "update outs must NEVER persist apiToken");
    assert.deepEqual(updated.outs.http.cors.origins, ["https://siem.example.com"]);
    const pulumiPatchCall = mockCf.ops.slice(pulumiOpsBeforePatch).find((o) => o.method === "PATCH");
    assert.deepEqual(Object.keys(pulumiPatchCall.body).sort(), ["http", "worker_binding"]);

    const schemaReplaceDiff = await provider.diff(created.id, updated.outs, {
      ...corsUpdateInputs,
      schema: { fields: loadedFields.slice(0, 1) },
    });
    assert.equal(schemaReplaceDiff.changes, true);
    assert.deepEqual(schemaReplaceDiff.replaces, ["schema"]);
    assert.equal(schemaReplaceDiff.deleteBeforeReplace, true);

    // Token must be scrubbed from error messages BEFORE slicing, including when straddling 200/300 char bounds.
    const secretSentinel = "super_secret_token_never_echo_40chars_0000";
    process.env.CLOUDFLARE_API_TOKEN = secretSentinel;
    await assert.rejects(
      () => provider.create(checkGood.inputs),
      (err) => {
        assert.ok(!err.message.includes(secretSentinel), "API errors must scrub Bearer token");
        return true;
      }
    );

    mockCf.setNextResponse({ method: "GET", status: 200, rawBody: "x".repeat(161) + secretSentinel });
    await assert.rejects(
      () => provider.read(created.id, created.outs),
      (err) => {
        assert.ok(!err.message.includes(secretSentinel.slice(0, 10)), "200 non-JSON slice must not leak token prefix");
        assert.ok(err.message.includes("[REDACTED]"));
        return true;
      }
    );

    mockCf.setNextResponse({ method: "GET", status: 404, rawBody: "x".repeat(161) + secretSentinel });
    await assert.rejects(
      () => provider.read(created.id, created.outs),
      (err) => {
        assert.ok(!err.message.includes(secretSentinel.slice(0, 10)), "404 non-JSON slice must not leak token prefix");
        assert.ok(err.message.includes("[REDACTED]"));
        return true;
      }
    );

    mockCf.setNextResponse({
      method: "GET",
      status: 403,
      rawBody: JSON.stringify({ success: false, errors: [{ message: "y".repeat(261) + secretSentinel }] }),
    });
    await assert.rejects(
      () => provider.read(created.id, created.outs),
      (err) => {
        assert.ok(!err.message.includes(secretSentinel.slice(0, 10)), "403 JSON error slice must not leak token prefix");
        assert.ok(err.message.includes("[REDACTED]"));
        return true;
      }
    );

    // 403 JSON error without `errors` array exercises the `trimmed` fallback redaction before 300-char slicing.
    const rawFallbackBody = JSON.stringify({
      success: false,
      message: "z".repeat(245) + secretSentinel,
    });
    assert.ok(
      rawFallbackBody.indexOf(secretSentinel) < 300 &&
        rawFallbackBody.indexOf(secretSentinel) + secretSentinel.length > 300
    );
    mockCf.setNextResponse({
      method: "GET",
      status: 403,
      rawBody: rawFallbackBody,
    });
    await assert.rejects(
      () => provider.read(created.id, created.outs),
      (err) => {
        assert.ok(!err.message.includes(secretSentinel.slice(0, 10)), "403 raw JSON fallback slice must not leak token prefix");
        assert.ok(err.message.includes("[REDACTED]"));
        return true;
      }
    );

    process.env.CLOUDFLARE_API_TOKEN = adminToken;
    // Empty 204 DELETE response is valid HTTP
    mockCf.setNextResponse({ method: "DELETE", status: 204, rawBody: "" });
    await provider.delete(created.id, updated.outs);
    // Genuine JSON 404 delete stays idempotent; genuine JSON 404 read returns {}
    await provider.delete(created.id, updated.outs);
    const missingRead = await provider.read(created.id, updated.outs);
    assert.deepEqual(missingRead, {});
  } finally {
    if (hadEnvToken) {
      process.env.CLOUDFLARE_API_TOKEN = prevEnvToken;
    } else {
      delete process.env.CLOUDFLARE_API_TOKEN;
    }
    await mockCf.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("6. Vector config passes validate and built-in VRL unit tests with zero warnings", () => {
  const vectorBin = requireBinary("vector");
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vec-val-"));
  try {
    const env = {
      ...process.env,
      VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
      OOF_VECTOR_DATA_DIR: tmpDataDir,
      OOF_BASIN_ENDPOINT: "https://example-stream.ingest.cloudflare.com",
      OOF_INGEST_TOKEN: "dummy-basin-token",
    };

    const valRes = spawnSync(vectorBin, ["validate", "--no-environment", VECTOR_CONFIG_PATH], {
      cwd: REPO_ROOT,
      env,
      encoding: "utf8",
    });
    assert.equal(valRes.status, 0, `${valRes.stdout}\n${valRes.stderr}`);

    const testRes = spawnSync(vectorBin, ["test", VECTOR_CONFIG_PATH], {
      cwd: REPO_ROOT,
      env,
      encoding: "utf8",
    });
    assert.equal(testRes.status, 0, `${testRes.stdout}\n${testRes.stderr}`);
    assert.ok(!/WARN\s/.test(testRes.stdout + testRes.stderr), `Unexpected Vector warnings:\n${testRes.stderr}`);
  } finally {
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test("7. Fluent Bit config and OTel Collector bridge enforce safety/wire invariants and pass dry-run", () => {
  const fbBin = requireBinary("fluent-bit");
  const fbConf = fs.readFileSync(FLUENT_BIT_CONF_PATH, "utf8");
  assert.ok(!/\$\{[A-Z0-9_]+:-/.test(fbConf), "Fluent Bit does not support ${VAR:-default} syntax");
  assert.match(fbConf, /json_date_key\s+false/);
  assert.match(fbConf, /tls\s+On/);
  assert.match(fbConf, /tls\.verify\s+On/);
  assert.match(fbConf, /tls\.verify_hostname\s+On/);
  assert.match(fbConf, /retain_metadata_in_forward_mode\s+false/);
  assert.match(fbConf, /Shared_Key\s+\$\{OOF_INGEST_TOKEN\}/);
  assert.match(fbConf, /Match_Regex\s+\^oof\\\.\(journald\|otlp_raw\)\$/);

  const fbDry = spawnSync(fbBin, ["--dry-run", "-c", FLUENT_BIT_CONF_PATH], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      OOF_BASIN_HOST: "example-stream.ingest.cloudflare.com",
      OOF_INGEST_TOKEN: "dummy-basin-token",
    },
    encoding: "utf8",
  });
  assert.equal(fbDry.status, 0, `${fbDry.stdout}\n${fbDry.stderr}`);
  assert.ok((fbDry.stdout + fbDry.stderr).includes("configuration test is successful"));

  const otelConf = fs.readFileSync(OTELCOL_CONF_PATH, "utf8");
  assert.match(otelConf, /encoding:\s*proto/);
  assert.match(otelConf, /OOF_OTLP_BRIDGE_ENDPOINT:-http:\/\/127\.0\.0\.1:4320/);
  assert.match(otelConf, /OOF_OTLP_GRPC_LISTEN=127\.0\.0\.1:4319/);
  assert.match(otelConf, /OOF_OTLP_HTTP_LISTEN=127\.0\.0\.1:4320/);
  assert.ok(!/^\s+journald:/m.test(otelConf), "otelcol.yaml journald receiver must be commented out by default");

  const skillDoc = fs.readFileSync(path.join(REPO_ROOT, "skills/setup-cloudflare-basin-iceberg/SKILL.md"), "utf8");
  assert.match(skillDoc, /OOF_OTLP_GRPC_LISTEN=127\.0\.0\.1:4319/);
  assert.match(skillDoc, /OOF_OTLP_HTTP_LISTEN=127\.0\.0\.1:4320/);

  const vecConfText = fs.readFileSync(VECTOR_CONFIG_PATH, "utf8");
  assert.match(vecConfText, /OOF_OTLP_GRPC_LISTEN.*127\.0\.0\.1:4319/);
  assert.match(vecConfText, /OOF_OTLP_HTTP_LISTEN.*127\.0\.0\.1:4320/);

  const vecBin = requireBinary("vector");
  const tmpCoLocDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-vec-coloc-"));
  try {
    const vecColocVal = spawnSync(vecBin, ["validate", "--no-environment", VECTOR_CONFIG_PATH], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
        OOF_VECTOR_DATA_DIR: tmpCoLocDir,
        OOF_BASIN_ENDPOINT: "https://example-stream.ingest.cloudflare.com",
        OOF_INGEST_TOKEN: "dummy-basin-token",
        OOF_OTLP_GRPC_LISTEN: "127.0.0.1:4319",
        OOF_OTLP_HTTP_LISTEN: "127.0.0.1:4320",
      },
      encoding: "utf8",
    });
    assert.equal(vecColocVal.status, 0, `${vecColocVal.stdout}\n${vecColocVal.stderr}`);
  } finally {
    fs.rmSync(tmpCoLocDir, { recursive: true, force: true });
  }
});

test("8. Live E2E wire conformance: Vector and Fluent Bit emit identical valid OCSF v1.3.0 batches", async () => {
  const vectorBin = requireBinary("vector");
  const fbBin = requireBinary("fluent-bit");
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8"));
  const vectorRaw = fs.readFileSync(VECTOR_CONFIG_PATH, "utf8");
  const jrnVrl = extractVectorTransformVrl(vectorRaw, "ocsf_journald");
  const otlpVrl = extractVectorTransformVrl(vectorRaw, "ocsf_otlp_logs");

  const testToken = "test-basin-token-xyz";
  const mockBasin = await startMockBasinServer(testToken);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-e2e-"));

  let vectorProc;
  let fbProc;

  try {
    // --- Part A: Live Vector E2E (http_server journald JSON input + real OTLP HTTP protobuf -> basin_http) ---
    const [vecJrnPort, vecOtlpGrpcPort, vecOtlpHttpPort, fbJrnPort, fbOtlpPort, fbFwdPort] = await getFreePorts(6);
    const vecDataDir = path.join(tmpDir, "vector-data");
    fs.mkdirSync(vecDataDir, { recursive: true });

    const vecE2eConfig = {
      data_dir: vecDataDir,
      sources: {
        journald: {
          type: "http_server",
          address: `127.0.0.1:${vecJrnPort}`,
          decoding: { codec: "json" },
          path_key: "",
        },
        otlp: {
          type: "opentelemetry",
          grpc: { address: `127.0.0.1:${vecOtlpGrpcPort}` },
          http: { address: `127.0.0.1:${vecOtlpHttpPort}` },
        },
      },
      transforms: {
        ocsf_journald: { type: "remap", inputs: ["journald"], source: jrnVrl },
        ocsf_otlp_logs: { type: "remap", inputs: ["otlp.logs"], source: otlpVrl },
      },
      sinks: {
        basin_http: {
          type: "http",
          inputs: ["ocsf_journald", "ocsf_otlp_logs"],
          uri: `http://127.0.0.1:${mockBasin.port}/`,
          method: "post",
          compression: "gzip",
          encoding: { codec: "json" },
          auth: { strategy: "bearer", token: testToken },
          batch: { max_events: 20, timeout_secs: 1 },
        },
        unused_otlp_apm: {
          type: "blackhole",
          inputs: ["otlp.metrics", "otlp.traces"],
          print_interval_secs: 0,
        },
      },
    };
    const vecConfigFile = path.join(tmpDir, "vector.e2e.json");
    fs.writeFileSync(vecConfigFile, JSON.stringify(vecE2eConfig, null, 2));

    vectorProc = spawn(vectorBin, ["--config-json", vecConfigFile], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let vecStderr = "";
    vectorProc.stderr.on("data", (d) => {
      vecStderr += d.toString("utf8");
    });

    await waitForTcpReady(vecJrnPort);
    await waitForTcpReady(vecOtlpHttpPort);

    const jrnNormal = {
      MESSAGE: "Accepted publickey for alice from 198.51.100.4 port 54321 ssh2",
      PRIORITY: "4",
      SYSLOG_FACILITY: "10",
      SYSLOG_IDENTIFIER: "sshd",
      _SYSTEMD_UNIT: "sshd.service",
      _TRANSPORT: "syslog",
      _HOSTNAME: "host-a",
      _MACHINE_ID: "mach-a",
      _BOOT_ID: "boot-a",
      _PID: "4242",
      _UID: "1000",
      _COMM: "sshd",
      _EXE: "/usr/sbin/sshd",
      _CMDLINE: "sshd: alice [priv]",
      _SOURCE_REALTIME_TIMESTAMP: "1731676800123000",
      __REALTIME_TIMESTAMP: "1731676800124000",
      __CURSOR: "cur-a",
      EXTRA_ATTR: "ssh-ok",
    };

    const jrnEdge = {
      MESSAGE: "edge record",
      PRIORITY: "99",
      _HOSTNAME: "host-edge",
      _UID: "1e5",
      _PID: "inf",
      _SOURCE_REALTIME_TIMESTAMP: 10000000000000000,
      __REALTIME_TIMESTAMP: "1731676801000000",
    };

    const jrnFallback = {
      MESSAGE: "fallback check",
      PRIORITY: "03",
      _HOSTNAME: "host-fb",
      TRACE_ID: "",
      OTEL_TRACE_ID: "0af7651916cd43dd8448eb211c80319c",
      SPAN_ID: "0000000000000000",
      OTEL_SPAN_ID: "b7ad6b7169203331",
      _PID: "invalid",
      SYSLOG_PID: "4242",
      _SOURCE_REALTIME_TIMESTAMP: "999999999999999999",
      __REALTIME_TIMESTAMP: "253402300799999999",
    };

    // Send journald records to Vector
    for (const payload of [jrnNormal, jrnEdge, jrnFallback]) {
      const r = await fetch(`http://127.0.0.1:${vecJrnPort}/`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      assert.ok(r.ok, `Vector http_server rejected payload: ${r.status}`);
    }

    const otlpPayload = encodeOtlpLogsRequest({
      resourceAttrs: {
        "service.name": "billing-api",
        "host.name": "app-01",
        "os.type": "linux",
        "process.pid": 888,
        "deployment.environment": "prod",
      },
      scopeName: "billing.logger",
      logRecords: [
        {
          timeUnixNano: 1736496000250000000n,
          observedTimeUnixNano: 1736496000300000000n,
          severityNumber: 17,
          severityText: "ERROR",
          body: "card charge timeout",
          attributes: { "user.id": "1001", "user.name": "alice", "order.id": "ord-7" },
          traceIdHex: "0af7651916cd43dd8448eb211c80319c",
          spanIdHex: "b7ad6b7169203331",
        },
      ],
    });

    const otlpEdgePayload = encodeOtlpLogsRequest({
      resourceAttrs: { "service.name": "bsd-svc", "os.type": "freebsd", "process.pid": "bad" },
      scopeName: "",
      logRecords: [
        {
          timeUnixNano: 0n,
          observedTimeUnixNano: 1736496005122999900n,
          severityNumber: 0,
          body: { event: "structured", ok: true },
          attributes: { "process.pid": 777, "user.id": "", "enduser.id": "2002" },
          traceIdHex: "00000000000000000000000000000000",
          spanIdHex: "0000000000000000",
        },
        {
          timeUnixNano: 0n,
          observedTimeUnixNano: 999900n,
          severityNumber: 9,
          body: "sub-ms observed fallback",
        },
      ],
    });

    for (const pb of [otlpPayload, otlpEdgePayload]) {
      const r = await fetch(`http://127.0.0.1:${vecOtlpHttpPort}/v1/logs`, {
        method: "POST",
        headers: { "content-type": "application/x-protobuf" },
        body: pb,
      });
      assert.ok(r.ok, `Vector OTLP /v1/logs rejected protobuf: ${r.status}`);
    }

    await waitForCondition(() => mockBasin.records.length >= 6, 15000);
    await terminateProcess(vectorProc);
    assert.equal(vecStderr.includes("ERROR "), false, `Vector stderr errors:\n${vecStderr}`);

    const vectorRecords = mockBasin.records.splice(0, mockBasin.records.length);
    assert.equal(vectorRecords.length, 6, `Expected 6 Vector OCSF records, got ${vectorRecords.length}`);
    for (const rec of vectorRecords) {
      assertConformsToOcsfContract(rec, basinSchema);
    }

    const vecJrnNormalOut = vectorRecords.find((r) => r.metadata.original_event_uid === "cur-a");
    assert.ok(vecJrnNormalOut, "missing Vector normal journald output");
    assert.equal(vecJrnNormalOut.severity_id, 3);
    assert.equal(vecJrnNormalOut.severity, "Medium");
    assert.equal(vecJrnNormalOut.time, 1731676800123);
    assert.equal(vecJrnNormalOut.time_dt, "2024-11-15T13:20:00.123Z");
    assert.equal(vecJrnNormalOut.actor.user.uid, "1000");
    assert.equal(vecJrnNormalOut.actor.user.uid_numeric, 1000);
    assert.equal(vecJrnNormalOut.unmapped.EXTRA_ATTR, "ssh-ok");

    const vecJrnEdgeOut = vectorRecords.find((r) => r.message === "edge record");
    assert.ok(vecJrnEdgeOut, "missing Vector edge journald output");
    assert.equal(vecJrnEdgeOut.severity_id, 0);
    assert.equal(vecJrnEdgeOut.severity, "Unknown");
    assert.equal(vecJrnEdgeOut.time, 1731676801000);
    assert.equal(vecJrnEdgeOut.actor.user.uid, "1e5");
    assert.equal(vecJrnEdgeOut.actor.user.uid_numeric, undefined);
    assert.equal(vecJrnEdgeOut.actor.process, undefined);
    assert.equal(vecJrnEdgeOut.unmapped, undefined);

    const vecJrnFallbackOut = vectorRecords.find((r) => r.message === "fallback check");
    assert.ok(vecJrnFallbackOut, "missing Vector fallback journald output");
    assert.equal(vecJrnFallbackOut.severity_id, 0);
    assert.equal(vecJrnFallbackOut.severity, "Unknown");
    assert.equal(vecJrnFallbackOut.metadata.log_level, "03");
    assert.equal(vecJrnFallbackOut.metadata.correlation_uid, "0af7651916cd43dd8448eb211c80319c");
    assert.equal(vecJrnFallbackOut.unmapped.span_id, "b7ad6b7169203331");
    assert.equal(vecJrnFallbackOut.actor.process.pid, 4242);
    assert.equal(vecJrnFallbackOut.time, 253402300799999);
    assert.equal(vecJrnFallbackOut.time_dt, "9999-12-31T23:59:59.999Z");

    const vecOtlpOut = vectorRecords.find((r) => r.message === "card charge timeout");
    assert.ok(vecOtlpOut, "missing Vector normal OTLP output");
    assert.equal(vecOtlpOut.severity_id, 4);
    assert.equal(vecOtlpOut.device.os.name, "Linux");
    assert.equal(vecOtlpOut.device.os.type_id, 200);
    assert.equal(vecOtlpOut.metadata.correlation_uid, "0af7651916cd43dd8448eb211c80319c");
    assert.equal(vecOtlpOut.unmapped.span_id, "b7ad6b7169203331");
    assert.equal(vecOtlpOut.unmapped.attributes["order.id"], "ord-7");

    const vecOtlpEdgeOut = vectorRecords.find((r) => r.log_name === "bsd-svc" && r.message !== "sub-ms observed fallback");
    assert.ok(vecOtlpEdgeOut, "missing Vector edge OTLP output");
    assert.equal(vecOtlpEdgeOut.device.os, undefined, "unknown os.type must omit device.os");
    assert.equal(vecOtlpEdgeOut.metadata.correlation_uid, undefined, "all-zero trace_id must be omitted");
    assert.equal(vecOtlpEdgeOut.time, 1736496005122, "must fall back to truncated observed_timestamp when timeUnixNano=0");
    assert.equal(vecOtlpEdgeOut.metadata.logged_time, 1736496005122);
    assert.equal(vecOtlpEdgeOut.actor.process.pid, 777);
    assert.equal(vecOtlpEdgeOut.actor.user.uid, "2002");
    assert.equal(vecOtlpEdgeOut.actor.user.uid_numeric, 2002);
    assert.equal(typeof vecOtlpEdgeOut.message, "string");

    const vecOtlpSubMsOut = vectorRecords.find((r) => r.message === "sub-ms observed fallback");
    assert.ok(vecOtlpSubMsOut, "missing Vector sub-ms observed fallback output");
    assert.ok(vecOtlpSubMsOut.time >= 1700000000000, "sub-ms observed_timestamp must fall back to now()");
    assert.ok(vecOtlpSubMsOut.metadata.logged_time >= 1700000000000);

    // --- Part B: Live Fluent Bit E2E (derived from real fluent-bit.conf + ocsf.lua -> loopback forward -> http) ---
    mockBasin.requests.length = 0;
    const fbConfFile = path.join(tmpDir, "fluent-bit.e2e.conf");
    const fbConfTemplate = fs.readFileSync(FLUENT_BIT_CONF_PATH, "utf8");
    const fbConfContent = fbConfTemplate
      .replace(/^(\s*Flush\s+)5$/m, (_, p) => `${p}1`)
      .replace(
        /\[INPUT\]\s+Name\s+systemd[\s\S]*?(?=\n\[INPUT\])/,
        `[INPUT]\n    Name               http\n    Tag                oof.journald\n    Listen             127.0.0.1\n    Port               ${fbJrnPort}\n`
      )
      .replace(/^(\s*Port\s+)4318$/m, (_, p) => `${p}${fbOtlpPort}`)
      .replace(/^(\s*Port\s+)24225$/gm, (_, p) => `${p}${fbFwdPort}`)
      .replace(/^(\s*Script\s+)ocsf\.lua$/m, (_, p) => `${p}${FLUENT_BIT_LUA_PATH}`)
      .replace(/^(\s*Host\s+)\$\{OOF_BASIN_HOST\}$/m, (_, p) => `${p}127.0.0.1`)
      .replace(/^(\s*Port\s+)443$/m, (_, p) => `${p}${mockBasin.port}`)
      .replace(/^(\s*tls\s+)On$/m, (_, p) => `${p}Off`);
    assert.equal(/\bName\s+systemd\b/.test(fbConfContent), false, "failed to substitute systemd input in test config");
    assert.equal(fbConfContent.includes("${OOF_BASIN_HOST}"), false, "failed to substitute OOF_BASIN_HOST");
    assert.equal(fbConfContent.includes("${OOF_INGEST_TOKEN}"), true, "test must exercise Shared_Key and Bearer env interpolation");
    fs.writeFileSync(fbConfFile, fbConfContent);

    fbProc = spawn(fbBin, ["-c", fbConfFile], {
      cwd: REPO_ROOT,
      env: { ...process.env, OOF_INGEST_TOKEN: testToken },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let fbOutput = "";
    fbProc.stdout.on("data", (d) => {
      fbOutput += d.toString("utf8");
    });
    fbProc.stderr.on("data", (d) => {
      fbOutput += d.toString("utf8");
    });

    await waitForCondition(() => fbOutput.includes(`listening on 127.0.0.1:${fbFwdPort}`), 10000, 50);
    await waitForTcpReady(fbJrnPort);
    await waitForTcpReady(fbOtlpPort);

    // Send dummy OTLP metrics & traces first to confirm non-log signals return 2xx and never leak to Basin HTTP output
    const fbMetricsRes = await fetch(`http://127.0.0.1:${fbOtlpPort}/v1/metrics`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        resourceMetrics: [
          {
            resource: {},
            scopeMetrics: [
              {
                scope: {},
                metrics: [
                  {
                    name: "dummy.counter",
                    gauge: { dataPoints: [{ timeUnixNano: "1736496000000000000", asInt: "1" }] },
                  },
                ],
              },
            ],
          },
        ],
      }),
    });
    assert.ok(fbMetricsRes.ok, `Fluent Bit OTLP /v1/metrics unexpected status: ${fbMetricsRes.status}`);

    const fbTracesRes = await fetch(`http://127.0.0.1:${fbOtlpPort}/v1/traces`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        resourceSpans: [
          {
            resource: {},
            scopeSpans: [
              {
                scope: {},
                spans: [
                  {
                    traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
                    spanId: "00f067aa0ba902b7",
                    name: "dummy-span",
                    startTimeUnixNano: "1736496000000000000",
                    endTimeUnixNano: "1736496001000000000",
                  },
                ],
              },
            ],
          },
        ],
      }),
    });
    assert.ok(fbTracesRes.ok, `Fluent Bit OTLP /v1/traces unexpected status: ${fbTracesRes.status}`);

    for (const payload of [jrnNormal, jrnEdge, jrnFallback]) {
      const r = await fetch(`http://127.0.0.1:${fbJrnPort}/`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      assert.ok(r.ok, `Fluent Bit http input rejected payload: ${r.status}`);
    }

    for (const pb of [otlpPayload, otlpEdgePayload]) {
      const r = await fetch(`http://127.0.0.1:${fbOtlpPort}/v1/logs`, {
        method: "POST",
        headers: { "content-type": "application/x-protobuf" },
        body: pb,
      });
      assert.ok(r.ok, `Fluent Bit OTLP /v1/logs rejected protobuf: ${r.status}`);
    }

    await waitForCondition(() => mockBasin.records.length >= 6, 15000);
    await terminateProcess(fbProc);
    assert.equal(/\[error\]/i.test(fbOutput), false, `Fluent Bit reported errors:\n${fbOutput}`);

    for (const reqInfo of mockBasin.requests) {
      assert.equal(reqInfo.method, "POST");
      assert.equal(reqInfo.isGzip, true);
      assert.match(reqInfo.headers["content-type"] || "", /^application\/json/i);
    }

    const fbRecords = mockBasin.records.splice(0, mockBasin.records.length);
    assert.equal(fbRecords.length, 6, `Expected exactly 6 Fluent Bit OCSF log records, got ${fbRecords.length}`);
    for (const rec of fbRecords) {
      assert.equal(Object.hasOwn(rec, "date"), false, "Fluent Bit json_date_key=false must suppress 'date' key");
      assert.equal(Object.hasOwn(rec, "__internal__"), false, "Fluent Bit forward metadata stripping must suppress '__internal__' key");
      assertConformsToOcsfContract(rec, basinSchema);
    }

    // Cross-collector parity checks between Vector and Fluent Bit
    const fbJrnNormalOut = fbRecords.find((r) => r.metadata.original_event_uid === "cur-a");
    assert.ok(fbJrnNormalOut, "missing Fluent Bit normal journald output");
    assert.equal(fbJrnNormalOut.severity_id, vecJrnNormalOut.severity_id);
    assert.equal(fbJrnNormalOut.severity, vecJrnNormalOut.severity);
    assert.equal(fbJrnNormalOut.time, vecJrnNormalOut.time);
    assert.equal(fbJrnNormalOut.time_dt, vecJrnNormalOut.time_dt);
    assert.deepEqual(fbJrnNormalOut.actor, vecJrnNormalOut.actor);
    assert.deepEqual(fbJrnNormalOut.device, vecJrnNormalOut.device);
    assert.deepEqual(fbJrnNormalOut.unmapped, vecJrnNormalOut.unmapped);

    const fbJrnEdgeOut = fbRecords.find((r) => r.message === "edge record");
    assert.ok(fbJrnEdgeOut, "missing Fluent Bit edge journald output");
    assert.equal(fbJrnEdgeOut.severity_id, 0);
    assert.equal(fbJrnEdgeOut.time, vecJrnEdgeOut.time);
    assert.equal(fbJrnEdgeOut.actor.user.uid, "1e5");
    assert.equal(fbJrnEdgeOut.actor.user.uid_numeric, undefined);
    assert.equal(fbJrnEdgeOut.actor.process, undefined);
    assert.equal(fbJrnEdgeOut.unmapped, undefined, "empty unmapped must be omitted, never []");

    const fbJrnFallbackOut = fbRecords.find((r) => r.message === "fallback check");
    assert.ok(fbJrnFallbackOut, "missing Fluent Bit fallback journald output");
    assert.equal(fbJrnFallbackOut.severity_id, vecJrnFallbackOut.severity_id);
    assert.equal(fbJrnFallbackOut.severity, vecJrnFallbackOut.severity);
    assert.equal(fbJrnFallbackOut.time, vecJrnFallbackOut.time);
    assert.equal(fbJrnFallbackOut.time_dt, vecJrnFallbackOut.time_dt);
    assert.equal(fbJrnFallbackOut.metadata.log_level, vecJrnFallbackOut.metadata.log_level);
    assert.equal(fbJrnFallbackOut.metadata.correlation_uid, vecJrnFallbackOut.metadata.correlation_uid);
    assert.deepEqual(fbJrnFallbackOut.actor, vecJrnFallbackOut.actor);
    assert.deepEqual(fbJrnFallbackOut.unmapped, vecJrnFallbackOut.unmapped);

    const fbOtlpOut = fbRecords.find((r) => r.message === "card charge timeout");
    assert.ok(fbOtlpOut, "missing Fluent Bit normal OTLP output");
    assert.equal(fbOtlpOut.severity_id, vecOtlpOut.severity_id);
    assert.equal(fbOtlpOut.severity, vecOtlpOut.severity);
    assert.equal(fbOtlpOut.time, vecOtlpOut.time);
    assert.equal(fbOtlpOut.time_dt, vecOtlpOut.time_dt);
    assert.equal(fbOtlpOut.metadata.correlation_uid, vecOtlpOut.metadata.correlation_uid);
    assert.deepEqual(fbOtlpOut.device, vecOtlpOut.device);
    assert.deepEqual(fbOtlpOut.actor, vecOtlpOut.actor);
    assert.deepEqual(fbOtlpOut.unmapped, vecOtlpOut.unmapped);

    const fbOtlpEdgeOut = fbRecords.find((r) => r.log_name === "bsd-svc" && r.message !== "sub-ms observed fallback");
    assert.ok(fbOtlpEdgeOut, "missing Fluent Bit edge OTLP output");
    assert.equal(fbOtlpEdgeOut.device.os, undefined, "unknown os.type must omit device.os");
    assert.equal(fbOtlpEdgeOut.metadata.correlation_uid, undefined, "all-zero binary trace_id must be omitted");
    assert.equal(fbOtlpEdgeOut.time, vecOtlpEdgeOut.time);
    assert.equal(fbOtlpEdgeOut.metadata.logged_time, vecOtlpEdgeOut.metadata.logged_time);
    assert.deepEqual(fbOtlpEdgeOut.actor, vecOtlpEdgeOut.actor);
    assert.equal(typeof fbOtlpEdgeOut.message, "string");

    const fbOtlpSubMsOut = fbRecords.find((r) => r.message === "sub-ms observed fallback");
    assert.ok(fbOtlpSubMsOut, "missing Fluent Bit sub-ms observed fallback output");
    assert.ok(fbOtlpSubMsOut.time >= 1700000000000, "sub-ms observed_timestamp must fall back to now()");
    assert.ok(fbOtlpSubMsOut.metadata.logged_time >= 1700000000000);
  } finally {
    await terminateProcess(vectorProc);
    await terminateProcess(fbProc);
    await mockBasin.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("9. GitHub Actions monitoring: Vector webhook E2E, direct Action E2E, and SQL contract parity", async () => {
  const vectorBin = requireBinary("vector");
  const basinSchema = JSON.parse(fs.readFileSync(BASIN_SCHEMA_PATH, "utf8"));

  // Verify SQL query file targets siem.ocsf_event_log_activity and OCSF class_uid = 1008
  const ghaSql = fs.readFileSync(GHA_MONITORING_SQL_PATH, "utf8");
  assert.match(ghaSql, /FROM\s+siem\.ocsf_event_log_activity/i);
  assert.match(ghaSql, /class_uid\s*=\s*1008/);
  assert.match(ghaSql, /log_provider\s*=\s*'github-actions'/);
  assert.match(ghaSql, /actions\.runner\.%/);

  // Verify action.yml uses node20 (zero shell scripts)
  const actionYml = fs.readFileSync(GHA_DIRECT_ACTION_PATH, "utf8");
  assert.match(actionYml, /using:\s*"?node20"?/);
  assert.match(actionYml, /main:\s*"?emit-ocsf\.mjs"?/);

  const testToken = "test-basin-gha-token-xyz";
  const webhookSecret = "super-secret-gh-webhook-key-!@#";
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-gha-e2e-"));
  const mockBasin = await startMockBasinServer(testToken);
  let vecProc;

  try {
    // Part A: Validate and run built-in VRL tests in adapters/collect/vector-github-actions/vector.yaml
    const vecVal = spawnSync(
      vectorBin,
      ["validate", "--no-environment", "--dangerously-allow-env-var-interpolation", VECTOR_GHA_CONFIG_PATH],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          OOF_VECTOR_DATA_DIR: path.join(tmpDir, "val-data"),
          OOF_BASIN_ENDPOINT: `http://127.0.0.1:${mockBasin.port}/`,
          OOF_INGEST_TOKEN: testToken,
          OOF_GITHUB_WEBHOOK_SECRET: webhookSecret,
          OOF_GHA_WEBHOOK_LISTEN: "127.0.0.1:8088",
        },
        encoding: "utf8",
      }
    );
    assert.equal(vecVal.status, 0, `vector-github-actions validate failed:\n${vecVal.stdout}\n${vecVal.stderr}`);

    const vecTest = spawnSync(
      vectorBin,
      ["test", VECTOR_GHA_CONFIG_PATH],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: "true",
          OOF_VECTOR_DATA_DIR: path.join(tmpDir, "test-data"),
          OOF_BASIN_ENDPOINT: `http://127.0.0.1:${mockBasin.port}/`,
          OOF_INGEST_TOKEN: testToken,
          OOF_GITHUB_WEBHOOK_SECRET: webhookSecret,
        },
        encoding: "utf8",
      }
    );
    assert.equal(vecTest.status, 0, `vector-github-actions test failed:\n${vecTest.stdout}\n${vecTest.stderr}`);

    // Part B: Live Vector GitHub Webhook E2E (HMAC-SHA256 verification + OCSF v1.3.0 -> mock Basin)
    const [ghaPort] = await getFreePorts(1);
    const liveDataDir = path.join(tmpDir, "live-gha-data");
    fs.mkdirSync(liveDataDir, { recursive: true });

    vecProc = spawn(
      vectorBin,
      ["--dangerously-allow-env-var-interpolation", "--config", VECTOR_GHA_CONFIG_PATH],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          OOF_VECTOR_DATA_DIR: liveDataDir,
          OOF_BASIN_ENDPOINT: `http://127.0.0.1:${mockBasin.port}/`,
          OOF_INGEST_TOKEN: testToken,
          OOF_GITHUB_WEBHOOK_SECRET: webhookSecret,
          OOF_GHA_WEBHOOK_LISTEN: `127.0.0.1:${ghaPort}`,
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let vecStderr = "";
    vecProc.stderr.on("data", (d) => {
      vecStderr += d.toString("utf8");
    });
    await waitForTcpReady(ghaPort);

    const signBody = (raw) => "sha256=" + crypto.createHmac("sha256", webhookSecret).update(raw).digest("hex");

    const runPayload = JSON.stringify({
      action: "completed",
      repository: { full_name: "acme/core" },
      organization: { login: "acme" },
      workflow_run: {
        id: 100200300,
        name: "Release",
        path: ".github/workflows/release.yml",
        run_number: 18,
        run_attempt: 2,
        status: "completed",
        conclusion: "failure",
        event: "pull_request_target",
        head_branch: "pr-branch",
        head_sha: "deadbeef1234",
        html_url: "https://github.com/acme/core/actions/runs/100200300",
        created_at: "2025-03-01T10:00:00Z",
        run_started_at: "2025-03-01T10:00:15Z",
        updated_at: "2025-03-01T10:03:15Z",
        head_repository: { full_name: "fork-user/core" },
        triggering_actor: { login: "external-dev", id: 424242 },
      },
    });

    const jobPayload = JSON.stringify({
      action: "completed",
      repository: { full_name: "acme/core" },
      sender: { login: "external-dev", id: 424242 },
      workflow_job: {
        id: 999888,
        run_id: 100200300,
        run_attempt: 2,
        workflow_name: "Release",
        name: "deploy-prod",
        status: "completed",
        conclusion: "success",
        head_branch: "pr-branch",
        head_sha: "deadbeef1234",
        created_at: "2025-03-01T10:00:15Z",
        started_at: "2025-03-01T10:00:25Z",
        completed_at: "2025-03-01T10:02:25Z",
        runner_id: 55,
        runner_name: "nixos-runner-01",
        runner_group_name: "prod",
        labels: ["self-hosted", "linux", "x64"],
      },
    });

    const badPayload = JSON.stringify({
      action: "completed",
      repository: { full_name: "attacker/evil" },
      workflow_run: { id: 666, name: "Spoofed", status: "completed", conclusion: "success" },
    });

    // Send 1 invalid-signature webhook (must be dropped by verify_github_signature)
    const badRes = await fetch(`http://127.0.0.1:${ghaPort}/webhook/github`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "workflow_run",
        "x-github-delivery": "deliv-invalid",
        "x-hub-signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
      },
      body: badPayload,
    });
    assert.ok(badRes.ok);

    // Send 2 valid HMAC-signed webhooks
    for (const [ev, delivery, raw] of [
      ["workflow_run", "deliv-e2e-run", runPayload],
      ["workflow_job", "deliv-e2e-job", jobPayload],
    ]) {
      const r = await fetch(`http://127.0.0.1:${ghaPort}/webhook/github`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-github-event": ev,
          "x-github-delivery": delivery,
          "x-hub-signature-256": signBody(raw),
        },
        body: raw,
      });
      assert.ok(r.ok, `Vector webhook rejected ${ev}: ${r.status}`);
    }

    await waitForCondition(() => mockBasin.records.length >= 2, 15000);
    await terminateProcess(vecProc);
    assert.equal(vecStderr.includes("ERROR "), false, `Vector webhook stderr errors:\n${vecStderr}`);

    const ghaWebhookRecords = mockBasin.records.splice(0, mockBasin.records.length);
    assert.equal(ghaWebhookRecords.length, 2, `Expected exactly 2 valid webhook records (invalid dropped), got ${ghaWebhookRecords.length}`);
    for (const rec of ghaWebhookRecords) {
      assertConformsToOcsfContract(rec, basinSchema);
      assert.equal(rec.log_provider, "github-actions");
    }

    const runRec = ghaWebhookRecords.find((r) => r.metadata.original_event_uid === "deliv-e2e-run");
    assert.ok(runRec, "missing workflow_run webhook OCSF record");
    assert.equal(runRec.severity_id, 4);
    assert.equal(runRec.severity, "High");
    assert.equal(runRec.log_name, "acme/core:Release");
    assert.equal(runRec.metadata.correlation_uid, "100200300");
    assert.equal(runRec.actor.user.name, "external-dev");
    assert.equal(runRec.actor.user.uid, "424242");
    assert.equal(runRec.actor.user.uid_numeric, 424242);
    assert.equal(runRec.unmapped.duration_ms, 180000);
    assert.equal(runRec.unmapped.queue_duration_ms, 15000);
    assert.equal(runRec.unmapped.is_fork_pr, true);
    assert.equal(runRec.unmapped.trigger_event, "pull_request_target");

    const jobRec = ghaWebhookRecords.find((r) => r.metadata.original_event_uid === "deliv-e2e-job");
    assert.ok(jobRec, "missing workflow_job webhook OCSF record");
    assert.equal(jobRec.severity_id, 1);
    assert.equal(jobRec.device.type_id, 1);
    assert.equal(jobRec.device.type, "Server");
    assert.equal(jobRec.device.hostname, "nixos-runner-01");
    assert.equal(jobRec.device.os.name, "Linux");
    assert.equal(jobRec.device.os.type_id, 200);
    assert.equal(jobRec.unmapped.is_self_hosted, true);

    // Part C: Direct serverless GitHub Action (emit-ocsf.mjs -> mock Basin HTTP)
    const directMod = await import(pathToFileURL(GHA_DIRECT_MODULE_PATH).href);
    const { endpoint, token, event } = directMod.buildInputFromEnv({
      INPUT_BASIN_ENDPOINT: `http://127.0.0.1:${mockBasin.port}/`,
      INPUT_INGEST_TOKEN: testToken,
      INPUT_CONCLUSION: "failure",
      INPUT_DURATION_MS: "45000",
      INPUT_IS_SELF_HOSTED: "true",
      INPUT_EXTRA_JSON: JSON.stringify({ environment: "staging" }),
      GITHUB_REPOSITORY: "acme/core",
      GITHUB_WORKFLOW: "CI",
      GITHUB_JOB: "unit-tests",
      GITHUB_EVENT_NAME: "push",
      GITHUB_ACTOR: "alice",
      GITHUB_ACTOR_ID: "1001",
      GITHUB_RUN_ID: "777888999",
      GITHUB_RUN_NUMBER: "12",
      GITHUB_RUN_ATTEMPT: "2",
      GITHUB_REF: "refs/heads/main",
      GITHUB_SHA: "cafebabe",
      RUNNER_NAME: "self-hosted-02",
      RUNNER_OS: "Linux",
      OTEL_TRACE_ID: "0af7651916cd43dd8448eb211c80319c",
    });

    assertConformsToOcsfContract(event, basinSchema);
    assert.equal(event.severity_id, 4);
    assert.equal(event.severity, "High");
    assert.equal(event.log_provider, "github-actions");
    assert.equal(event.log_name, "acme/core:CI");
    assert.equal(event.metadata.correlation_uid, "0af7651916cd43dd8448eb211c80319c");
    assert.equal(event.device.type_id, 1);
    assert.equal(event.device.os.type_id, 200);
    assert.equal(event.unmapped.environment, "staging");

    const sendRes = await directMod.sendToBasin([event], { endpoint, token });
    assert.equal(sendRes.status, 200);
    assert.equal(sendRes.count, 1);

    await waitForCondition(() => mockBasin.records.length >= 1, 5000);
    const directRec = mockBasin.records.pop();
    assertConformsToOcsfContract(directRec, basinSchema);
    assert.equal(directRec.metadata.original_event_uid, "777888999:2:unit-tests");
  } finally {
    await terminateProcess(vecProc);
    await mockBasin.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
