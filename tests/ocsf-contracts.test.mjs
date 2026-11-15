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

const BASIN_SCHEMA_PATH = path.join(REPO_ROOT, "contracts/ocsf/event-log-activity.basin.json");
const PIPELINE_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/pipeline.sql");
const HUNTING_SQL_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql");
const PROVISION_SCRIPT_PATH = path.join(REPO_ROOT, "adapters/storage/cloudflare-basin-iceberg/provision-basin.sh");
const STACK_SCHEMA_PATH = path.join(REPO_ROOT, "manifest/stack.schema.json");
const STACK_EXAMPLE_PATH = path.join(REPO_ROOT, "manifest/examples/cloudflare-basin-ocsf.yaml");
const VECTOR_CONFIG_PATH = path.join(REPO_ROOT, "adapters/collect/vector-journald/vector.yaml");
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
  const res = spawnSync("which", [name], { encoding: "utf8" });
  if (res.status !== 0) {
    throw new Error(`Required test runtime binary '${name}' is not in PATH`);
  }
  return res.stdout.trim();
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
      assert.ok(depth < 2, `struct field '${field.name}' exceeds Wrangler max nesting depth <= 2`);
      validateBasinFields(field.fields, depth + 1);
    }

    if (field.type === "list") {
      assert.ok(depth < 2, `list field '${field.name}' exceeds Wrangler max nesting depth <= 2`);
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

test("1. OCSF v1.3.0 Basin stream schema conforms to Wrangler SchemaField limits and OCSF invariants", () => {
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

test("4. Repository link integrity and zero stale worker/YARA/proprietary schema references", () => {
  const gitList = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.equal(gitList.status, 0);
  const trackedFiles = gitList.stdout.trim().split("\n").filter(Boolean);

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
    "skills/compose-observability-stack/SKILL.md",
    "skills/compose-observability-stack/references/component-catalog.md",
    "skills/setup-cloudflare-basin-iceberg/SKILL.md",
    "skills/setup-cloudflare-basin-iceberg/references/basin-troubleshooting.md",
  ];
  const pathRefRe = /\b(?:adapters|contracts|manifest|skills|tests)\/[a-zA-Z0-9._\/-]+\.(?:yaml|yml|json|sql|sh|lua|conf|md|mjs)\b/g;
  for (const doc of docFiles) {
    const text = fs.readFileSync(path.join(REPO_ROOT, doc), "utf8");
    for (const match of text.matchAll(pathRefRe)) {
      const refPath = path.join(REPO_ROOT, match[0]);
      assert.ok(fs.existsSync(refPath), `Missing referenced path '${match[0]}' in '${doc}'`);
    }
  }
});

test("5. provision-basin.sh dry-run plan, secret redaction, and argument validation", () => {
  const sentinelSecret = "secret-catalog-token-do-not-leak-987";
  const dryRun = spawnSync(
    PROVISION_SCRIPT_PATH,
    ["--dry-run", "--bucket", "oof-telemetry", "--namespace", "siem", "--table", "ocsf_event_log_activity"],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, BASIN_CATALOG_TOKEN: sentinelSecret },
      encoding: "utf8",
    }
  );
  assert.equal(dryRun.status, 0, dryRun.stderr);
  assert.ok(!dryRun.stdout.includes(sentinelSecret), "dry-run must never echo BASIN_CATALOG_TOKEN");
  assert.ok(dryRun.stdout.includes("--http-enabled true"));
  assert.ok(dryRun.stdout.includes("--http-auth true"));
  assert.ok(dryRun.stdout.includes("--type r2-data-catalog"));
  assert.ok(dryRun.stdout.includes("contracts/ocsf/event-log-activity.basin.json"));
  assert.ok(dryRun.stdout.includes("<BASIN_CATALOG_TOKEN>"));
  assert.ok(dryRun.stdout.includes("INSERT INTO ocsf_event_log_sink"));

  // Custom schema path acceptance
  const customSchema = spawnSync(PROVISION_SCRIPT_PATH, ["--dry-run", "--schema-file", BASIN_SCHEMA_PATH], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.equal(customSchema.status, 0, customSchema.stderr);

  // Negative validations
  const badTable = spawnSync(PROVISION_SCRIPT_PATH, ["--dry-run", "--table", "foo; DROP TABLE bar"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.notEqual(badTable.status, 0);

  const badBucket = spawnSync(PROVISION_SCRIPT_PATH, ["--dry-run", "--bucket", "Bad_Bucket"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.notEqual(badBucket.status, 0);

  const badRoll = spawnSync(PROVISION_SCRIPT_PATH, ["--dry-run", "--roll-interval", "30"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.notEqual(badRoll.status, 0);

  const missingTokenLive = spawnSync(PROVISION_SCRIPT_PATH, [], {
    cwd: REPO_ROOT,
    env: { ...process.env, BASIN_CATALOG_TOKEN: "" },
    encoding: "utf8",
  });
  assert.notEqual(missingTokenLive.status, 0);
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
