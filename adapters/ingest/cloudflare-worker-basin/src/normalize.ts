import { EventSymbols, MAX_SCAN_BYTES, RuleDetector, RuleMatch } from "./yara";

export interface TelemetryLogRecord {
  event_id: string;
  observed_at: string;
  event_time: string;
  host: string;
  service_name: string;
  systemd_unit: string | null;
  syslog_identifier: string | null;
  transport: string | null;
  priority: number;
  severity: string;
  pid: number | null;
  uid: number | null;
  comm: string | null;
  exe: string | null;
  cmdline: string | null;
  boot_id: string | null;
  machine_id: string | null;
  message: string;
  trace_id: string | null;
  span_id: string | null;
  yara_matched: boolean;
  yara_rules: string[];
  yara_tags: string[];
  attributes_json: string | null;
}

const SEVERITY_BY_PRIORITY = [
  "EMERG",
  "ALERT",
  "CRIT",
  "ERR",
  "WARN",
  "NOTICE",
  "INFO",
  "DEBUG",
] as const;

const KNOWN_CONSUMED_KEYS = new Set([
  "event_id",
  "__CURSOR",
  "observed_at",
  "event_time",
  "timestamp",
  "time",
  "__REALTIME_TIMESTAMP",
  "__MONOTONIC_TIMESTAMP",
  "host",
  "_HOSTNAME",
  "service_name",
  "systemd_unit",
  "_SYSTEMD_UNIT",
  "syslog_identifier",
  "SYSLOG_IDENTIFIER",
  "transport",
  "_TRANSPORT",
  "priority",
  "PRIORITY",
  "severity",
  "pid",
  "_PID",
  "uid",
  "_UID",
  "comm",
  "_COMM",
  "exe",
  "_EXE",
  "cmdline",
  "_CMDLINE",
  "boot_id",
  "_BOOT_ID",
  "machine_id",
  "_MACHINE_ID",
  "message",
  "MESSAGE",
  "trace_id",
  "TRACE_ID",
  "OTEL_TRACE_ID",
  "span_id",
  "SPAN_ID",
  "OTEL_SPAN_ID",
  "yara_matched",
  "yara_rules",
  "yara_tags",
  "attributes_json",
]);

const MAX_ATTRIBUTES_JSON_BYTES = 16 * 1024;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: false });

const CONSUMED_OTEL_ATTR_KEYS = new Set([
  "event.id",
  "journald.cursor",
  "host.name",
  "service.name",
  "systemd.unit",
  "syslog.identifier",
  "journald.transport",
  "process.pid",
  "user.id",
  "process.command",
  "process.executable.path",
  "process.command_line",
  "host.boot_id",
  "host.id",
  "syslog.priority",
  "yara.rules",
  "yara.tags",
]);

export class OtlpUnpackError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function ownProp(record: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

function pickOwn(
  record: Record<string, unknown>,
  camelKey: string,
  snakeKey: string,
): unknown {
  if (Object.hasOwn(record, camelKey)) {
    return record[camelKey];
  }
  if (camelKey !== snakeKey && Object.hasOwn(record, snakeKey)) {
    return record[snakeKey];
  }
  return undefined;
}

function pickNonEmptyString(
  record: Record<string, unknown>,
  keys: readonly string[],
): string | null {
  for (const key of keys) {
    const val = ownProp(record, key);
    if (typeof val === "string" && val.length > 0) {
      return val;
    }
  }
  return null;
}

function parseSafeInt(value: unknown): number | null {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) ? value : null;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

const PRIORITY_BY_TEXT = new Map<string, number>([
  ["emerg", 0],
  ["panic", 0],
  ["alert", 1],
  ["crit", 2],
  ["critical", 2],
  ["err", 3],
  ["error", 3],
  ["warn", 4],
  ["warning", 4],
  ["notice", 5],
  ["info", 6],
  ["informational", 6],
  ["debug", 7],
]);

function parsePriority(rawPriority: unknown): number {
  const parsed = parseSafeInt(rawPriority);
  if (parsed !== null) {
    if (parsed < 0) return 0;
    if (parsed > 7) return 7;
    return parsed;
  }
  if (typeof rawPriority === "string") {
    const mapped = PRIORITY_BY_TEXT.get(rawPriority.trim().toLowerCase());
    if (mapped !== undefined) {
      return mapped;
    }
  }
  return 6;
}

function parseIsoTimestamp(value: unknown): string | null {
  if (typeof value !== "string" || value.trim().length === 0) {
    return null;
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    return null;
  }
  return new Date(ms).toISOString();
}

function parseRealtimeTimestampUs(value: unknown): string | null {
  let usBigInt: bigint | null = null;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    usBigInt = BigInt(value.trim());
  } else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    usBigInt = BigInt(value);
  }
  if (usBigInt === null) {
    return null;
  }
  const msNum = Number(usBigInt / 1000n);
  if (!Number.isFinite(msNum)) {
    return null;
  }
  const date = new Date(msNum);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function parseMessageField(raw: unknown): { text: string; bytes: Uint8Array } {
  if (typeof raw === "string") {
    return { text: raw, bytes: textEncoder.encode(raw) };
  }
  if (Array.isArray(raw)) {
    const byteValues: number[] = [];
    let allBytes = true;
    for (const item of raw) {
      if (typeof item === "number" && Number.isInteger(item) && item >= 0 && item <= 255) {
        byteValues.push(item);
      } else {
        allBytes = false;
        break;
      }
    }
    if (allBytes) {
      const bytes = Uint8Array.from(byteValues);
      return { text: textDecoder.decode(bytes), bytes };
    }
    const serialized = JSON.stringify(raw);
    return { text: serialized, bytes: textEncoder.encode(serialized) };
  }
  if (raw === null || raw === undefined) {
    return { text: "", bytes: new Uint8Array(0) };
  }
  if (typeof raw === "object") {
    const serialized = JSON.stringify(raw);
    return { text: serialized, bytes: textEncoder.encode(serialized) };
  }
  const text = String(raw);
  return { text, bytes: textEncoder.encode(text) };
}

function parseStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item === "string" && item.length > 0 && !out.includes(item)) {
      out.push(item);
    }
  }
  return out;
}

function buildScanBuffer(
  messageBytes: Uint8Array,
  fields: {
    cmdline: string | null;
    exe: string | null;
    syslog_identifier: string | null;
    systemd_unit: string | null;
  },
): Uint8Array {
  const metadataParts = [
    fields.cmdline,
    fields.exe,
    fields.syslog_identifier,
    fields.systemd_unit,
  ].filter((part): part is string => part !== null && part.length > 0);

  if (metadataParts.length === 0) {
    return messageBytes.length > MAX_SCAN_BYTES
      ? messageBytes.subarray(0, MAX_SCAN_BYTES)
      : messageBytes;
  }

  const metaBytes = textEncoder.encode(`\n${metadataParts.join("\n")}`);
  const msgCap = Math.max(0, MAX_SCAN_BYTES - metaBytes.length);
  const slicedMsg =
    messageBytes.length > msgCap ? messageBytes.subarray(0, msgCap) : messageBytes;

  const combined = new Uint8Array(slicedMsg.length + metaBytes.length);
  combined.set(slicedMsg, 0);
  combined.set(metaBytes, slicedMsg.length);
  return combined;
}

function copyOwnEntries(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): void {
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) {
      target[key] = value;
    }
  }
}

function parseUnixNanoToIso(value: unknown): string | null {
  let nsBigInt: bigint | null = null;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    nsBigInt = BigInt(value.trim());
  } else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    nsBigInt = BigInt(value);
  }
  if (nsBigInt === null || nsBigInt <= 0n) {
    return null;
  }
  const msNum = Number(nsBigInt / 1_000_000n);
  if (!Number.isFinite(msNum)) {
    return null;
  }
  const date = new Date(msNum);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function decodeBase64Bytes(encoded: string): number[] | null {
  try {
    const bin = atob(encoded.trim());
    const out: number[] = new Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}

function decodeOtlpAttributes(rawAttrs: unknown): Record<string, unknown> {
  const out = Object.create(null) as Record<string, unknown>;
  if (rawAttrs === undefined || rawAttrs === null) {
    return out;
  }
  if (!Array.isArray(rawAttrs)) {
    throw new OtlpUnpackError(400, "OTLP attributes must be an array");
  }
  for (const entry of rawAttrs) {
    if (!isPlainObject(entry)) {
      throw new OtlpUnpackError(400, "OTLP attribute entry must be an object");
    }
    const key = ownProp(entry, "key");
    if (typeof key !== "string" || key.length === 0) {
      throw new OtlpUnpackError(400, "OTLP attribute entry requires a non-empty string key");
    }
    const rawVal = ownProp(entry, "value");
    out[key] = rawVal === undefined ? null : decodeOtlpAnyValue(rawVal);
  }
  return out;
}

function decodeOtlpAnyValue(rawValue: unknown): unknown {
  if (!isPlainObject(rawValue)) {
    if (Array.isArray(rawValue)) {
      return rawValue.map(decodeOtlpAnyValue);
    }
    return rawValue;
  }

  const strVal = pickOwn(rawValue, "stringValue", "string_value");
  if (strVal !== undefined) {
    return typeof strVal === "string" ? strVal : String(strVal);
  }

  const boolVal = pickOwn(rawValue, "boolValue", "bool_value");
  if (boolVal !== undefined) {
    return Boolean(boolVal);
  }

  const intVal = pickOwn(rawValue, "intValue", "int_value");
  if (intVal !== undefined) {
    return parseSafeInt(intVal) ?? intVal;
  }

  const doubleVal = pickOwn(rawValue, "doubleValue", "double_value");
  if (doubleVal !== undefined) {
    return doubleVal;
  }

  const bytesVal = pickOwn(rawValue, "bytesValue", "bytes_value");
  if (bytesVal !== undefined) {
    if (typeof bytesVal === "string") {
      return decodeBase64Bytes(bytesVal) ?? bytesVal;
    }
    return bytesVal;
  }

  const arrayVal = pickOwn(rawValue, "arrayValue", "array_value");
  if (arrayVal !== undefined) {
    if (!isPlainObject(arrayVal)) {
      return [];
    }
    const values = ownProp(arrayVal, "values");
    return Array.isArray(values) ? values.map(decodeOtlpAnyValue) : [];
  }

  const kvlistVal = pickOwn(rawValue, "kvlistValue", "kvlist_value");
  if (kvlistVal !== undefined) {
    if (!isPlainObject(kvlistVal)) {
      return Object.create(null);
    }
    return decodeOtlpAttributes(ownProp(kvlistVal, "values"));
  }

  // Empty AnyValue `{}` represents unset/null rather than literal "{}" text.
  if (Object.keys(rawValue).length === 0) {
    return null;
  }

  return rawValue;
}

function otelSeverityToPriority(raw: unknown): number | null {
  const num = parseSafeInt(raw);
  if (num !== null) {
    if (num <= 0) return null;
    if (num <= 8) return 7;
    if (num <= 10) return 6;
    if (num <= 12) return 5;
    if (num <= 16) return 4;
    if (num <= 20) return 3;
    if (num <= 22) return 2;
    if (num === 23) return 1;
    return 0;
  }
  if (typeof raw === "string") {
    const normalized = raw.trim().toUpperCase().replace(/^SEVERITY_NUMBER_/, "");
    if (normalized === "" || normalized === "UNSPECIFIED") return null;
    if (normalized.startsWith("TRACE") || normalized.startsWith("DEBUG")) return 7;
    if (normalized === "INFO" || normalized === "INFO2") return 6;
    if (normalized === "INFO3" || normalized === "INFO4") return 5;
    if (normalized.startsWith("WARN")) return 4;
    if (normalized.startsWith("ERROR")) return 3;
    if (normalized === "FATAL" || normalized === "FATAL2") return 2;
    if (normalized === "FATAL3") return 1;
    if (normalized === "FATAL4") return 0;
  }
  return null;
}

function cleanOtelHexId(raw: unknown): string | null {
  if (typeof raw !== "string") {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0 || /^0+$/.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function resolveFirstAttr(
  sources: readonly (Record<string, unknown> | null)[],
  keys: readonly string[],
): unknown {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const val = ownProp(source, key);
      if (val !== undefined && val !== null && val !== "") {
        return val;
      }
    }
  }
  return undefined;
}

function normalizeOtelSeverityText(raw: unknown): string | null {
  if (typeof raw !== "string") {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const mapped = PRIORITY_BY_TEXT.get(trimmed.toLowerCase());
  if (mapped !== undefined) {
    return SEVERITY_BY_PRIORITY[mapped] ?? "INFO";
  }
  return trimmed;
}

function flattenOtlpLogRecord(
  logRecord: Record<string, unknown>,
  resourceAttrs: Record<string, unknown>,
  scopeName: string | null,
): Record<string, unknown> {
  const out = Object.create(null) as Record<string, unknown>;
  const logAttrs = decodeOtlpAttributes(ownProp(logRecord, "attributes"));

  const rawBody = ownProp(logRecord, "body");
  const decodedBody = rawBody !== undefined ? decodeOtlpAnyValue(rawBody) : null;
  const bodyFields = isPlainObject(decodedBody) ? decodedBody : null;

  const sources: readonly (Record<string, unknown> | null)[] = [
    logAttrs,
    resourceAttrs,
    bodyFields,
  ];

  const eventId = resolveFirstAttr(sources, [
    "event.id",
    "event_id",
    "journald.cursor",
    "__CURSOR",
  ]);
  if (eventId !== undefined) out.event_id = eventId;

  const observedAt = parseUnixNanoToIso(
    pickOwn(logRecord, "observedTimeUnixNano", "observed_time_unix_nano"),
  );
  if (observedAt !== null) out.observed_at = observedAt;

  const eventTime = parseUnixNanoToIso(
    pickOwn(logRecord, "timeUnixNano", "time_unix_nano"),
  );
  if (eventTime !== null) {
    out.event_time = eventTime;
  } else if (bodyFields && ownProp(bodyFields, "__REALTIME_TIMESTAMP") !== undefined) {
    out.__REALTIME_TIMESTAMP = ownProp(bodyFields, "__REALTIME_TIMESTAMP");
  }

  const host = resolveFirstAttr(sources, ["host.name", "host", "_HOSTNAME"]);
  if (host !== undefined) out.host = host;

  const systemdUnit = resolveFirstAttr(sources, ["systemd.unit", "systemd_unit", "_SYSTEMD_UNIT"]);
  if (systemdUnit !== undefined) out.systemd_unit = systemdUnit;

  const syslogIdentifier = resolveFirstAttr(sources, [
    "syslog.identifier",
    "syslog_identifier",
    "SYSLOG_IDENTIFIER",
  ]);
  if (syslogIdentifier !== undefined) out.syslog_identifier = syslogIdentifier;

  const transport = resolveFirstAttr(sources, [
    "journald.transport",
    "transport",
    "_TRANSPORT",
  ]);
  if (transport !== undefined) out.transport = transport;

  const pid = resolveFirstAttr(sources, ["process.pid", "pid", "_PID"]);
  if (pid !== undefined) out.pid = pid;

  const uid = resolveFirstAttr(sources, ["user.id", "uid", "_UID"]);
  if (uid !== undefined) out.uid = uid;

  const comm = resolveFirstAttr(sources, ["process.command", "comm", "_COMM"]);
  if (comm !== undefined) out.comm = comm;

  const exe = resolveFirstAttr(sources, ["process.executable.path", "exe", "_EXE"]);
  if (exe !== undefined) out.exe = exe;

  const cmdline = resolveFirstAttr(sources, [
    "process.command_line",
    "cmdline",
    "_CMDLINE",
  ]);
  if (cmdline !== undefined) out.cmdline = cmdline;

  const bootId = resolveFirstAttr(sources, ["host.boot_id", "boot_id", "_BOOT_ID"]);
  if (bootId !== undefined) out.boot_id = bootId;

  const machineId = resolveFirstAttr(sources, ["host.id", "machine_id", "_MACHINE_ID"]);
  if (machineId !== undefined) out.machine_id = machineId;

  const serviceAttr = resolveFirstAttr([logAttrs, resourceAttrs], [
    "service.name",
    "service_name",
  ]);
  if (
    typeof serviceAttr === "string" &&
    serviceAttr !== "unknown_service" &&
    !serviceAttr.startsWith("unknown_service:")
  ) {
    out.service_name = serviceAttr;
  } else if (
    systemdUnit === undefined &&
    syslogIdentifier === undefined &&
    comm === undefined &&
    scopeName !== null
  ) {
    out.service_name = scopeName;
  }

  const rawSeverityText = pickOwn(logRecord, "severityText", "severity_text");
  const normalizedSeverity = normalizeOtelSeverityText(rawSeverityText);
  if (normalizedSeverity !== null) {
    out.severity = normalizedSeverity;
  }

  const explicitPriority = resolveFirstAttr(sources, [
    "syslog.priority",
    "priority",
    "PRIORITY",
  ]);
  if (explicitPriority !== undefined) {
    out.priority = explicitPriority;
  } else {
    const sevNumPriority = otelSeverityToPriority(
      pickOwn(logRecord, "severityNumber", "severity_number"),
    );
    if (sevNumPriority !== null) {
      out.priority = sevNumPriority;
    } else if (typeof rawSeverityText === "string" && rawSeverityText.trim().length > 0) {
      out.priority = rawSeverityText;
    }
  }

  const traceId =
    cleanOtelHexId(pickOwn(logRecord, "traceId", "trace_id")) ??
    cleanOtelHexId(resolveFirstAttr(sources, ["trace_id", "TRACE_ID", "OTEL_TRACE_ID"]));
  if (traceId !== null) out.trace_id = traceId;

  const spanId =
    cleanOtelHexId(pickOwn(logRecord, "spanId", "span_id")) ??
    cleanOtelHexId(resolveFirstAttr(sources, ["span_id", "SPAN_ID", "OTEL_SPAN_ID"]));
  if (spanId !== null) out.span_id = spanId;

  const yaraRules = resolveFirstAttr(sources, ["yara.rules", "yara_rules"]);
  if (yaraRules !== undefined) out.yara_rules = yaraRules;

  const yaraTags = resolveFirstAttr(sources, ["yara.tags", "yara_tags"]);
  if (yaraTags !== undefined) out.yara_tags = yaraTags;

  if (bodyFields) {
    const bodyMsg = ownProp(bodyFields, "message") ?? ownProp(bodyFields, "MESSAGE");
    out.message = bodyMsg !== undefined ? bodyMsg : JSON.stringify(bodyFields);
  } else {
    out.message = decodedBody;
  }

  const extraSources = [logAttrs, resourceAttrs, bodyFields];
  for (const src of extraSources) {
    if (!src) continue;
    for (const [key, value] of Object.entries(src)) {
      if (
        value !== undefined &&
        !CONSUMED_OTEL_ATTR_KEYS.has(key) &&
        !KNOWN_CONSUMED_KEYS.has(key) &&
        !Object.hasOwn(out, key)
      ) {
        out[key] = value;
      }
    }
  }
  if (scopeName !== null && !Object.hasOwn(out, "otel.scope.name")) {
    out["otel.scope.name"] = scopeName;
  }

  return out;
}

export function unpackOtlpLogsPayload(
  payload: Record<string, unknown>,
  maxRecords: number,
): Record<string, unknown>[] | null {
  const resourceLogs = pickOwn(payload, "resourceLogs", "resource_logs");
  if (resourceLogs === undefined) {
    return null;
  }
  if (!Array.isArray(resourceLogs)) {
    throw new OtlpUnpackError(400, "OTLP resourceLogs must be an array");
  }

  const records: Record<string, unknown>[] = [];
  for (const resourceEntry of resourceLogs) {
    if (!isPlainObject(resourceEntry)) {
      throw new OtlpUnpackError(400, "OTLP resourceLogs entry must be an object");
    }
    const rawResource = ownProp(resourceEntry, "resource");
    let resourceAttrs = Object.create(null) as Record<string, unknown>;
    if (rawResource !== undefined && rawResource !== null) {
      if (!isPlainObject(rawResource)) {
        throw new OtlpUnpackError(400, "OTLP resource must be an object");
      }
      resourceAttrs = decodeOtlpAttributes(ownProp(rawResource, "attributes"));
    }

    const scopeLogs = pickOwn(resourceEntry, "scopeLogs", "scope_logs");
    if (scopeLogs === undefined || scopeLogs === null) {
      continue;
    }
    if (!Array.isArray(scopeLogs)) {
      throw new OtlpUnpackError(400, "OTLP scopeLogs must be an array");
    }

    for (const scopeEntry of scopeLogs) {
      if (!isPlainObject(scopeEntry)) {
        throw new OtlpUnpackError(400, "OTLP scopeLogs entry must be an object");
      }
      const rawScope = ownProp(scopeEntry, "scope");
      let scopeName: string | null = null;
      if (rawScope !== undefined && rawScope !== null) {
        if (!isPlainObject(rawScope)) {
          throw new OtlpUnpackError(400, "OTLP scope must be an object");
        }
        const nameVal = ownProp(rawScope, "name");
        if (typeof nameVal === "string" && nameVal.length > 0) {
          scopeName = nameVal;
        }
      }

      const logRecords = pickOwn(scopeEntry, "logRecords", "log_records");
      if (logRecords === undefined || logRecords === null) {
        continue;
      }
      if (!Array.isArray(logRecords)) {
        throw new OtlpUnpackError(400, "OTLP logRecords must be an array");
      }

      for (const logRecord of logRecords) {
        if (!isPlainObject(logRecord)) {
          throw new OtlpUnpackError(400, "OTLP logRecord must be an object");
        }
        records.push(flattenOtlpLogRecord(logRecord, resourceAttrs, scopeName));
        if (records.length > maxRecords) {
          throw new OtlpUnpackError(
            413,
            `Batch exceeds maximum of ${maxRecords} records`,
          );
        }
      }
    }
  }

  if (records.length === 0) {
    throw new OtlpUnpackError(400, "OTLP payload contains no logRecords");
  }

  return records;
}

function buildAttributesJson(
  raw: Record<string, unknown>,
  yaraMatches: RuleMatch[],
): string | null {
  const attrs = Object.create(null) as Record<string, unknown>;

  const rawAttributesJson = ownProp(raw, "attributes_json");
  if (typeof rawAttributesJson === "string" && rawAttributesJson.length > 0) {
    try {
      const parsed = JSON.parse(rawAttributesJson) as unknown;
      if (isPlainObject(parsed)) {
        copyOwnEntries(attrs, parsed);
      } else {
        attrs.upstream_attributes = rawAttributesJson;
      }
    } catch {
      attrs.upstream_attributes = rawAttributesJson;
    }
  }

  for (const [key, value] of Object.entries(raw)) {
    if (!KNOWN_CONSUMED_KEYS.has(key) && value !== undefined) {
      attrs[key] = value;
    }
  }

  if (yaraMatches.length > 0) {
    attrs.yara_matches = yaraMatches.map((m) => ({
      name: m.name,
      namespace: m.namespace,
      tags: m.tags,
      metadata: m.metadata,
      patterns: m.patterns,
    }));
  }

  if (Object.keys(attrs).length === 0) {
    return null;
  }

  const json = JSON.stringify(attrs);
  if (textEncoder.encode(json).length <= MAX_ATTRIBUTES_JSON_BYTES) {
    return json;
  }

  // Drop bulky extra attributes first while preserving compact YARA match summary.
  if (yaraMatches.length > 0) {
    const compact = JSON.stringify({
      yara_matches: yaraMatches.map((m) => ({ name: m.name, tags: m.tags })),
      truncated: true,
    });
    if (textEncoder.encode(compact).length <= MAX_ATTRIBUTES_JSON_BYTES) {
      return compact;
    }
  }

  return JSON.stringify({ truncated: true });
}

export function normalizeAndDetect(
  raw: Record<string, unknown>,
  detector: RuleDetector,
  nowIso: string = new Date().toISOString(),
): TelemetryLogRecord {
  const observed_at = parseIsoTimestamp(ownProp(raw, "observed_at")) ?? nowIso;
  const event_time =
    parseIsoTimestamp(ownProp(raw, "event_time")) ??
    parseIsoTimestamp(ownProp(raw, "timestamp")) ??
    parseIsoTimestamp(ownProp(raw, "time")) ??
    parseRealtimeTimestampUs(ownProp(raw, "__REALTIME_TIMESTAMP")) ??
    observed_at;

  const host = pickNonEmptyString(raw, ["host", "_HOSTNAME"]) ?? "unknown";
  const systemd_unit = pickNonEmptyString(raw, ["systemd_unit", "_SYSTEMD_UNIT"]);
  const syslog_identifier = pickNonEmptyString(raw, [
    "syslog_identifier",
    "SYSLOG_IDENTIFIER",
  ]);
  const transport = pickNonEmptyString(raw, ["transport", "_TRANSPORT"]);
  const comm = pickNonEmptyString(raw, ["comm", "_COMM"]);
  const exe = pickNonEmptyString(raw, ["exe", "_EXE"]);
  const cmdline = pickNonEmptyString(raw, ["cmdline", "_CMDLINE"]);
  const boot_id = pickNonEmptyString(raw, ["boot_id", "_BOOT_ID"]);
  const machine_id = pickNonEmptyString(raw, ["machine_id", "_MACHINE_ID"]);

  const service_name =
    pickNonEmptyString(raw, ["service_name"]) ??
    systemd_unit ??
    syslog_identifier ??
    comm ??
    "unknown";

  const priority = parsePriority(ownProp(raw, "priority") ?? ownProp(raw, "PRIORITY"));
  const severity =
    pickNonEmptyString(raw, ["severity"]) ?? SEVERITY_BY_PRIORITY[priority] ?? "INFO";

  const pid = parseSafeInt(ownProp(raw, "pid") ?? ownProp(raw, "_PID"));
  const uid = parseSafeInt(ownProp(raw, "uid") ?? ownProp(raw, "_UID"));

  const trace_id = pickNonEmptyString(raw, ["trace_id", "TRACE_ID", "OTEL_TRACE_ID"]);
  const span_id = pickNonEmptyString(raw, ["span_id", "SPAN_ID", "OTEL_SPAN_ID"]);

  const rawMessage = ownProp(raw, "message");
  const parsedMsg =
    rawMessage !== undefined && rawMessage !== null
      ? parseMessageField(rawMessage)
      : parseMessageField(ownProp(raw, "MESSAGE"));

  const event_id =
    pickNonEmptyString(raw, ["event_id", "__CURSOR"]) ?? crypto.randomUUID();

  const symbols: EventSymbols = {
    systemd_unit: systemd_unit ?? "",
    syslog_identifier: syslog_identifier ?? "",
    transport: transport ?? "",
    comm: comm ?? "",
    exe: exe ?? "",
    host,
    priority,
  };

  const scanBuffer = buildScanBuffer(parsedMsg.bytes, {
    cmdline,
    exe,
    syslog_identifier,
    systemd_unit,
  });
  const matches = detector.scan(scanBuffer, symbols);

  const mergedRules = parseStringArray(ownProp(raw, "yara_rules"));
  const mergedTags = parseStringArray(ownProp(raw, "yara_tags"));

  for (const match of matches) {
    if (!mergedRules.includes(match.name)) {
      mergedRules.push(match.name);
    }
    for (const tag of match.tags) {
      if (!mergedTags.includes(tag)) {
        mergedTags.push(tag);
      }
    }
  }

  return {
    event_id,
    observed_at,
    event_time,
    host,
    service_name,
    systemd_unit,
    syslog_identifier,
    transport,
    priority,
    severity,
    pid,
    uid,
    comm,
    exe,
    cmdline,
    boot_id,
    machine_id,
    message: parsedMsg.text,
    trace_id,
    span_id,
    yara_matched: mergedRules.length > 0,
    yara_rules: mergedRules,
    yara_tags: mergedTags,
    attributes_json: buildAttributesJson(raw, matches),
  };
}
