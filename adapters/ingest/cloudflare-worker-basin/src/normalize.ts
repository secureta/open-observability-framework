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
  "_otel_scope_service",
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
  "attributes.json",
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

function stringifyJsonPreservingNonFinite(value: unknown): string {
  return JSON.stringify(value, (_key, val: unknown) =>
    typeof val === "number" && !Number.isFinite(val) ? String(val) : val,
  );
}

function tryDecodeByteArray(value: unknown): Uint8Array | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const byteValues: number[] = new Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item === "number" && Number.isInteger(item) && item >= 0 && item <= 255) {
      byteValues[i] = item;
    } else {
      return null;
    }
  }
  return Uint8Array.from(byteValues);
}

function pickOwnNonNull(
  record: Record<string, unknown>,
  camelKey: string,
  snakeKey: string,
): unknown {
  const camelVal = ownProp(record, camelKey);
  if (camelVal !== undefined && camelVal !== null) {
    return camelVal;
  }
  if (camelKey !== snakeKey) {
    const snakeVal = ownProp(record, snakeKey);
    if (snakeVal !== undefined && snakeVal !== null) {
      return snakeVal;
    }
  }
  return undefined;
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
    return Number.isSafeInteger(value) ? (value === 0 ? 0 : value) : null;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) ? (parsed === 0 ? 0 : parsed) : null;
  }
  return null;
}

function resolveFirstSafeInt(
  record: Record<string, unknown>,
  keys: readonly string[],
): number | null {
  for (const key of keys) {
    const parsed = parseSafeInt(ownProp(record, key));
    if (parsed !== null) {
      return parsed;
    }
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

function tryParsePriority(rawPriority: unknown): number | null {
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
  return null;
}

function resolveValidPriority(
  sources: readonly (Record<string, unknown> | null)[],
  keys: readonly string[] = ["syslog.priority", "priority", "PRIORITY"],
): number | null {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const parsed = tryParsePriority(ownProp(source, key));
      if (parsed !== null) {
        return parsed;
      }
    }
  }
  return null;
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
  const decodedBytes = tryDecodeByteArray(raw);
  if (decodedBytes !== null) {
    return { text: textDecoder.decode(decodedBytes), bytes: decodedBytes };
  }
  if (Array.isArray(raw)) {
    const serialized = stringifyJsonPreservingNonFinite(raw);
    return { text: serialized, bytes: textEncoder.encode(serialized) };
  }
  if (raw === null || raw === undefined) {
    return { text: "", bytes: new Uint8Array(0) };
  }
  if (typeof raw === "object") {
    const serialized = stringifyJsonPreservingNonFinite(raw);
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
  extraParts: readonly string[] = [],
): Uint8Array {
  const canonicalParts = [
    fields.cmdline,
    fields.exe,
    fields.syslog_identifier,
    fields.systemd_unit,
  ].filter((part): part is string => part !== null && part.length > 0);

  const rawCanonicalBytes =
    canonicalParts.length > 0
      ? textEncoder.encode(`${messageBytes.length > 0 ? "\n" : ""}${canonicalParts.join("\n")}`)
      : new Uint8Array(0);

  const half = Math.floor(MAX_SCAN_BYTES / 2);
  let msgTake: number;
  let canTake: number;
  if (messageBytes.length + rawCanonicalBytes.length <= MAX_SCAN_BYTES) {
    msgTake = messageBytes.length;
    canTake = rawCanonicalBytes.length;
  } else if (messageBytes.length <= half) {
    msgTake = messageBytes.length;
    canTake = MAX_SCAN_BYTES - msgTake;
  } else if (rawCanonicalBytes.length <= half) {
    canTake = rawCanonicalBytes.length;
    msgTake = MAX_SCAN_BYTES - canTake;
  } else {
    msgTake = half;
    canTake = MAX_SCAN_BYTES - half;
  }

  const slicedMsg =
    messageBytes.length > msgTake ? messageBytes.subarray(0, msgTake) : messageBytes;
  const canonicalBytes =
    rawCanonicalBytes.length > canTake
      ? rawCanonicalBytes.subarray(0, canTake)
      : rawCanonicalBytes;

  let remainingForExtra = Math.max(0, MAX_SCAN_BYTES - (slicedMsg.length + canonicalBytes.length));
  const extraChunks: Uint8Array[] = [];
  let extraByteLen = 0;
  if (remainingForExtra > 0) {
    let needSep = slicedMsg.length + canonicalBytes.length > 0;
    for (const part of extraParts) {
      if (part.length === 0) continue;
      const chunkText = needSep ? `\n${part}` : part;
      const encoded = textEncoder.encode(chunkText);
      needSep = true;
      if (encoded.length <= remainingForExtra) {
        extraChunks.push(encoded);
        extraByteLen += encoded.length;
        remainingForExtra -= encoded.length;
      } else {
        extraChunks.push(encoded.subarray(0, remainingForExtra));
        extraByteLen += remainingForExtra;
        remainingForExtra = 0;
        break;
      }
    }
  }

  if (canonicalBytes.length === 0 && extraByteLen === 0) {
    return slicedMsg;
  }

  const combined = new Uint8Array(slicedMsg.length + canonicalBytes.length + extraByteLen);
  let offset = 0;
  combined.set(slicedMsg, offset);
  offset += slicedMsg.length;
  if (canonicalBytes.length > 0) {
    combined.set(canonicalBytes, offset);
    offset += canonicalBytes.length;
  }
  for (const chunk of extraChunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
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

const OTLP_ANYVALUE_KEYS = new Set([
  "stringValue",
  "string_value",
  "boolValue",
  "bool_value",
  "intValue",
  "int_value",
  "doubleValue",
  "double_value",
  "bytesValue",
  "bytes_value",
  "arrayValue",
  "array_value",
  "kvlistValue",
  "kvlist_value",
]);

const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;

function decodeBase64Bytes(encoded: string): number[] | null {
  if (encoded.length === 0) {
    return [];
  }
  const isStandard = /^[A-Za-z0-9+/]*={0,2}$/.test(encoded);
  const isUrlSafe = !isStandard && /^[A-Za-z0-9\-_]*={0,2}$/.test(encoded);
  if (!isStandard && !isUrlSafe) {
    return null;
  }
  const unpadded = encoded.replace(/=+$/, "");
  const padCount = encoded.length - unpadded.length;
  if (padCount > 2) {
    return null;
  }
  const rem = unpadded.length % 4;
  if (rem === 1) {
    return null;
  }
  if (padCount > 0 && (unpadded.length + padCount) % 4 !== 0) {
    return null;
  }
  const std = isUrlSafe
    ? unpadded.replace(/-/g, "+").replace(/_/g, "/")
    : unpadded;
  const padded = rem === 0 ? std : std + "=".repeat(4 - rem);
  try {
    const bin = atob(padded);
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
    out[key] =
      rawVal === undefined || rawVal === null
        ? null
        : decodeOtlpAnyValue(rawVal);
  }
  return out;
}

function decodeOtlpAnyValue(rawValue: unknown): unknown {
  if (!isPlainObject(rawValue)) {
    throw new OtlpUnpackError(400, "OTLP AnyValue must be an object");
  }

  let setFieldCount = 0;
  for (const key of Object.keys(rawValue)) {
    if (!OTLP_ANYVALUE_KEYS.has(key)) {
      continue;
    }
    const val = rawValue[key];
    if (val !== undefined && val !== null) {
      setFieldCount++;
    }
  }

  if (setFieldCount === 0) {
    return null;
  }
  if (setFieldCount > 1) {
    throw new OtlpUnpackError(400, "OTLP AnyValue must set at most one value field");
  }

  const strVal = pickOwnNonNull(rawValue, "stringValue", "string_value");
  if (strVal !== undefined) {
    if (typeof strVal !== "string") {
      throw new OtlpUnpackError(400, "OTLP stringValue must be a string");
    }
    return strVal;
  }

  const boolVal = pickOwnNonNull(rawValue, "boolValue", "bool_value");
  if (boolVal !== undefined) {
    if (typeof boolVal !== "boolean") {
      throw new OtlpUnpackError(400, "OTLP boolValue must be a boolean");
    }
    return boolVal;
  }

  const intVal = pickOwnNonNull(rawValue, "intValue", "int_value");
  if (intVal !== undefined) {
    if (typeof intVal === "number") {
      if (!Number.isInteger(intVal)) {
        throw new OtlpUnpackError(400, "OTLP intValue must be an integer");
      }
      const big = BigInt(intVal);
      if (big < INT64_MIN || big > INT64_MAX) {
        throw new OtlpUnpackError(400, "OTLP intValue is outside signed 64-bit integer range");
      }
      return Number.isSafeInteger(intVal) ? (intVal === 0 ? 0 : intVal) : big.toString();
    }
    if (typeof intVal === "string" && /^-?\d+$/.test(intVal)) {
      const big = BigInt(intVal);
      if (big < INT64_MIN || big > INT64_MAX) {
        throw new OtlpUnpackError(400, "OTLP intValue is outside signed 64-bit integer range");
      }
      return parseSafeInt(intVal) ?? intVal;
    }
    throw new OtlpUnpackError(400, "OTLP intValue must be an integer or decimal integer string");
  }

  const doubleVal = pickOwnNonNull(rawValue, "doubleValue", "double_value");
  if (doubleVal !== undefined) {
    if (typeof doubleVal === "number") {
      return doubleVal;
    }
    if (typeof doubleVal === "string") {
      if (doubleVal === "NaN") return Number.NaN;
      if (doubleVal === "Infinity") return Number.POSITIVE_INFINITY;
      if (doubleVal === "-Infinity") return Number.NEGATIVE_INFINITY;
      if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(doubleVal)) {
        const parsed = Number(doubleVal);
        if (Number.isFinite(parsed)) {
          return parsed;
        }
      }
    }
    throw new OtlpUnpackError(400, "OTLP doubleValue must be a valid ProtoJSON double");
  }

  const bytesVal = pickOwnNonNull(rawValue, "bytesValue", "bytes_value");
  if (bytesVal !== undefined) {
    if (typeof bytesVal !== "string") {
      throw new OtlpUnpackError(400, "OTLP bytesValue must be a base64 string");
    }
    const decoded = decodeBase64Bytes(bytesVal);
    if (decoded === null) {
      throw new OtlpUnpackError(400, "OTLP bytesValue must be a valid base64 string");
    }
    return decoded;
  }

  const arrayVal = pickOwnNonNull(rawValue, "arrayValue", "array_value");
  if (arrayVal !== undefined) {
    if (!isPlainObject(arrayVal)) {
      throw new OtlpUnpackError(400, "Invalid OTLP arrayValue");
    }
    const values = ownProp(arrayVal, "values");
    if (values === undefined || values === null) {
      return [];
    }
    if (!Array.isArray(values)) {
      throw new OtlpUnpackError(400, "OTLP arrayValue.values must be an array");
    }
    return values.map((item) => decodeOtlpAnyValue(item));
  }

  const kvlistVal = pickOwnNonNull(rawValue, "kvlistValue", "kvlist_value");
  if (!isPlainObject(kvlistVal)) {
    throw new OtlpUnpackError(400, "Invalid OTLP kvlistValue");
  }
  return decodeOtlpAttributes(ownProp(kvlistVal, "values"));
}

function mergeAttributesJsonSource(
  target: Record<string, unknown>,
  source: unknown,
): void {
  if (typeof source === "string" && source.length > 0) {
    try {
      const parsed = JSON.parse(source) as unknown;
      if (isPlainObject(parsed)) {
        copyOwnEntries(target, parsed);
      } else {
        target.upstream_attributes = source;
      }
    } catch {
      target.upstream_attributes = source;
    }
    return;
  }
  if (isPlainObject(source)) {
    copyOwnEntries(target, source);
  }
}

function isValidServiceName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value !== "unknown_service" &&
    !value.startsWith("unknown_service:")
  );
}

function resolveValidServiceName(
  sources: readonly (Record<string, unknown> | null)[],
): string | null {
  for (const source of sources) {
    if (!source) continue;
    for (const key of ["service.name", "service_name"] as const) {
      const val = ownProp(source, key);
      if (isValidServiceName(val)) {
        return val;
      }
    }
  }
  return null;
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

function resolveValidHexId(
  sources: readonly (Record<string, unknown> | null)[],
  keys: readonly string[],
): string | null {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const cleaned = cleanOtelHexId(ownProp(source, key));
      if (cleaned !== null) {
        return cleaned;
      }
    }
  }
  return null;
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
  const decodedBody =
    rawBody !== undefined && rawBody !== null ? decodeOtlpAnyValue(rawBody) : null;
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

  const serviceName = resolveValidServiceName(sources);
  if (serviceName !== null) {
    out.service_name = serviceName;
  }
  if (scopeName !== null) {
    out._otel_scope_service = scopeName;
  }

  const rawSeverityText = pickOwn(logRecord, "severityText", "severity_text");
  const normalizedSeverity = normalizeOtelSeverityText(rawSeverityText);
  if (normalizedSeverity !== null) {
    out.severity = normalizedSeverity;
  }

  const explicitPriority = resolveValidPriority(sources);
  if (explicitPriority !== null) {
    out.priority = explicitPriority;
  } else {
    const sevNumPriority = otelSeverityToPriority(
      pickOwn(logRecord, "severityNumber", "severity_number"),
    );
    if (sevNumPriority !== null) {
      out.priority = sevNumPriority;
    } else if (typeof rawSeverityText === "string" && rawSeverityText.trim().length > 0) {
      const textPriority = tryParsePriority(rawSeverityText);
      if (textPriority !== null) {
        out.priority = textPriority;
      }
    }
  }

  const traceId =
    cleanOtelHexId(pickOwn(logRecord, "traceId", "trace_id")) ??
    resolveValidHexId(sources, ["trace_id", "TRACE_ID", "OTEL_TRACE_ID"]);
  if (traceId !== null) out.trace_id = traceId;

  const spanId =
    cleanOtelHexId(pickOwn(logRecord, "spanId", "span_id")) ??
    resolveValidHexId(sources, ["span_id", "SPAN_ID", "OTEL_SPAN_ID"]);
  if (spanId !== null) out.span_id = spanId;

  const yaraRules = resolveFirstAttr(sources, ["yara.rules", "yara_rules"]);
  if (yaraRules !== undefined) out.yara_rules = yaraRules;

  const yaraTags = resolveFirstAttr(sources, ["yara.tags", "yara_tags"]);
  if (yaraTags !== undefined) out.yara_tags = yaraTags;

  if (bodyFields) {
    const primaryBodyMsg = ownProp(bodyFields, "message");
    const bodyMsg =
      primaryBodyMsg !== undefined && primaryBodyMsg !== null
        ? primaryBodyMsg
        : ownProp(bodyFields, "MESSAGE");
    out.message =
      bodyMsg !== undefined
        ? bodyMsg
        : stringifyJsonPreservingNonFinite(bodyFields);
  } else {
    out.message = decodedBody;
  }

  const mergedOtlpAttrs = Object.create(null) as Record<string, unknown>;
  let hasMergedOtlpAttrs = false;
  for (const attrLayer of [bodyFields, resourceAttrs, logAttrs]) {
    if (!attrLayer) continue;
    for (const attrKey of ["attributes.json", "attributes_json"] as const) {
      const candidate = ownProp(attrLayer, attrKey);
      if (candidate !== undefined && candidate !== null && candidate !== "") {
        mergeAttributesJsonSource(mergedOtlpAttrs, candidate);
        hasMergedOtlpAttrs = true;
      }
    }
  }
  if (hasMergedOtlpAttrs) {
    out.attributes_json = stringifyJsonPreservingNonFinite(mergedOtlpAttrs);
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

const HOST_KEYS = ["host", "_HOSTNAME", "host.name"] as const;
const SYSTEMD_UNIT_KEYS = ["systemd_unit", "_SYSTEMD_UNIT", "systemd.unit"] as const;
const SYSLOG_IDENTIFIER_KEYS = [
  "syslog_identifier",
  "SYSLOG_IDENTIFIER",
  "syslog.identifier",
] as const;
const TRANSPORT_KEYS = ["transport", "_TRANSPORT", "journald.transport"] as const;
const COMM_KEYS = ["comm", "_COMM", "process.command"] as const;
const EXE_KEYS = ["exe", "_EXE", "process.executable.path"] as const;
const CMDLINE_KEYS = ["cmdline", "_CMDLINE", "process.command_line"] as const;
const BOOT_ID_KEYS = ["boot_id", "_BOOT_ID", "host.boot_id"] as const;
const MACHINE_ID_KEYS = ["machine_id", "_MACHINE_ID", "host.id"] as const;
const PID_KEYS = ["pid", "_PID", "process.pid"] as const;
const UID_KEYS = ["uid", "_UID", "user.id"] as const;
const TRACE_ID_KEYS = ["trace_id", "TRACE_ID", "OTEL_TRACE_ID"] as const;
const SPAN_ID_KEYS = ["span_id", "SPAN_ID", "OTEL_SPAN_ID"] as const;
const EVENT_ID_KEYS = ["event_id", "event.id", "__CURSOR", "journald.cursor"] as const;

const EMBEDDED_ENVELOPE_SKIP_KEYS = new Set([
  ...KNOWN_CONSUMED_KEYS,
  ...CONSUMED_OTEL_ATTR_KEYS,
]);

interface ExtractedTelemetryFields {
  observedAt: string | null;
  eventTime: string | null;
  eventId: string | null;
  host: string | null;
  serviceName: string | null;
  systemdUnit: string | null;
  syslogIdentifier: string | null;
  transport: string | null;
  comm: string | null;
  exe: string | null;
  cmdline: string | null;
  bootId: string | null;
  machineId: string | null;
  pid: number | null;
  uid: number | null;
  priority: number | null;
  severity: string | null;
  traceId: string | null;
  spanId: string | null;
  yaraRules: string[];
  yaraTags: string[];
}

function extractCommonTelemetryFields(record: Record<string, unknown>): ExtractedTelemetryFields {
  const yaraRules: string[] = [];
  pushUniqueStrings(yaraRules, parseStringArray(ownProp(record, "yara_rules")));
  pushUniqueStrings(yaraRules, parseStringArray(ownProp(record, "yara.rules")));

  const yaraTags: string[] = [];
  pushUniqueStrings(yaraTags, parseStringArray(ownProp(record, "yara_tags")));
  pushUniqueStrings(yaraTags, parseStringArray(ownProp(record, "yara.tags")));

  return {
    observedAt: parseIsoTimestamp(ownProp(record, "observed_at")),
    eventTime:
      parseIsoTimestamp(ownProp(record, "event_time")) ??
      parseIsoTimestamp(ownProp(record, "timestamp")) ??
      parseIsoTimestamp(ownProp(record, "time")) ??
      parseRealtimeTimestampUs(ownProp(record, "__REALTIME_TIMESTAMP")),
    eventId: pickNonEmptyString(record, EVENT_ID_KEYS),
    host: pickNonEmptyString(record, HOST_KEYS),
    serviceName: resolveValidServiceName([record]),
    systemdUnit: pickNonEmptyString(record, SYSTEMD_UNIT_KEYS),
    syslogIdentifier: pickNonEmptyString(record, SYSLOG_IDENTIFIER_KEYS),
    transport: pickNonEmptyString(record, TRANSPORT_KEYS),
    comm: pickNonEmptyString(record, COMM_KEYS),
    exe: pickNonEmptyString(record, EXE_KEYS),
    cmdline: pickNonEmptyString(record, CMDLINE_KEYS),
    bootId: pickNonEmptyString(record, BOOT_ID_KEYS),
    machineId: pickNonEmptyString(record, MACHINE_ID_KEYS),
    pid: resolveFirstSafeInt(record, PID_KEYS),
    uid: resolveFirstSafeInt(record, UID_KEYS),
    priority: resolveValidPriority([record], ["priority", "PRIORITY", "syslog.priority"]),
    severity: pickNonEmptyString(record, ["severity"]),
    traceId: resolveValidHexId([record], TRACE_ID_KEYS),
    spanId: resolveValidHexId([record], SPAN_ID_KEYS),
    yaraRules,
    yaraTags,
  };
}

interface EmbeddedEnvelope {
  messageField: { text: string; bytes: Uint8Array } | null;
  fields: ExtractedTelemetryFields;
  rawRecord: Record<string, unknown>;
}

function parseEmbeddedMessageEnvelope(text: string): EmbeddedEnvelope | null {
  if (!text.trimStart().startsWith("{")) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) {
    return null;
  }
  const primaryMsg = ownProp(parsed, "message");
  const candidateMsg =
    primaryMsg !== undefined && primaryMsg !== null
      ? primaryMsg
      : ownProp(parsed, "MESSAGE");

  let messageField: { text: string; bytes: Uint8Array } | null = null;
  if (typeof candidateMsg === "string") {
    messageField = {
      text: candidateMsg,
      bytes: textEncoder.encode(candidateMsg),
    };
  } else {
    const decodedBytes = tryDecodeByteArray(candidateMsg);
    if (decodedBytes !== null) {
      messageField = {
        text: textDecoder.decode(decodedBytes),
        bytes: decodedBytes,
      };
    }
  }

  return {
    messageField,
    fields: extractCommonTelemetryFields(parsed),
    rawRecord: parsed,
  };
}

function pushUniqueStrings(target: string[], additions: readonly string[]): void {
  for (const item of additions) {
    if (item.length > 0 && !target.includes(item)) {
      target.push(item);
    }
  }
}

const MAX_WALK_NODES = 8192;

const YARA_META_SKIP_KEYS = new Set([
  "yara_matched",
  "yara_rules",
  "yara.rules",
  "yara_tags",
  "yara.tags",
]);

function collectScanStrings(
  root: unknown,
  parts: string[],
  budget: { remaining: number },
): boolean {
  const stack: Array<{ value: unknown; keyPrefix: string }> = [
    { value: root, keyPrefix: "" },
  ];
  let visitedNodes = 0;

  while (stack.length > 0) {
    if (budget.remaining <= 0) {
      return false;
    }
    if (visitedNodes >= MAX_WALK_NODES) {
      return true;
    }
    const current = stack.pop()!;
    visitedNodes++;
    const { value, keyPrefix } = current;

    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === "string") {
      if (value.length === 0) continue;
      const fragment = keyPrefix.length > 0 ? `${keyPrefix}=${value}` : value;
      parts.push(fragment);
      budget.remaining -= textEncoder.encode(fragment).length + 1;
      continue;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      const fragment = keyPrefix.length > 0 ? `${keyPrefix}=${String(value)}` : String(value);
      parts.push(fragment);
      budget.remaining -= textEncoder.encode(fragment).length + 1;
      continue;
    }
    if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) {
        stack.push({ value: value[i], keyPrefix });
      }
      continue;
    }
    if (typeof value === "object") {
      const entries = Object.entries(value);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [k, v] = entries[i]!;
        stack.push({ value: v, keyPrefix: k });
      }
    }
  }

  return false;
}

function buildAttributesJson(
  raw: Record<string, unknown>,
  yaraMatches: RuleMatch[],
  embeddedAttributesJson: unknown = undefined,
): string | null {
  const attrs = Object.create(null) as Record<string, unknown>;

  if (embeddedAttributesJson !== undefined && embeddedAttributesJson !== null && embeddedAttributesJson !== "") {
    mergeAttributesJsonSource(attrs, embeddedAttributesJson);
  }

  for (const attrKey of ["attributes.json", "attributes_json"] as const) {
    const candidate = ownProp(raw, attrKey);
    if (candidate !== undefined && candidate !== null && candidate !== "") {
      mergeAttributesJsonSource(attrs, candidate);
    }
  }

  for (const [key, value] of Object.entries(raw)) {
    if (!KNOWN_CONSUMED_KEYS.has(key) && !CONSUMED_OTEL_ATTR_KEYS.has(key) && value !== undefined) {
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

  const json = stringifyJsonPreservingNonFinite(attrs);
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
  const outer = extractCommonTelemetryFields(raw);

  const rawMessage = ownProp(raw, "message");
  const initialMsg =
    rawMessage !== undefined && rawMessage !== null
      ? parseMessageField(rawMessage)
      : parseMessageField(ownProp(raw, "MESSAGE"));

  const embedded = parseEmbeddedMessageEnvelope(initialMsg.text);
  const parsedMsg = embedded?.messageField ?? initialMsg;
  const embeddedFields = embedded?.fields ?? null;

  const observed_at = outer.observedAt ?? embeddedFields?.observedAt ?? nowIso;
  const event_time = outer.eventTime ?? embeddedFields?.eventTime ?? observed_at;

  const host = outer.host ?? embeddedFields?.host ?? "unknown";
  const systemd_unit = outer.systemdUnit ?? embeddedFields?.systemdUnit ?? null;
  const syslog_identifier =
    outer.syslogIdentifier ?? embeddedFields?.syslogIdentifier ?? null;
  const transport = outer.transport ?? embeddedFields?.transport ?? null;
  const comm = outer.comm ?? embeddedFields?.comm ?? null;
  const exe = outer.exe ?? embeddedFields?.exe ?? null;
  const cmdline = outer.cmdline ?? embeddedFields?.cmdline ?? null;
  const boot_id = outer.bootId ?? embeddedFields?.bootId ?? null;
  const machine_id = outer.machineId ?? embeddedFields?.machineId ?? null;

  const service_name =
    outer.serviceName ??
    embeddedFields?.serviceName ??
    systemd_unit ??
    syslog_identifier ??
    comm ??
    pickNonEmptyString(raw, ["_otel_scope_service"]) ??
    "unknown";

  const priority = outer.priority ?? embeddedFields?.priority ?? 6;
  const severity =
    outer.severity ??
    embeddedFields?.severity ??
    SEVERITY_BY_PRIORITY[priority] ??
    "INFO";

  const pid = outer.pid ?? embeddedFields?.pid ?? null;
  const uid = outer.uid ?? embeddedFields?.uid ?? null;

  const trace_id = outer.traceId ?? embeddedFields?.traceId ?? null;
  const span_id = outer.spanId ?? embeddedFields?.spanId ?? null;
  const event_id = outer.eventId ?? embeddedFields?.eventId ?? crypto.randomUUID();

  let embeddedExtraAttrs: Record<string, unknown> | undefined;
  let hasEmbeddedExtraAttrs = false;
  if (embedded !== null) {
    const extra = Object.create(null) as Record<string, unknown>;
    for (const attrKey of ["attributes.json", "attributes_json"] as const) {
      const candidate = ownProp(embedded.rawRecord, attrKey);
      if (candidate !== undefined && candidate !== null && candidate !== "") {
        mergeAttributesJsonSource(extra, candidate);
        hasEmbeddedExtraAttrs = true;
      }
    }
    for (const [key, value] of Object.entries(embedded.rawRecord)) {
      if (value !== undefined && !EMBEDDED_ENVELOPE_SKIP_KEYS.has(key)) {
        extra[key] = value;
        hasEmbeddedExtraAttrs = true;
      }
    }
    const shadowedChecks: ReadonlyArray<[string, string | null, string | null]> = [
      ["host", outer.host, embedded.fields.host],
      ["systemd_unit", outer.systemdUnit, embedded.fields.systemdUnit],
      ["syslog_identifier", outer.syslogIdentifier, embedded.fields.syslogIdentifier],
      ["transport", outer.transport, embedded.fields.transport],
      ["comm", outer.comm, embedded.fields.comm],
      ["exe", outer.exe, embedded.fields.exe],
      ["cmdline", outer.cmdline, embedded.fields.cmdline],
    ];
    for (const [canonicalKey, outerVal, embeddedVal] of shadowedChecks) {
      if (outerVal !== null && embeddedVal !== null && outerVal !== embeddedVal) {
        extra[canonicalKey] = embeddedVal;
        hasEmbeddedExtraAttrs = true;
      }
    }
    if (hasEmbeddedExtraAttrs) {
      embeddedExtraAttrs = extra;
    }
  }

  const embeddedScanParts: string[] = [];
  if (embedded !== null) {
    const budget = { remaining: MAX_SCAN_BYTES };
    const scanEmbeddedRecord = Object.create(null) as Record<string, unknown>;
    for (const [key, value] of Object.entries(embedded.rawRecord)) {
      if (value === undefined || value === null) continue;
      if (YARA_META_SKIP_KEYS.has(key)) continue;
      if (
        (key === "message" || key === "MESSAGE") &&
        embedded.messageField !== null &&
        value === embedded.messageField.text
      ) {
        continue;
      }
      if ((key === "cmdline" || key === "_CMDLINE" || key === "process.command_line") && value === cmdline) {
        continue;
      }
      if ((key === "exe" || key === "_EXE" || key === "process.executable.path") && value === exe) {
        continue;
      }
      if ((key === "syslog_identifier" || key === "SYSLOG_IDENTIFIER" || key === "syslog.identifier") && value === syslog_identifier) {
        continue;
      }
      if ((key === "systemd_unit" || key === "_SYSTEMD_UNIT" || key === "systemd.unit") && value === systemd_unit) {
        continue;
      }
      if (
        (key === "attributes_json" || key === "attributes.json") &&
        typeof value === "string" &&
        value.trimStart().startsWith("{")
      ) {
        try {
          const parsedAttr = JSON.parse(value) as unknown;
          if (isPlainObject(parsedAttr)) {
            scanEmbeddedRecord[key] = parsedAttr;
            continue;
          }
        } catch {
          // Keep original string below when not valid JSON object.
        }
      }
      scanEmbeddedRecord[key] = value;
    }

    const walkTruncated = collectScanStrings(scanEmbeddedRecord, embeddedScanParts, budget);
    if (walkTruncated && budget.remaining > 0 && initialMsg.text.length > 0) {
      embeddedScanParts.push(initialMsg.text);
    }
  }

  const symbols: EventSymbols = {
    systemd_unit: systemd_unit ?? "",
    syslog_identifier: syslog_identifier ?? "",
    transport: transport ?? "",
    comm: comm ?? "",
    exe: exe ?? "",
    host,
    priority,
  };

  const scanBuffer = buildScanBuffer(
    parsedMsg.bytes,
    {
      cmdline,
      exe,
      syslog_identifier,
      systemd_unit,
    },
    embeddedScanParts,
  );
  const matches = detector.scan(scanBuffer, symbols);

  const mergedRules = [...outer.yaraRules];
  const mergedTags = [...outer.yaraTags];
  if (embeddedFields) {
    pushUniqueStrings(mergedRules, embeddedFields.yaraRules);
    pushUniqueStrings(mergedTags, embeddedFields.yaraTags);
  }

  for (const match of matches) {
    pushUniqueStrings(mergedRules, [match.name]);
    pushUniqueStrings(mergedTags, match.tags);
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
    attributes_json: buildAttributesJson(raw, matches, embeddedExtraAttrs),
  };
}
