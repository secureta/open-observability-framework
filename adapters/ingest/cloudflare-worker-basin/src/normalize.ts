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

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pickNonEmptyString(
  record: Record<string, unknown>,
  keys: readonly string[],
): string | null {
  for (const key of keys) {
    const val = record[key];
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

const PRIORITY_BY_TEXT: Readonly<Record<string, number>> = {
  emerg: 0,
  panic: 0,
  alert: 1,
  crit: 2,
  critical: 2,
  err: 3,
  error: 3,
  warn: 4,
  warning: 4,
  notice: 5,
  info: 6,
  informational: 6,
  debug: 7,
};

function parsePriority(rawPriority: unknown): number {
  const parsed = parseSafeInt(rawPriority);
  if (parsed !== null) {
    if (parsed < 0) return 0;
    if (parsed > 7) return 7;
    return parsed;
  }
  if (typeof rawPriority === "string") {
    const mapped = PRIORITY_BY_TEXT[rawPriority.trim().toLowerCase()];
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

function buildAttributesJson(
  raw: Record<string, unknown>,
  yaraMatches: RuleMatch[],
): string | null {
  const attrs: Record<string, unknown> = {};

  if (typeof raw.attributes_json === "string" && raw.attributes_json.length > 0) {
    try {
      const parsed = JSON.parse(raw.attributes_json) as unknown;
      if (isPlainObject(parsed)) {
        Object.assign(attrs, parsed);
      } else {
        attrs.upstream_attributes = raw.attributes_json;
      }
    } catch {
      attrs.upstream_attributes = raw.attributes_json;
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
  const observed_at = parseIsoTimestamp(raw.observed_at) ?? nowIso;
  const event_time =
    parseIsoTimestamp(raw.event_time) ??
    parseIsoTimestamp(raw.timestamp) ??
    parseIsoTimestamp(raw.time) ??
    parseRealtimeTimestampUs(raw.__REALTIME_TIMESTAMP) ??
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

  const priority = parsePriority(raw.priority ?? raw.PRIORITY);
  const severity =
    pickNonEmptyString(raw, ["severity"]) ?? SEVERITY_BY_PRIORITY[priority] ?? "INFO";

  const pid = parseSafeInt(raw.pid ?? raw._PID);
  const uid = parseSafeInt(raw.uid ?? raw._UID);

  const trace_id = pickNonEmptyString(raw, ["trace_id", "TRACE_ID", "OTEL_TRACE_ID"]);
  const span_id = pickNonEmptyString(raw, ["span_id", "SPAN_ID", "OTEL_SPAN_ID"]);

  const parsedMsg =
    raw.message !== undefined && raw.message !== null
      ? parseMessageField(raw.message)
      : parseMessageField(raw.MESSAGE);

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

  const mergedRules = parseStringArray(raw.yara_rules);
  const mergedTags = parseStringArray(raw.yara_tags);

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
