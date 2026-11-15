import {
  isPlainObject,
  normalizeAndDetect,
  OtlpUnpackError,
  TelemetryLogRecord,
  unpackOtlpLogsPayload,
} from "./normalize";
import defaultRuleSource from "./rules/linux_journal_core.yar";
import defaultWasmModule from "./wasm/oof_yara_wasm.wasm";
import { getCachedWasmDetector, RuleDetector } from "./yara";

export interface PipelineStream<T = TelemetryLogRecord> {
  send(records: T[]): Promise<void>;
}

export interface IngestEnv {
  TELEMETRY_STREAM: PipelineStream<TelemetryLogRecord>;
  INGEST_AUTH_TOKEN: string;
  YARA_RULES_TEXT?: string;
}

export interface HandlerOptions {
  wasmModule?: WebAssembly.Module;
  ruleSource?: string;
  detector?: RuleDetector;
}

export const MAX_BODY_BYTES = 5 * 1024 * 1024;
export const MAX_BATCH_RECORDS = 1000;

const SUPPORTED_CONTENT_TYPES = new Set([
  "application/json",
  "application/x-ndjson",
  "application/ndjson",
  "text/plain",
]);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function validateContentType(request: Request): void {
  const rawContentType = request.headers.get("content-type")?.trim();
  if (!rawContentType) {
    return;
  }
  const mediaType = rawContentType.split(";")[0]!.trim().toLowerCase();
  if (mediaType.length === 0) {
    return;
  }
  if (!SUPPORTED_CONTENT_TYPES.has(mediaType)) {
    throw new HttpError(
      415,
      `Unsupported Content-Type: ${mediaType} (use JSON, NDJSON, or OTLP JSON with encoding: json)`,
    );
  }
}

async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", textEncoder.encode(a)),
    crypto.subtle.digest("SHA-256", textEncoder.encode(b)),
  ]);
  const bytesA = new Uint8Array(hashA);
  const bytesB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < bytesA.length; i++) {
    diff |= (bytesA[i] ?? 0) ^ (bytesB[i] ?? 0);
  }
  return diff === 0;
}

function extractBearerToken(headerValue: string | null): string | null {
  if (!headerValue) {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
  if (!match || !match[1]) {
    return null;
  }
  const token = match[1].trim();
  return token.length > 0 ? token : null;
}

function createByteCapStream(
  maxBytes: number,
  onLimitExceeded: () => void,
): TransformStream<Uint8Array, Uint8Array> {
  let total = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      total += chunk.byteLength;
      if (total > maxBytes) {
        onLimitExceeded();
        controller.error(new HttpError(413, `Request payload exceeds ${maxBytes} bytes`));
        return;
      }
      controller.enqueue(chunk);
    },
  });
}

async function readStreamCapped(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!value || value.byteLength === 0) {
      continue;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new HttpError(413, `Request payload exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

async function readRequestBodyText(request: Request): Promise<string> {
  if (!request.body) {
    throw new HttpError(400, "Empty request body");
  }

  const rawEncoding = request.headers.get("content-encoding")?.trim().toLowerCase() ?? "";
  let bytes: Uint8Array;

  if (rawEncoding === "" || rawEncoding === "identity") {
    bytes = await readStreamCapped(request.body, MAX_BODY_BYTES);
  } else if (rawEncoding === "gzip") {
    let compressedSizeExceeded = false;
    try {
      const cappedCompressed = request.body.pipeThrough(
        createByteCapStream(MAX_BODY_BYTES, () => {
          compressedSizeExceeded = true;
        }),
      );
      const decompressed = cappedCompressed.pipeThrough(
        new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>,
      );
      bytes = await readStreamCapped(decompressed, MAX_BODY_BYTES);
    } catch (err) {
      if (compressedSizeExceeded) {
        throw new HttpError(413, `Request payload exceeds ${MAX_BODY_BYTES} bytes`);
      }
      if (err instanceof HttpError) {
        throw err;
      }
      throw new HttpError(400, "Invalid gzip-compressed request body");
    }
  } else {
    throw new HttpError(415, `Unsupported Content-Encoding: ${rawEncoding}`);
  }

  if (bytes.byteLength === 0) {
    throw new HttpError(400, "Empty request body");
  }

  try {
    return textDecoder.decode(bytes);
  } catch {
    throw new HttpError(400, "Request body must be valid UTF-8");
  }
}

function parseNdjsonRecords(text: string): Record<string, unknown>[] {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    throw new HttpError(400, "No log records provided");
  }
  if (lines.length > MAX_BATCH_RECORDS) {
    throw new HttpError(413, `Batch exceeds maximum of ${MAX_BATCH_RECORDS} records`);
  }

  const records: Record<string, unknown>[] = [];
  for (let i = 0; i < lines.length; i++) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(lines[i]!);
    } catch {
      throw new HttpError(400, `Invalid JSON at NDJSON line ${i + 1}`);
    }
    if (!isPlainObject(parsed)) {
      throw new HttpError(400, `Expected JSON object at NDJSON line ${i + 1}`);
    }
    records.push(parsed);
  }
  return records;
}

function parseLogRecords(text: string): Record<string, unknown>[] {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    throw new HttpError(400, "Empty request body");
  }

  if (trimmed.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new HttpError(400, "Invalid JSON array payload");
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new HttpError(400, "JSON array must contain at least one log object");
    }
    if (parsed.length > MAX_BATCH_RECORDS) {
      throw new HttpError(413, `Batch exceeds maximum of ${MAX_BATCH_RECORDS} records`);
    }
    for (let i = 0; i < parsed.length; i++) {
      if (!isPlainObject(parsed[i])) {
        throw new HttpError(400, `Record at index ${i} must be a JSON object`);
      }
    }
    return parsed as Record<string, unknown>[];
  }

  if (trimmed.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      // Multiple JSON objects separated by newlines (NDJSON) fail single-doc JSON.parse.
      return parseNdjsonRecords(trimmed);
    }
    if (!isPlainObject(parsed)) {
      throw new HttpError(400, "Payload must be a JSON object");
    }
    try {
      const otlpRecords = unpackOtlpLogsPayload(parsed, MAX_BATCH_RECORDS);
      if (otlpRecords !== null) {
        return otlpRecords;
      }
    } catch (err) {
      if (err instanceof OtlpUnpackError) {
        throw new HttpError(err.status, err.message);
      }
      throw new HttpError(400, "Invalid OTLP logs payload");
    }
    return [parsed];
  }

  throw new HttpError(400, "Payload must be JSON object, JSON array, or NDJSON");
}

function jsonResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export function createIngestHandler(options: HandlerOptions = {}) {
  return {
    async fetch(request: Request, env: IngestEnv): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === "/healthz") {
        if (request.method !== "GET") {
          return jsonResponse({ error: "Method Not Allowed" }, 405);
        }
        return jsonResponse({ status: "ok", detector: "yara-wasm" }, 200);
      }

      if (url.pathname !== "/v1/logs") {
        return jsonResponse({ error: "Not Found" }, 404);
      }

      if (request.method !== "POST") {
        return jsonResponse({ error: "Method Not Allowed" }, 405);
      }

      const expectedToken = env.INGEST_AUTH_TOKEN?.trim() ?? "";
      if (expectedToken.length === 0) {
        return jsonResponse({ error: "Ingest auth token is not configured" }, 500);
      }

      const providedToken = extractBearerToken(request.headers.get("authorization"));
      if (!providedToken || !(await constantTimeEqual(providedToken, expectedToken))) {
        return jsonResponse({ error: "Unauthorized" }, 401);
      }

      if (!env.TELEMETRY_STREAM || typeof env.TELEMETRY_STREAM.send !== "function") {
        return jsonResponse({ error: "TELEMETRY_STREAM pipeline binding is unavailable" }, 500);
      }

      let rawRecords: Record<string, unknown>[];
      try {
        validateContentType(request);
        const bodyText = await readRequestBodyText(request);
        rawRecords = parseLogRecords(bodyText);
      } catch (err) {
        if (err instanceof HttpError) {
          return jsonResponse({ error: err.message }, err.status);
        }
        return jsonResponse({ error: "Bad Request" }, 400);
      }

      let detector: RuleDetector;
      try {
        if (options.detector) {
          detector = options.detector;
        } else {
          const wasmMod = options.wasmModule ?? defaultWasmModule;
          const rules = env.YARA_RULES_TEXT ?? options.ruleSource ?? defaultRuleSource;
          detector = getCachedWasmDetector(wasmMod, rules);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to initialize YARA detector";
        return jsonResponse({ error: msg }, 500);
      }

      const nowIso = new Date().toISOString();
      let normalized: TelemetryLogRecord[];
      try {
        normalized = rawRecords.map((rec) => normalizeAndDetect(rec, detector, nowIso));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to inspect telemetry batch";
        return jsonResponse({ error: msg }, 500);
      }

      const matched = normalized.reduce((acc, rec) => acc + (rec.yara_matched ? 1 : 0), 0);

      try {
        await env.TELEMETRY_STREAM.send(normalized);
      } catch {
        return jsonResponse({ error: "Failed to deliver telemetry batch to Basin stream" }, 502);
      }

      return jsonResponse({ accepted: normalized.length, matched }, 202);
    },
  };
}

export default createIngestHandler();
