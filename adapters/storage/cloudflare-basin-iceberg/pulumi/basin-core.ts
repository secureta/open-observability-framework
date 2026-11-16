import * as fs from "node:fs";
import * as path from "node:path";

export const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";

export interface BasinField {
  name: string;
  type: string;
  required: boolean;
  unit?: string;
  sql_name?: string;
  metadata_key?: string;
  fields?: BasinField[];
  items?: Omit<BasinField, "name" | "required"> & { required?: boolean };
}

export interface BasinStreamFormat {
  type: "json" | "parquet";
  compression?: string;
  decimal_encoding?: string;
  row_group_bytes?: number;
  timestamp_format?: string;
  unstructured?: boolean;
}

export interface BasinStreamHttpConfig {
  enabled: boolean;
  authentication: boolean;
  cors: {
    origins: string[];
  };
}

export interface BasinStreamWorkerBinding {
  enabled: boolean;
}

export interface BasinStreamSchema {
  fields: BasinField[];
  inferred?: boolean;
}

export interface BasinStructuredStreamInputs {
  accountId: string;
  apiBaseUrl: string;
  apiToken?: string;
  name: string;
  format: BasinStreamFormat;
  http: BasinStreamHttpConfig;
  workerBinding: BasinStreamWorkerBinding;
  schema: BasinStreamSchema;
}

export interface BasinStructuredStreamState {
  accountId: string;
  apiBaseUrl: string;
  name: string;
  format: BasinStreamFormat;
  http: BasinStreamHttpConfig;
  workerBinding: BasinStreamWorkerBinding;
  schema: BasinStreamSchema;
  endpoint: string;
  version: number;
}

export interface BasinSettingsValidationInput {
  accountId: string;
  catalogToken: string;
  apiBaseUrl: string;
  bucketName: string;
  namespace: string;
  tableName: string;
  streamName: string;
  sinkName: string;
  pipelineName: string;
  rollIntervalSeconds: number;
  ingestTokenName?: string;
}

export const ACCOUNT_ID_RE = /^[a-fA-F0-9]{32}$/;
export const API_BASE_URL_RE =
  /^(https:\/\/[A-Za-z0-9.-]+(:[0-9]+)?|http:\/\/(127\.0\.0\.1|localhost):[0-9]+)\/client\/v4$/;
export const BUCKET_NAME_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
export const SQL_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const PIPELINE_NAME_RE = /^[A-Za-z0-9_]+$/;

export function resolveDefaultRepoPaths(fromDir: string): {
  schemaFile: string;
  pipelineSqlFile: string;
} {
  return {
    schemaFile: path.resolve(fromDir, "../../../../contracts/ocsf/event-log-activity.basin.json"),
    pipelineSqlFile: path.resolve(fromDir, "../pipeline.sql"),
  };
}

export function validateBasinSettings(settings: BasinSettingsValidationInput): void {
  if (!ACCOUNT_ID_RE.test(settings.accountId)) {
    throw new Error("accountId must be a 32-character hexadecimal Cloudflare account ID.");
  }
  if (!settings.catalogToken || settings.catalogToken.trim().length === 0) {
    throw new Error("catalogToken must not be empty.");
  }
  if (!API_BASE_URL_RE.test(settings.apiBaseUrl)) {
    throw new Error(
      "apiBaseUrl must end with /client/v4 and use https:// (or loopback http://127.0.0.1:<port> / http://localhost:<port> for local tests)."
    );
  }
  if (!BUCKET_NAME_RE.test(settings.bucketName)) {
    throw new Error(
      "bucketName must be 3-63 lowercase DNS-label characters matching ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$."
    );
  }
  if (!SQL_IDENTIFIER_RE.test(settings.namespace)) {
    throw new Error("namespace must match ^[A-Za-z_][A-Za-z0-9_]*$.");
  }
  if (!SQL_IDENTIFIER_RE.test(settings.tableName)) {
    throw new Error("tableName must match ^[A-Za-z_][A-Za-z0-9_]*$.");
  }
  if (!SQL_IDENTIFIER_RE.test(settings.streamName)) {
    throw new Error("streamName must match ^[A-Za-z_][A-Za-z0-9_]*$.");
  }
  if (!SQL_IDENTIFIER_RE.test(settings.sinkName)) {
    throw new Error("sinkName must match ^[A-Za-z_][A-Za-z0-9_]*$.");
  }
  if (settings.streamName === settings.sinkName) {
    throw new Error("streamName and sinkName must be distinct SQL identifiers.");
  }
  if (!PIPELINE_NAME_RE.test(settings.pipelineName)) {
    throw new Error("pipelineName must match ^[A-Za-z0-9_]+$.");
  }
  if (
    !Number.isInteger(settings.rollIntervalSeconds) ||
    settings.rollIntervalSeconds < 60 ||
    settings.rollIntervalSeconds > 2147483647
  ) {
    throw new Error("rollIntervalSeconds must be an integer between 60 and 2147483647.");
  }
  if (settings.ingestTokenName !== undefined && settings.ingestTokenName.trim().length === 0) {
    throw new Error("ingestTokenName must not be empty.");
  }
}

export function loadBasinSchemaFields(schemaFile: string): BasinField[] {
  const parsed = JSON.parse(fs.readFileSync(schemaFile, "utf8")) as { fields?: unknown };
  if (!Array.isArray(parsed.fields) || parsed.fields.length === 0) {
    throw new Error(`Invalid Basin schema file '${schemaFile}': missing non-empty fields array.`);
  }
  return parsed.fields as BasinField[];
}

export function renderPipelineSql(
  pipelineSqlFile: string,
  sinkName: string,
  streamName: string
): string {
  if (!SQL_IDENTIFIER_RE.test(sinkName) || !SQL_IDENTIFIER_RE.test(streamName)) {
    throw new Error("sinkName and streamName must match ^[A-Za-z_][A-Za-z0-9_]*$.");
  }
  if (sinkName === streamName) {
    throw new Error("streamName and sinkName must be distinct SQL identifiers.");
  }
  const rawSql = fs.readFileSync(pipelineSqlFile, "utf8");
  return rawSql.replaceAll("__SINK_NAME__", sinkName).replaceAll("__STREAM_NAME__", streamName);
}

export function extractHostFromEndpoint(endpoint: string): string {
  const match = /^https?:\/\/([^/]+)/.exec(endpoint);
  if (!match) {
    throw new Error(`Unexpected stream endpoint URL '${endpoint}'.`);
  }
  return match[1];
}

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeValue(item));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const prop = (value as Record<string, unknown>)[key];
      if (prop !== undefined) {
        out[key] = canonicalizeValue(prop);
      }
    }
    return out;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

function scrubSecret(text: string, secret?: string): string {
  if (!secret) {
    return text;
  }
  return text.split(secret).join("[REDACTED]");
}

function resolveApiToken(props?: { apiToken?: string }): string {
  const token = (props?.apiToken || process.env.CLOUDFLARE_API_TOKEN || "").trim();
  if (!token) {
    throw new Error(
      "Missing Cloudflare API token for BasinStructuredStream (set Pulumi secret 'apiToken' or CLOUDFLARE_API_TOKEN)."
    );
  }
  return token;
}

function normalizeHttpConfig(raw: unknown): BasinStreamHttpConfig {
  const obj = (raw && typeof raw === "object" ? raw : {}) as {
    enabled?: unknown;
    authentication?: unknown;
    cors?: { origins?: unknown };
  };
  return {
    enabled: Boolean(obj.enabled ?? true),
    authentication: Boolean(obj.authentication ?? true),
    cors: {
      origins: Array.isArray(obj.cors?.origins)
        ? obj.cors.origins.filter((v): v is string => typeof v === "string")
        : [],
    },
  };
}

function normalizeFormat(raw: unknown): BasinStreamFormat {
  const obj = (raw && typeof raw === "object" ? raw : {}) as BasinStreamFormat;
  const out: BasinStreamFormat = {
    type: obj.type === "parquet" ? "parquet" : "json",
  };
  if (obj.compression !== undefined) out.compression = obj.compression;
  if (obj.decimal_encoding !== undefined) out.decimal_encoding = obj.decimal_encoding;
  if (obj.row_group_bytes !== undefined) out.row_group_bytes = obj.row_group_bytes;
  if (obj.timestamp_format !== undefined) out.timestamp_format = obj.timestamp_format;
  // Server injects unstructured = false by default; omit when false to avoid false replacement diffs.
  if (obj.unstructured === true) out.unstructured = true;
  return out;
}

function normalizeSchema(raw: unknown, fallback?: BasinStreamSchema): BasinStreamSchema {
  const obj = (raw && typeof raw === "object" ? raw : {}) as {
    fields?: unknown;
    inferred?: unknown;
  };
  const fields = Array.isArray(obj.fields) ? (obj.fields as BasinField[]) : (fallback?.fields ?? []);
  const out: BasinStreamSchema = { fields };
  // Server injects inferred = false by default; preserve only explicit true.
  if (obj.inferred === true) out.inferred = true;
  return out;
}

function normalizeWorkerBinding(raw: unknown): BasinStreamWorkerBinding {
  const obj = (raw && typeof raw === "object" ? raw : {}) as { enabled?: unknown };
  return { enabled: Boolean(obj.enabled ?? false) };
}

interface CloudflareEnvelope<T> {
  success?: boolean;
  errors?: Array<{ code?: number; message?: string }>;
  result?: T;
}

interface BasinStreamApiResult {
  id: string;
  name?: string;
  endpoint?: string;
  version?: number;
  format?: unknown;
  http?: unknown;
  worker_binding?: unknown;
  schema?: unknown;
}

async function cfRequest<T>(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  url: string,
  token: string,
  body?: unknown,
  allowNotFound = false
): Promise<{ status: number; data: CloudflareEnvelope<T> | null }> {
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Cloudflare Basin API ${method} request failed: ${scrubSecret(msg, token)}`);
  }

  if (allowNotFound && response.status === 404) {
    return { status: 404, data: null };
  }

  const rawText = await response.text();
  let parsed: CloudflareEnvelope<T> | null = null;
  if (rawText.trim().length > 0) {
    try {
      parsed = JSON.parse(rawText) as CloudflareEnvelope<T>;
    } catch {
      parsed = null;
    }
  }

  if (!response.ok || (parsed && parsed.success === false)) {
    const apiErrs = parsed?.errors?.map((e) => e.message).filter(Boolean).join("; ");
    const detail = scrubSecret(apiErrs || rawText || response.statusText, token);
    throw new Error(`Cloudflare Basin API ${method} ${url} failed (${response.status}): ${detail}`);
  }

  return { status: response.status, data: parsed };
}

export class BasinStructuredStreamProvider {
  async check(
    _olds: unknown,
    news: BasinStructuredStreamInputs
  ): Promise<{ inputs: BasinStructuredStreamInputs; failures?: Array<{ property: string; reason: string }> }> {
    const failures: Array<{ property: string; reason: string }> = [];
    if (!ACCOUNT_ID_RE.test(news.accountId || "")) {
      failures.push({
        property: "accountId",
        reason: "must be a 32-character hexadecimal Cloudflare account ID",
      });
    }
    const baseUrl = news.apiBaseUrl || DEFAULT_API_BASE_URL;
    if (!API_BASE_URL_RE.test(baseUrl)) {
      failures.push({
        property: "apiBaseUrl",
        reason: "must end with /client/v4 and use https:// (or loopback http://127.0.0.1:<port>)",
      });
    }
    if (!SQL_IDENTIFIER_RE.test(news.name || "")) {
      failures.push({
        property: "name",
        reason: "must match ^[A-Za-z_][A-Za-z0-9_]*$",
      });
    }
    if (!Array.isArray(news.schema?.fields) || news.schema.fields.length === 0) {
      failures.push({
        property: "schema.fields",
        reason: "must contain at least one OCSF field definition",
      });
    }

    const sanitizedInputs: BasinStructuredStreamInputs = {
      accountId: news.accountId,
      apiBaseUrl: baseUrl,
      ...(news.apiToken !== undefined ? { apiToken: news.apiToken } : {}),
      name: news.name,
      format: normalizeFormat(news.format),
      http: normalizeHttpConfig(news.http),
      workerBinding: normalizeWorkerBinding(news.workerBinding),
      schema: normalizeSchema(news.schema),
    };

    return failures.length > 0 ? { inputs: sanitizedInputs, failures } : { inputs: sanitizedInputs };
  }

  async diff(
    _id: string,
    olds: BasinStructuredStreamState,
    news: BasinStructuredStreamInputs
  ): Promise<{ changes?: boolean; replaces?: string[]; deleteBeforeReplace?: boolean }> {
    const replaces: string[] = [];

    if (olds.accountId !== news.accountId) replaces.push("accountId");
    if ((olds.apiBaseUrl || DEFAULT_API_BASE_URL) !== (news.apiBaseUrl || DEFAULT_API_BASE_URL)) {
      replaces.push("apiBaseUrl");
    }
    if (olds.name !== news.name) replaces.push("name");
    if (canonicalJson(normalizeFormat(olds.format)) !== canonicalJson(normalizeFormat(news.format))) {
      replaces.push("format");
    }
    if (canonicalJson(normalizeSchema(olds.schema)) !== canonicalJson(normalizeSchema(news.schema))) {
      replaces.push("schema");
    }

    const httpChanged =
      canonicalJson(normalizeHttpConfig(olds.http)) !== canonicalJson(normalizeHttpConfig(news.http));
    const workerBindingChanged =
      canonicalJson(normalizeWorkerBinding(olds.workerBinding)) !==
      canonicalJson(normalizeWorkerBinding(news.workerBinding));

    const changes = replaces.length > 0 || httpChanged || workerBindingChanged;
    return replaces.length > 0
      ? { changes: true, replaces, deleteBeforeReplace: true }
      : { changes };
  }

  private buildState(
    inputs: BasinStructuredStreamInputs,
    result: BasinStreamApiResult
  ): BasinStructuredStreamState {
    // Secret hygiene: NEVER persist apiToken in state outputs (`outs`).
    return {
      accountId: inputs.accountId,
      apiBaseUrl: inputs.apiBaseUrl || DEFAULT_API_BASE_URL,
      name: result.name ?? inputs.name,
      format: normalizeFormat(result.format ?? inputs.format),
      http: normalizeHttpConfig(result.http ?? inputs.http),
      workerBinding: normalizeWorkerBinding(result.worker_binding ?? inputs.workerBinding),
      schema: normalizeSchema(result.schema, inputs.schema),
      endpoint: result.endpoint ?? `https://${result.id}.ingest.cloudflare.com`,
      version: typeof result.version === "number" ? result.version : 1,
    };
  }

  async create(
    inputs: BasinStructuredStreamInputs
  ): Promise<{ id: string; outs: BasinStructuredStreamState }> {
    const token = resolveApiToken(inputs);
    const baseUrl = inputs.apiBaseUrl || DEFAULT_API_BASE_URL;
    const url = `${baseUrl}/accounts/${inputs.accountId}/pipelines/v1/streams`;

    const payload = {
      name: inputs.name,
      format: inputs.format,
      http: inputs.http,
      worker_binding: inputs.workerBinding,
      schema: inputs.schema,
    };

    const { data } = await cfRequest<BasinStreamApiResult>("POST", url, token, payload);
    const result = data?.result;
    if (!result?.id) {
      throw new Error("Cloudflare Basin stream creation response missing result.id.");
    }

    return {
      id: result.id,
      outs: this.buildState(inputs, result),
    };
  }

  async read(
    id: string,
    props?: Partial<BasinStructuredStreamState> & { apiToken?: string }
  ): Promise<{ id?: string; props?: BasinStructuredStreamState }> {
    if (!props?.accountId) {
      throw new Error("Cannot read BasinStructuredStream without accountId in state.");
    }
    const token = resolveApiToken(props);
    const baseUrl = props.apiBaseUrl || DEFAULT_API_BASE_URL;
    const url = `${baseUrl}/accounts/${props.accountId}/pipelines/v1/streams/${id}`;

    const { status, data } = await cfRequest<BasinStreamApiResult>("GET", url, token, undefined, true);
    if (status === 404 || !data?.result) {
      return {};
    }

    const result = data.result;
    const state: BasinStructuredStreamState = {
      accountId: props.accountId,
      apiBaseUrl: baseUrl,
      name: result.name ?? props.name ?? "",
      format: normalizeFormat(result.format ?? props.format),
      http: normalizeHttpConfig(result.http ?? props.http),
      workerBinding: normalizeWorkerBinding(result.worker_binding ?? props.workerBinding),
      schema: normalizeSchema(result.schema, props.schema),
      endpoint: result.endpoint ?? `https://${result.id}.ingest.cloudflare.com`,
      version: typeof result.version === "number" ? result.version : (props.version ?? 1),
    };

    return { id: result.id ?? id, props: state };
  }

  async update(
    id: string,
    _olds: BasinStructuredStreamState,
    news: BasinStructuredStreamInputs
  ): Promise<{ outs: BasinStructuredStreamState }> {
    const token = resolveApiToken(news);
    const baseUrl = news.apiBaseUrl || DEFAULT_API_BASE_URL;
    const url = `${baseUrl}/accounts/${news.accountId}/pipelines/v1/streams/${id}`;

    // PATCH endpoint accepts ONLY `http` and `worker_binding`.
    const patchBody = {
      http: news.http,
      worker_binding: news.workerBinding,
    };

    const { data } = await cfRequest<BasinStreamApiResult>("PATCH", url, token, patchBody);
    const result = data?.result ?? { id };
    return {
      outs: this.buildState(news, { ...result, id: result.id ?? id }),
    };
  }

  async delete(
    id: string,
    props: BasinStructuredStreamState & { apiToken?: string }
  ): Promise<void> {
    if (!props?.accountId) {
      return;
    }
    const token = resolveApiToken(props);
    const baseUrl = props.apiBaseUrl || DEFAULT_API_BASE_URL;
    const url = `${baseUrl}/accounts/${props.accountId}/pipelines/v1/streams/${id}`;

    await cfRequest<unknown>("DELETE", url, token, undefined, true);
  }
}
