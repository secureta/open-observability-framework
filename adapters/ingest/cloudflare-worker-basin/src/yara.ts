export const MAX_SCAN_BYTES = 64 * 1024;

export interface EventSymbols {
  systemd_unit: string;
  syslog_identifier: string;
  transport: string;
  comm: string;
  exe: string;
  host: string;
  priority: number;
}

export interface RuleMatch {
  name: string;
  namespace: string;
  tags: string[];
  metadata: Record<string, string | number | boolean>;
  patterns: string[];
}

export interface RuleDetector {
  scan(payload: Uint8Array, symbols: EventSymbols): RuleMatch[];
}

interface WasmYaraExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  oof_alloc(size: number): number;
  oof_dealloc(ptr: number, size: number): void;
  oof_compile(rulesPtr: number, rulesLen: number): number;
  oof_free_scanner(handle: number): number;
  oof_scan(
    handle: number,
    payloadPtr: number,
    payloadLen: number,
    symbolsJsonPtr: number,
    symbolsJsonLen: number,
  ): number;
  oof_last_output_ptr(): number;
  oof_last_output_len(): number;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function assertExports(exports: WebAssembly.Exports): WasmYaraExports {
  const candidate = exports as Partial<WasmYaraExports>;
  if (
    !(candidate.memory instanceof WebAssembly.Memory) ||
    typeof candidate.oof_alloc !== "function" ||
    typeof candidate.oof_dealloc !== "function" ||
    typeof candidate.oof_compile !== "function" ||
    typeof candidate.oof_free_scanner !== "function" ||
    typeof candidate.oof_scan !== "function" ||
    typeof candidate.oof_last_output_ptr !== "function" ||
    typeof candidate.oof_last_output_len !== "function"
  ) {
    throw new Error("WASM module is missing required oof_yara_wasm exports");
  }
  return candidate as WasmYaraExports;
}

export class WasmYaraDetector implements RuleDetector {
  private readonly exports: WasmYaraExports;
  private handle: number;

  constructor(wasmModule: WebAssembly.Module, ruleSource: string) {
    const instance = new WebAssembly.Instance(wasmModule, {});
    this.exports = assertExports(instance.exports);

    const ruleBytes = textEncoder.encode(ruleSource);
    const rulesPtr = this.allocAndWrite(ruleBytes);
    try {
      const handle = this.exports.oof_compile(rulesPtr, ruleBytes.length);
      if (handle === 0) {
        throw new Error(this.readLastOutputText() || "YARA rule compilation failed");
      }
      this.handle = handle;
    } finally {
      if (rulesPtr !== 0 && ruleBytes.length > 0) {
        this.exports.oof_dealloc(rulesPtr, ruleBytes.length);
      }
    }
  }

  scan(payload: Uint8Array, symbols: EventSymbols): RuleMatch[] {
    if (this.handle === 0) {
      throw new Error("YARA scanner has been disposed");
    }

    const bounded =
      payload.length > MAX_SCAN_BYTES ? payload.subarray(0, MAX_SCAN_BYTES) : payload;
    const symbolsBytes = textEncoder.encode(JSON.stringify(symbols));

    const payloadPtr = this.allocAndWrite(bounded);
    let symbolsPtr = 0;
    try {
      symbolsPtr = this.allocAndWrite(symbolsBytes);
      const count = this.exports.oof_scan(
        this.handle,
        payloadPtr,
        bounded.length,
        symbolsPtr,
        symbolsBytes.length,
      );
      if (count < 0) {
        throw new Error(this.readLastOutputText() || "YARA WASM scan error");
      }
      if (count === 0) {
        return [];
      }
      const rawJson = this.readLastOutputText();
      return JSON.parse(rawJson) as RuleMatch[];
    } finally {
      if (symbolsPtr !== 0 && symbolsBytes.length > 0) {
        this.exports.oof_dealloc(symbolsPtr, symbolsBytes.length);
      }
      if (payloadPtr !== 0 && bounded.length > 0) {
        this.exports.oof_dealloc(payloadPtr, bounded.length);
      }
    }
  }

  get heapByteLength(): number {
    return this.exports.memory.buffer.byteLength;
  }

  dispose(): void {
    if (this.handle !== 0) {
      this.exports.oof_free_scanner(this.handle);
      this.handle = 0;
    }
  }

  private allocAndWrite(bytes: Uint8Array): number {
    if (bytes.length === 0) {
      return 0;
    }
    const ptr = this.exports.oof_alloc(bytes.length);
    if (ptr === 0) {
      throw new Error(`WASM allocation failed for ${bytes.length} bytes`);
    }
    new Uint8Array(this.exports.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  private readLastOutputText(): string {
    const len = this.exports.oof_last_output_len();
    if (len === 0) {
      return "";
    }
    const ptr = this.exports.oof_last_output_ptr();
    const view = new Uint8Array(this.exports.memory.buffer, ptr, len);
    return textDecoder.decode(view);
  }
}

const detectorCache = new WeakMap<WebAssembly.Module, Map<string, WasmYaraDetector>>();
const MAX_CACHED_RULESETS = 8;

export function getCachedWasmDetector(
  wasmModule: WebAssembly.Module,
  ruleSource: string,
): WasmYaraDetector {
  let byRule = detectorCache.get(wasmModule);
  if (!byRule) {
    byRule = new Map();
    detectorCache.set(wasmModule, byRule);
  }
  const existing = byRule.get(ruleSource);
  if (existing) {
    return existing;
  }
  const created = new WasmYaraDetector(wasmModule, ruleSource);
  if (byRule.size >= MAX_CACHED_RULESETS) {
    const oldestKey = byRule.keys().next().value;
    if (oldestKey !== undefined) {
      const oldest = byRule.get(oldestKey);
      oldest?.dispose();
      byRule.delete(oldestKey);
    }
  }
  byRule.set(ruleSource, created);
  return created;
}
