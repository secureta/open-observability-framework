---
name: manage-yara-detection
description: >-
  Use this skill when adding, testing, or compiling YARA rules for OOF, rebuilding
  the Rust boreal WASM module for Cloudflare Workers, or switching detection placement
  between edge-ingest (WASM) and host-agent (YARA-X / Kunai).
---

# Manage YARA Detection Rules & Placement

OOF uses standard `.yar` files (default: [linux_journal_core.yar](../../rules/yara/linux_journal_core.yar)) compatible with both `boreal` (edge-ingest WASM) and `YARA-X` / `Kunai` (host-agent).

## Rule Authoring Guidelines

- **Avoid `import "time"` in edge rules**: `oof-yara-wasm` intentionally omits the `time` module because `SystemTime::now()` panics on `wasm32-unknown-unknown`. `math`, `string`, and `hash` modules are enabled.
- **Use pre-defined journald external symbols**: Edge scanning pre-defines `systemd_unit`, `syslog_identifier`, `transport`, `comm`, `exe`, `host` (strings) and `priority` (integer, default `6`). Example:
  ```yara
  rule SSHD_High_Priority_Alert : auth {
    strings:
      $msg = "Failed password"
    condition:
      systemd_unit == "sshd.service" and priority <= 4 and $msg
  }
  ```
- **Scan budget**: Edge WASM scans up to `64 KiB` per event (`message` + `cmdline` + `exe` + `syslog_identifier` + `systemd_unit`).

## Steps to Update Rules & Rebuild WASM

1. Edit or add `.yar` rules under `rules/yara/` and sync to `adapters/ingest/cloudflare-worker-basin/src/rules/linux_journal_core.yar` (or run [build-yara-wasm.sh](./scripts/build-yara-wasm.sh) after copying).
2. Run Rust unit tests for `oof-yara-wasm`:
   ```bash
   cargo test --manifest-path adapters/detect/yara-wasm/Cargo.toml
   ```
3. Rebuild the `wasm32-unknown-unknown` binary and copy it into the Worker bundle:
   ```bash
   ./skills/manage-yara-detection/scripts/build-yara-wasm.sh
   ```
4. Run Worker typecheck and Vitest suite against the compiled `.wasm`:
   ```bash
   npm --prefix adapters/ingest/cloudflare-worker-basin run typecheck
   npm --prefix adapters/ingest/cloudflare-worker-basin test
   ```

## Switching Detection Placement (`edge-ingest` vs `host-agent` vs `hybrid`)

- **`edge-ingest`**: Default. The Cloudflare Worker scans every `journald` event inline using `oof-yara-wasm`.
- **`host-agent`**: Follow [adapters/detect/host-yara-x/README.md](../../adapters/detect/host-yara-x/README.md) to scan host files/memory with `yr` or Kunai and emit `yara_rules` / `yara_tags` via `journald`.
- **`hybrid`**: Run both; `normalizeAndDetect` automatically merges upstream `yara_rules` and `yara_tags` with edge WASM matches without duplicate rule names.
