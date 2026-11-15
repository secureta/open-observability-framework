# Open Observability Framework (OOF) — Agent Guide

This repository provides a modular, skill-driven framework for assembling **SIEM + APM** observability platforms from interchangeable services with minimal custom glue code.

## Workspace Discovery & Skills

Project skills are registered in [.agents/skills.json](./.agents/skills.json) and live under `skills/`:
- `compose-observability-stack`: Design or adapt `oof.stack.yaml` across the 6 framework slots (`collect`, `detect`, `ingest`, `storage`, `apm`, `query`).
- `setup-cloudflare-basin-iceberg`: Provision Cloudflare R2, Basin Catalog, Stream, Iceberg Sink, Basin Pipeline, and deploy the Worker + collector.
- `manage-yara-detection`: Author `.yar` rules, test and rebuild `oof-yara-wasm`, or switch detection placement (`edge-ingest`, `host-agent`, `hybrid`).

## Invariants

1. **Canonical 24-Field Contract**: Never alter fields in `contracts/schemas/journal-logs.basin.json`, `adapters/ingest/cloudflare-worker-basin/src/normalize.ts`, `adapters/collect/vector-journald/vector.yaml`, or `adapters/storage/cloudflare-basin-iceberg/pipeline.sql` independently — update all four together and keep the schema test passing.
2. **Cloudflare Workers WASM Constraint**: Do **not** replace `boreal` (`oof-yara-wasm`) with `@virustotal/yara-x` inside Cloudflare Workers. `workerd` forbids runtime `WebAssembly.Module(bytes)` compilation; `oof-yara-wasm` evaluates rules in pure Rust with static WASM import and zero runtime codegen.
3. **No Time Syscalls on `wasm32-unknown-unknown`**: Keep `boreal::module::Time`, `ScanParams::timeout_duration`, and `ScanParams::compute_statistics` disabled in `adapters/detect/yara-wasm`.
4. **Secret Hygiene**: Never commit tokens or echo `BASIN_CATALOG_TOKEN` / `INGEST_AUTH_TOKEN` in provisioning logs.
