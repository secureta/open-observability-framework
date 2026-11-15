---
name: compose-observability-stack
description: >-
  Use this skill when designing, modifying, or extending a SIEM + APM observability
  stack with interchangeable services across the Open Observability Framework slots
  (collect, detect, ingest, storage, apm, query).
---

# Compose an Open Observability Stack (SIEM + APM)

Build observability platforms by composing existing services across 6 decoupled slots while keeping custom glue code minimal and all adapters aligned to the canonical envelope in [telemetry-envelope.md](../../contracts/telemetry-envelope.md).

## Workflow

1. **Inspect the slot schema and example manifest**
   - Read [stack.schema.json](../../manifest/stack.schema.json) and [cloudflare-basin-siem.yaml](../../manifest/examples/cloudflare-basin-siem.yaml).
   - Consult [component-catalog.md](./references/component-catalog.md) for supported adapters per slot.

2. **Create or update `oof.stack.yaml` (e.g., from the example manifest)**
   - **Collect (`collect`)**: Pick `vector-journald` (VRL normalization, low footprint) or `otel-collector-journald` (unified SIEM `journald` + APM `otlp`).
   - **Detect (`detect`)**: Pick `edge-ingest` (`yara-wasm` inside Worker), `host-agent` (`yara-x` CLI / Kunai), or `hybrid` (merges host + edge rule matches).
   - **Ingest (`ingest`)**: Pick `cloudflare-worker-basin` (auth, normalization, WASM YARA) or direct Basin HTTP if detection lives on-host.
   - **Storage (`storage`)**: Use `cloudflare-basin-iceberg` (Apache Iceberg tables on Cloudflare R2 via Basin Pipelines + Basin Catalog).
   - **APM (`apm`)**: Set `apm.enabled: true` and pick OTLP trace/metric adapters when ready to ingest spans and metrics alongside `trace_id`-correlated logs.
   - **Query (`query`)**: Combine `basin-sql` (serverless Cloudflare SQL) with external Iceberg engines like `duckdb`, `pyiceberg`, or Spark.

3. **Validate contracts and wiring**
   - Ensure the chosen collector emits fields matching [journal-logs.basin.json](../../contracts/schemas/journal-logs.basin.json).
   - Validate `oof.stack.yaml` against `manifest/stack.schema.json` using `python3` or `yq` + JSON Schema validator if available.
   - Proceed to [setup-cloudflare-basin-iceberg](../setup-cloudflare-basin-iceberg/SKILL.md) to provision and deploy.
