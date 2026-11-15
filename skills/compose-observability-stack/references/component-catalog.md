# Component Catalog by Framework Slot

Each slot can swap services independently because adapters speak the 24-field canonical envelope ([journal-logs.basin.json](../../../contracts/schemas/journal-logs.basin.json)).

| Slot | Adapter ID | Path / Reference | Best For |
| :--- | :--- | :--- | :--- |
| `collect` | `vector-journald` | `adapters/collect/vector-journald/vector.yaml` | Production `systemd-journald` shipping with VRL normalization & gzipped NDJSON |
| `collect` | `otel-collector-journald` | `adapters/collect/otel-collector-journald/otelcol.yaml` | Unified SIEM (`journald`) + APM (`otlp` traces/metrics) host agent |
| `detect` | `yara-wasm` (`edge-ingest`) | `adapters/detect/yara-wasm/` | Zero-host-dependency inline YARA inspection inside Cloudflare Workers |
| `detect` | `host-yara-x` (`host-agent`) | `adapters/detect/host-yara-x/README.md` | File/memory scanning via `yr` (YARA-X) or Kunai, logged to `journald` |
| `ingest` | `cloudflare-worker-basin` | `adapters/ingest/cloudflare-worker-basin/` | Auth, schema normalization, WASM YARA scan, `TELEMETRY_STREAM.send()` |
| `storage` | `cloudflare-basin-iceberg` | `adapters/storage/cloudflare-basin-iceberg/` | Serverless R2 + Basin Catalog Apache Iceberg lakehouse |
| `apm` | `otlp-basin-iceberg` (extension) | `otelcol.yaml` + `trace_id`/`span_id` fields | Correlating application traces/metrics with host security logs |
| `query` | `basin-sql`, `duckdb` | `adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql` | Ad-hoc SQL threat hunting & APM-SIEM correlation over Iceberg |
