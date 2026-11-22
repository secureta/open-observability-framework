# Component Catalog by Framework Slot

Each slot can swap services independently because adapters speak standard open schemas starting with OCSF v1.3.0 `Event Log Activity` (`1008`, [event-log-activity.basin.json](../../../contracts/ocsf/event-log-activity.basin.json)).

| Slot | Adapter ID | Path / Reference | Best For |
| :--- | :--- | :--- | :--- |
| `schema` | `ocsf` (`v1.3.0`, `1008`) | `contracts/ocsf/event-log-activity.basin.json` | Vendor-neutral SIEM + APM log standardization (`ecs`/`cim` extensible later) |
| `collect` | `vector-journald` | `adapters/collect/vector-journald/vector.yaml` | Host `systemd-journald` + OTLP (`4317`/`4318`) -> VRL OCSF v1.3.0 -> gzipped JSON array |
| `collect` | `fluent-bit-journald` | `adapters/collect/fluent-bit-journald/fluent-bit.conf` | Ultra-lightweight `systemd` + `opentelemetry` -> Lua OCSF v1.3.0 -> gzipped JSON array |
| `collect` | `otel-collector-journald` | `adapters/collect/otel-collector-journald/otelcol.yaml` | OTLP agent/gateway forwarding protobuf logs (`encoding: proto`) to Vector or Fluent Bit |
| `collect` | `vector-github-actions` | `adapters/collect/vector-github-actions/vector.yaml` | GitHub Webhook (`workflow_run`, `workflow_job`, security alerts) with HMAC-SHA256 verification -> OCSF v1.3.0 -> Basin HTTP |
| `collect` | `github-actions-direct` | `adapters/collect/github-actions-direct/action.yml` | Serverless Node.js 20 GitHub Action emitting OCSF v1.3.0 directly to Basin HTTP (`direct-basin-http`) |
| `collect` (NixOS) | `oof-collector` | `flake.nix` (`nixosModules.default`) | Hardened systemd deployment for Vector / Fluent Bit + optional OTel bridge, GitHub Actions webhook collector & secret `environmentFile` |
| `detect` | `disabled` (default) / optional | `manifest/stack.schema.json` (`detect.enabled`) | Lean ingestion without custom runtime compute; add host `yara-x`/lakehouse SQL if needed |
| `ingest` | `direct-basin-http` | `adapters/storage/cloudflare-basin-iceberg/terraform/main.tf` · `adapters/storage/cloudflare-basin-iceberg/pulumi/index.ts` | Zero-Worker direct HTTPS ingestion (`http.enabled = true`, `http.authentication = true`) |
| `storage` | `cloudflare-basin-iceberg` | `adapters/storage/cloudflare-basin-iceberg/pipeline.sql` | Serverless R2 + Basin Catalog Apache Iceberg lakehouse (`siem.ocsf_event_log_activity`) |
| `apm` | `otlp-basin-iceberg` (extension) | `otelcol.yaml` + `metadata.correlation_uid` | Correlating application traces/metrics (`trace_id`) with OCSF system logs |
| `query` | `basin-sql`, `duckdb` | `adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql` · `github_actions_monitoring.sql` · `github_actions_monitoring.basin.sql` | Ad-hoc SQL threat hunting, CI/CD observability & SIEM monitoring, and APM-SIEM correlation over Iceberg |
