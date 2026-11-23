# Component Catalog by Framework Slot

Each slot can swap services independently because adapters speak standard open schemas starting with OCSF v1.3.0 `Event Log Activity` (`1008`, [event-log-activity.basin.json](../../../contracts/ocsf/event-log-activity.basin.json)).

| Slot | Adapter ID | Path / Reference | Best For |
| :--- | :--- | :--- | :--- |
| `schema` | `ocsf` (`v1.3.0`, `1008`) | `contracts/ocsf/event-log-activity.basin.json` | Vendor-neutral SIEM + APM log standardization (`ecs`/`cim` extensible later) |
| `schema` (FinOps) | `focus` (`v1.0`) | `contracts/focus/cost-and-usage.basin.json` | Vendor-neutral FinOps Open Cost and Usage Specification (FOCUS v1.0) for Cloudflare & GitHub cost monitoring |
| `collect` | `finops-billing` | `adapters/collect/finops-billing/collect-focus.mjs` | Zero-dependency Node.js 20+ collector pulling Cloudflare GraphQL Analytics (R2/Pipelines) & GitHub Billing Usage API -> FOCUS v1.0 -> Basin HTTP |
| `collect` | `vector-journald` | `adapters/collect/vector-journald/vector.yaml` | Host `systemd-journald` + OTLP (`4317`/`4318`) -> VRL OCSF v1.3.0 -> gzipped JSON array |
| `collect` | `fluent-bit-journald` | `adapters/collect/fluent-bit-journald/fluent-bit.conf` | Ultra-lightweight `systemd` + `opentelemetry` -> Lua OCSF v1.3.0 -> gzipped JSON array |
| `collect` | `otel-collector-journald` | `adapters/collect/otel-collector-journald/otelcol.yaml` | OTLP agent/gateway forwarding protobuf logs (`encoding: proto`) to Vector or Fluent Bit |
| `collect` | `vector-github-actions` | `adapters/collect/vector-github-actions/vector.yaml` | GitHub Webhook (`workflow_run`, `workflow_job`, security alerts) with HMAC-SHA256 verification -> OCSF v1.3.0 -> Basin HTTP |
| `collect` | `github-actions-direct` | `adapters/collect/github-actions-direct/action.yml` | Serverless Node.js 20 GitHub Action emitting OCSF v1.3.0 directly to Basin HTTP (`direct-basin-http`) |
| `collect` | `prometheus-pull` | `adapters/collect/prometheus-pull/prometheus.yml` | Loopback Prometheus `/metrics` pull scraper with strict metric/label allowlists and local TSDB query API (disabled by default) |
| `collect` | `cloudflare-audit-logs` | `adapters/collect/cloudflare-audit-logs/poller.mjs` | Checkpointed Cloudflare Account Audit Logs REST API poller (multi-page pagination) -> OCSF v1.3.0 -> Basin HTTP |
| `collect` | `vector-cloudflare-logpush` | `adapters/collect/vector-cloudflare-logpush/vector.yaml` | Cloudflare Logpush HTTP Push receiver (`http_requests`, `firewall_events`, `dns_logs`, `access_requests`, `gateway_dns`) -> VRL OCSF v1.3.0 -> Basin HTTP |
| `collect` | `cloudflare-graphql-exporter` | `adapters/collect/cloudflare-graphql-exporter/exporter.mjs` | Zero-dependency loopback Prometheus exporter for Cloudflare GraphQL Analytics (`httpRequests1mGroups`) |
| `collect` (NixOS) | `oof-collector` | `flake.nix` (`nixosModules.default`) | Hardened systemd deployment for Vector / Fluent Bit + optional OTel bridge, GitHub Actions webhook, Cloudflare Audit Logs / Logpush / GraphQL Exporter, optional Prometheus pull, & secret `environmentFile` |
| `detect` | `disabled` (default) / optional | `manifest/stack.schema.json` (`detect.enabled`) | Lean ingestion without custom runtime compute; add host `yara-x`/lakehouse SQL if needed |
| `ingest` | `direct-basin-http` | `adapters/storage/cloudflare-basin-iceberg/terraform/main.tf` · `adapters/storage/cloudflare-basin-iceberg/pulumi/index.ts` | Zero-Worker direct HTTPS ingestion (`http.enabled = true`, `http.authentication = true`) |
| `storage` | `cloudflare-basin-iceberg` | `adapters/storage/cloudflare-basin-iceberg/pipeline.sql` | Serverless R2 + Basin Catalog Apache Iceberg lakehouse (`siem.ocsf_event_log_activity`) |
| `apm` | `otlp-basin-iceberg` (extension) | `otelcol.yaml` + `metadata.correlation_uid` | Correlating application traces/metrics (`trace_id`) with OCSF system logs |
| `ai` | `vector-ai-coding-agents` (`otel-genai`) | `contracts/otel-genai/genai-usage.basin.json` · `adapters/collect/vector-ai-coding-agents/vector.yaml` | Metadata-only coding-agent AI usage (Claude Code, Codex CLI, Antigravity/herdr, Pi) -> `ai.genai_usage` |
| `query` | `basin-sql`, `duckdb` | `adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql` · `github_actions_monitoring.sql` · `github_actions_monitoring.basin.sql` · `ai_coding_agents.sql` | Ad-hoc SQL threat hunting, CI/CD & AI usage observability, and APM-SIEM correlation over Iceberg |
