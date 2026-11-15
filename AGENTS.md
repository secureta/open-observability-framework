# Open Observability Framework (OOF) — Agent Guide

This repository provides a modular, skill-driven framework for assembling **SIEM + APM** observability platforms from standard OSS collectors and serverless lakehouse storage with **zero custom ingestion runtime glue**.

## Workspace Discovery & Skills

Project skills are registered in [.agents/skills.json](./.agents/skills.json) and live under `skills/`:
- `compose-observability-stack`: Design or adapt `oof.stack.yaml` across framework slots (`schema`, `collect`, `detect`, `ingest`, `storage`, `apm`, `query`).
- `setup-cloudflare-basin-iceberg`: Provision Cloudflare R2, Basin Catalog, authenticated OCSF Basin Stream (`direct-basin-http`), Iceberg Sink, Basin Pipeline, and configure Vector / Fluent Bit / OTel Collector.

## Invariants

1. **Standard Schema Only (OCSF v1.3.0 Contract Parity)**: Keep [contracts/ocsf/event-log-activity.basin.json](./contracts/ocsf/event-log-activity.basin.json), [adapters/storage/cloudflare-basin-iceberg/pipeline.sql](./adapters/storage/cloudflare-basin-iceberg/pipeline.sql), [adapters/collect/vector-journald/vector.yaml](./adapters/collect/vector-journald/vector.yaml), and [adapters/collect/fluent-bit-journald/ocsf.lua](./adapters/collect/fluent-bit-journald/ocsf.lua) in strict lockstep. Never introduce proprietary top-level schema fields, and keep `activity_id = 99` (`"Other"`) and `type_uid = 100899` for general log records in OCSF `Event Log Activity` (`1008`).
2. **Zero Custom Edge Runtime Glue (`direct-basin-http`)**: Do not add a custom Worker or custom auth shim in the ingestion path; send telemetry directly to Basin's native HTTPS endpoint (`--http-enabled true --http-auth true`) using Cloudflare Account API Tokens (`Basin Pipelines Send`).
3. **Collector Wire & Safety Invariants**:
   - **Vector (`>= 0.60`)**: Any config interpolating env vars must be validated and executed with `--dangerously-allow-env-var-interpolation` (or `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true`), and never place raw braced placeholder examples inside `#` comments.
   - **Fluent Bit (`v5.x`)**: Do **not** use `${VAR:-default}` syntax, always set `json_date_key false`, `tls On`, `tls.verify On`, and `tls.verify_hostname On` in `http` outputs, never emit empty Lua `{}` tables that serialize into JSON `[]`, keep the explicit 5-parameter `to_ocsf(tag, ts, group, metadata, record)` arity so `filter_lua` passes OTLP `group` and `metadata`, and keep the authenticated loopback `forward` hop (`127.0.0.1:24225`, `retain_metadata_in_forward_mode false`) so `http` output never injects `"__internal__"`.
   - **OTel Collector bridge**: Keep `encoding: proto` on `otlphttp` exporters (compatible with both Vector and Fluent Bit) and target a non-self-looping endpoint (default `http://127.0.0.1:4320`, distinct from `4317`/`4318`); when co-locating Vector on the same host, move both `OOF_OTLP_GRPC_LISTEN=127.0.0.1:4319` and `OOF_OTLP_HTTP_LISTEN=127.0.0.1:4320`.
4. **Secret Hygiene**: Never commit API tokens or echo `BASIN_CATALOG_TOKEN` / `OOF_INGEST_TOKEN` in provisioning logs or tests.
