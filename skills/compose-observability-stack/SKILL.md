---
name: compose-observability-stack
description: >-
  Use this skill when designing, modifying, or extending a SIEM + APM observability
  stack with interchangeable services across the Open Observability Framework slots
  (schema, collect, detect, ingest, storage, apm, query).
---

# Compose an Open Observability Stack (SIEM + APM)

Build observability platforms by composing standard open-source collectors and serverless lakehouse services around open schemas ([contracts/ocsf/README.md](../../contracts/ocsf/README.md)) with zero proprietary ingestion workers.

## Workflow

1. **Inspect the slot schema and OCSF example manifest**
   - Read [stack.schema.json](../../manifest/stack.schema.json) and [cloudflare-basin-ocsf.yaml](../../manifest/examples/cloudflare-basin-ocsf.yaml).
   - Consult [component-catalog.md](./references/component-catalog.md) for supported adapters per slot.

2. **Create or update `oof.stack.yaml` (e.g., from the example manifest)**
   - **Schema (`schema`)**: Select a standard profile (`ocsf` v1.3.0 with `class_uid: 1008` is implemented; `ecs` and `cim` are planned extension profiles — do not create proprietary custom fields).
   - **Collect (`collect`)**: Pick `vector-journald` (Vector VRL normalization for `journald` + `otlp`), `fluent-bit-journald` (lightweight Fluent Bit `systemd` + `opentelemetry` Lua filter), or pair either with `otel-collector-journald` as an OTLP forwarding bridge (`otlphttp` protobuf -> port `4320`). On NixOS hosts, use [flake.nix](../../flake.nix) (`nixosModules.default` -> `services.oof-collector`) for declarative deployment and automatic bridge port isolation.
   - **Detect (`detect`)**: Keep `enabled: false` by default, or set `enabled: true` with `host-agent` / `lakehouse-batch` rules when needed.
   - **Ingest (`ingest`)**: Use `direct-basin-http` with `auth: basin-api-token` (Cloudflare Account API Token with `Pipelines Send` / `Basin Pipelines Send`, native Basin HTTP endpoint with `http.enabled = true` and `http.authentication = true`).
   - **Storage (`storage`)**: Use `cloudflare-basin-iceberg` (Apache Iceberg tables on Cloudflare R2 provisioned declaratively via [terraform/main.tf](../../adapters/storage/cloudflare-basin-iceberg/terraform/main.tf) or [pulumi/index.ts](../../adapters/storage/cloudflare-basin-iceberg/pulumi/index.ts), inspected via Cloudflare's unified `cf` CLI).
   - **APM (`apm`)**: Set `apm.enabled: true` and enable trace/metric exporters in `otelcol.yaml` when correlating application spans/metrics alongside OCSF logs via `metadata.correlation_uid` (`trace_id`).
   - **Query (`query`)**: Combine `basin-sql` (serverless Cloudflare SQL) with external Iceberg engines like `duckdb`, `pyiceberg`, or Spark.

3. **Validate contracts and wiring**
   - Ensure collectors emit OCSF v1.3.0 records conforming to [event-log-activity.basin.json](../../contracts/ocsf/event-log-activity.basin.json).
   - Run the verification suite (`nix flake check` or `node --test tests/ocsf-contracts.test.mjs`) to verify manifest, Cloud IaC validation/lifecycle, Basin SQL column parity, NixOS module evaluation, and collector wire output.
   - Proceed to [setup-cloudflare-basin-iceberg](../setup-cloudflare-basin-iceberg/SKILL.md) to provision and deploy.
