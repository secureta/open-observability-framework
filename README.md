# Open Observability Framework (OOF)

**Open Observability Framework (OOF)** is a modular, AI-skill-driven framework for building **SIEM + APM** platforms using standard open telemetry schemas and direct-to-lakehouse shipping with minimal custom glue code.

Logs from **`systemd-journald`** and **OpenTelemetry (`OTLP`)** are normalized on the host by **Vector** or **Fluent Bit** into **OCSF v1.3.0 (`Event Log Activity`, `class_uid: 1008`)** and shipped directly over HTTPS (`direct-basin-http`) into **Cloudflare Basin -> Apache Iceberg on R2**.

---

## Architecture (`journald` / `OTLP` -> OCSF v1.3.0 -> Direct Basin HTTP -> Iceberg)

```mermaid
flowchart LR
  Host["Linux Host (systemd-journald)"] -->|"Vector or Fluent Bit"| Collect["Host Collector (Vector / Fluent Bit)"]
  Apps["Apps / Services (OTLP)"] -->|"gRPC/HTTP protobuf (4317/4318)"| Collect
  Apps -->|"Optional local/edge OTel bridge"| OTel["OTel Collector Bridge (otelcol.yaml)"]
  OTel -->|"otlphttp encoding: proto (4320)"| Collect
  Collect -->|"OCSF v1.3.0 (1008) HTTPS + Account API Token"| Basin["Cloudflare Basin Stream (direct-basin-http)"]
  Basin -->|"Basin Pipeline SQL"| Iceberg["Basin Catalog / Apache Iceberg on R2"]
  Iceberg -->|"Query"| Query["Basin SQL / DuckDB / PyIceberg"]
```

### Pluggable Framework Slots

| Slot | Default Choice | Alternatives / Extensions |
| :--- | :--- | :--- |
| `schema` | [OCSF v1.3.0 Event Log Activity (`1008`)](./contracts/ocsf/event-log-activity.basin.json) | Extensible via `schema.profile` (`ecs`, `cim`) — zero proprietary fields |
| `collect` | [Vector (`journald` + `otlp`)](./adapters/collect/vector-journald/vector.yaml) | [Fluent Bit (`systemd` + `opentelemetry`)](./adapters/collect/fluent-bit-journald/fluent-bit.conf), [OTel Collector Bridge](./adapters/collect/otel-collector-journald/otelcol.yaml) |
| `detect` | Disabled by default (`detect.enabled: false`) | Host-agent (`yara-x` / `kunai`) or lakehouse-batch SQL rules |
| `ingest` | `direct-basin-http` (`--http-enabled true --http-auth true`) | Authenticated via Cloudflare Account API Token (`Basin Pipelines Send`) |
| `storage` | [Cloudflare Basin Iceberg](./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh) | [Pipeline SQL](./adapters/storage/cloudflare-basin-iceberg/pipeline.sql) |
| `apm` | `metadata.correlation_uid` (`trace_id`) + `unmapped.span_id` | Full OTLP Traces + Metrics exporters via `otelcol.yaml` |
| `query` | Basin SQL & DuckDB | [Hunting SQL](./adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql), PyIceberg, Spark |

---

## Repository Map

- [manifest/stack.schema.json](./manifest/stack.schema.json) & [manifest/examples/cloudflare-basin-ocsf.yaml](./manifest/examples/cloudflare-basin-ocsf.yaml) — Declarative stack manifest schema & OCSF example
- [contracts/ocsf/event-log-activity.basin.json](./contracts/ocsf/event-log-activity.basin.json) & [contracts/ocsf/README.md](./contracts/ocsf/README.md) — Official OCSF v1.3.0 Event Log Activity (`1008`) Basin schema & field mapping specification
- [adapters/collect/vector-journald/vector.yaml](./adapters/collect/vector-journald/vector.yaml) — Vector `journald` + `otlp` collector with VRL OCSF v1.3.0 normalization & built-in unit tests
- [adapters/collect/fluent-bit-journald/fluent-bit.conf](./adapters/collect/fluent-bit-journald/fluent-bit.conf) & [adapters/collect/fluent-bit-journald/ocsf.lua](./adapters/collect/fluent-bit-journald/ocsf.lua) — Fluent Bit `systemd` + `opentelemetry` collector with Lua OCSF v1.3.0 normalization
- [adapters/collect/otel-collector-journald/otelcol.yaml](./adapters/collect/otel-collector-journald/otelcol.yaml) — OpenTelemetry Collector (`otlp` -> `otlphttp` protobuf bridge)
- [adapters/storage/cloudflare-basin-iceberg/](./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh) — Wrangler provisioning script, OCSF Iceberg pipeline SQL, and SIEM/APM hunting queries
- [tests/ocsf-contracts.test.mjs](./tests/ocsf-contracts.test.mjs) — Zero-dependency contract, CLI, and live E2E wire/schema test suite
- [skills/](./skills/compose-observability-stack/SKILL.md) — Agent skills (`compose-observability-stack`, `setup-cloudflare-basin-iceberg`)

---

## Quick Verification (Local)

```bash
# 1. Lint provisioning script
shellcheck adapters/storage/cloudflare-basin-iceberg/provision-basin.sh

# 2. Validate Basin provisioning plan without touching Cloudflare
./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh --dry-run

# 3. Validate Vector config + VRL OCSF unit tests
VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
  vector validate --no-environment adapters/collect/vector-journald/vector.yaml
VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
  vector test adapters/collect/vector-journald/vector.yaml

# 4. Run full contract + Vector & Fluent Bit E2E wire conformance suite
nix shell nixpkgs#vector nixpkgs#fluent-bit -c node --test tests/ocsf-contracts.test.mjs
```

## Deploying to Cloudflare Basin

See [skills/setup-cloudflare-basin-iceberg/SKILL.md](./skills/setup-cloudflare-basin-iceberg/SKILL.md) for the complete provisioning and sender token setup runbook.
