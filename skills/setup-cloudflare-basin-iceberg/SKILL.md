---
name: setup-cloudflare-basin-iceberg
description: >-
  Use this skill when provisioning Cloudflare R2, Basin Catalog, authenticated
  OCSF Basin Stream (direct-basin-http), Iceberg Sink, Basin Pipeline, and
  configuring Vector, Fluent Bit, or OpenTelemetry Collector to store telemetry
  into Apache Iceberg.
---

# Setup Cloudflare Basin Iceberg Pipeline

Follow these steps to provision Cloudflare Basin resources and configure direct OCSF v1.3.0 ingestion (`journald` / `OTLP` -> `Vector` or `Fluent Bit` -> `Direct Basin HTTP` -> `Iceberg`).

## Prerequisites

- Node.js + `wrangler` (or `npx wrangler`) authenticated (`npx wrangler login` or `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`).
- A Basin Catalog API token stored in `BASIN_CATALOG_TOKEN` (R2 Data Catalog write token).

## Steps

1. **Validate locally before provisioning**
   ```bash
   ./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh --dry-run \
     --bucket oof-telemetry --namespace siem --table ocsf_event_log_activity
   ```
   Verify the generated Wrangler commands (`--http-enabled true --http-auth true`, `--type r2-data-catalog`) and rendered [pipeline.sql](../../adapters/storage/cloudflare-basin-iceberg/pipeline.sql).

2. **Provision R2, Basin Catalog, Stream, Iceberg Sink, and Pipeline**
   ```bash
   export BASIN_CATALOG_TOKEN="<your-catalog-token>"
   ./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh \
     --bucket oof-telemetry \
     --namespace siem \
     --table ocsf_event_log_activity \
     --stream ocsf_event_log_stream \
     --sink ocsf_event_log_sink \
     --pipeline ocsf_event_log_to_iceberg
   ```
   Copy the emitted `https://<STREAM_ID>.ingest.cloudflare.com` endpoint URL (also retrievable via `npx wrangler basin pipelines streams get ocsf_event_log_stream`).

3. **Create Sender API Token (`Basin Pipelines Send`)**
   - In the Cloudflare dashboard, create an **Account API Token** with permission **`Account -> Basin Pipelines -> Send`**.
   - Prefer short-lived or per-environment tokens (up to 500 account tokens supported); rotate tokens with zero downtime by overlapping old/new tokens before revoking old ones.
   - Store the token in host secret management (`OOF_INGEST_TOKEN`) and never log or commit it.

4. **Configure and Start Your Host Collector**
   - **Option A — Vector (`adapters/collect/vector-journald/vector.yaml`)**:
     Set `OOF_BASIN_ENDPOINT="https://<STREAM_ID>.ingest.cloudflare.com"` and `OOF_INGEST_TOKEN="<api-token>"`. Vector `>= 0.60` requires `--dangerously-allow-env-var-interpolation` (or `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true`):
     ```bash
     VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
       vector validate --no-environment adapters/collect/vector-journald/vector.yaml
     VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
       vector --config adapters/collect/vector-journald/vector.yaml
     ```
   - **Option B — Fluent Bit (`adapters/collect/fluent-bit-journald/fluent-bit.conf`)**:
     Set `OOF_BASIN_HOST="<STREAM_ID>.ingest.cloudflare.com"` (hostname only, no `https://`) and `OOF_INGEST_TOKEN="<api-token>"`:
     ```bash
     fluent-bit --dry-run -c adapters/collect/fluent-bit-journald/fluent-bit.conf
     fluent-bit -c adapters/collect/fluent-bit-journald/fluent-bit.conf
     ```
   - **Option C — Co-located OTel Collector Bridge (`adapters/collect/otel-collector-journald/otelcol.yaml`)**:
     Keep `journald` commented out in `otelcol.yaml` when Vector or Fluent Bit already reads journald. Move Vector's OTLP listeners to `OOF_OTLP_GRPC_LISTEN=127.0.0.1:4319` and `OOF_OTLP_HTTP_LISTEN=127.0.0.1:4320` (avoiding collision with `otelcol`'s `4317`/`4318`), or set Fluent Bit's `opentelemetry` `Port 4320`, so both match `OOF_OTLP_BRIDGE_ENDPOINT=http://127.0.0.1:4320`.

5. **Verify Iceberg Ingestion**
   - Send a compliant test OCSF array to `https://<STREAM_ID>.ingest.cloudflare.com` with `Authorization: Bearer $OOF_INGEST_TOKEN` and wait past `--roll-interval` (default `60` seconds).
   - Query `siem.ocsf_event_log_activity` using Basin SQL or DuckDB with [siem_hunting.sql](../../adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql).
   - Consult [basin-troubleshooting.md](./references/basin-troubleshooting.md) if rows do not appear in Iceberg.
