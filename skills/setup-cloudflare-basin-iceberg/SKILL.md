---
name: setup-cloudflare-basin-iceberg
description: >-
  Use this skill when provisioning Cloudflare R2, Basin Catalog, authenticated
  OCSF Basin Stream (direct-basin-http), Iceberg Sink, Basin Pipeline, and
  configuring Vector, Fluent Bit, or OpenTelemetry Collector to store telemetry
  into Apache Iceberg.
---

# Setup Cloudflare Basin Iceberg Pipeline

Follow these steps to provision Cloudflare Basin resources declaratively via **Terraform / OpenTofu** or **Pulumi (TypeScript)**, verify with Cloudflare's unified **`cf`** CLI, and configure direct OCSF v1.3.0 ingestion (`journald` / `OTLP` -> `Vector` or `Fluent Bit` -> `Direct Basin HTTP` -> `Iceberg`).

## Prerequisites

- **Provisioning tool**: OpenTofu (`tofu`, or offline pre-bundled `nix run .#oof-tofu`) **or** Terraform `>= 1.6.0` **or** Pulumi (`pulumi` + Node.js `>= 22`).
- **Cloudflare API credentials**:
  - `cloudflare_account_id` (32-hex Cloudflare Account ID).
  - Admin provisioning API token (`CLOUDFLARE_API_TOKEN` / `TF_VAR_cloudflare_api_token`) with `Workers R2 Storage Write`, `Workers R2 Data Catalog Write`, `Pipelines Read`, `Pipelines Write` (plus `Account API Tokens Read/Write` if minting the ingest token via IaC).
  - R2 Data Catalog API token (`TF_VAR_catalog_token` / Pulumi secret `catalogToken`) for Iceberg sink authentication.
- **Inspection CLI (optional)**: Cloudflare unified `cf` CLI (`cf auth login` or `CLOUDFLARE_API_TOKEN`).

## Steps

1. **Choose your Cloud IaC tool and validate locally**
   - **Option A — Terraform / OpenTofu** (`adapters/storage/cloudflare-basin-iceberg/terraform/`):
     Consumes [event-log-activity.basin.json](../../contracts/ocsf/event-log-activity.basin.json) and [pipeline.sql](../../adapters/storage/cloudflare-basin-iceberg/pipeline.sql) directly, using `magodo/restful` for the Basin stream so recursive OCSF `type = "struct"` columns are preserved verbatim.
     ```bash
     cd adapters/storage/cloudflare-basin-iceberg/terraform
     cp terraform.tfvars.example terraform.tfvars
     export TF_VAR_cloudflare_api_token="<ADMIN_API_TOKEN>"
     export TF_VAR_catalog_token="<CATALOG_API_TOKEN>"

     # Either offline-ready Nix OpenTofu (plugins pre-bundled):
     nix run ../../../..#oof-tofu -- -chdir=. init -backend=false
     nix run ../../../..#oof-tofu -- -chdir=. plan

     # Or standard OpenTofu / Terraform:
     tofu init
     tofu plan
     ```
   - **Option B — Pulumi TypeScript** (`adapters/storage/cloudflare-basin-iceberg/pulumi/`):
     Uses `@pulumi/cloudflare` (`R2Bucket`, `R2DataCatalog`, `PipelineSink`, `Pipeline`) plus `BasinStructuredStream` (`pulumi/stream.ts` + `pulumi/basin-core.ts`) to preserve `type: "struct"` OCSF columns.
     ```bash
     cd adapters/storage/cloudflare-basin-iceberg/pulumi
     npm install
     export CLOUDFLARE_API_TOKEN="<ADMIN_API_TOKEN>"

     pulumi stack init prod
     pulumi config set accountId "<32_HEX_ACCOUNT_ID>"
     pulumi config set --secret catalogToken "<CATALOG_API_TOKEN>"
     pulumi preview
     ```
     (`CLOUDFLARE_API_TOKEN` must remain in the environment rather than Pulumi config so `refresh` and `destroy` authenticate without persisting tokens in dynamic state.)

2. **Apply Cloud Infrastructure and Verify with `cf` CLI**
   - Terraform / OpenTofu:
     ```bash
     tofu apply
     tofu output stream_endpoint
     tofu output stream_host
     ```
   - Pulumi:
     ```bash
     pulumi up
     pulumi stack output streamEndpoint
     pulumi stack output streamHost
     ```
   - Inspect live state and SQL using Cloudflare's `cf` CLI (never use legacy CLI tools):
     ```bash
     cf auth whoami
     cf r2 buckets list --output json
     cf basin-catalog get oof-telemetry --output json
     cf pipelines streams list --output json
     cf pipelines streams get "<STREAM_ID>" --output json
     cf pipelines sinks get "<SINK_ID>" --output json
     cf pipelines get "<PIPELINE_ID>" --output json
     ```

3. **Provision Sender API Token (`Pipelines Send`)**
   - **Declarative option**: Set `create_ingest_token = true` (Terraform) or `pulumi config set createIngestToken true` (Pulumi) to mint an Account API Token scoped to `Pipelines Send` / `Basin Pipelines Send` (`ingest_token` / `ingestToken` output).
   - **Out-of-band option** (avoids storing the ingest secret in IaC state): Create an **Account API Token** in the Cloudflare dashboard granted **`Account -> Basin Pipelines -> Send`** (`Pipelines Send`).
   - Store the token in your host secret manager (`OOF_INGEST_TOKEN`) — never commit or log it.

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
   - **Option D — Declarative NixOS Flake Module (`flake.nix`)**:
     Import `oof.nixosModules.default` and configure `services.oof-collector` with your host secret manager's out-of-store `environmentFile` (never a `/nix/store/...` path):
     ```nix
     {
       imports = [ oof.nixosModules.default ];

       services.oof-collector = {
         enable = true;
         collector = "vector"; # or "fluent-bit"
         environmentFile = config.sops.secrets."oof-collector.env".path; # contains OOF_BASIN_ENDPOINT / OOF_BASIN_HOST + OOF_INGEST_TOKEN
         otelBridge.enable = true; # automatically shifts collector OTLP ports to 4319/4320
       };
     }
     ```

5. **Verify Iceberg Ingestion**
   - Wait past `roll_interval_seconds` (minimum `60` seconds, default `300` seconds) after sending a test event batch to `https://<STREAM_ID>.ingest.cloudflare.com` with `Authorization: Bearer $OOF_INGEST_TOKEN`.
   - Query the Iceberg table using Basin SQL or DuckDB with [siem_hunting.sql](../../adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql).
   - Consult [basin-troubleshooting.md](./references/basin-troubleshooting.md) if rows do not appear in Iceberg.
