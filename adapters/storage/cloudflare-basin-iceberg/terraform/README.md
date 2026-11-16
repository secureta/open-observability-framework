# Cloudflare Basin + Iceberg IaC (Terraform / OpenTofu)

Provisions the complete `direct-basin-http` + Apache Iceberg storage layer declaratively using:
- `cloudflare/cloudflare` (`>= 5.19.0, < 6.0.0`) for `cloudflare_r2_bucket`, `cloudflare_r2_data_catalog`, `cloudflare_pipeline_sink`, `cloudflare_pipeline`, and optional `cloudflare_account_token`
- `magodo/restful` (`~> 0.25`) for `restful_resource.ocsf_stream` so the full recursive OCSF v1.3.0 `type = "struct"` schema in [contracts/ocsf/event-log-activity.basin.json](../../../../contracts/ocsf/event-log-activity.basin.json) is preserved verbatim without flattening `struct` fields to `json` strings
- [adapters/storage/cloudflare-basin-iceberg/pipeline.sql](../pipeline.sql) as the single SQL template source of truth

## Required Secrets

Export secrets via environment variables (never commit `*.tfvars` or `*.tfstate*`):

```bash
export TF_VAR_cloudflare_api_token="<CLOUDFLARE_API_TOKEN>"
export TF_VAR_catalog_token="<R2_DATA_CATALOG_TOKEN>"
```

Recommended token permissions for `cloudflare_api_token`:
- Account: `Workers R2 Storage Write`, `Workers R2 Data Catalog Write`, `Pipelines Read`, `Pipelines Write`
- Add `Account API Tokens Read` + `Account API Tokens Write` only if setting `create_ingest_token = true`

## Usage

### Option A: Offline Pre-Bundled Nix OpenTofu (`oof-tofu`)

No provider download or internet registry lookup needed for `init`:

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit cloudflare_account_id / bucket_name / namespace / table_name in terraform.tfvars

nix run ../../../..#oof-tofu -- -chdir=. init -backend=false
nix run ../../../..#oof-tofu -- -chdir=. plan
nix run ../../../..#oof-tofu -- -chdir=. apply
```

### Option B: Standard OpenTofu / Terraform CLI

```bash
cp terraform.tfvars.example terraform.tfvars
tofu init
tofu plan
tofu apply
```

> Use an encrypted remote backend (`backend "s3"`, Pulumi Cloud, Terraform Cloud, etc.) in production because `catalog_token` and optional `ingest_token` are stored in Terraform state.

## Collector Output Mapping & `cf` CLI Verification

Read outputs and configure your host collector (`OOF_BASIN_ENDPOINT` for Vector, `OOF_BASIN_HOST` for Fluent Bit):

```bash
tofu output stream_endpoint
tofu output stream_host
tofu output -raw ingest_token   # if create_ingest_token = true
```

Verify deployed resources with Cloudflare's unified `cf` CLI:

```bash
cf pipelines streams get "$(tofu output -raw stream_id)" --output json
cf pipelines get "$(tofu output -raw pipeline_id)" --output json
```
