# Cloudflare Basin + Iceberg IaC (Pulumi TypeScript)

Provisions the complete `direct-basin-http` + Apache Iceberg storage layer declaratively using:
- `@pulumi/cloudflare` (`^6.24.0`) for `R2Bucket`, `R2DataCatalog`, `PipelineSink`, `Pipeline`, and optional `AccountToken`
- `BasinStructuredStream` (`pulumi/stream.ts` + `pulumi/basin-core.ts`) as a dynamic resource calling Cloudflare REST v4 directly so recursive `type: "struct"` OCSF v1.3.0 fields in [contracts/ocsf/event-log-activity.basin.json](../../../../contracts/ocsf/event-log-activity.basin.json) are preserved verbatim
- [adapters/storage/cloudflare-basin-iceberg/pipeline.sql](../pipeline.sql) as the single SQL template source of truth

## Setup & Configuration

Install dependencies (or enter the repo Nix dev shell):

```bash
npm install
export CLOUDFLARE_API_TOKEN="<CLOUDFLARE_API_TOKEN>"
```

> Keeping `CLOUDFLARE_API_TOKEN` in the environment (rather than only `apiToken` config) allows `pulumi refresh` and `pulumi destroy` to authenticate without ever writing `apiToken` into dynamic resource state.

Select or initialize a stack and configure required values:

```bash
pulumi stack init prod
pulumi config set accountId "<32_HEX_ACCOUNT_ID>"
pulumi config set --secret catalogToken "<R2_DATA_CATALOG_TOKEN>"

# Optional overrides:
pulumi config set bucketName "oof-security-lake"
pulumi config set namespace "ocsf"
pulumi config set tableName "event_log_activity"
pulumi config set createIngestToken "true"
```

Preview and deploy:

```bash
pulumi preview
pulumi up
```

## Collector Output Mapping & `cf` CLI Verification

```bash
pulumi stack output streamEndpoint
pulumi stack output streamHost
pulumi stack output --show-secrets ingestToken   # if createIngestToken = true
```

Verify deployed resources with Cloudflare's unified `cf` CLI:

```bash
cf pipelines streams get "$(pulumi stack output streamId)" --output json
cf pipelines get "$(pulumi stack output pipelineId)" --output json
```
