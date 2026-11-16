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

> `CLOUDFLARE_API_TOKEN` must be exported in the environment (do not set `apiToken` in Pulumi stack config) so `pulumi preview`, `pulumi up`, `pulumi refresh`, and `pulumi destroy` all authenticate consistently without persisting API tokens in dynamic resource state.

Select or initialize a stack and configure required values:

```bash
pulumi stack init prod
pulumi config set accountId "<32_HEX_ACCOUNT_ID>"
pulumi config set --secret catalogToken "<R2_DATA_CATALOG_TOKEN>"

# Optional overrides (defaults shown match manifest/examples/cloudflare-basin-ocsf.yaml and queries/siem_hunting.sql):
pulumi config set bucketName "oof-telemetry"
pulumi config set namespace "siem"
pulumi config set tableName "ocsf_event_log_activity"
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
