# Vector Cloudflare Audit Logs Collector (`vector-cloudflare-audit-logs`)

Polls the Cloudflare Account Audit Logs REST API (`/client/v4/accounts/<account_id>/audit_logs`), normalizes each audit record into official **OCSF v1.3.0 `Event Log Activity` (`class_uid: 1008`, `activity_id: 99`, `type_uid: 100899`)**, and ships gzipped JSON arrays directly to Cloudflare Basin HTTP (`direct-basin-http`).

Available on **all Cloudflare plans** (including Free).

## Environment Variables

- `OOF_BASIN_ENDPOINT` — Basin HTTP ingest URL (`https://<STREAM_ID>.ingest.cloudflare.com`)
- `OOF_INGEST_TOKEN` — Cloudflare Account API Token with `Pipelines Send` / `Basin Pipelines Send`
- `OOF_CLOUDFLARE_ACCOUNT_ID` — 32-hex Cloudflare Account ID
- `OOF_CLOUDFLARE_API_TOKEN` — Cloudflare Account API Token with `Account -> Audit Logs -> Read`
- `OOF_CLOUDFLARE_API_BASE_URL` *(optional)* — Defaults to `https://api.cloudflare.com/client/v4`
- `OOF_CLOUDFLARE_AUDIT_PER_PAGE` *(optional)* — Defaults to `100`
- `OOF_VECTOR_DATA_DIR` *(optional)* — Defaults to `/var/lib/vector`

## Validation & Local Unit Tests

```bash
VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_DATA_DIR="$(mktemp -d)" \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
OOF_CLOUDFLARE_ACCOUNT_ID="0123456789abcdef0123456789abcdef" \
OOF_CLOUDFLARE_API_TOKEN="dummy" \
  vector validate --no-environment adapters/collect/vector-cloudflare-audit-logs/vector.yaml

VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_DATA_DIR="$(mktemp -d)" \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
OOF_CLOUDFLARE_ACCOUNT_ID="0123456789abcdef0123456789abcdef" \
OOF_CLOUDFLARE_API_TOKEN="dummy" \
  vector test adapters/collect/vector-cloudflare-audit-logs/vector.yaml
```

## Deduplication Note

Because polling fetches recent audit log windows on each interval, overlapping events share the same Cloudflare audit log UUID in `metadata.original_event_uid` (and `unmapped.audit_log_id`). Queries in `adapters/storage/cloudflare-basin-iceberg/queries/cloudflare_monitoring.sql` and `cloudflare_monitoring.basin.sql` deduplicate by `metadata.original_event_uid` using `ROW_NUMBER()`.
