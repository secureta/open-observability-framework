# Vector Cloudflare Logpush Collector (`vector-cloudflare-logpush`)

Receives Cloudflare Logpush HTTP Push deliveries (gzip-compressed NDJSON), enforces HTTP Basic authentication directly at the Vector `http_server` boundary (returning **HTTP 401 Unauthorized** on missing or invalid credentials so Cloudflare retries delivery), drops destination ownership verification probes (`{"content":"tests"}`), normalizes `http_requests`, `firewall_events`, `dns_logs`, `access_requests`, and `gateway_dns` into official **OCSF v1.3.0 `Event Log Activity` (`class_uid: 1008`, `activity_id: 99`, `type_uid: 100899`)**, and ships gzipped JSON arrays directly to Cloudflare Basin HTTP (`direct-basin-http`).

## Environment Variables

- `OOF_BASIN_ENDPOINT` — Basin HTTP ingest URL (`https://<STREAM_ID>.ingest.cloudflare.com`)
- `OOF_INGEST_TOKEN` — Cloudflare Account API Token with `Pipelines Send` / `Basin Pipelines Send`
- `OOF_CLOUDFLARE_LOGPUSH_TOKEN` — Shared HTTP Basic password verified at the `http_server` source boundary
- `OOF_CLOUDFLARE_LOGPUSH_USER` *(optional)* — HTTP Basic username (default: `logpush`)
- `OOF_CF_LOGPUSH_LISTEN` *(optional)* — Defaults to `127.0.0.1:8089` (terminate TLS in front via reverse proxy or Cloudflare Tunnel)
- `OOF_VECTOR_DATA_DIR` *(optional)* — Defaults to `/var/lib/vector`

## Cloudflare Logpush Destination URL Example

Encode `logpush:<OOF_CLOUDFLARE_LOGPUSH_TOKEN>` as Base64 and pass it in the `header_Authorization` query parameter:

```text
https://logpush.example.com/logpush/cloudflare?header_Authorization=Basic%20<BASE64_USER_PASS>&header_X-Cloudflare-Dataset=http_requests
```

You can also provision Cloudflare Logpush Jobs declaratively using `logpush_jobs` in [adapters/storage/cloudflare-basin-iceberg/terraform/main.tf](../../storage/cloudflare-basin-iceberg/terraform/main.tf) or `logpushJobs` in [adapters/storage/cloudflare-basin-iceberg/pulumi/index.ts](../../storage/cloudflare-basin-iceberg/pulumi/index.ts).

## Validation & Local Unit Tests

```bash
VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_DATA_DIR="$(mktemp -d)" \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
OOF_CLOUDFLARE_LOGPUSH_TOKEN="test-token" \
  vector validate --no-environment adapters/collect/vector-cloudflare-logpush/vector.yaml

VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_DATA_DIR="$(mktemp -d)" \
OOF_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_INGEST_TOKEN="dummy" \
OOF_CLOUDFLARE_LOGPUSH_TOKEN="test-token" \
  vector test adapters/collect/vector-cloudflare-logpush/vector.yaml
```
