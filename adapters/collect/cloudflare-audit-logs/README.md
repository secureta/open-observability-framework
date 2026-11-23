# Cloudflare Audit Logs Collector (`cloudflare-audit-logs`)

Zero-dependency Node.js (`>= 22`) checkpointed poller for the Cloudflare Account Audit Logs REST API (`/client/v4/accounts/<account_id>/audit_logs`).

On each poll cycle it:
1. Bounds the query to `[since, before]` using the persisted checkpoint (`since = lastBefore`, `before = now`).
2. Iterates through **all pages** (`page=1..total_pages`, `direction=asc`) so bursts exceeding `per_page` are never dropped.
3. Deduplicates boundary IDs against the persisted `recentIds` window and normalizes every record into official **OCSF v1.3.0 `Event Log Activity` (`class_uid: 1008`, `activity_id: 99`, `type_uid: 100899`)**.
4. Ships gzipped JSON arrays directly to Cloudflare Basin HTTP (`direct-basin-http`).
5. Advances the checkpoint file atomically (`tmp` + `rename`) **only after all pages are fetched and accepted by Basin**.

Available on **all Cloudflare plans** (including Free).

## Environment Variables

- `OOF_BASIN_ENDPOINT` — Basin HTTP ingest URL (`https://<STREAM_ID>.ingest.cloudflare.com`)
- `OOF_INGEST_TOKEN` — Cloudflare Account API Token with `Pipelines Send` / `Basin Pipelines Send`
- `OOF_CLOUDFLARE_ACCOUNT_ID` — 32-hex Cloudflare Account ID
- `OOF_CLOUDFLARE_API_TOKEN` — Cloudflare Account API Token with `Account -> Audit Logs -> Read`
- `OOF_CF_AUDIT_CHECKPOINT_FILE` *(optional)* — Defaults to `${STATE_DIRECTORY}/checkpoint.json`
- `OOF_CLOUDFLARE_API_BASE_URL` *(optional)* — Defaults to `https://api.cloudflare.com/client/v4`
- `OOF_CLOUDFLARE_AUDIT_PER_PAGE` *(optional)* — Defaults to `100`
- `OOF_CLOUDFLARE_AUDIT_POLL_INTERVAL_SECS` *(optional)* — Defaults to `60`
- `OOF_CLOUDFLARE_AUDIT_LOOKBACK_SECS` *(optional)* — Initial lookback when no checkpoint exists (default: `300`)
