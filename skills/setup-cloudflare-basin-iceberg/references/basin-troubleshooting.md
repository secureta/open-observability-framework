# Cloudflare Basin Iceberg Troubleshooting

## HTTP `401` / `403` when posting to Direct Basin HTTP (`*.ingest.cloudflare.com`)
- **Account API Token required**: Basin native HTTP authentication (`http.authentication = true`) validates **Cloudflare Account API Tokens** granted `Account -> Basin Pipelines -> Send` (`Pipelines Send` / `Basin Pipelines Send`), not user-scoped or arbitrary shared secrets.
- **Fluent Bit `Host` vs Vector `uri`**: Vector uses full URL `OOF_BASIN_ENDPOINT="https://<STREAM_ID>.ingest.cloudflare.com"`, whereas Fluent Bit requires hostname only in `OOF_BASIN_HOST="<STREAM_ID>.ingest.cloudflare.com"` with `Port 443` and `URI /`.

## Rows accepted (`200` / `202`), missing in Iceberg table
- **Roll interval**: Basin sinks buffer until `roll_interval_seconds` (minimum `60` seconds for `r2_data_catalog`, default `300`) or size threshold before committing an Iceberg snapshot. Wait at least one roll interval before querying.
- **Schema mismatch**: Basin drops records that violate [event-log-activity.basin.json](../../../contracts/ocsf/event-log-activity.basin.json) (e.g. non-array payload, `"date"` key injected when `json_date_key false` is missing in Fluent Bit, `"__internal__"` key injected if OTLP `oof.otlp_raw` bypasses `forward` `retain_metadata_in_forward_mode false`, `"boolean"` instead of `"bool"`, empty `{}` serialized as `[]` for `unmapped`, or non-integer values for `int64` fields like `time` or `actor.process.pid`).
- **Timestamp format**: Ensure `time` is epoch milliseconds (`int64`) and `time_dt` is an RFC 3339 UTC string `"YYYY-MM-DDTHH:MM:SS.sssZ"`.

## Vector `validate` or `otlp` HTTP ingest errors (`Vector >= 0.60`)
- **Env var interpolation**: Run Vector with `--dangerously-allow-env-var-interpolation` or `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true`. Avoid writing braced `${...}` literals inside `#` comments because Vector scans raw text before YAML comment stripping.
- **OTLP HTTP Content-Type**: Vector's `opentelemetry` HTTP source (`:4318`) expects `application/x-protobuf` (`encoding: proto` in `otelcol.yaml`), not `application/json`.

## Fluent Bit configuration or Lua filter issues (`Fluent Bit v5.x`)
- **No `${VAR:-default}` syntax**: Fluent Bit does not support `:-` fallback syntax inside `.conf` files and expands unset expressions to `""`.
- **TLS hostname verification**: Always set both `tls.verify On` and `tls.verify_hostname On` in `[OUTPUT] http` (`tls.verify_hostname` defaults to `Off`).
- **5-argument Lua callback arity**: With `Time_As_Table On`, Fluent Bit checks the Lua function's fixed parameter count (`nparams == 5`). Declare `function to_ocsf(tag, ts, group, metadata, record)` explicitly (not varargs `...`) so Fluent Bit supplies `group` and `metadata` and accepts 4 return values (`code, ts, {}, out`) that clear per-record `log_metadata`.
- **Suppressing `"__internal__"` on OTLP logs**: Fluent Bit v5 `out_http` (`Format json`) injects `"__internal__": {"group_attributes": ...}` if OTLP chunks retain `group_attributes`. Route `oof.otlp_raw` through the authenticated loopback `forward` output/input (`127.0.0.1:24225`, `Shared_Key ${OOF_INGEST_TOKEN}`, `retain_metadata_in_forward_mode false`) to `oof.otlp`, and use `Match_Regex ^oof\.(journald|otlp_raw)$` on `filter_lua` to avoid double-filtering.

## IaC (`terraform` / `pulumi`) & `cf` CLI compatibility
- **Preserving OCSF `struct` columns**: Upstream `cloudflare_pipeline_stream` (`cloudflare/cloudflare` `v5.x` and `@pulumi/cloudflare` `v6.x`) rejects `type = "struct"` on `schema.fields`. Keep stream provisioning on `restful_resource.ocsf_stream` (`magodo/restful`) in Terraform/OpenTofu and `BasinStructuredStream` (`pulumi/stream.ts`) in Pulumi rather than degrading `struct` columns to `json`.
- **Sink type**: Basin Iceberg sinks in `cloudflare_pipeline_sink` / `cloudflare.PipelineSink` require `type = "r2_data_catalog"` with `format = { type = "parquet" }`.
- **Inspecting live resources & SQL with `cf` CLI**:
  - `cf auth whoami`
  - `cf basin-catalog get <bucket> --output json`
  - `cf pipelines streams list --output json` / `cf pipelines streams get <stream-id> --output json`
  - `cf pipelines sinks get <sink-id> --output json`
  - `cf pipelines get <pipeline-id> --output json`
  - `cf pipelines validate-sql --sql "$(cat adapters/storage/cloudflare-basin-iceberg/pipeline.sql)"`
