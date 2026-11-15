# Cloudflare Basin Iceberg Troubleshooting

## Rows accepted by Worker (`202`), missing in Iceberg table
- **Roll interval**: Basin sinks buffer until `--roll-interval` (minimum and default `60` seconds for `r2-data-catalog`) or size threshold before committing an Iceberg snapshot. Wait at least one roll interval before querying.
- **Schema mismatch**: Basin Pipelines uses `"bool"` (not `"boolean"`) in stream schemas and drops rows at sink delivery if a required field is `null` or typed incompatibly (e.g. float instead of `int64`). Verify payloads against [journal-logs.basin.json](../../../contracts/schemas/journal-logs.basin.json).
- **Stream binding uses name instead of Stream ID**: Confirm `wrangler.jsonc` `pipelines[0].stream` is set to the **Stream ID** (returned by `wrangler basin pipelines streams create` or `wrangler basin pipelines streams list`), not the human-readable stream name (`journal_stream`).

## Wrangler command & flag compatibility
- **Sink type**: Wrangler v4 `wrangler basin pipelines sinks create` requires `--type r2-data-catalog` (or `--type r2`), not `--type basin-catalog`.
- **Catalog enablement**: Prefer `wrangler basin catalog enable <bucket>` (`r2 bucket catalog enable` is a legacy hidden alias).
- Depending on Wrangler release, Basin resources may live under `wrangler basin pipelines ...` or `wrangler pipelines ...`. Inspect available subcommands via `npx wrangler basin --help`.

## Worker returns `502` on `/v1/logs`
- `env.TELEMETRY_STREAM.send()` threw an error. Check `npx wrangler tail` and confirm the pipeline stream still exists (`npx wrangler basin pipelines streams list`).
