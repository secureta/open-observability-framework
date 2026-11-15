# Cloudflare Basin Iceberg Troubleshooting

## Rows accepted by Worker (`202`), missing in Iceberg table
- **Roll interval**: Basin sinks buffer until `--roll-interval` (default `60` seconds) or size threshold before committing an Iceberg snapshot. Wait at least one roll interval before querying.
- **Schema mismatch**: Basin Pipelines drops rows at sink delivery if a required field is `null` or typed incompatibly (e.g. float instead of `int64`). Verify payloads against [journal-logs.basin.json](../../../contracts/schemas/journal-logs.basin.json).
- **Stream binding**: Confirm `wrangler.jsonc` `pipelines[0].stream` matches the exact stream name created via `wrangler basin pipelines streams create`.

## Wrangler command namespace compatibility
- Depending on Wrangler release, Basin resources may live under `wrangler basin pipelines ...` or `wrangler pipelines ...`, and catalog management under `wrangler r2 bucket catalog enable` or `wrangler basin catalog create`.
- Inspect available subcommands in your installed Wrangler version via `npx wrangler basin --help`.

## Worker returns `502` on `/v1/logs`
- `env.TELEMETRY_STREAM.send()` threw an error. Check `npx wrangler tail` and confirm the pipeline stream still exists (`npx wrangler basin pipelines streams list`).
