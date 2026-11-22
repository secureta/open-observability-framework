# GitHub Actions Direct Basin Collector (`github-actions-direct`)

Zero-dependency Node.js 20 GitHub Action that emits **OCSF v1.3.0 `Event Log Activity` (`1008`, `activity_id: 99`)** records directly to Cloudflare Basin HTTP (`direct-basin-http`) as gzipped JSON arrays — no always-on collector host or custom Worker required.

## Usage in a Workflow

Store `OOF_BASIN_ENDPOINT` and `OOF_INGEST_TOKEN` in your repository or organization secrets, and invoke this action at the end of a job with `if: always()`:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: npm test

      - name: Emit OCSF telemetry to Cloudflare Basin
        if: always()
        uses: <org>/open-observability-framework/adapters/collect/github-actions-direct@main
        with:
          basin_endpoint: ${{ secrets.OOF_BASIN_ENDPOINT }}
          ingest_token: ${{ secrets.OOF_INGEST_TOKEN }}
          conclusion: ${{ job.status }}
```

## Security & Secret Hygiene

- Never print `OOF_INGEST_TOKEN` in workflow logs; pass it via GitHub Secrets (`${{ secrets.OOF_INGEST_TOKEN }}`).
- For untrusted fork pull requests (`pull_request`), secrets are not exposed to fork jobs; use either a separate `workflow_run` observer workflow or the `vector-github-actions` webhook adapter (`adapters/collect/vector-github-actions/vector.yaml`) for complete repository/organization coverage.
