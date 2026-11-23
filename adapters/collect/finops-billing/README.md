# FinOps Billing & Usage Collector (`finops-billing`)

Zero-dependency Node.js 20+ collector that pulls daily usage and billing records from **Cloudflare** (R2 storage, Class A/B operations, optional Pipelines) and **GitHub** (Enhanced Billing Platform API: Actions, Packages, Shared Storage), normalizes them into **FOCUS v1.0** ([cost-and-usage.basin.json](../../../contracts/focus/cost-and-usage.basin.json)), and ships gzipped JSON arrays directly to Cloudflare Basin HTTP (`direct-basin-http`).

## Required Environment Variables

### Basin Sink Target (required unless `--dry-run`)
- `OOF_FOCUS_BASIN_ENDPOINT`: Authenticated Basin HTTPS stream URL for `finops.focus_cost_and_usage` (from Terraform `focus_stream_endpoint` or Pulumi `focusStreamEndpoint`)
- `OOF_INGEST_TOKEN`: Cloudflare Account API Token with `Pipelines Send` / `Basin Pipelines Send`

### Cloudflare Source (enable Cloudflare R2 / Pipelines collection)
- `CLOUDFLARE_ACCOUNT_ID`: 32-character hexadecimal Cloudflare account ID
- `CLOUDFLARE_API_TOKEN`: Scoped read-only API token with `Account Analytics:Read`
- `CLOUDFLARE_ACCOUNT_NAME` *(optional)*: Human-readable billing account name
- `OOF_CF_INCLUDE_PIPELINES` *(optional)*: Set to `"true"` to also query `pipelinesOperatorAdaptiveGroups.sum.bytesIn` for Cloudflare Pipelines usage
- `OOF_CF_PRICING_JSON` *(optional)*: JSON object overriding default USD list prices (`r2StoragePerGbMonth`, `r2ClassAPerMillionOps`, `r2ClassBPerMillionOps`, `pipelinesPerGbIngested`, `daysPerBillingMonth`). Note: Cloudflare Analytics rows emit `ListCost` estimates with `BilledCost = 0` / `EffectiveCost = 0` (`Tags.cost_basis = "list_price_estimate"`) so they are not conflated with invoice charges.

### GitHub Source (enable GitHub Actions / Packages / Storage collection)
- `GITHUB_ORG` or `GITHUB_USER`: Target GitHub organization or user login
- `GITHUB_TOKEN`: Fine-grained PAT / GitHub App token with `Billing:Read` (or `Administration:Read`)

### Common Options
- `OOF_FINOPS_DATE` *(optional)*: Target UTC date (`YYYY-MM-DD`). Defaults to the previous complete UTC day.

## Usage

```bash
# Dry-run (prints normalized FOCUS v1.0 records to stdout without sending to Basin)
node adapters/collect/finops-billing/collect-focus.mjs --dry-run

# Ship daily FOCUS v1.0 records directly to Basin HTTP
node adapters/collect/finops-billing/collect-focus.mjs
```

## Scheduled Execution Example (GitHub Actions Cron)

```yaml
on:
  schedule:
    - cron: "15 1 * * *" # Daily at 01:15 UTC (collects previous UTC day)
  workflow_dispatch:

jobs:
  collect-finops:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - name: Collect Cloudflare & GitHub FOCUS v1.0 records
        env:
          OOF_FOCUS_BASIN_ENDPOINT: ${{ secrets.OOF_FOCUS_BASIN_ENDPOINT }}
          OOF_INGEST_TOKEN: ${{ secrets.OOF_INGEST_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_ANALYTICS_READ_TOKEN }}
          GITHUB_ORG: ${{ github.repository_owner }}
          GITHUB_TOKEN: ${{ secrets.OOF_GITHUB_BILLING_TOKEN }}
        run: node adapters/collect/finops-billing/collect-focus.mjs
```
