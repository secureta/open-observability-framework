# FOCUS v1.0 Cost & Usage Contract (`cost-and-usage.basin.json`)

This directory defines the vendor-neutral FinOps telemetry contract for the Open Observability Framework (OOF), strictly adhering to the **FinOps Open Cost and Usage Specification (FOCUS) v1.0**.

## Design Principles

- **Standard Schema Only**: Every top-level column in [cost-and-usage.basin.json](./cost-and-usage.basin.json) is an official FOCUS v1.0 column name (43 columns). Zero proprietary top-level fields are introduced.
- **Separate Table from OCSF Logs**: Cost and billing records are ingested into a dedicated Basin stream and Apache Iceberg table (`finops.focus_cost_and_usage` by default) so OCSF `Event Log Activity` (`1008`) remains strictly unchanged.
- **Direct Basin HTTP**: Records are shipped over HTTPS (`direct-basin-http`) using Cloudflare Account API Tokens (`Pipelines Send` / `Basin Pipelines Send`) with zero custom edge Workers.

## Provider Mapping Summary

| FOCUS v1.0 Column | Cloudflare (`R2`, `Pipelines`) | GitHub (`Actions`, `Packages`, `Storage`) |
| :--- | :--- | :--- |
| `ProviderName` / `PublisherName` / `InvoiceIssuerName` | `"Cloudflare"` | `"GitHub"` |
| `BillingAccountId` | Cloudflare 32-char Account ID | GitHub Organization or User login |
| `ServiceCategory` | `"Storage"` (`R2`), `"Analytics"` (`Pipelines`) | `"Developer Tools"` (`Actions`, `Packages`), `"Storage"` (`Shared Storage`) |
| `ServiceName` | `"Cloudflare R2"`, `"Cloudflare Pipelines"` | `"GitHub Actions"`, `"GitHub Packages"`, `"GitHub Shared Storage"` |
| `ResourceName` / `ResourceId` | R2 bucket name / Pipeline name | Repository name (`owner/repo` or repo slug) |
| `SkuId` | e.g. `r2_storage_standard`, `r2_class_a_ops`, `r2_class_b_ops`, `pipelines_ingest_gb` | GitHub Billing `sku` (e.g. `actions_linux`, `actions_macos`, `actions_windows`) |
| `ConsumedQuantity` / `ConsumedUnit` | GB-month, Operations, GB | Minutes, GB-Hours, GB |
| `BilledCost` / `EffectiveCost` / `ListCost` | Calculated USD cost (configurable unit pricing) | `netAmount` / `netAmount` / `grossAmount` from GitHub Billing API |
| `ChargePeriodStart` / `ChargePeriodEnd` | UTC period boundaries (RFC 3339 ms) | UTC day/usage window boundaries (RFC 3339 ms) |
| `Tags` | JSON object (`oof_collector`, `pricing_source`, `bucket`, etc.) | JSON object (`oof_collector`, `organization`, `repository`, `product`, etc.) |

## Lockstep Files

Keep the following files in strict column lockstep:
1. [contracts/focus/cost-and-usage.basin.json](./cost-and-usage.basin.json)
2. [adapters/storage/cloudflare-basin-iceberg/focus_pipeline.sql](../../adapters/storage/cloudflare-basin-iceberg/focus_pipeline.sql)
3. [adapters/collect/finops-billing/collect-focus.mjs](../../adapters/collect/finops-billing/collect-focus.mjs)
