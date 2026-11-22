# Open Observability Framework threat model

This model describes the deployment defaults and configuration options in this repository. Production deployment details and risk acceptance remain open.

## System overview

OOF assembles a SIEM log pipeline from standard OSS collectors and Cloudflare storage. Host collectors normalize logs into OCSF v1.3.0 Event Log Activity (class 1008) and send them to Cloudflare Basin's authenticated HTTPS endpoint. Basin writes them to an Apache Iceberg table in R2 through the R2 Data Catalog. [AGENTS.md](AGENTS.md)

```text
journald / OTLP apps → optional OTel bridge for OTLP → Vector or Fluent Bit
  → authenticated Basin stream → Basin SQL → Iceberg sink → R2 → SIEM queries
```

## Components

| Name | Code | Notes |
|---|---|---|
| **Vector collector** | `adapters/collect/vector-journald/vector.yaml` | journald + OTLP (gRPC/HTTP) sources, VRL → OCSF, http sink to Basin with disk buffer. |
| **Fluent Bit collector** | `adapters/collect/fluent-bit-journald/` (`fluent-bit.conf`, `ocsf.lua`) | systemd + OTLP inputs, Lua → OCSF, loopback `forward` hop on 127.0.0.1:24225 with `Shared_Key = OOF_INGEST_TOKEN`, TLS http output. |
| **OTel bridge** | `adapters/collect/otel-collector-journald/otelcol.yaml` | OTLP receivers 4317/4318, `otlphttp` (plain http by default) to the collector on 4320. |
| **NixOS module** | `flake.nix` (`nixosModules.default`, `services.oof-collector`, packaged wrappers, checks) | systemd units with `DynamicUser`, `systemd-journal` group, `EnvironmentFile` secrets outside `/nix/store`, listener/endpoint validation. |
| **Basin IaC** | [`terraform/`](adapters/storage/cloudflare-basin-iceberg/terraform/), [`pulumi/`](adapters/storage/cloudflare-basin-iceberg/pulumi/), [`pipeline.sql`](adapters/storage/cloudflare-basin-iceberg/pipeline.sql) | Provisions the authenticated Basin stream, Iceberg sink, R2 and its Data Catalog, SQL pipeline, and optional account-scoped ingest token. |
| **OCSF contract** | `contracts/ocsf/`, `tests/ocsf-contracts.test.mjs`, `manifest/` | Schema shared by IaC and collectors; tests enforce lockstep. |

## Trust boundaries and entry points

1. **Host processes → collector.** Local processes can write log messages to journald. Journald assigns trusted fields such as `_UID`, `_PID`, and `_COMM`. The unauthenticated OTLP listeners bind to loopback by default on ports 4317–4320. Operators can change those addresses. Fluent Bit also uses a separate loopback Forward hop authenticated with `OOF_INGEST_TOKEN` as its shared key.
2. **OTel bridge → collector.** The default bridge endpoint uses HTTP on loopback. An operator can point the bridge at a remote collector.
3. **Collector → Basin.** The internet-reachable HTTPS stream requires an account API token with `Pipelines Send`. Operators can configure allowed browser origins on the stream. Fluent Bit explicitly enables certificate and hostname verification.
4. **Provisioning runner → Cloudflare API.** Terraform and Pulumi use an account API token for resource management. The sink uses a separate `catalog_token` for R2 and Data Catalog writes. The IaC modules allow HTTPS API endpoint overrides and loopback HTTP overrides for local tests.
5. **Iceberg → query clients.** Cloudflare-side access and credentials govern reads from the lake. The repository provides sample hunting SQL. [SIEM hunting queries](adapters/storage/cloudflare-basin-iceberg/queries/siem_hunting.sql)
6. **Dependencies → deployment tooling.** Nix flake inputs, npm packages, and Terraform providers run within the permissions of the provisioning or collector environment that loads them.

## Assets

- **Cloudflare credentials.** Protect the account API token, catalog token, and collector ingest token. Terraform state contains the catalog token and, when the module creates one, the ingest token. Terraform state encryption depends on the backend. Pulumi marks corresponding secret values and reads the provisioning API token from the environment. [Terraform setup](adapters/storage/cloudflare-basin-iceberg/terraform/README.md) · [Pulumi setup](adapters/storage/cloudflare-basin-iceberg/pulumi/README.md)
- **SIEM record integrity.** Downstream queries can rely on OCSF identity, timestamp, and severity fields. OTLP actor and device identities are sender-supplied claims.
- **Log confidentiality.** Messages, command lines, OTLP attributes, and resource fields can contain personal data or application secrets. They can persist in collector buffers and the Iceberg lake.
- **Collection availability.** Flooding or interrupted delivery can delay or drop events and leave detection gaps.

## Attacker profiles

- A local unprivileged user or compromised application can submit or flood logs through journald or local OTLP.
- A network attacker may reach an OTLP receiver exposed beyond loopback or observe or modify an unencrypted bridge connection to a remote collector.
- A holder of a leaked ingest token can send records through the public Basin endpoint within that token's scope.
- A compromised dependency can run with the permissions of the tooling that loads it.

## Existing controls

- Loopback-only default listeners; Nix assertions reject hostnames, invalid IPs, self-loops, wildcard bridge targets, and `environmentFile` inside `/nix/store`.
- systemd hardening: `DynamicUser`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`.
- TLS for production Basin ingestion and a scoped ingest credential. The OTel bridge applies a memory limiter, and Vector uses a bounded disk buffer and finite retries.
- Terraform sensitive values, Pulumi secret values, API token scrubbing in `basin-core.ts`, and `.gitignore` entries for local secret and state files.
- Contract tests keep collectors and schema in lockstep.

## Out of scope / accepted risk

The deployment owner has yet to confirm any exclusions or accepted risks.

## Open questions

- Who deploys the framework, and which monitored hosts run workloads from different trust domains?
- Which deployments expose OTLP beyond loopback or send bridge traffic across hosts? Who can query stored data?
- Which assets are critical, and which operational choices, such as remote listeners or retaining ingest tokens in IaC state, are accepted risks?
