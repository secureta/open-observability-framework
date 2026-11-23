# Prometheus Pull Metrics Adapter (`prometheus-pull`)

Collects Prometheus `/metrics` endpoints over HTTP pull, stores `(timestamp, value)` time-series samples in a dedicated local Prometheus TSDB (separate from the OCSF log ingestion pipeline), and exposes loopback-only query endpoints.

## Why a Separate Time-Series Path

OOF's log pipeline normalizes `systemd-journald` and OTLP logs into OCSF v1.3.0 `Event Log Activity` (`class_uid: 1008`) for Cloudflare Basin Iceberg. Time-series metrics are kept out of the OCSF log schema so that:

- No proprietary fields are added to the OCSF contract.
- Samples are stored natively as `(timestamp, value)` time series with PromQL range/instant query support.
- Scrape health (`up`) is recorded on every scrape interval independently of metric values.

## Verified `cloudflared` Metric

Verified against `cloudflared version 2026.10.7`:

```text
# HELP cloudflared_tunnel_ha_connections Number of active ha connections
# TYPE cloudflared_tunnel_ha_connections gauge
cloudflared_tunnel_ha_connections 4
```

- Initial allowlisted metric: `cloudflared_tunnel_ha_connections` only.
- Label hygiene: `relabel_configs` replaces `instance` (which would otherwise carry `IP:port` or hostname) with the logical `job_name`, and `metric_relabel_configs` applies `action: labelkeep` with `^(__name__|job)$` (plus any explicitly configured `allowedLabels`) so tunnel IDs, IPs, hostnames, edge locations, and connection IDs are never stored.
- Enablement note: if `cloudflared` starts with `--metrics 127.0.0.1:0` (ephemeral loopback port), pin `--metrics` to a fixed loopback port (e.g. `127.0.0.1:20241`) before enabling scraping.

## Distinguishing Zero vs. Scrape Failure vs. Missing Data

| State | `up{job="cloudflared"}` | `cloudflared_tunnel_ha_connections{job="cloudflared"}` | `absent(cloudflared_tunnel_ha_connections{job="cloudflared"})` |
| :--- | :--- | :--- | :--- |
| Healthy (active connections) | `1` | `> 0` (e.g. `4`) | empty |
| Healthy (zero connections) | `1` | `0` (sample present) | empty |
| Scrape failure (timeout, HTTP 5xx, malformed text, refused) | `0` | empty (stale / absent) | `1` |
| Metric missing (HTTP 200 without target metric) | `1` | empty | `1` |
| Collector stopped / no scrapes recorded | empty | empty | `1` |

## Querying Samples (Loopback Only)

Default query API listener: `http://127.0.0.1:9090`.

```bash
# Instant query (current value + sample timestamp)
curl -fsS --get 'http://127.0.0.1:9090/api/v1/query' \
  --data-urlencode 'query=cloudflared_tunnel_ha_connections{job="cloudflared"}'

# Instant scrape health
curl -fsS --get 'http://127.0.0.1:9090/api/v1/query' \
  --data-urlencode 'query=up{job="cloudflared"}'

# Range query over time (timestamps + values)
curl -fsS --get 'http://127.0.0.1:9090/api/v1/query_range' \
  --data-urlencode 'query=cloudflared_tunnel_ha_connections{job="cloudflared"}' \
  --data-urlencode 'start=2026-11-22T00:00:00Z' \
  --data-urlencode 'end=2026-11-22T01:00:00Z' \
  --data-urlencode 'step=30s'

# Or via promtool
promtool query instant http://127.0.0.1:9090 'cloudflared_tunnel_ha_connections{job="cloudflared"}'
```

## Declarative NixOS Configuration (Disabled by Default)

Import `oof.nixosModules.default` from `flake.nix`. `services.oof-collector.prometheus.enable` defaults to `false`:

```nix
services.oof-collector.prometheus = {
  enable = false; # Set to true when ready to enable
  listenAddress = "127.0.0.1:9090";
  defaultScrapeInterval = "30s";
  defaultScrapeTimeout = "5s";
  targets.cloudflared = {
    endpoint = "http://127.0.0.1:20241/metrics";
    scrapeInterval = "30s";
    scrapeTimeout = "5s";
    metrics = [ "cloudflared_tunnel_ha_connections" ];
  };
};
```
