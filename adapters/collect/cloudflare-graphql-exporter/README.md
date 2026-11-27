# Cloudflare GraphQL Analytics Prometheus Exporter (`cloudflare-graphql-exporter`)

Zero-dependency Node.js (`>= 22`) loopback exporter that queries the **Cloudflare GraphQL Analytics API** (`httpRequests1mGroups`) and exposes Prometheus text-format metrics at `/metrics` for scraping by OOF's `prometheus-pull` adapter.

Time-series metrics remain separated from the OCSF v1.3.0 log schema (`siem.ocsf_event_log_activity`) so no proprietary fields enter the Iceberg log contract.

## Exported Metrics

All zone metrics carry only a single low-cardinality `zone` label (the configured zone alias or 32-hex zone ID):

- `cloudflare_zone_requests_total{zone="..."}`
- `cloudflare_zone_requests_cached{zone="..."}`
- `cloudflare_zone_requests_encrypted{zone="..."}`
- `cloudflare_zone_threats_total{zone="..."}`
- `cloudflare_zone_bandwidth_bytes{zone="..."}`
- `cloudflare_zone_bandwidth_cached_bytes{zone="..."}`
- `cloudflare_zone_requests_status_2xx{zone="..."}`
- `cloudflare_zone_requests_status_3xx{zone="..."}`
- `cloudflare_zone_requests_status_4xx{zone="..."}`
- `cloudflare_zone_requests_status_5xx{zone="..."}`
- `cloudflare_graphql_scrape_success` (`1` on success, `0` on API/network error)
- `cloudflare_graphql_scrape_duration_seconds`

## Environment Variables

- `OOF_CLOUDFLARE_API_TOKEN` *(required)* — Cloudflare API Token with `Zone -> Analytics -> Read`
- `OOF_CLOUDFLARE_ZONE_IDS` *(required)* — Comma-separated 32-hex Zone IDs or `alias=zoneId` pairs (e.g. `prod=0123456789abcdef0123456789abcdef`)
- `OOF_CF_EXPORTER_LISTEN` *(optional)* — Defaults to `127.0.0.1:9199`
- `OOF_CLOUDFLARE_GRAPHQL_ENDPOINT` *(optional)* — Defaults to `https://api.cloudflare.com/client/v4/graphql`
- `OOF_CF_EXPORTER_DATASET` *(optional)* — GraphQL dataset to query: `httpRequests1mGroups` (default, Pro+ plans) or `httpRequests1hGroups` (Free plans)
- `OOF_CF_EXPORTER_WINDOW_MINUTES` *(optional)* — Aggregation lookback window in minutes (default: `5` for `httpRequests1mGroups`, `60` for `httpRequests1hGroups`; range `1..60` for 1m, `60..1440` for 1h)
- `OOF_CF_EXPORTER_CACHE_TTL_SECS` *(optional)* — Scrape response cache TTL in seconds (default: `60`)
- `OOF_CF_EXPORTER_TIMEOUT_MS` *(optional)* — Upstream GraphQL HTTP timeout in ms (default: `10000`)

## NixOS Configuration Example (`services.oof-collector`)

```nix
services.oof-collector = {
  cloudflareGraphqlExporter = {
    enable = true;
    listen = "127.0.0.1:9199";
    # dataset = "httpRequests1hGroups"; # Required for Cloudflare Free-plan zones
    environmentFile = config.sops.secrets."oof-cf-analytics.env".path;
  };

  prometheus = {
    enable = true;
    targets.cloudflare_analytics = {
      endpoint = "http://127.0.0.1:9199/metrics";
      scrapeInterval = "60s";
      scrapeTimeout = "15s";
      allowedLabels = [ "zone" ];
      metrics = [
        "cloudflare_zone_requests_total"
        "cloudflare_zone_requests_cached"
        "cloudflare_zone_threats_total"
        "cloudflare_zone_bandwidth_bytes"
        "cloudflare_zone_requests_status_4xx"
        "cloudflare_zone_requests_status_5xx"
        "cloudflare_graphql_scrape_success"
        "cloudflare_graphql_scrape_duration_seconds"
      ];
    };
  };
};
```
