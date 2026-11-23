-- Open Observability Framework — Cloudflare SIEM & Edge Observability Queries (DuckDB dialect)
-- Target Iceberg table: siem.ocsf_event_log_activity (OCSF v1.3.0 class_uid = 1008)
-- For Cloudflare Basin SQL (`json_get_str` / `json_get_int` / `json_get_bool`), see cloudflare_monitoring.basin.sql.

-- ============================================================================
-- Part 1: Cloudflare Account Audit Logs (Deduplicated by original_event_uid)
-- ============================================================================

-- 1. High-risk or failed Cloudflare account audit actions
WITH dedup_audit AS (
  SELECT
    time_dt,
    time,
    severity,
    severity_id,
    log_name,
    actor.user.name AS actor_email,
    actor.user.uid AS actor_uid,
    metadata.original_event_uid AS audit_log_id,
    json_extract_string(unmapped, '$.action_type') AS action_type,
    CAST(json_extract(unmapped, '$.action_result') AS BOOLEAN) AS action_result,
    json_extract_string(unmapped, '$.resource_type') AS resource_type,
    json_extract_string(unmapped, '$.resource_id') AS resource_id,
    json_extract_string(unmapped, '$.actor_ip') AS actor_ip,
    json_extract_string(unmapped, '$.interface') AS iface,
    message,
    ROW_NUMBER() OVER (
      PARTITION BY metadata.original_event_uid
      ORDER BY time DESC
    ) AS rn
  FROM siem.ocsf_event_log_activity
  WHERE class_uid = 1008
    AND log_provider = 'cloudflare-audit-logs'
    AND metadata.original_event_uid IS NOT NULL
)
SELECT
  time_dt,
  severity,
  actor_email,
  actor_ip,
  iface,
  action_type,
  action_result,
  resource_type,
  resource_id,
  message
FROM dedup_audit
WHERE rn = 1
  AND (severity_id >= 3 OR action_result = FALSE)
ORDER BY time DESC
LIMIT 200;

-- ============================================================================
-- Part 2: Cloudflare Logpush Edge Telemetry (HTTP, WAF, Access)
-- ============================================================================

-- 2. HTTP traffic health, error rate, and cache hit ratio by host
SELECT
  json_extract_string(unmapped, '$.request_host') AS request_host,
  COUNT(*) AS total_requests,
  SUM(CASE WHEN CAST(json_extract(unmapped, '$.edge_status') AS INTEGER) >= 500 THEN 1 ELSE 0 END) AS status_5xx,
  SUM(CASE WHEN CAST(json_extract(unmapped, '$.edge_status') AS INTEGER) BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS status_4xx,
  SUM(CASE WHEN json_extract_string(unmapped, '$.cache_status') = 'hit' THEN 1 ELSE 0 END) AS cache_hits,
  ROUND(
    100.0 * SUM(CASE WHEN CAST(json_extract(unmapped, '$.edge_status') AS INTEGER) >= 500 THEN 1 ELSE 0 END) / COUNT(*),
    2
  ) AS error_5xx_pct,
  ROUND(
    100.0 * SUM(CASE WHEN json_extract_string(unmapped, '$.cache_status') = 'hit' THEN 1 ELSE 0 END) / COUNT(*),
    2
  ) AS cache_hit_pct
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'cloudflare-logpush'
  AND json_extract_string(unmapped, '$.cloudflare_dataset') = 'http_requests'
GROUP BY request_host
ORDER BY status_5xx DESC, total_requests DESC
LIMIT 100;

-- 3. Top WAF / Firewall enforced actions (block, drop, connectionclose, challenges; excludes log-only matches)
SELECT
  json_extract_string(unmapped, '$.request_host') AS request_host,
  json_extract_string(unmapped, '$.waf_action') AS waf_action,
  json_extract_string(unmapped, '$.waf_source') AS waf_source,
  json_extract_string(unmapped, '$.waf_rule_id') AS waf_rule_id,
  json_extract_string(unmapped, '$.client_ip') AS client_ip,
  json_extract_string(unmapped, '$.client_country') AS client_country,
  COUNT(*) AS event_count,
  MAX(time_dt) AS last_seen
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'cloudflare-logpush'
  AND json_extract_string(unmapped, '$.cloudflare_dataset') = 'firewall_events'
  AND json_extract_string(unmapped, '$.waf_action') IN (
    'block',
    'drop',
    'connectionclose',
    'connection_close',
    'force_connection_close',
    'challenge',
    'managedchallenge',
    'managed_challenge',
    'jschallenge',
    'interactivechallenge',
    'l7ddos'
  )
GROUP BY request_host, waf_action, waf_source, waf_rule_id, client_ip, client_country
ORDER BY event_count DESC
LIMIT 100;

-- 4. Denied Zero Trust Access authentication requests
SELECT
  time_dt,
  device.hostname AS app_host,
  actor.user.name AS user_email,
  json_extract_string(unmapped, '$.access_app_uid') AS app_uid,
  json_extract_string(unmapped, '$.client_ip') AS client_ip,
  json_extract_string(unmapped, '$.client_country') AS client_country,
  message
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'cloudflare-logpush'
  AND json_extract_string(unmapped, '$.cloudflare_dataset') = 'access_requests'
  AND CAST(json_extract(unmapped, '$.access_allowed') AS BOOLEAN) = FALSE
ORDER BY time DESC
LIMIT 200;
