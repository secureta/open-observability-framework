-- Open Observability Framework — FinOps & Cost Monitoring Queries (Cloudflare Basin SQL dialect)
-- Covers:
--   Part 1: GitHub Actions estimated runner cost & waste from siem.ocsf_event_log_activity (OCSF v1.3.0)
--   Part 2: Cloudflare Basin / R2 ingestion volume cost drivers from siem.ocsf_event_log_activity (OCSF v1.3.0)
--   Part 3: Actual billed/effective cost & usage from finops.focus_cost_and_usage (FOCUS v1.0)
-- Uses Cloudflare Basin SQL JSON scalar functions (`json_get_str`, `json_get_int`).
-- For DuckDB dialect, see finops_monitoring.sql.

-- ============================================================================
-- Part 1: GitHub Actions Estimated Runner Cost & Waste (OCSF Iceberg Table)
-- ============================================================================

-- 1. Estimated GitHub-hosted runner minutes & USD cost by repository, workflow, and OS
-- Deduplicates webhook retries by numeric unmapped.job_id and separates collector_source to avoid double-counting.
WITH dedup_jobs AS (
  SELECT
    metadata.product.name AS collector_source,
    log_name,
    device.type AS runner_type,
    COALESCE(device.os.name, 'Linux') AS runner_os,
    severity_id,
    CAST(json_get_int(unmapped, 'duration_ms') AS DOUBLE) AS duration_ms,
    CASE
      WHEN metadata.product.name = 'Vector'
        AND json_get_int(unmapped, 'job_id') IS NOT NULL THEN
        ROW_NUMBER() OVER (
          PARTITION BY metadata.product.name, json_get_int(unmapped, 'job_id')
          ORDER BY time DESC
        )
      ELSE 1
    END AS rn
  FROM siem.ocsf_event_log_activity
  WHERE class_uid = 1008
    AND log_provider = 'github-actions'
    AND json_get_str(unmapped, 'github_event') = 'workflow_job'
    AND json_get_str(unmapped, 'status') = 'completed'
    AND json_get_int(unmapped, 'duration_ms') IS NOT NULL
),
priced_jobs AS (
  SELECT
    collector_source,
    log_name,
    runner_type,
    runner_os,
    severity_id,
    CEIL(CASE WHEN duration_ms > 0 THEN duration_ms ELSE 0 END / 60000.0) AS billable_minutes,
    CASE
      WHEN runner_type = 'Server' THEN 0.0
      WHEN runner_os = 'macOS' THEN 0.080
      WHEN runner_os = 'Windows' THEN 0.016
      ELSE 0.008
    END AS usd_per_minute
  FROM dedup_jobs
  WHERE rn = 1
)
SELECT
  collector_source,
  log_name,
  runner_type,
  runner_os,
  COUNT(*) AS completed_jobs,
  SUM(billable_minutes) AS total_billable_minutes,
  ROUND(SUM(billable_minutes * usd_per_minute), 4) AS estimated_usd,
  ROUND(SUM(CASE WHEN severity_id >= 4 THEN billable_minutes * usd_per_minute ELSE 0.0 END), 4) AS failed_job_usd
FROM priced_jobs
GROUP BY collector_source, log_name, runner_type, runner_os
ORDER BY estimated_usd DESC, total_billable_minutes DESC
LIMIT 100;

-- 2. GitHub Actions waste: failed, cancelled, timed-out, or retried jobs (run_attempt > 1)
WITH dedup_jobs AS (
  SELECT
    metadata.product.name AS collector_source,
    log_name,
    device.type AS runner_type,
    COALESCE(device.os.name, 'Linux') AS runner_os,
    severity_id,
    metadata.log_level AS conclusion,
    COALESCE(json_get_int(unmapped, 'run_attempt'), 1) AS run_attempt,
    CAST(json_get_int(unmapped, 'duration_ms') AS DOUBLE) AS duration_ms,
    CASE
      WHEN metadata.product.name = 'Vector'
        AND json_get_int(unmapped, 'job_id') IS NOT NULL THEN
        ROW_NUMBER() OVER (
          PARTITION BY metadata.product.name, json_get_int(unmapped, 'job_id')
          ORDER BY time DESC
        )
      ELSE 1
    END AS rn
  FROM siem.ocsf_event_log_activity
  WHERE class_uid = 1008
    AND log_provider = 'github-actions'
    AND json_get_str(unmapped, 'github_event') = 'workflow_job'
    AND json_get_str(unmapped, 'status') = 'completed'
    AND json_get_int(unmapped, 'duration_ms') IS NOT NULL
)
SELECT
  collector_source,
  log_name,
  runner_os,
  COUNT(*) AS waste_jobs,
  SUM(CEIL(CASE WHEN duration_ms > 0 THEN duration_ms ELSE 0 END / 60000.0)) AS waste_minutes,
  ROUND(SUM(
    CEIL(CASE WHEN duration_ms > 0 THEN duration_ms ELSE 0 END / 60000.0) *
    CASE
      WHEN runner_type = 'Server' THEN 0.0
      WHEN runner_os = 'macOS' THEN 0.080
      WHEN runner_os = 'Windows' THEN 0.016
      ELSE 0.008
    END
  ), 4) AS estimated_waste_usd
FROM dedup_jobs
WHERE rn = 1
  AND (severity_id >= 2 OR run_attempt > 1)
GROUP BY collector_source, log_name, runner_os
ORDER BY estimated_waste_usd DESC, waste_minutes DESC
LIMIT 100;

-- ============================================================================
-- Part 2: Cloudflare Basin & R2 Ingestion Cost Drivers (OCSF Iceberg Table)
-- ============================================================================

-- 3. Top telemetry volume producers by log_provider, host, and log_name
SELECT
  log_provider,
  device.hostname AS host,
  log_name,
  COUNT(*) AS event_count,
  ROUND(SUM(
    COALESCE(LENGTH(message), 0) + COALESCE(LENGTH(CAST(unmapped AS VARCHAR)), 0)
  ) / 1048576.0, 4) AS approx_payload_mib
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
GROUP BY log_provider, device.hostname, log_name
ORDER BY approx_payload_mib DESC, event_count DESC
LIMIT 100;

-- 4. Daily ingestion volume trend (detect log explosions driving Basin/R2 spend)
SELECT
  DATE_TRUNC('day', time_dt) AS event_day,
  log_provider,
  COUNT(*) AS event_count,
  ROUND(SUM(
    COALESCE(LENGTH(message), 0) + COALESCE(LENGTH(CAST(unmapped AS VARCHAR)), 0)
  ) / 1048576.0, 4) AS approx_payload_mib
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
GROUP BY DATE_TRUNC('day', time_dt), log_provider
ORDER BY event_day DESC, approx_payload_mib DESC
LIMIT 200;

-- ============================================================================
-- Part 3: Actual Cost & Usage (FOCUS v1.0 Iceberg Table: finops.focus_cost_and_usage)
-- ============================================================================

-- 5. Daily cost & usage summary by provider, service, and SKU
SELECT
  DATE_TRUNC('day', ChargePeriodStart) AS charge_day,
  ProviderName,
  ServiceCategory,
  ServiceName,
  SkuId,
  BillingCurrency,
  ConsumedUnit,
  ROUND(SUM(ConsumedQuantity), 4) AS total_consumed_quantity,
  ROUND(SUM(ListCost), 4) AS total_list_cost,
  ROUND(SUM(BilledCost), 4) AS total_billed_cost,
  ROUND(SUM(EffectiveCost), 4) AS total_effective_cost
FROM finops.focus_cost_and_usage
GROUP BY
  DATE_TRUNC('day', ChargePeriodStart),
  ProviderName,
  ServiceCategory,
  ServiceName,
  SkuId,
  BillingCurrency,
  ConsumedUnit
ORDER BY charge_day DESC, total_effective_cost DESC
LIMIT 200;

-- 6. Top cost-bearing resources (Cloudflare R2 buckets, Pipelines, GitHub repositories)
SELECT
  ProviderName,
  ServiceName,
  ResourceType,
  ResourceName,
  BillingCurrency,
  ROUND(SUM(ConsumedQuantity), 4) AS total_consumed_quantity,
  ROUND(SUM(BilledCost), 4) AS total_billed_cost,
  ROUND(SUM(EffectiveCost), 4) AS total_effective_cost,
  MIN(ChargePeriodStart) AS first_charge_start,
  MAX(ChargePeriodEnd) AS last_charge_end
FROM finops.focus_cost_and_usage
GROUP BY ProviderName, ServiceName, ResourceType, ResourceName, BillingCurrency
ORDER BY total_effective_cost DESC
LIMIT 100;

-- 7. Daily spend anomaly detection vs. rolling 7-day baseline per provider & service
WITH daily_spend AS (
  SELECT
    DATE_TRUNC('day', ChargePeriodStart) AS charge_day,
    ProviderName,
    ServiceName,
    BillingCurrency,
    SUM(EffectiveCost) AS daily_effective_cost
  FROM finops.focus_cost_and_usage
  GROUP BY DATE_TRUNC('day', ChargePeriodStart), ProviderName, ServiceName, BillingCurrency
),
with_baseline AS (
  SELECT
    charge_day,
    ProviderName,
    ServiceName,
    BillingCurrency,
    daily_effective_cost,
    AVG(daily_effective_cost) OVER (
      PARTITION BY ProviderName, ServiceName, BillingCurrency
      ORDER BY charge_day
      ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING
    ) AS prev_7d_avg_cost
  FROM daily_spend
)
SELECT
  charge_day,
  ProviderName,
  ServiceName,
  BillingCurrency,
  ROUND(daily_effective_cost, 4) AS daily_effective_cost,
  ROUND(prev_7d_avg_cost, 4) AS prev_7d_avg_cost,
  ROUND(
    CASE
      WHEN prev_7d_avg_cost IS NOT NULL AND prev_7d_avg_cost > 0
        THEN daily_effective_cost / prev_7d_avg_cost
      ELSE NULL
    END,
    2
  ) AS spike_ratio
FROM with_baseline
WHERE prev_7d_avg_cost IS NOT NULL
  AND prev_7d_avg_cost > 0
  AND daily_effective_cost > prev_7d_avg_cost * 1.5
ORDER BY charge_day DESC, spike_ratio DESC
LIMIT 100;
