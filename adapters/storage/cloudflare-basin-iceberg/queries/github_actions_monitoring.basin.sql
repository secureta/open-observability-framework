-- Open Observability Framework — GitHub Actions CI/CD Observability & SIEM Queries (Cloudflare Basin SQL dialect)
-- Target Iceberg table: siem.ocsf_event_log_activity (OCSF v1.3.0 class_uid = 1008)
-- Uses Cloudflare Basin SQL JSON scalar functions (`json_get_str`, `json_get_int`, `json_get_bool`).
-- For DuckDB dialect, see github_actions_monitoring.sql.

-- ============================================================================
-- Part 1: CI/CD Observability (Reliability, Latency, Retries, Runner Capacity)
-- ============================================================================

-- 1. Workflow reliability & failure rate by repository and workflow
SELECT
  log_name,
  COUNT(*) AS total_runs,
  SUM(CASE WHEN severity_id >= 4 THEN 1 ELSE 0 END) AS failed_runs,
  SUM(CASE WHEN severity_id = 3 THEN 1 ELSE 0 END) AS timed_out_or_warning_runs,
  SUM(CASE WHEN severity_id = 2 THEN 1 ELSE 0 END) AS cancelled_or_skipped_runs,
  ROUND(100.0 * SUM(CASE WHEN severity_id >= 4 THEN 1 ELSE 0 END) / COUNT(*), 2) AS failure_rate_pct,
  MIN(time_dt) AS first_seen,
  MAX(time_dt) AS last_seen
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_str(unmapped, 'github_event') = 'workflow_run'
  AND json_get_str(unmapped, 'status') = 'completed'
GROUP BY log_name
ORDER BY failed_runs DESC, failure_rate_pct DESC
LIMIT 100;

-- 2. Slowest workflow runs & job queue latency (duration_ms / queue_duration_ms)
SELECT
  time_dt,
  log_name,
  device.hostname AS runner_or_repo,
  device.type AS runner_type,
  actor.user.name AS actor,
  json_get_int(unmapped, 'run_id') AS run_id,
  metadata.correlation_uid AS correlation_uid,
  metadata.log_level AS conclusion,
  json_get_int(unmapped, 'duration_ms') AS duration_ms,
  json_get_int(unmapped, 'queue_duration_ms') AS queue_duration_ms,
  json_get_str(unmapped, 'html_url') AS html_url
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_int(unmapped, 'duration_ms') IS NOT NULL
ORDER BY duration_ms DESC
LIMIT 100;

-- 3. Flaky / retried workflow runs (run_attempt > 1)
SELECT
  time_dt,
  log_name,
  json_get_int(unmapped, 'run_id') AS run_id,
  metadata.correlation_uid AS correlation_uid,
  json_get_int(unmapped, 'run_attempt') AS run_attempt,
  metadata.log_level AS conclusion,
  actor.user.name AS actor,
  message
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_int(unmapped, 'run_attempt') > 1
ORDER BY time DESC
LIMIT 200;

-- 4. Runner utilization breakdown (GitHub-hosted Virtual vs Self-hosted Server vs Unknown)
SELECT
  device.type AS runner_type,
  device.hostname AS runner_name,
  device.os.name AS runner_os,
  COUNT(*) AS completed_jobs,
  SUM(CASE WHEN severity_id >= 4 THEN 1 ELSE 0 END) AS failed_jobs,
  AVG(CAST(json_get_int(unmapped, 'duration_ms') AS DOUBLE)) AS avg_duration_ms,
  AVG(CAST(json_get_int(unmapped, 'queue_duration_ms') AS DOUBLE)) AS avg_queue_ms
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_str(unmapped, 'github_event') = 'workflow_job'
  AND json_get_str(unmapped, 'status') = 'completed'
GROUP BY device.type, device.hostname, device.os.name
ORDER BY completed_jobs DESC
LIMIT 100;

-- ============================================================================
-- Part 2: CI/CD Security & SIEM Hunting (Risky Triggers, Alerts, Runners)
-- ============================================================================

-- 5. High-risk workflow triggers (pull_request_target, fork PRs, manual workflow_dispatch)
SELECT
  time_dt,
  log_name,
  actor.user.name AS triggering_actor,
  actor.user.uid AS actor_uid,
  json_get_int(unmapped, 'run_id') AS run_id,
  metadata.correlation_uid AS correlation_uid,
  json_get_str(unmapped, 'trigger_event') AS trigger_event,
  json_get_str(unmapped, 'head_branch') AS head_branch,
  json_get_str(unmapped, 'head_sha') AS head_sha,
  json_get_bool(unmapped, 'is_fork_pr') AS is_fork_pr,
  json_get_str(unmapped, 'html_url') AS html_url
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND (
    json_get_str(unmapped, 'trigger_event') IN ('pull_request_target', 'workflow_dispatch')
    OR json_get_bool(unmapped, 'is_fork_pr') = TRUE
  )
ORDER BY time DESC
LIMIT 200;

-- 6. GitHub Security Alerts (secret scanning, code scanning, dependabot)
SELECT
  time_dt,
  severity,
  severity_id,
  log_name AS repository,
  actor.user.name AS actor,
  json_get_str(unmapped, 'github_event') AS alert_type,
  json_get_str(unmapped, 'action') AS action,
  json_get_str(unmapped, 'alert_rule') AS rule_or_secret_type,
  json_get_str(unmapped, 'html_url') AS html_url,
  message
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_str(unmapped, 'github_event') IN (
    'secret_scanning_alert',
    'code_scanning_alert',
    'dependabot_alert'
  )
ORDER BY severity_id DESC, time DESC
LIMIT 200;

-- 7. Self-hosted Runner systemd-journald errors & privilege escalation hunting
SELECT
  time_dt,
  device.hostname AS runner_host,
  log_name AS systemd_unit,
  severity,
  severity_id,
  actor.user.uid AS user_uid,
  actor.process.name AS process_name,
  actor.process.cmd_line AS cmd_line,
  message
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND (
    (log_name LIKE 'actions.runner.%' AND severity_id >= 3)
    OR (
      log_name IN ('sudo', 'su', 'sshd.service')
      AND device.hostname IN (
        SELECT DISTINCT device.hostname
        FROM siem.ocsf_event_log_activity
        WHERE log_name LIKE 'actions.runner.%'
      )
    )
  )
ORDER BY time DESC
LIMIT 200;

-- 8. Correlate all jobs & webhook events for a specific GitHub Actions run_id
-- Filters by numeric unmapped.run_id so trace-linked direct jobs (where metadata.correlation_uid holds trace_id) are included.
SELECT
  time_dt,
  log_provider,
  log_name,
  severity,
  device.hostname AS runner_host,
  actor.user.name AS actor,
  actor.process.name AS job_or_workflow,
  metadata.correlation_uid AS correlation_uid,
  metadata.original_event_uid AS event_uid,
  message,
  unmapped
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND log_provider = 'github-actions'
  AND json_get_int(unmapped, 'run_id') = 100200300
ORDER BY time ASC;
