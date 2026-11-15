-- Open Observability Framework — OCSF v1.3.0 SIEM & APM Hunting Queries
-- Target Iceberg table: siem.ocsf_event_log_activity (class_uid = 1008)

-- 1. High-severity authentication & privilege events (sshd / sudo / su)
SELECT
  time_dt,
  device.hostname AS host,
  log_name,
  severity,
  severity_id,
  actor.user.uid AS user_uid,
  actor.process.pid AS pid,
  actor.process.cmd_line AS cmd_line,
  message
FROM siem.ocsf_event_log_activity
WHERE class_uid = 1008
  AND severity_id >= 3
  AND (
    log_name IN ('sshd.service', 'ssh.service', 'sshd', 'sudo', 'su')
    OR actor.process.name IN ('sshd', 'sudo', 'su')
  )
ORDER BY time DESC
LIMIT 200;

-- 2. Error / Critical / Fatal summary by host, unit/scope, and severity
SELECT
  device.hostname AS host,
  log_name,
  log_provider,
  severity,
  COUNT(*) AS event_count,
  MIN(time_dt) AS first_seen,
  MAX(time_dt) AS last_seen
FROM siem.ocsf_event_log_activity
WHERE severity_id >= 4
GROUP BY device.hostname, log_name, log_provider, severity
ORDER BY event_count DESC
LIMIT 100;

-- 3. Root / UID 0 process executions with command lines
SELECT
  time_dt,
  device.hostname AS host,
  actor.process.name AS process_name,
  actor.process.path AS executable_path,
  actor.process.cmd_line AS cmd_line,
  message
FROM siem.ocsf_event_log_activity
WHERE actor.user.uid = '0'
  AND actor.process.cmd_line IS NOT NULL
ORDER BY time DESC
LIMIT 200;

-- 4. SIEM <-> APM Correlation Pivot: trace_id stored in metadata.correlation_uid
SELECT
  time_dt,
  device.hostname AS host,
  log_provider,
  log_name,
  severity,
  metadata.correlation_uid AS trace_id,
  metadata.original_event_uid AS event_or_span_uid,
  actor.user.uid AS user_uid,
  message,
  unmapped
FROM siem.ocsf_event_log_activity
WHERE metadata.correlation_uid = '<TRACE_ID>'
ORDER BY time ASC;
