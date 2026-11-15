-- Open Observability Framework - SIEM & APM Hunting Queries (Cloudflare Basin SQL / DuckDB Iceberg)

-- 1. Recent YARA Detections across all Linux hosts
SELECT
  event_time,
  host,
  service_name,
  systemd_unit,
  priority,
  yara_rules,
  yara_tags,
  cmdline,
  message
FROM siem.journal_logs
WHERE yara_matched = true
ORDER BY event_time DESC
LIMIT 100;

-- 2. Detection rule frequency by host and MITRE/YARA tag
SELECT
  host,
  yara_rules,
  COUNT(*) AS hit_count,
  MIN(event_time) AS first_seen,
  MAX(event_time) AS last_seen
FROM siem.journal_logs
WHERE yara_matched = true
GROUP BY host, yara_rules
ORDER BY hit_count DESC;

-- 3. High-severity authentication & privilege failures (sshd / sudo)
SELECT
  event_time,
  host,
  systemd_unit,
  syslog_identifier,
  uid,
  pid,
  message
FROM siem.journal_logs
WHERE priority <= 4
  AND (
    systemd_unit IN ('sshd.service', 'ssh.service')
    OR syslog_identifier IN ('sshd', 'sudo', 'su')
  )
ORDER BY event_time DESC
LIMIT 200;

-- 4. SIEM -> APM Correlation Pivot: Inspect all logs tied to an application trace_id
SELECT
  event_time,
  host,
  service_name,
  trace_id,
  span_id,
  severity,
  yara_matched,
  yara_rules,
  message
FROM siem.journal_logs
WHERE trace_id IS NOT NULL
  AND trace_id = '<TRACE_ID>'
ORDER BY event_time ASC;
