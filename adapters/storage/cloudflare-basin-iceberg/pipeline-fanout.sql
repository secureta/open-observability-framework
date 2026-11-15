-- Cloudflare Basin Pipeline SQL (Dual-Table Fan-Out Variant)
-- Routes all canonical journal logs to `journal_iceberg_sink` and duplicates
-- YARA detections into a dedicated `yara_detections_sink` Iceberg table for
-- low-latency alerting and SIEM triage.

INSERT INTO journal_iceberg_sink
SELECT
  event_id,
  observed_at,
  event_time,
  host,
  service_name,
  systemd_unit,
  syslog_identifier,
  transport,
  priority,
  severity,
  pid,
  uid,
  comm,
  exe,
  cmdline,
  boot_id,
  machine_id,
  message,
  trace_id,
  span_id,
  yara_matched,
  yara_rules,
  yara_tags,
  attributes_json
FROM journal_stream;

INSERT INTO yara_detections_sink
SELECT
  event_id,
  observed_at,
  event_time,
  host,
  service_name,
  systemd_unit,
  syslog_identifier,
  transport,
  priority,
  severity,
  pid,
  uid,
  comm,
  exe,
  cmdline,
  boot_id,
  machine_id,
  message,
  trace_id,
  span_id,
  yara_matched,
  yara_rules,
  yara_tags,
  attributes_json
FROM journal_stream
WHERE yara_matched = true;
