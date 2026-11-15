-- Cloudflare Basin Pipeline SQL: Canonical Journal Logs -> Iceberg Sink
-- Placeholders `__SINK_NAME__` and `__STREAM_NAME__` are rendered by provision-basin.sh
-- (defaults: sink = journal_iceberg_sink, stream = journal_stream).

INSERT INTO __SINK_NAME__
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
FROM __STREAM_NAME__;
