-- Cloudflare Basin Pipeline SQL: OCSF v1.3.0 Event Log Activity (1008) -> Iceberg Sink
-- Rendered by Terraform/OpenTofu (terraform/main.tf) and Pulumi (pulumi/basin-core.ts) (__SINK_NAME__ and __STREAM_NAME__ substituted)

INSERT INTO __SINK_NAME__
SELECT
  category_uid,
  category_name,
  class_uid,
  class_name,
  type_uid,
  type_name,
  activity_id,
  activity_name,
  severity_id,
  severity,
  time,
  time_dt,
  message,
  log_name,
  log_provider,
  metadata,
  device,
  actor,
  unmapped
FROM __STREAM_NAME__;
