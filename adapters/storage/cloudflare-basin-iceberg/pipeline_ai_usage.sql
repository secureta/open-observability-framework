-- Cloudflare Basin Pipeline SQL: OTel GenAI Usage (ai.genai_usage) -> Iceberg Sink
-- Rendered by Terraform/OpenTofu (terraform/main.tf) and Pulumi (pulumi/index.ts) (__SINK_NAME__ and __STREAM_NAME__ substituted)

INSERT INTO __SINK_NAME__
SELECT
  time,
  time_dt,
  event_name,
  operation_name,
  trace_id,
  span_id,
  session_id,
  status,
  error_type,
  duration_ms,
  service,
  host,
  gen_ai,
  attributes
FROM __STREAM_NAME__;
