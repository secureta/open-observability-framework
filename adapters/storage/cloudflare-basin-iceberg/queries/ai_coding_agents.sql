-- Open Observability Framework — Coding Agent AI Usage Queries (OTel GenAI SemConv)
-- Target Iceberg table: ai.genai_usage (metadata-only, capture_content = none)

-- 1. Daily token usage and estimated cost by coding agent and model
SELECT
  DATE_TRUNC('day', time_dt) AS day,
  service.name AS agent,
  gen_ai.provider_name AS provider,
  COALESCE(gen_ai.response_model, gen_ai.request_model) AS model,
  COUNT(*) AS requests,
  SUM(COALESCE(gen_ai.usage.input_tokens, 0)) AS input_tokens,
  SUM(COALESCE(gen_ai.usage.output_tokens, 0)) AS output_tokens,
  SUM(COALESCE(gen_ai.usage.cache_read_tokens, 0)) AS cache_read_tokens,
  SUM(COALESCE(gen_ai.usage.cache_creation_tokens, 0)) AS cache_creation_tokens,
  SUM(COALESCE(gen_ai.usage.reasoning_tokens, 0)) AS reasoning_tokens,
  SUM(COALESCE(gen_ai.usage.total_tokens, 0)) AS total_tokens,
  ROUND(SUM(COALESCE(gen_ai.usage.cost_usd, 0.0)), 4) AS total_cost_usd,
  ROUND(AVG(duration_ms), 1) AS avg_duration_ms
FROM ai.genai_usage
WHERE operation_name IN ('chat', 'invoke_agent')
GROUP BY 1, 2, 3, 4
ORDER BY day DESC, total_tokens DESC
LIMIT 200;

-- 2. Tool execution volume, failure rate, and latency by agent & tool name
SELECT
  service.name AS agent,
  gen_ai.tool_name AS tool_name,
  COUNT(*) AS total_calls,
  SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_calls,
  ROUND(100.0 * SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) / COUNT(*), 2) AS error_rate_pct,
  ROUND(AVG(duration_ms), 1) AS avg_duration_ms
FROM ai.genai_usage
WHERE operation_name = 'execute_tool'
  AND gen_ai.tool_name IS NOT NULL
GROUP BY 1, 2
ORDER BY total_calls DESC
LIMIT 100;

-- 3. Session summary by workspace / repository (active coding sessions)
SELECT
  service.name AS agent,
  session_id,
  MAX(host.workspace) AS workspace,
  MAX(host.vcs_repository) AS repo,
  MAX(host.vcs_ref) AS branch,
  MIN(time_dt) AS started_at,
  MAX(time_dt) AS last_event_at,
  COUNT(*) AS event_count,
  SUM(COALESCE(gen_ai.usage.total_tokens, 0)) AS total_tokens,
  ROUND(SUM(COALESCE(gen_ai.usage.cost_usd, 0.0)), 4) AS total_cost_usd
FROM ai.genai_usage
WHERE session_id IS NOT NULL
GROUP BY 1, 2
ORDER BY last_event_at DESC
LIMIT 100;

-- 4. AI-SIEM Correlation Pivot: join coding-agent trace_id with host OCSF 1008 logs
SELECT
  u.time_dt AS ai_time,
  u.service.name AS agent,
  u.session_id,
  u.operation_name,
  u.gen_ai.tool_name AS tool_name,
  u.status AS ai_status,
  s.time_dt AS host_log_time,
  s.device.hostname AS host,
  s.log_name,
  s.severity,
  s.actor.process.cmd_line AS host_cmd_line,
  s.message AS host_message
FROM ai.genai_usage AS u
INNER JOIN siem.ocsf_event_log_activity AS s
  ON u.trace_id = s.metadata.correlation_uid
WHERE u.trace_id IS NOT NULL
ORDER BY u.time DESC
LIMIT 200;
