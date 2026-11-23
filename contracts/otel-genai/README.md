# OpenTelemetry GenAI Semantic Conventions — AI Usage Contract (`ai.genai_usage`)

This contract defines the **metadata-only** Cloudflare Basin / Apache Iceberg schema ([genai-usage.basin.json](./genai-usage.basin.json)) for recording coding-agent and LLM usage telemetry based on **OpenTelemetry Semantic Conventions for Generative AI (`gen_ai.*`)** and standard OTel Resource attributes (`service.*`, `host.*`, `vcs.*`).

## Design Principles

1. **Metadata Only (`capture_content: none`)**:
   - Collectors MUST NOT emit prompts, completions, chain-of-thought (`thinking`), file contents, or tool arguments.
   - Only operational metadata (provider, model, token counts, cost, latency, tool names, decision outcomes, session/workspace identifiers) is persisted.
2. **Standard Naming & Basin Depth Compliance**:
   - Follows OTel GenAI (`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.usage.*`) and OTel Resource conventions.
   - Preserves Basin's recursive `type = "struct"` nesting limit (`depth <= 2`: `gen_ai.usage.*`).
3. **SIEM + APM Correlation**:
   - `trace_id` joins directly with `siem.ocsf_event_log_activity.metadata.correlation_uid` so coding-agent actions can be correlated with host `systemd-journald` / audit events in SQL.

## Coding Agent Source Mapping

| Source | Protocol | `service.name` | Mapped Events |
| :--- | :--- | :--- | :--- |
| **Claude Code** | OTLP (`4327`/`4328`) | `claude-code` | `claude_code.api_request` -> `chat`, `claude_code.api_error` -> `chat` (`error`), `claude_code.tool_result` -> `execute_tool`, `claude_code.user_prompt` -> `session` |
| **Codex CLI** | OTLP (`4327`/`4328`) | `codex-cli` | `codex.sse_event` / `codex.api_request` -> `chat`, `codex.tool_result` / `codex.tool_decision` -> `execute_tool`, `codex.conversation_starts` -> `session` |
| **Antigravity (`agy`) / herdr** | Local JSONL (`transcript.jsonl`) | `antigravity` | `PLANNER_RESPONSE` -> `invoke_agent` (tool names & counts only; `content`, `thinking`, `tool_calls[].arguments` stripped), `USER_INPUT` -> `session` |
| **Pi (`pi-coding-agent`)** | Local JSONL (`~/.pi/agent/sessions/**/*.jsonl`) | `pi` | `message` (`role: assistant`) -> `chat` (`provider`, `model`, `usage`, `cost`, `stopReason`, tool names only; `text` & `thinking` stripped), `session` / `model_change` -> `session` |

## Lockstep Files

Keep the following files in strict schema parity:
- [contracts/otel-genai/genai-usage.basin.json](./genai-usage.basin.json)
- [adapters/storage/cloudflare-basin-iceberg/pipeline_ai_usage.sql](../../adapters/storage/cloudflare-basin-iceberg/pipeline_ai_usage.sql)
- [adapters/collect/vector-ai-coding-agents/vector.yaml](../../adapters/collect/vector-ai-coding-agents/vector.yaml)
- [adapters/storage/cloudflare-basin-iceberg/queries/ai_coding_agents.sql](../../adapters/storage/cloudflare-basin-iceberg/queries/ai_coding_agents.sql)
