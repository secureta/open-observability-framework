# Vector Coding-Agent AI Usage Collector (`vector-ai-coding-agents`)

Collects **metadata-only** AI usage telemetry (`capture_content: none`) from local coding agents into `ai.genai_usage` ([genai-usage.basin.json](../../../contracts/otel-genai/genai-usage.basin.json)) via Cloudflare Basin Direct HTTP (`direct-basin-http`).

Prompts, completions, chain-of-thought (`thinking`), and tool arguments are stripped in VRL and never leave the host.

## Supported Coding Agents

First, generate a local shared Bearer token for authenticated OTLP HTTP ingestion (`OOF_AI_OTLP_AUTH_TOKEN`):
```bash
export OOF_AI_OTLP_AUTH_TOKEN="$(openssl rand -hex 32)"
```

### 1. Claude Code (OTLP/HTTP JSON)
Use the **logs-only** OTLP environment variables so the local collector token is never sent to separate OTLP metrics or traces providers:
```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=http/json
export OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:4328/v1/logs
export OTEL_EXPORTER_OTLP_LOGS_HEADERS="Authorization=Bearer ${OOF_AI_OTLP_AUTH_TOKEN}"
export OTEL_LOG_USER_PROMPTS=0
```

### 2. Codex CLI (OTLP/HTTP JSON)
Add the `[otel]` block to `~/.codex/config.toml` (replace `<OOF_AI_OTLP_AUTH_TOKEN>` with your token):
```toml
[otel]
log_user_prompt = false
exporter = { otlp-http = { endpoint = "http://127.0.0.1:4328/v1/logs", protocol = "json", headers = { Authorization = "Bearer <OOF_AI_OTLP_AUTH_TOKEN>" } } }
```

### 3. Antigravity (`agy`) / herdr Sessions (Local JSONL)
Point Vector to Antigravity's transcript logs:
```bash
export OOF_AGY_TRANSCRIPT_GLOB="$HOME/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript.jsonl"
```

### 4. Pi (`pi-coding-agent`, Local JSONL)
Point Vector to Pi's session logs:
```bash
export OOF_PI_SESSIONS_GLOB="$HOME/.pi/agent/sessions/**/*.jsonl"
```

## Optional Prompt / Completion Capture (`OOF_AI_CAPTURE_CONTENT`)

By default (`OOF_AI_CAPTURE_CONTENT=none`), prompts, completions, chain-of-thought (`thinking`), and tool arguments are stripped before shipping.

To opt into capturing prompts and assistant text replies inside `attributes.prompt` / `attributes.completion` (still keeping `thinking` and tool arguments stripped):

| Mode | Behavior |
| :--- | :--- |
| `none` (default) | Metadata only; no prompt or completion text leaves the host. |
| `redacted` | Redacts private keys, `Bearer` tokens, API keys (`sk-...`, `ghp_...`, `AKIA...`, `xox...`), and emails, and truncates at 8,192 characters. |
| `full` | Captures unredacted text (truncated at 8,192 characters). |

When enabling `redacted` or `full`, also opt in on OTLP agents if desired:
- **Claude Code**: `export OTEL_LOG_USER_PROMPTS=1` (and enable assistant response logging if supported by your Claude Code version)
- **Codex CLI**: set `log_user_prompt = true` (and `log_agent_responses = true` for assistant replies) under `[otel]` in `~/.codex/config.toml`
- **Antigravity / Pi**: no extra agent config required (Vector reads prompts/replies directly from local JSONL).

```bash
export OOF_AI_CAPTURE_CONTENT=redacted
```

## Security Note
- The local OTLP/HTTP JSON listener (`127.0.0.1:4328/v1/logs`) enforces `Authorization: Bearer <OOF_AI_OTLP_AUTH_TOKEN>` at the HTTP listener layer, returning `HTTP 401 Unauthorized` for missing or invalid tokens before any batch is accepted.
- No unauthenticated gRPC listener is exposed, and `OTEL_EXPORTER_OTLP_LOGS_HEADERS` scopes the local Bearer token strictly to logs so it is never sent to external metrics/traces providers.

## Running & Validating Locally

```bash
VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_AI_DATA_DIR="$(mktemp -d)" \
OOF_AI_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_AI_INGEST_TOKEN="dummy" \
OOF_AI_OTLP_AUTH_TOKEN="dummy-local-otlp-token" \
  vector validate --no-environment adapters/collect/vector-ai-coding-agents/vector.yaml

VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
OOF_VECTOR_AI_DATA_DIR="$(mktemp -d)" \
OOF_AI_BASIN_ENDPOINT="https://example.ingest.cloudflare.com" \
OOF_AI_INGEST_TOKEN="dummy" \
OOF_AI_OTLP_AUTH_TOKEN="dummy-local-otlp-token" \
  vector test adapters/collect/vector-ai-coding-agents/vector.yaml
```
