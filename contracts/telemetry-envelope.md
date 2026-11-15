# Canonical Telemetry Envelope (SIEM + APM)

All log collectors, detection engines, and storage sinks in the Open Observability Framework share a single 24-field canonical envelope defined for Cloudflare Basin Pipelines in [`journal-logs.basin.json`](./schemas/journal-logs.basin.json).

Keeping every adapter aligned to this contract ensures:
1. Collectors (`vector-journald`, `otel-collector-journald`, `fluent-bit`) can be swapped without modifying storage schemas or query SQL.
2. SIEM security signals (`yara_*`, `uid`, `exe`, `cmdline`) and APM trace correlation (`service_name`, `trace_id`, `span_id`) live in the same Iceberg record for cross-signal pivoting.
3. Cloudflare Basin Pipelines never silently drop rows due to schema mismatches at Iceberg sink delivery.

---

## Field Mapping

| Canonical Field | Type | Required | `systemd-journald` Source | OTel LogRecord / APM Source | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `string` | Yes | `__CURSOR` / generated UUID | `attributes["event.id"]` / UUID | Unique event identifier |
| `observed_at` | `string` | Yes | Ingest / collector UTC ISO-8601 | `observed_time_unix_nano` (ISO) | Edge ingestion timestamp |
| `event_time` | `string` | Yes | `__REALTIME_TIMESTAMP` (µs → ISO) | `time_unix_nano` (ISO) | Falls back to `observed_at` if invalid |
| `host` | `string` | Yes | `_HOSTNAME` | `resource["host.name"]` | Defaults to `"unknown"` |
| `service_name` | `string` | Yes | `_SYSTEMD_UNIT` / `SYSLOG_IDENTIFIER` / `_COMM` | `resource["service.name"]` | Shared SIEM/APM service key |
| `systemd_unit` | `string` | No | `_SYSTEMD_UNIT` | `attributes["systemd.unit"]` | e.g. `sshd.service` |
| `syslog_identifier` | `string` | No | `SYSLOG_IDENTIFIER` | `attributes["syslog.identifier"]` | e.g. `sudo`, `sshd` |
| `transport` | `string` | No | `_TRANSPORT` | `attributes["journald.transport"]` | `stdout`, `syslog`, `journal`, `kernel` |
| `priority` | `int32` | Yes | `PRIORITY` (`0..7`, default `6`) | Mapped from `severity_number` | Syslog priority level |
| `severity` | `string` | Yes | Derived from `priority` | `severity_text` | `EMERG`..`DEBUG` |
| `pid` | `int64` | No | `_PID` | `attributes["process.pid"]` | Parsed signed 64-bit integer |
| `uid` | `int64` | No | `_UID` | `attributes["user.id"]` | Parsed signed 64-bit integer |
| `comm` | `string` | No | `_COMM` | `attributes["process.command"]` | Process short name |
| `exe` | `string` | No | `_EXE` | `attributes["process.executable.path"]` | Executable path |
| `cmdline` | `string` | No | `_CMDLINE` | `attributes["process.command_line"]` | Full command line |
| `boot_id` | `string` | No | `_BOOT_ID` | `attributes["host.boot_id"]` | Linux boot UUID |
| `machine_id` | `string` | No | `_MACHINE_ID` | `attributes["host.id"]` | `/etc/machine-id` |
| `message` | `string` | Yes | `MESSAGE` (string or byte array) | `body` | Empty string if absent; raw bytes scanned by YARA |
| `trace_id` | `string` | No | `TRACE_ID` / `OTEL_TRACE_ID` | `trace_id` | 32-hex W3C Trace Context ID |
| `span_id` | `string` | No | `SPAN_ID` / `OTEL_SPAN_ID` | `span_id` | 16-hex W3C Span ID |
| `yara_matched` | `bool` | Yes | `false` or host detector output | `false` | `true` when `yara_rules.length > 0` |
| `yara_rules` | `list<string>` | Yes | Upstream host matches (`[]`) | `[]` | Deduplicated rule identifiers |
| `yara_tags` | `list<string>` | Yes | Upstream host tags (`[]`) | `[]` | Deduplicated rule tags |
| `attributes_json` | `string` | No | Extra fields + YARA match details | Remaining resource/log attributes | Bounded JSON string (`<= 16 KiB`) |

---

## Detection Placement Composition

- **`edge-ingest` (Worker + WASM YARA)**: The Worker reconstructs raw `MESSAGE` bytes (including binary byte arrays from `journald` JSON exports) plus `cmdline`, `exe`, `syslog_identifier`, and `systemd_unit`, evaluates YARA rules via `oof-yara-wasm`, and sets `yara_matched`, `yara_rules`, `yara_tags`, and `attributes_json.yara_matches`.
- **`host-agent` (Kunai / YARA-X CLI)**: The host writes pre-populated `yara_rules` / `yara_tags` into structured `journald` JSON.
- **`hybrid`**: The Worker merges upstream host-side `yara_rules` and `yara_tags` with edge WASM detections into a unified deduplicated list (`yara_matched = mergedRules.length > 0`).

---

## Severity Mapping

| Syslog `priority` | `severity` |
| :--- | :--- |
| `0` | `EMERG` |
| `1` | `ALERT` |
| `2` | `CRIT` |
| `3` | `ERR` |
| `4` | `WARN` |
| `5` | `NOTICE` |
| `6` | `INFO` |
| `7` | `DEBUG` |
