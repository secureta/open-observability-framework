# OCSF v1.3.0 Contract — Event Log Activity (`1008`)

OOF avoids custom/proprietary log envelopes and standardizes on open schemas via `schema.profile` in the stack manifest ([stack.schema.json](../../manifest/stack.schema.json)):

- **`ocsf` (implemented default)**: **Open Cybersecurity Schema Framework v1.3.0**, class **`Event Log Activity`** (`category_uid = 1` System Activity, `class_uid = 1008`).
- **`ecs` / `cim` (planned extension profiles)**: Elastic Common Schema (`ecs`) and Splunk Common Information Model (`cim`) can be added later as sibling schema contracts under `contracts/ecs/` or `contracts/cim/` without altering ingest or Iceberg transport.

All Basin Stream fields in [event-log-activity.basin.json](./event-log-activity.basin.json) map 1:1 to standard OCSF v1.3.0 attributes and remain within Cloudflare Basin's struct nesting limit (depth <= 2) and primitive type set (`string`, `int32`, `int64`, `timestamp`, `struct`, `json`).

---

## Class, Type & Activity Constants

In upstream OCSF `Event Log Activity` (`1008`), `activity_id` values `1..10` represent **audit log lifecycle management actions** (`1 = Clear`, `2 = Delete`, `3 = Export`, `4 = Archive`, `5 = Rotate`, `6 = Start`, `7 = Stop`, `8 = Restart`, `9 = Enable`, `10 = Disable`).

Therefore, normal `systemd-journald` and OTLP log entries MUST use **`activity_id = 99` (`"Other"`)**:

| Field | Value | Meaning |
| :--- | :--- | :--- |
| `category_uid` / `category_name` | `1` / `"System Activity"` | OCSF System Activity category |
| `class_uid` / `class_name` | `1008` / `"Event Log Activity"` | OCSF Event Log Activity class |
| `activity_id` / `activity_name` | `99` / `"Other"` | General logged system/application event |
| `type_uid` / `type_name` | `100899` / `"Event Log Activity: Other"` | `class_uid * 100 + activity_id` |
| `metadata.version` | `"1.3.0"` | OCSF schema version |

---

## Severity Normalization (`severity_id` / `severity`)

Both [Vector](../../adapters/collect/vector-journald/vector.yaml) and [Fluent Bit](../../adapters/collect/fluent-bit-journald/ocsf.lua) apply the exact same OCSF v1.3.0 severity mapping:

| OCSF `severity_id` | OCSF `severity` | syslog / `journald` `PRIORITY` | OpenTelemetry `severity_number` |
| :--- | :--- | :--- | :--- |
| `6` | `"Fatal"` | `0` (emerg) | `21..24` (FATAL) |
| `5` | `"Critical"` | `1` (alert), `2` (crit) | — |
| `4` | `"High"` | `3` (err) | `17..20` (ERROR) |
| `3` | `"Medium"` | `4` (warning) | `13..16` (WARN) |
| `2` | `"Low"` | `5` (notice) | — |
| `1` | `"Informational"` | `6` (info), `7` (debug) | `1..12` (TRACE / DEBUG / INFO) |
| `0` | `"Unknown"` | missing / invalid (incl. zero-padded `"03"`) / out of range (`0..7`) | `0` / missing / invalid |

---

## Collector Field Mapping

| OCSF Path (Basin Type) | `systemd-journald` Source | OTLP Logs Source | Notes |
| :--- | :--- | :--- | :--- |
| `time` (`int64`) | `_SOURCE_REALTIME_TIMESTAMP` -> `__REALTIME_TIMESTAMP` -> `timestamp` -> `now()` | `timestamp` -> fallback `observed_timestamp` -> `now()` | Unix epoch **milliseconds** (`int64`, truncated via `floor` and bounded to `[1, 253402300799999]`; journald microsecond strings accept `[1000, 253402300799999999]`, numeric JSON integers require IEEE-754 safe range `[1000, 9007199254740991]`) |
| `time_dt` (`timestamp`, `millisecond`) | Formatted from `time` | Formatted from `time` | 4-digit UTC RFC 3339 string `"YYYY-MM-DDTHH:MM:SS.sssZ"` (`1970..9999`) |
| `message` (`string`) | `MESSAGE` / `message` | `body` / `message` | Primary log message |
| `log_name` (`string`) | `_SYSTEMD_UNIT` -> `SYSLOG_IDENTIFIER` | `scope.name` -> `resources["service.name"]` | Unit, identifier, or instrumentation scope |
| `log_provider` (`string`) | `_TRANSPORT` -> `"systemd-journald"` | `"opentelemetry"` | Telemetry source subsystem |
| `metadata.product` (`struct`) | Vector / Fluent Bit metadata | Vector / Fluent Bit metadata | `{ name, vendor_name }` |
| `metadata.original_event_uid` (`string`) | `__CURSOR` | `attributes["event.id"]` -> `span_id` | Source record locator |
| `metadata.correlation_uid` (`string`) | `TRACE_ID` / `OTEL_TRACE_ID` / `trace_id` | `trace_id` (16-byte binary or 32-char hex) | Lowercase hex; omitted when empty or all zeros (`0000...`) |
| `metadata.logged_time` (`int64`) | `__REALTIME_TIMESTAMP` -> `now()` | `observed_timestamp` -> `now()` | Collector ingestion epoch **milliseconds** (truncated via `floor` and bounded to `[1, 253402300799999]`; Fluent Bit `filter_lua` exposes `observed_timestamp` as IEEE-754 `double` ns before truncation) |
| `metadata.log_level` (`string`) | `PRIORITY` (string) | `severity_text` | Raw source severity text/code |
| `metadata.log_facility` (`string`) | `SYSLOG_FACILITY` | — | Syslog facility code |
| `device.type_id` / `type` | `1` / `"Server"` | `0` / `"Unknown"` | OCSF `device.type_id` is required |
| `device.hostname` (`string`) | `_HOSTNAME` -> `host` | `resources["host.name"]` -> `resources["service.instance.id"]` | Host identifier |
| `device.uid` (`string`) | `_MACHINE_ID` | `resources["host.id"]` | Host/machine unique ID |
| `device.os_machine_uuid` (`string`) | `_MACHINE_ID` | — | systemd machine UUID |
| `device.boot_uid` (`string`) | `_BOOT_ID` | — | Kernel boot UUID |
| `device.os` (`struct`) | `{ name: "Linux", type_id: 200 }` | Mapped from `resources["os.type"]` (`linux`=`200`, `windows`=`100`, `darwin`/`macos`=`300`) | OCSF requires both `name` and `type_id`; omitted on OTLP if unknown |
| `actor.process.pid` (`int64`) | `_PID` -> `SYSLOG_PID` | `resources["process.pid"]` -> `attributes["process.pid"]` | Strict base-10 non-negative integer |
| `actor.process.name` (`string`) | `_COMM` -> `SYSLOG_IDENTIFIER` | `resources["process.executable.name"]` -> `resources["service.name"]` | Process/service name |
| `actor.process.path` (`string`) | `_EXE` | `resources["process.executable.path"]` | Executable path |
| `actor.process.cmd_line` (`string`) | `_CMDLINE` | `resources["process.command_line"]` | Command line string |
| `actor.user.uid` (`string`) | `_UID` (string) | `attributes["user.id"]` -> `attributes["enduser.id"]` | OCSF `user.uid` is `string_t` |
| `actor.user.uid_numeric` (`int64`) | `_UID` (parsed int if `^[0-9]{1,15}$`) | `user.id` (parsed int if `^[0-9]{1,15}$`) | Only populated alongside `actor.user.uid` |
| `actor.user.name` (`string`) | — | `attributes["user.name"]` -> `attributes["user.full_name"]` | Username if present |
| `unmapped` (`json`) | Non-consumed fields + valid `span_id` | Non-consumed `attributes` / `resources` + valid `span_id` | Omitted (`null`) when empty; never serialized as `[]` |

---

## GitHub Actions Telemetry Mapping

Both [Vector GitHub Actions Webhook Collector](../../adapters/collect/vector-github-actions/vector.yaml) (`vector-github-actions`) and [GitHub Actions Direct Action](../../adapters/collect/github-actions-direct/emit-ocsf.mjs) (`github-actions-direct`) emit standard OCSF v1.3.0 `Event Log Activity` (`1008`, `activity_id = 99`, `type_uid = 100899`) with `log_provider = "github-actions"`:

| OCSF Path | GitHub Actions Source | Notes |
| :--- | :--- | :--- |
| `severity_id` / `severity` | `conclusion` / `status` / alert severity | `critical`=`5`, `failure`/`startup_failure`/`high`=`4`, `timed_out`/`action_required`/`medium`=`3`, `cancelled`/`skipped`/`low`=`2`, `success`/`queued`/`in_progress`=`1`, unknown=`0` |
| `log_name` | `"<owner>/<repo>:<workflow>"` | Falls back to `<owner>/<repo>` or webhook event name |
| `log_provider` | `"github-actions"` | Identifies CI/CD telemetry in `siem.ocsf_event_log_activity` |
| `metadata.original_event_uid` | `X-GitHub-Delivery` / `<run_id>:<run_attempt>:<job>` | Unique delivery or job execution identifier |
| `metadata.correlation_uid` | `OTEL_TRACE_ID` -> `run_id` | Links workflow runs, jobs, and optional APM traces |
| `device.type_id` / `type` | `1` / `"Server"` (self-hosted), `6` / `"Virtual"` (GitHub-hosted), `0` / `"Unknown"` | Runner execution environment |
| `device.hostname` | `runner_name` -> `repository.full_name` | Runner or repository identifier |
| `device.os` | Runner labels / `RUNNER_OS` | `linux`/`ubuntu`=`200`, `windows`=`100`, `macos`/`darwin`=`300`; omitted if unknown |
| `actor.user.name` / `uid` | `triggering_actor` -> `actor` -> `sender` -> `GITHUB_ACTOR` | Triggering user login and numeric ID |
| `unmapped` | `github_event`, `repository`, `workflow`, `job`, `run_id`, `run_attempt`, `trigger_event`, `is_fork_pr`, `is_self_hosted`, `duration_ms`, `queue_duration_ms`, `alert_rule`, `html_url` | Structured CI/CD observability & SIEM fields |
