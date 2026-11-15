# Host-Side YARA-X / Kunai Detection Adapter (`host-agent`)

Use this pattern when you want YARA scanning on **files, memory, or process artifacts on the Linux host** (instead of or in addition to edge WASM scanning of `journald` log streams), while keeping the exact same Cloudflare Basin Iceberg pipeline and schema.

## Option A: Kunai + YARA

Configure Kunai to emit JSON events with YARA file scan results to stdout (collected by `systemd-journald` or Vector):

- Set `yara` rules path to `rules/yara/linux_journal_core.yar` (or your malware rule directory).
- Vector (`adapters/collect/vector-journald/vector.yaml`) automatically preserves `yara_rules` and `yara_tags` if emitted as JSON in `journald` `MESSAGE` or structured fields.

## Option B: YARA-X CLI (`yr`) -> `systemd-cat` / `journald`

Emit host scan findings directly into `journald` as structured JSON so Vector and the Cloudflare Worker ingest them into `journal_logs` / `yara_detections`:

```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="${1:-/etc/oof/rules/linux_journal_core.yar}"
TARGET_PATH="${2:-/tmp}"

# Requires yara-x CLI (`yr`) >= 1.x
yr scan --output-format json "${RULES_FILE}" "${TARGET_PATH}" | \
  jq -c --arg host "$(hostname -f)" '
    select((.matches | length) > 0) |
    {
      host: $host,
      service_name: "host-yara-x",
      priority: 2,
      severity: "CRIT",
      message: ("YARA-X host match on " + (.path // "unknown")),
      yara_matched: true,
      yara_rules: [.matches[].identifier],
      yara_tags: ([.matches[].tags[]?] | unique),
      attributes_json: ({ target_path: .path, detector: "host-yara-x" } | tojson)
    }
  ' | systemd-cat -t oof-yara-x -p crit
```

When `detect.placement` is `hybrid`, the Cloudflare Worker (`adapters/ingest/cloudflare-worker-basin/`) merges upstream `yara_rules` / `yara_tags` from `host-yara-x` with any additional edge WASM rule matches.
