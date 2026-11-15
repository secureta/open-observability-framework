#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SCHEMA_FILE="${REPO_ROOT}/contracts/ocsf/event-log-activity.basin.json"
SQL_TEMPLATE="${SCRIPT_DIR}/pipeline.sql"

BUCKET="oof-telemetry"
NAMESPACE="siem"
TABLE="ocsf_event_log_activity"
STREAM="ocsf_event_log_stream"
SINK="ocsf_event_log_sink"
PIPELINE="ocsf_event_log_to_iceberg"
ROLL_INTERVAL="60"
CATALOG_TOKEN="${BASIN_CATALOG_TOKEN:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: provision-basin.sh [options]

Provision Cloudflare R2 Bucket + Basin Catalog + Authenticated OCSF Basin Stream + Iceberg Sink + Pipeline.

Options:
  --schema-file <path>     Basin stream JSON schema (default: contracts/ocsf/event-log-activity.basin.json)
  --bucket <name>          R2 bucket name (default: oof-telemetry)
  --namespace <name>       Iceberg catalog namespace (default: siem)
  --table <name>           Iceberg table name (default: ocsf_event_log_activity)
  --stream <name>          Basin stream name (default: ocsf_event_log_stream)
  --sink <name>            Basin sink name (default: ocsf_event_log_sink)
  --pipeline <name>        Basin pipeline name (default: ocsf_event_log_to_iceberg)
  --roll-interval <secs>   Sink commit interval in seconds (default: 60, min: 60)
  --catalog-token <token>  Basin catalog API token (or set BASIN_CATALOG_TOKEN env var)
  --dry-run                Validate inputs and print Wrangler commands without executing
  -h, --help               Show this help
EOF
}

validate_sql_ident() {
  local label="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    echo "error: invalid ${label} '${value}' (expected ^[a-zA-Z_][a-zA-Z0-9_]*$)" >&2
    exit 1
  fi
}

validate_bucket_name() {
  local value="$1"
  if [[ ! "${value}" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]]; then
    echo "error: invalid bucket '${value}' (expected 3-63 lowercase letters, numbers, or hyphens starting/ending with alphanumeric)" >&2
    exit 1
  fi
}

validate_entity_name() {
  local label="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "error: invalid ${label} '${value}' (expected ^[a-zA-Z0-9_]+$)" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema-file)
      [[ $# -ge 2 ]] || { echo "error: --schema-file requires a value" >&2; exit 1; }
      SCHEMA_FILE="$2"
      shift 2
      ;;
    --bucket)
      [[ $# -ge 2 ]] || { echo "error: --bucket requires a value" >&2; exit 1; }
      BUCKET="$2"
      shift 2
      ;;
    --namespace)
      [[ $# -ge 2 ]] || { echo "error: --namespace requires a value" >&2; exit 1; }
      NAMESPACE="$2"
      shift 2
      ;;
    --table)
      [[ $# -ge 2 ]] || { echo "error: --table requires a value" >&2; exit 1; }
      TABLE="$2"
      shift 2
      ;;
    --stream)
      [[ $# -ge 2 ]] || { echo "error: --stream requires a value" >&2; exit 1; }
      STREAM="$2"
      shift 2
      ;;
    --sink)
      [[ $# -ge 2 ]] || { echo "error: --sink requires a value" >&2; exit 1; }
      SINK="$2"
      shift 2
      ;;
    --pipeline)
      [[ $# -ge 2 ]] || { echo "error: --pipeline requires a value" >&2; exit 1; }
      PIPELINE="$2"
      shift 2
      ;;
    --roll-interval)
      [[ $# -ge 2 ]] || { echo "error: --roll-interval requires a value" >&2; exit 1; }
      ROLL_INTERVAL="$2"
      shift 2
      ;;
    --catalog-token)
      [[ $# -ge 2 ]] || { echo "error: --catalog-token requires a value" >&2; exit 1; }
      CATALOG_TOKEN="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_bucket_name "${BUCKET}"
validate_entity_name "pipeline" "${PIPELINE}"
validate_sql_ident "namespace" "${NAMESPACE}"
validate_sql_ident "table" "${TABLE}"
validate_sql_ident "stream" "${STREAM}"
validate_sql_ident "sink" "${SINK}"

if [[ ! "${ROLL_INTERVAL}" =~ ^[0-9]+$ ]]; then
  echo "error: invalid --roll-interval '${ROLL_INTERVAL}' (expected integer between 60 and 2147483647 for r2-data-catalog sinks)" >&2
  exit 1
fi
ROLL_INTERVAL_NORM="${ROLL_INTERVAL#"${ROLL_INTERVAL%%[!0]*}"}"
ROLL_INTERVAL_NORM="${ROLL_INTERVAL_NORM:-0}"
if (( ${#ROLL_INTERVAL_NORM} > 10 )) || (( 10#${ROLL_INTERVAL_NORM} < 60 || 10#${ROLL_INTERVAL_NORM} > 2147483647 )); then
  echo "error: invalid --roll-interval '${ROLL_INTERVAL}' (expected integer between 60 and 2147483647 for r2-data-catalog sinks)" >&2
  exit 1
fi
ROLL_INTERVAL="${ROLL_INTERVAL_NORM}"

if [[ ! -f "${SCHEMA_FILE}" ]]; then
  echo "error: missing schema file at ${SCHEMA_FILE}" >&2
  exit 1
fi

if [[ ! -f "${SQL_TEMPLATE}" ]]; then
  echo "error: missing SQL template at ${SQL_TEMPLATE}" >&2
  exit 1
fi

if [[ "${DRY_RUN}" == false ]] && [[ -z "${CATALOG_TOKEN}" ]]; then
  echo "error: BASIN_CATALOG_TOKEN (or --catalog-token) is required for live provisioning" >&2
  exit 1
fi

run_wrangler() {
  if command -v wrangler >/dev/null 2>&1; then
    wrangler "$@"
  else
    npx wrangler "$@"
  fi
}

run_wrangler_idempotent() {
  local out=""
  local rc=0
  set +e
  out="$(run_wrangler "$@" 2>&1)"
  rc=$?
  set -e
  if [[ -n "${out}" ]]; then
    printf '%s\n' "${out}"
  fi
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${out}" =~ [Aa]lready[[:space:]]+(exists|enabled) ]]; then
    return 0
  fi
  echo "error: wrangler command failed (exit ${rc})" >&2
  return "${rc}"
}

RENDERED_SQL="$(mktemp "${TMPDIR:-/tmp}/oof-pipeline.XXXXXX.sql")"
cleanup() {
  rm -f "${RENDERED_SQL}"
}
trap cleanup EXIT

sed -e "s/__SINK_NAME__/${SINK}/g" -e "s/__STREAM_NAME__/${STREAM}/g" "${SQL_TEMPLATE}" > "${RENDERED_SQL}"

if [[ "${DRY_RUN}" == true ]]; then
  cat <<EOF
# [dry-run] Cloudflare Basin Iceberg Provisioning Plan (Direct Basin HTTP + OCSF)
# Schema:    ${SCHEMA_FILE}
# Bucket:    ${BUCKET}
# Namespace: ${NAMESPACE}
# Table:     ${TABLE}
# Stream:    ${STREAM}
# Sink:      ${SINK}
# Pipeline:  ${PIPELINE}

npx wrangler r2 bucket create "${BUCKET}"
npx wrangler basin catalog enable "${BUCKET}"
# Direct Basin HTTP ingest enabled with native API token auth (--http-enabled true --http-auth true).
# streams create outputs an Endpoint URL (https://<STREAM_ID>.ingest.cloudflare.com).
npx wrangler basin pipelines streams create "${STREAM}" \\
  --schema-file "${SCHEMA_FILE}" \\
  --http-enabled true \\
  --http-auth true
npx wrangler basin pipelines sinks create "${SINK}" \\
  --type r2-data-catalog \\
  --bucket "${BUCKET}" \\
  --namespace "${NAMESPACE}" \\
  --table "${TABLE}" \\
  --roll-interval "${ROLL_INTERVAL}" \\
  --catalog-token "<BASIN_CATALOG_TOKEN>"
npx wrangler basin pipelines create "${PIPELINE}" \\
  --sql-file "${RENDERED_SQL}"

# Post-provisioning sender auth setup:
# 1. Create a Cloudflare Account API Token scoped to Account -> Basin Pipelines -> Send.
# 2. For Vector:     OOF_BASIN_ENDPOINT="https://<STREAM_ID>.ingest.cloudflare.com" OOF_INGEST_TOKEN="<API_TOKEN>"
# 3. For Fluent Bit: OOF_BASIN_HOST="<STREAM_ID>.ingest.cloudflare.com" OOF_INGEST_TOKEN="<API_TOKEN>"

# Rendered Pipeline SQL (${RENDERED_SQL}):
EOF
  cat "${RENDERED_SQL}"
  exit 0
fi

if ! command -v wrangler >/dev/null 2>&1 && ! command -v npx >/dev/null 2>&1; then
  echo "error: wrangler or npx (Node.js) is required to run Cloudflare Wrangler" >&2
  exit 1
fi

echo "[oof] Creating R2 bucket '${BUCKET}' (if not already present)..."
run_wrangler_idempotent r2 bucket create "${BUCKET}"

echo "[oof] Enabling Basin Catalog on '${BUCKET}'..."
run_wrangler_idempotent basin catalog enable "${BUCKET}"

echo "[oof] Creating authenticated HTTP Basin stream '${STREAM}'..."
STREAM_CREATE_OUT="$(NO_COLOR=1 run_wrangler basin pipelines streams create "${STREAM}" \
  --schema-file "${SCHEMA_FILE}" \
  --http-enabled true \
  --http-auth true)"
printf '%s\n' "${STREAM_CREATE_OUT}"

ANSI_ESC=$'\033'
STREAM_CREATE_CLEAN="$(printf '%s\n' "${STREAM_CREATE_OUT}" | sed "s/${ANSI_ESC}\\[[0-9;]*m//g")"
STREAM_ID=""
STREAM_ENDPOINT=""
id_pattern="with id '([^']+)'"
endpoint_pattern="Endpoint:[[:space:]]+(https://[^[:space:]]+)"
if [[ "${STREAM_CREATE_CLEAN}" =~ ${id_pattern} ]]; then
  STREAM_ID="${BASH_REMATCH[1]}"
fi
if [[ "${STREAM_CREATE_CLEAN}" =~ ${endpoint_pattern} ]]; then
  STREAM_ENDPOINT="${BASH_REMATCH[1]}"
elif [[ -n "${STREAM_ID}" ]]; then
  STREAM_ENDPOINT="https://${STREAM_ID}.ingest.cloudflare.com"
fi

echo "[oof] Creating Basin Iceberg sink '${SINK}' -> ${NAMESPACE}.${TABLE}..."
run_wrangler basin pipelines sinks create "${SINK}" \
  --type r2-data-catalog \
  --bucket "${BUCKET}" \
  --namespace "${NAMESPACE}" \
  --table "${TABLE}" \
  --roll-interval "${ROLL_INTERVAL}" \
  --catalog-token "${CATALOG_TOKEN}"

echo "[oof] Creating Basin pipeline '${PIPELINE}'..."
run_wrangler basin pipelines create "${PIPELINE}" \
  --sql-file "${RENDERED_SQL}"

echo "[oof] Provisioning complete."
echo "[oof] Next: create a Cloudflare Account API Token with 'Account -> Basin Pipelines -> Send' permission."
if [[ -n "${STREAM_ENDPOINT}" ]]; then
  STREAM_HOST="${STREAM_ENDPOINT#https://}"
  STREAM_HOST="${STREAM_HOST%%/*}"
  echo "[oof]   Vector:     export OOF_BASIN_ENDPOINT='${STREAM_ENDPOINT}' OOF_INGEST_TOKEN='<API_TOKEN>'"
  echo "[oof]   Fluent Bit: export OOF_BASIN_HOST='${STREAM_HOST}' OOF_INGEST_TOKEN='<API_TOKEN>'"
else
  echo "[oof]   Run 'npx wrangler basin pipelines streams get ${STREAM}' to inspect your HTTPS Endpoint for Vector/Fluent Bit."
fi
