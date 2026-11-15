#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SCHEMA_FILE="${REPO_ROOT}/contracts/schemas/journal-logs.basin.json"
SQL_TEMPLATE="${SCRIPT_DIR}/pipeline.sql"

BUCKET="oof-telemetry"
NAMESPACE="siem"
TABLE="journal_logs"
STREAM="journal_stream"
SINK="journal_iceberg_sink"
PIPELINE="journal_to_iceberg"
ROLL_INTERVAL="60"
CATALOG_TOKEN="${BASIN_CATALOG_TOKEN:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: provision-basin.sh [options]

Provision Cloudflare R2 Bucket + Basin Catalog + Basin Stream + Iceberg Sink + Pipeline.

Options:
  --bucket <name>          R2 bucket name (default: oof-telemetry)
  --namespace <name>       Iceberg catalog namespace (default: siem)
  --table <name>           Iceberg table name (default: journal_logs)
  --stream <name>          Basin stream name (default: journal_stream)
  --sink <name>            Basin sink name (default: journal_iceberg_sink)
  --pipeline <name>        Basin pipeline name (default: journal_to_iceberg)
  --roll-interval <secs>   Sink commit interval in seconds (default: 60)
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

validate_resource_name() {
  local label="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]]; then
    echo "error: invalid ${label} '${value}' (expected ^[a-zA-Z0-9][a-zA-Z0-9_-]*$)" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

validate_resource_name "bucket" "${BUCKET}"
validate_resource_name "pipeline" "${PIPELINE}"
validate_sql_ident "namespace" "${NAMESPACE}"
validate_sql_ident "table" "${TABLE}"
validate_sql_ident "stream" "${STREAM}"
validate_sql_ident "sink" "${SINK}"

if [[ ! "${ROLL_INTERVAL}" =~ ^[0-9]+$ ]] || [[ "${ROLL_INTERVAL}" -lt 1 ]]; then
  echo "error: invalid --roll-interval '${ROLL_INTERVAL}' (expected positive integer)" >&2
  exit 1
fi

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

RENDERED_SQL="$(mktemp "${TMPDIR:-/tmp}/oof-pipeline.XXXXXX.sql")"
cleanup() {
  rm -f "${RENDERED_SQL}"
}
trap cleanup EXIT

sed -e "s/__SINK_NAME__/${SINK}/g" -e "s/__STREAM_NAME__/${STREAM}/g" "${SQL_TEMPLATE}" > "${RENDERED_SQL}"

if [[ "${DRY_RUN}" == true ]]; then
  cat <<EOF
# [dry-run] Cloudflare Basin Iceberg Provisioning Plan
# Bucket:    ${BUCKET}
# Namespace: ${NAMESPACE}
# Table:     ${TABLE}
# Stream:    ${STREAM}
# Sink:      ${SINK}
# Pipeline:  ${PIPELINE}

npx wrangler r2 bucket create "${BUCKET}"
npx wrangler r2 bucket catalog enable "${BUCKET}"
npx wrangler basin pipelines streams create "${STREAM}" \\
  --schema-file "${SCHEMA_FILE}"
npx wrangler basin pipelines sinks create "${SINK}" \\
  --type basin-catalog \\
  --bucket "${BUCKET}" \\
  --namespace "${NAMESPACE}" \\
  --table "${TABLE}" \\
  --roll-interval "${ROLL_INTERVAL}" \\
  --catalog-token "<BASIN_CATALOG_TOKEN>"
npx wrangler basin pipelines create "${PIPELINE}" \\
  --sql-file "${RENDERED_SQL}"

# Rendered Pipeline SQL (${RENDERED_SQL}):
EOF
  cat "${RENDERED_SQL}"
  exit 0
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx (Node.js) is required to run wrangler" >&2
  exit 1
fi

echo "[oof] Creating R2 bucket '${BUCKET}' (if not already present)..."
npx wrangler r2 bucket create "${BUCKET}" || true

echo "[oof] Enabling Basin / R2 Data Catalog on '${BUCKET}'..."
npx wrangler r2 bucket catalog enable "${BUCKET}" || true

echo "[oof] Creating Basin stream '${STREAM}'..."
npx wrangler basin pipelines streams create "${STREAM}" \
  --schema-file "${SCHEMA_FILE}"

echo "[oof] Creating Basin Iceberg sink '${SINK}' -> ${NAMESPACE}.${TABLE}..."
npx wrangler basin pipelines sinks create "${SINK}" \
  --type basin-catalog \
  --bucket "${BUCKET}" \
  --namespace "${NAMESPACE}" \
  --table "${TABLE}" \
  --roll-interval "${ROLL_INTERVAL}" \
  --catalog-token "${CATALOG_TOKEN}"

echo "[oof] Creating Basin pipeline '${PIPELINE}'..."
npx wrangler basin pipelines create "${PIPELINE}" \
  --sql-file "${RENDERED_SQL}"

echo "[oof] Provisioning complete. Next: bind stream '${STREAM}' to TELEMETRY_STREAM in wrangler.jsonc and deploy the Worker."
