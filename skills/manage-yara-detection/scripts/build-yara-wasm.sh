#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CRATE_MANIFEST="${REPO_ROOT}/adapters/detect/yara-wasm/Cargo.toml"
WASM_TARGET="wasm32-unknown-unknown"
WASM_OUT="${REPO_ROOT}/adapters/detect/yara-wasm/target/${WASM_TARGET}/release/oof_yara_wasm.wasm"
RULES_SRC="${REPO_ROOT}/rules/yara/linux_journal_core.yar"
WORKER_WASM_DIR="${REPO_ROOT}/adapters/ingest/cloudflare-worker-basin/src/wasm"
WORKER_WASM_DEST="${WORKER_WASM_DIR}/oof_yara_wasm.wasm"
WORKER_RULES_DIR="${REPO_ROOT}/adapters/ingest/cloudflare-worker-basin/src/rules"
WORKER_RULES_DEST="${WORKER_RULES_DIR}/linux_journal_core.yar"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required to build oof-yara-wasm" >&2
  exit 1
fi

has_host_cc=false
if command -v cc >/dev/null 2>&1 || [[ -n "${CC:-}" ]]; then
  has_host_cc=true
fi

has_wasm_lld=false
if command -v lld >/dev/null 2>&1 || command -v wasm-ld >/dev/null 2>&1 || command -v rust-lld >/dev/null 2>&1; then
  has_wasm_lld=true
fi

echo "[oof] Building oof-yara-wasm for ${WASM_TARGET}..."
if [[ "${has_host_cc}" == true ]] && [[ "${has_wasm_lld}" == true ]]; then
  cargo build --manifest-path "${CRATE_MANIFEST}" --target "${WASM_TARGET}" --release
elif command -v nix >/dev/null 2>&1; then
  nix shell nixpkgs#gcc nixpkgs#lld -c cargo build --manifest-path "${CRATE_MANIFEST}" --target "${WASM_TARGET}" --release
else
  echo "error: C linker (cc) and WASM linker (lld/wasm-ld) are required in PATH" >&2
  exit 1
fi

if [[ ! -f "${WASM_OUT}" ]]; then
  echo "error: expected WASM artifact at ${WASM_OUT}" >&2
  exit 1
fi

mkdir -p "${WORKER_WASM_DIR}" "${WORKER_RULES_DIR}"
cp "${WASM_OUT}" "${WORKER_WASM_DEST}"
cp "${RULES_SRC}" "${WORKER_RULES_DEST}"

SIZE_BYTES="$(wc -c < "${WORKER_WASM_DEST}" | tr -d ' ')"
echo "[oof] Copied ${WORKER_WASM_DEST} (${SIZE_BYTES} bytes) and synced ${WORKER_RULES_DEST}"
