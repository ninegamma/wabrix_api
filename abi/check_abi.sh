#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd -- "${PROJECT_ROOT}"

if ! command -v cargo >/dev/null 2>&1; then
    printf 'ERROR: cargo not found in PATH\n' >&2
    exit 127
fi

printf '==> Cargo check (runs C and C/Rust ABI checks for wabrix_api)\n'
if WABRIX_API_ABI_VERBOSE=1 cargo check --locked --manifest-path "${PROJECT_ROOT}/Cargo.toml"; then
    printf 'PASS: Cargo compilation and ABI checks\n'
else
    status=$?
    printf 'FAIL: Cargo compilation or ABI checks (exit %s)\n' "${status}" >&2
    exit "${status}"
fi
