#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DENYLIST_REGEXES=(
  '(^|[^A-Za-z0-9_])(mockall)(::|\b)'
  '(^|[^A-Za-z0-9_])(mockito)(::|\b)'
  '(^|[^A-Za-z0-9_])(wiremock)(::|\b)'
  '(^|[^A-Za-z0-9_])(httmock)(::|\b)'
  '(^|[^A-Za-z0-9_])(httpmock)(::|\b)'
  '(^|[^A-Za-z0-9_])(faux)(::|\b)'
  '(^|[^A-Za-z0-9_])(mockall_double)(::|\b)'
)

RESTRICTED_DIRS=(
  "crates/pt-core/src/collect"
  "crates/pt-core/src/inference"
  "crates/pt-core/src/decision"
  "crates/pt-core/src/plan"
  "crates/pt-core/src/action"
  "crates/pt-core/src/session"
  "crates/pt-core/src/supervision"
)

ALLOWLIST_PATHS=(
  "crates/pt-core/src/mock_process.rs"
  "crates/pt-core/src/test_utils.rs"
  "crates/pt-core/tests"
  "test"
)

if ! command -v rg >/dev/null 2>&1; then
  echo "Error: ripgrep (rg) is required for no-mock policy checks." >&2
  exit 2
fi

RG_EXCLUDES=()
for path in "${ALLOWLIST_PATHS[@]}"; do
  RG_EXCLUDES+=("--glob" "!${path}")
  RG_EXCLUDES+=("--glob" "!${path}/**")
done

found=0
for pattern in "${DENYLIST_REGEXES[@]}"; do
  matches=$(rg -n -S --glob '*.rs' "${RG_EXCLUDES[@]}" "$pattern" "${RESTRICTED_DIRS[@]}" || true)
  if [[ -n "$matches" ]]; then
    echo "Forbidden mock usage matched regex: $pattern" >&2
    echo "$matches" >&2
    found=1
  fi
done

if [[ $found -ne 0 ]]; then
  echo "No-mock policy: FAILED" >&2
  exit 1
fi

echo "No-mock policy: OK"
