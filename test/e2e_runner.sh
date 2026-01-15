#!/usr/bin/env bash
# E2E runner harness: executes BATS E2E suites with JSONL metadata + artifacts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ROOT_DIR/target/test-logs/e2e}"
LOG_DIR="$ARTIFACT_ROOT/logs"

mkdir -p \
    "$ARTIFACT_ROOT" \
    "$ARTIFACT_ROOT/artifacts" \
    "$ARTIFACT_ROOT/snapshots" \
    "$ARTIFACT_ROOT/plans" \
    "$ARTIFACT_ROOT/telemetry" \
    "$LOG_DIR"

export BATS_TEST_TMPDIR="${BATS_TEST_TMPDIR:-$ARTIFACT_ROOT/bats-tmp}"
export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
mkdir -p "$BATS_TEST_TMPDIR"

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

BATS_ARGS=()
if [[ "$#" -eq 0 ]]; then
    BATS_ARGS=("$ROOT_DIR/test/pt_e2e_real.bats")
else
    BATS_ARGS=("$@")
fi

start_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
start_epoch=$(date +%s)

set +e
bats --tap "${BATS_ARGS[@]}" > "$LOG_DIR/bats.tap" 2> "$LOG_DIR/bats.stderr"
status=$?
set -e

end_epoch=$(date +%s)
end_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

duration_s=$((end_epoch - start_epoch))
tap_esc=$(json_escape "$LOG_DIR/bats.tap")
stderr_esc=$(json_escape "$LOG_DIR/bats.stderr")

printf '{"ts":"%s","event":"bats_complete","status":%s,"duration_s":%s,"start_ts":"%s","tap":"%s","stderr":"%s"}\n' \
    "$end_ts" \
    "$status" \
    "$duration_s" \
    "$start_ts" \
    "$tap_esc" \
    "$stderr_esc" \
    >> "$LOG_DIR/e2e_runner.jsonl"

echo "E2E run completed at $end_ts (status=$status, duration=${duration_s}s)"
exit "$status"
