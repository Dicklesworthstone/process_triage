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

if ! command -v bats >/dev/null 2>&1; then
    printf 'E2E runner requires bats (command not found)\n' >&2
    exit 127
fi

export BATS_TEST_TMPDIR="${BATS_TEST_TMPDIR:-$ARTIFACT_ROOT/bats-tmp}"
export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export TEST_LOG_FILE="${TEST_LOG_FILE:-$LOG_DIR/e2e_tests.jsonl}"
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

run_id_suffix=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 4 || true)
if [[ -z "$run_id_suffix" ]]; then
    run_id_suffix="0000"
fi
run_id="e2e-$(date -u '+%Y%m%d%H%M%S')-${run_id_suffix}"
export E2E_RUN_ID="$run_id"

start_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
start_epoch=$(date +%s)
git_sha=$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "")
os_name=$(uname -s 2>/dev/null || echo "unknown")
arch_name=$(uname -m 2>/dev/null || echo "unknown")
bats_version=$(bats --version 2>/dev/null || echo "")
args_joined=$(printf '%s ' "${BATS_ARGS[@]}")
args_joined=${args_joined% }
args_esc=$(json_escape "$args_joined")
run_id_esc=$(json_escape "$run_id")
git_sha_esc=$(json_escape "$git_sha")
os_esc=$(json_escape "$os_name")
arch_esc=$(json_escape "$arch_name")
bats_esc=$(json_escape "$bats_version")
artifact_root_esc=$(json_escape "$ARTIFACT_ROOT")
log_dir_esc=$(json_escape "$LOG_DIR")
printf '{"ts":"%s","event":"bats_start","run_id":"%s","git_sha":"%s","os":"%s","arch":"%s","bats_version":"%s","args":"%s","artifact_root":"%s","log_dir":"%s"}\n' \
    "$start_ts" \
    "$run_id_esc" \
    "$git_sha_esc" \
    "$os_esc" \
    "$arch_esc" \
    "$bats_esc" \
    "$args_esc" \
    "$artifact_root_esc" \
    "$log_dir_esc" \
    >> "$LOG_DIR/e2e_runner.jsonl"

set +e
tap_path="$LOG_DIR/bats.tap"
stderr_path="$LOG_DIR/bats.stderr"
bats --tap "${BATS_ARGS[@]}" > "$tap_path" 2> "$stderr_path"
status=$?
set -e

end_epoch=$(date +%s)
end_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

duration_s=$((end_epoch - start_epoch))
tap_esc=$(json_escape "$tap_path")
stderr_esc=$(json_escape "$stderr_path")
tap_bytes=$(wc -c < "$tap_path" 2>/dev/null | tr -d ' ' || echo "0")
stderr_bytes=$(wc -c < "$stderr_path" 2>/dev/null | tr -d ' ' || echo "0")
tap_total=0
tap_failed=0
tap_skipped=0
if [[ -f "$tap_path" ]]; then
    tap_total=$(awk '/^(ok|not ok) / { count++ } END { print count + 0 }' "$tap_path")
    tap_failed=$(awk '/^not ok / { count++ } END { print count + 0 }' "$tap_path")
    tap_skipped=$(awk '/^ok / && tolower($0) ~ /#[[:space:]]+skip([[:space:]]|$)/ { count++ } END { print count + 0 }' "$tap_path")
fi

printf '{"ts":"%s","event":"bats_complete","run_id":"%s","status":%s,"duration_s":%s,"start_ts":"%s","tap":"%s","stderr":"%s","tap_bytes":%s,"stderr_bytes":%s,"tap_total":%s,"tap_failed":%s,"tap_skipped":%s}\n' \
    "$end_ts" \
    "$run_id_esc" \
    "$status" \
    "$duration_s" \
    "$start_ts" \
    "$tap_esc" \
    "$stderr_esc" \
    "$tap_bytes" \
    "$stderr_bytes" \
    "$tap_total" \
    "$tap_failed" \
    "$tap_skipped" \
    >> "$LOG_DIR/e2e_runner.jsonl"

printf '{"ts":"%s","event":"bats_metadata","run_id":"%s","git_sha":"%s","os":"%s","arch":"%s","args":"%s"}\n' \
    "$end_ts" \
    "$run_id_esc" \
    "$git_sha_esc" \
    "$os_esc" \
    "$arch_esc" \
    "$args_esc" \
    >> "$LOG_DIR/e2e_runner.jsonl"
echo "E2E run completed at $end_ts (status=$status, duration=${duration_s}s)"
exit "$status"
