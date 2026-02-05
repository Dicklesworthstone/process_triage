#!/usr/bin/env bats
# E2E inference regression: agent plan with fixture config + ledger fields.

load "./test_helper/common.bash"

PT_CORE="${BATS_TEST_DIRNAME}/../target/release/pt-core"
PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup_file() {
    if [[ ! -x "$PT_CORE" ]]; then
        echo "# Building pt-core..." >&3
        (cd "$PROJECT_ROOT" && cargo build --release 2>/dev/null) || {
            echo "ERROR: Failed to build pt-core" >&2
            exit 1
        }
    fi
}

setup() {
    setup_test_env
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export PROCESS_TRIAGE_DATA="$TEST_DIR/data"
    mkdir -p "$PROCESS_TRIAGE_DATA"

    cp "$PROJECT_ROOT/test/fixtures/config/valid_priors.json" "$CONFIG_DIR/priors.json"
    cp "$PROJECT_ROOT/test/fixtures/config/valid_policy.json" "$CONFIG_DIR/policy.json"

    test_start "$BATS_TEST_NAME" "E2E inference fixture run"
}

teardown() {
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    teardown_test_env
}

require_jq() {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        skip "jq not installed"
    fi
}

log_inference_event() {
    local case_id="$1"
    local command="$2"
    local exit_code="$3"
    local duration_ms="$4"
    local artifact_path="$5"

    if [[ -z "${TEST_LOG_FILE:-}" ]]; then
        return 0
    fi

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local command_esc
    local artifact_esc
    command_esc=$(json_escape "$command")
    artifact_esc=$(json_escape "$artifact_path")

    printf '{"event":"inference_e2e","timestamp":"%s","phase":"e2e","case_id":"%s","command":"%s","exit_code":%s,"duration_ms":%s,"artifacts":[{"path":"%s","kind":"output"}]}' \
        "$ts" \
        "$case_id" \
        "$command_esc" \
        "$exit_code" \
        "$duration_ms" \
        "$artifact_esc" \
        >> "$TEST_LOG_FILE"
    printf '\n' >> "$TEST_LOG_FILE"
}

@test "agent plan emits ledger fields with fixture config" {
    require_jq

    local output_path="$TEST_DIR/agent_plan.json"
    local stderr_path="$TEST_DIR/agent_plan.stderr"
    local cmd_str="\"$PT_CORE\" -f json agent plan --min-posterior 0 --max-candidates 5 --sample-size 5 > \"$output_path\" 2> \"$stderr_path\""

    local start_ms
    start_ms=$(date +%s%3N)
    run bash -c "$cmd_str"
    local status_code=$status
    local end_ms
    end_ms=$(date +%s%3N)
    local duration_ms=$((end_ms - start_ms))

    log_inference_event "agent_plan_fixture" "$cmd_str" "$status_code" "$duration_ms" "$output_path"

    if [[ "$status_code" -ge 10 ]]; then
        test_error "pt-core agent plan failed (status=$status_code)"
        return 1
    fi

    local schema_version
    schema_version=$(jq -r '.schema_version // empty' "$output_path")
    [[ -n "$schema_version" ]]

    local candidates_len
    candidates_len=$(jq '.candidates | length' "$output_path")
    [[ "$candidates_len" -ge 0 ]]

    if [[ "$candidates_len" -gt 0 ]]; then
        jq -e '.candidates[0] | has("classification") and has("confidence") and has("evidence")' "$output_path" >/dev/null
        jq -e '.candidates[0].evidence | type == "array"' "$output_path" >/dev/null
        jq -e '.candidates[0].evidence[0] | has("factor") and has("detail") and has("strength")' "$output_path" >/dev/null
    fi

    BATS_TEST_COMPLETED=pass
}
