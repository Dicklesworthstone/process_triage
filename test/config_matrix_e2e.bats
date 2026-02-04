#!/usr/bin/env bats
# E2E config resolution + validation matrix with JSONL logging.
# See: bd-m3zh

load "./test_helper/common.bash"

setup() {
    setup_test_env

    local test_file_dir
    test_file_dir="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$test_file_dir")"
    PATH="$PROJECT_ROOT:$PATH"

    export ARTIFACT_DIR="$TEST_DIR/artifacts"
    export ARTIFACT_LOG_DIR="$ARTIFACT_DIR/logs"
    export ARTIFACT_STDOUT_DIR="$ARTIFACT_DIR/stdout"
    export ARTIFACT_STDERR_DIR="$ARTIFACT_DIR/stderr"
    export ARTIFACT_FIXTURE_DIR="$ARTIFACT_DIR/fixtures"
    mkdir -p \
        "$ARTIFACT_DIR" \
        "$ARTIFACT_LOG_DIR" \
        "$ARTIFACT_STDOUT_DIR" \
        "$ARTIFACT_STDERR_DIR" \
        "$ARTIFACT_FIXTURE_DIR"

    if [[ -z "${TEST_LOG_FILE:-}" ]]; then
        export TEST_LOG_FILE="$ARTIFACT_LOG_DIR/config_matrix.jsonl"
    else
        export TEST_LOG_FILE_SECONDARY="$ARTIFACT_LOG_DIR/config_matrix.jsonl"
    fi

    FIXTURES_DIR="$PROJECT_ROOT/crates/pt-config/tests/fixtures"

    test_start "config matrix" "resolution precedence + validation"
    test_info "Artifacts: $ARTIFACT_DIR"
}

teardown() {
    teardown_test_env
    test_end "config matrix" "pass"
}

write_config_dir() {
    local target_dir="$1"
    mkdir -p "$target_dir"
    cp "$FIXTURES_DIR/valid_priors.json" "$target_dir/priors.json"
    cp "$FIXTURES_DIR/valid_policy.json" "$target_dir/policy.json"
}

write_invalid_policy_dir() {
    local target_dir="$1"
    mkdir -p "$target_dir"
    cp "$FIXTURES_DIR/valid_priors.json" "$target_dir/priors.json"
    cp "$FIXTURES_DIR/invalid_policy_missing_pid1.json" "$target_dir/policy.json"
}

log_case_event() {
    local event="$1"
    local case_id="$2"
    local cmd="$3"
    local exit_code="$4"
    local duration_ms="$5"
    local out_file="$6"
    local err_file="$7"
    local schema_version="$8"
    local config_snapshot_path="$9"
    local validation_error="${10}"
    local fixture_path="${11:-}"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local cmd_esc
    local out_esc
    local err_esc
    local schema_esc
    local config_esc
    local error_esc
    local run_id_field
    local run_id_esc
    cmd_esc=$(json_escape "$cmd")
    out_esc=$(json_escape "$out_file")
    err_esc=$(json_escape "$err_file")
    schema_esc=$(json_escape "$schema_version")
    config_esc=$(json_escape "$config_snapshot_path")
    error_esc=$(json_escape "$validation_error")
    run_id_field=""
    if [[ -n "${E2E_RUN_ID:-}" ]]; then
        run_id_esc=$(json_escape "$E2E_RUN_ID")
        run_id_field=",\"run_id\":\"${run_id_esc}\""
    fi

    local artifacts_json
    artifacts_json="["
    if [[ -f "$out_file" ]]; then
        artifacts_json+="{\"path\":\"${out_esc}\",\"kind\":\"stdout\"}"
    fi
    if [[ -f "$err_file" ]]; then
        if [[ "$artifacts_json" != "[" ]]; then
            artifacts_json+=","
        fi
        artifacts_json+="{\"path\":\"${err_esc}\",\"kind\":\"stderr\"}"
    fi
    if [[ -n "$fixture_path" ]]; then
        local fixture_esc
        fixture_esc=$(json_escape "$fixture_path")
        if [[ "$artifacts_json" != "[" ]]; then
            artifacts_json+=","
        fi
        artifacts_json+="{\"path\":\"${fixture_esc}\",\"kind\":\"fixture\"}"
    fi
    artifacts_json+="]"

    printf '{"ts":"%s","event":"%s","case_id":"%s","command":"%s","exit_code":%s,"duration_ms":%s,"config_snapshot_path":"%s","schema_version":"%s","validation_error":"%s","artifacts":%s%s}\n' \
        "$ts" \
        "$event" \
        "$(json_escape "$case_id")" \
        "$cmd_esc" \
        "$exit_code" \
        "$duration_ms" \
        "$config_esc" \
        "$schema_esc" \
        "$error_esc" \
        "$artifacts_json" \
        "$run_id_field" \
        >> "$TEST_LOG_FILE"
}

run_cmd_logged() {
    local case_id="$1"
    local cmd="$2"
    local config_override="${3:-}"
    local fixture_path="${4:-}"
    local allow_failure="${5:-false}"
    local out_file="$ARTIFACT_STDOUT_DIR/${case_id}.stdout"
    local err_file="$ARTIFACT_STDERR_DIR/${case_id}.stderr"

    local start
    local end
    local duration_ms
    local cmd_with_redir

    start=$(date +%s)
    printf -v cmd_with_redir '%s > %q 2> %q' "$cmd" "$out_file" "$err_file"
    run bash -c "$cmd_with_redir"
    local exit_code="$status"
    end=$(date +%s)
    duration_ms=$(( (end - start) * 1000 ))

    local schema_version=""
    local config_snapshot_path=""
    local validation_error=""

    if [[ -s "$out_file" ]]; then
        schema_version=$(jq -r '.schema_version // ""' "$out_file" 2>/dev/null || printf "")
        config_snapshot_path=$(jq -r '.config_dir // ""' "$out_file" 2>/dev/null || printf "")
    fi

    if [[ -s "$err_file" ]]; then
        if [[ -z "$schema_version" ]]; then
            schema_version=$(jq -r '.schema_version // ""' "$err_file" 2>/dev/null || printf "")
        fi
        validation_error=$(jq -r '.error.message // ""' "$err_file" 2>/dev/null || printf "")
    fi

    if [[ -n "$config_override" ]]; then
        config_snapshot_path="$config_override"
    fi

    log_case_event "config_matrix" "$case_id" "$cmd" "$exit_code" "$duration_ms" \
        "$out_file" "$err_file" "$schema_version" "$config_snapshot_path" "$validation_error" \
        "$fixture_path"

    LAST_CMD_STATUS="$exit_code"
    if [[ "$allow_failure" == "true" ]]; then
        return 0
    fi

    return "$exit_code"
}

@test "config matrix: cli overrides env and xdg" {
    skip_if_no_jq

    local case_dir="$ARTIFACT_FIXTURE_DIR/cli_overrides"
    local cli_dir="$case_dir/cli"
    local env_dir="$case_dir/env"
    local xdg_dir="$case_dir/xdg"
    local xdg_config_dir="$xdg_dir/process_triage"

    write_config_dir "$cli_dir"
    write_config_dir "$env_dir"
    write_config_dir "$xdg_config_dir"

    export PROCESS_TRIAGE_CONFIG="$env_dir"
    export XDG_CONFIG_HOME="$xdg_dir"

    local cmd="pt --format json --config $cli_dir config show"
    run_cmd_logged "cli_overrides" "$cmd"
    [ "$status" -eq 0 ]

    local config_dir
    config_dir=$(jq -r '.config_dir' "$ARTIFACT_STDOUT_DIR/cli_overrides.stdout")
    [ "$config_dir" = "$cli_dir" ]

    local priors_path
    priors_path=$(jq -r '.priors.source.path' "$ARTIFACT_STDOUT_DIR/cli_overrides.stdout")
    [ "$priors_path" = "$cli_dir/priors.json" ]
}

@test "config matrix: env overrides xdg" {
    skip_if_no_jq

    local case_dir="$ARTIFACT_FIXTURE_DIR/env_overrides"
    local env_dir="$case_dir/env"
    local xdg_dir="$case_dir/xdg"
    local xdg_config_dir="$xdg_dir/process_triage"

    write_config_dir "$env_dir"
    write_config_dir "$xdg_config_dir"

    export PROCESS_TRIAGE_CONFIG="$env_dir"
    export XDG_CONFIG_HOME="$xdg_dir"

    local cmd="pt --format json config show"
    run_cmd_logged "env_overrides" "$cmd"
    [ "$status" -eq 0 ]

    local config_dir
    config_dir=$(jq -r '.config_dir' "$ARTIFACT_STDOUT_DIR/env_overrides.stdout")
    [ "$config_dir" = "$env_dir" ]
}

@test "config matrix: xdg fallback when env unset" {
    skip_if_no_jq

    local case_dir="$ARTIFACT_FIXTURE_DIR/xdg_fallback"
    local xdg_dir="$case_dir/xdg"
    local xdg_config_dir="$xdg_dir/process_triage"

    write_config_dir "$xdg_config_dir"

    unset PROCESS_TRIAGE_CONFIG
    export XDG_CONFIG_HOME="$xdg_dir"

    local cmd="pt --format json config show"
    run_cmd_logged "xdg_fallback" "$cmd"
    [ "$status" -eq 0 ]

    local config_dir
    config_dir=$(jq -r '.config_dir' "$ARTIFACT_STDOUT_DIR/xdg_fallback.stdout")
    [ "$config_dir" = "$xdg_config_dir" ]
}

@test "config matrix: validation errors are surfaced" {
    skip_if_no_jq

    local case_dir="$ARTIFACT_FIXTURE_DIR/invalid_policy"
    local bad_dir="$case_dir/bad_config"

    write_invalid_policy_dir "$bad_dir"

    export PROCESS_TRIAGE_CONFIG="$bad_dir"

    local cmd="pt --format json config validate"
    run_cmd_logged "invalid_policy" "$cmd" "$bad_dir" "$bad_dir/policy.json" "true"
    [ "$LAST_CMD_STATUS" -ne 0 ]

    local err_file="$ARTIFACT_STDERR_DIR/invalid_policy.stderr"
    local error_msg
    error_msg=$(jq -r '.error.message' "$err_file")
    [[ "$error_msg" == *"PID 1"* ]]

}
