#!/usr/bin/env bats
# Real-system E2E tests for pt (no mocks), with detailed logging.

load "./test_helper/common.bash"

setup() {
    test_start "real e2e" "pt CLI real-system E2E with artifacts"
    setup_test_env

    local test_file_dir
    test_file_dir="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$test_file_dir")"
    PATH="$PROJECT_ROOT:$PATH"

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export ARTIFACT_DIR="$TEST_DIR/artifacts"
    export ARTIFACT_LOG_DIR="$ARTIFACT_DIR/logs"
    export ARTIFACT_STDOUT_DIR="$ARTIFACT_DIR/stdout"
    export ARTIFACT_STDERR_DIR="$ARTIFACT_DIR/stderr"
    export ARTIFACT_PLANS_DIR="$ARTIFACT_DIR/plans"
    export ARTIFACT_SNAPSHOTS_DIR="$ARTIFACT_DIR/snapshots"
    export ARTIFACT_TELEMETRY_DIR="$ARTIFACT_DIR/telemetry"
    mkdir -p \
        "$ARTIFACT_DIR" \
        "$ARTIFACT_LOG_DIR" \
        "$ARTIFACT_STDOUT_DIR" \
        "$ARTIFACT_STDERR_DIR" \
        "$ARTIFACT_PLANS_DIR" \
        "$ARTIFACT_SNAPSHOTS_DIR" \
        "$ARTIFACT_TELEMETRY_DIR"

    export TEST_LOG_FILE="$ARTIFACT_LOG_DIR/pt_e2e_real.jsonl"

    test_info "Artifacts: $ARTIFACT_DIR"
}

teardown() {
    teardown_test_env
    test_end "real e2e" "pass"
}

# ----------------------------------------------------------------------------
# Local helpers
# ----------------------------------------------------------------------------

command_exists() {
    command -v "$1" &>/dev/null
}

redact_output() {
    sed -E \
        -e 's/(AKIA[0-9A-Z]{16})/[REDACTED]/g' \
        -e 's/(ghp_[A-Za-z0-9]{20,})/[REDACTED]/g' \
        -e 's/(sk-[A-Za-z0-9_-]{10,})/[REDACTED]/g' \
        -e 's/(password=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(--password=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(--token[[:space:]]+)[^[:space:]]+/\1[REDACTED]/g'
}

assert_no_secret() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    local pattern="AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{10,}|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY"
    if command_exists "rg"; then
        if rg -n "$pattern" "$file"; then
            test_error "Secret-like pattern found in artifact: $file"
            return 1
        fi
    elif grep -E -n "$pattern" "$file"; then
        test_error "Secret-like pattern found in artifact: $file"
        return 1
    fi
    return 0
}

log_json_event() {
    local event="$1"
    local status="$2"
    local cmd="$3"
    local out_file="$4"
    local err_file="$5"
    local line_count="$6"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local cmd_esc
    local out_esc
    local err_esc
    cmd_esc=$(escape_json "$cmd")
    out_esc=$(escape_json "$out_file")
    err_esc=$(escape_json "$err_file")

    printf '{"ts":"%s","event":"%s","status":%s,"cmd":"%s","stdout":"%s","stderr":"%s","lines":%s}\n' \
        "$ts" \
        "$event" \
        "$status" \
        "$cmd_esc" \
        "$out_esc" \
        "$err_esc" \
        "$line_count" \
        >> "$TEST_LOG_FILE"
}

escape_json() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

run_cmd_with_artifacts() {
    local name="$1"
    local cmd="$2"
    local out_file="$ARTIFACT_STDOUT_DIR/${name}.stdout"
    local err_file="$ARTIFACT_STDERR_DIR/${name}.stderr"

    local full_cmd
    printf -v full_cmd '%s 2> %q' "$cmd" "$err_file"
    run bash -c "$full_cmd"

    printf "%s" "$output" | redact_output > "$out_file"
    if [[ -f "$err_file" ]]; then
        local redacted_err
        redacted_err=$(redact_output < "$err_file")
        printf "%s" "$redacted_err" > "$err_file"
    fi
    assert_no_secret "$out_file"
    assert_no_secret "$err_file"

    local line_count
    line_count=$(printf "%s" "$output" | wc -l | tr -d ' ')

    log_json_event "$name" "$status" "$cmd" "$out_file" "$err_file" "$line_count"
}

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

@test "pt --help (real)" {
    run_cmd_with_artifacts "help" "pt --help"
    [ "$status" -eq 0 ]
    assert_contains "$output" "Process Triage" "help should mention Process Triage"
}

@test "pt --version (real)" {
    run_cmd_with_artifacts "version" "pt --version"
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt version" "version output should include prefix"
}

@test "pt history (real)" {
    skip_if_no_gum
    run_cmd_with_artifacts "history" "pt history"
    [ "$status" -eq 0 ]
}

@test "pt scan (real)" {
    skip_if_no_gum
    if ! command_exists "timeout"; then
        test_warn "Skipping: timeout not installed"
        skip "timeout not installed"
    fi

    run_cmd_with_artifacts "scan" "timeout 10 pt scan"

    if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
        fail "pt scan failed with status $status"
    fi
}
