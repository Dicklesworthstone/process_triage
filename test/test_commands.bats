#!/usr/bin/env bats
# Unit-style CLI command tests for pt
# Uses mocks to keep tests deterministic and dependency-light.

load "./test_helper/common.bash"

PT_SCRIPT="${BATS_TEST_DIRNAME}/../pt"

setup_file() {
    if [[ ! -x "$PT_SCRIPT" ]]; then
        echo "ERROR: pt script not found at $PT_SCRIPT" >&2
        exit 1
    fi
}

create_mock_gum() {
    cat > "${MOCK_BIN}/gum" << 'EOF_GUM'
#!/usr/bin/env bash
set -e

subcmd="$1"
shift || true

case "$subcmd" in
    style)
        last=""
        for arg in "$@"; do
            last="$arg"
        done
        if [[ -n "$last" ]]; then
            printf '%s\n' "$last"
        fi
        ;;
    spin)
        cmd=()
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == "--" ]]; then
                shift
                cmd=("$@")
                break
            fi
            shift
        done
        if [[ ${#cmd[@]} -gt 0 ]]; then
            "${cmd[@]}"
        fi
        ;;
    confirm)
        exit 0
        ;;
    choose)
        exit 1
        ;;
    *)
        exit 0
        ;;
esac
EOF_GUM
    chmod +x "${MOCK_BIN}/gum"
}

create_mock_clear() {
    cat > "${MOCK_BIN}/clear" << 'EOF_CLEAR'
#!/usr/bin/env bash
exit 0
EOF_CLEAR
    chmod +x "${MOCK_BIN}/clear"
}

setup() {
    setup_test_env

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    create_mock_gum
    create_mock_clear
    use_mock_bin

    test_start "$BATS_TEST_NAME" "CLI command test"
}

teardown() {
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    restore_path
    teardown_test_env
}

#==============================================================================
# HELP COMMAND TESTS
#==============================================================================

@test "Command: pt help shows usage information" {
    test_info "Running: pt help"
    run "$PT_SCRIPT" help

    assert_equals "0" "$status" "help should succeed"

    test_info "Verifying help content"
    assert_contains "$output" "Process Triage" "Should show tool name"
    assert_contains "$output" "scan" "Should document scan"
    assert_contains "$output" "history" "Should document history"
    assert_contains "$output" "clear" "Should document clear"
    assert_contains "$output" "help" "Should document help"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt --help is alias for help" {
    test_info "Running: pt --help"
    run "$PT_SCRIPT" --help

    assert_equals "0" "$status" "--help should succeed"
    assert_contains "$output" "Process Triage" "Should show same content as help"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt -h is alias for help" {
    test_info "Running: pt -h"
    run "$PT_SCRIPT" -h

    assert_equals "0" "$status" "-h should succeed"
    assert_contains "$output" "Process Triage" "Should show same content as help"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# VERSION COMMAND TESTS
#==============================================================================

@test "Command: pt --version shows version" {
    test_info "Running: pt --version"
    run "$PT_SCRIPT" --version

    assert_equals "0" "$status" "version should succeed"
    assert_contains "$output" "pt version" "Should show version prefix"

    test_info "Checking version format"
    [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt -v is alias for version" {
    test_info "Running: pt -v"
    run "$PT_SCRIPT" -v

    assert_equals "0" "$status" "-v should succeed"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt version is alias for --version" {
    test_info "Running: pt version"
    run "$PT_SCRIPT" version

    assert_equals "0" "$status" "version subcommand should succeed"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SCAN COMMAND TESTS
#==============================================================================

@test "Command: pt scan succeeds with no processes" {
    test_info "Setting up: empty process list"

    create_mock_ps ""

    test_info "Running: pt scan"
    run "$PT_SCRIPT" scan

    assert_equals "0" "$status" "scan should succeed"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt scan shows candidates when found" {
    test_info "Setting up: mock process list"

    cat > "${MOCK_BIN}/ps" << 'EOF_PS'
#!/usr/bin/env bash
if [[ "$*" == *"-eo"* ]]; then
    echo "12345 1000 7200 524288 0.0 ? bun test --watch"
fi
EOF_PS
    chmod +x "${MOCK_BIN}/ps"

    test_info "Running: pt scan"
    run "$PT_SCRIPT" scan

    assert_equals "0" "$status" "scan should succeed"

    test_info "Verifying output contains process info"
    assert_contains "$output" "bun test" "Should show candidate command"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt scan respects NO_COLOR" {
    test_info "Setting up: NO_COLOR environment"

    export NO_COLOR=1

    cat > "${MOCK_BIN}/ps" << 'EOF_PS'
#!/usr/bin/env bash
if [[ "$*" == *"-eo"* ]]; then
    echo "12345 1000 7200 524288 0.0 ? bun test --watch"
fi
EOF_PS
    chmod +x "${MOCK_BIN}/ps"

    test_info "Running: pt scan with NO_COLOR=1"
    run "$PT_SCRIPT" scan

    assert_not_contains "$output" $'\033' "Should not contain escape codes"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# HISTORY COMMAND TESTS
#==============================================================================

@test "Command: pt history with empty decisions" {
    test_info "Setting up: empty decision file"

    echo '{}' > "${CONFIG_DIR}/decisions.json"

    test_info "Running: pt history"
    run "$PT_SCRIPT" history

    assert_equals "0" "$status" "history should succeed"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt history shows saved decisions" {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        BATS_TEST_COMPLETED=pass
        skip "jq not installed"
    fi

    test_info "Setting up: populated decision file"

    cat > "${CONFIG_DIR}/decisions.json" << 'EOF'
{
    "bun test --watch": "kill",
    "gunicorn": "spare",
    "next dev": "kill"
}
EOF

    test_info "Running: pt history"
    run "$PT_SCRIPT" history

    assert_equals "0" "$status" "history should succeed"
    assert_contains "$output" "bun test" "Should show bun test pattern"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# CLEAR COMMAND TESTS
#==============================================================================

@test "Command: pt clear removes decisions (mocked confirm)" {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        BATS_TEST_COMPLETED=pass
        skip "jq not installed"
    fi

    test_info "Setting up: decisions to clear"

    echo '{"pattern1": "kill"}' > "${CONFIG_DIR}/decisions.json"

    test_info "Running: pt clear"
    run "$PT_SCRIPT" clear

    assert_equals "0" "$status" "clear should succeed"

    if command -v jq &>/dev/null; then
        local count
        count=$(jq 'length' "${CONFIG_DIR}/decisions.json")
        assert_equals "0" "$count" "Decision history should be cleared"
    fi

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# ERROR HANDLING TESTS
#==============================================================================

@test "Command: unknown command shows error" {
    test_info "Running: pt unknowncommand"
    run "$PT_SCRIPT" unknowncommand

    [[ $status -ne 0 ]]
    assert_contains "$output" "Unknown" "Should mention unknown or help"

    BATS_TEST_COMPLETED=pass
}

@test "Command: multiple unknown commands all fail" {
    for cmd in foo bar baz notacommand; do
        test_info "Testing unknown command: $cmd"
        run "$PT_SCRIPT" "$cmd"
        [[ $status -ne 0 ]]
    done

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# DEFAULT COMMAND TESTS
#==============================================================================

@test "Command: pt with no args runs default (run)" {
    test_info "Setting up: empty process list"

    create_mock_ps ""

    test_info "Running: pt (no arguments)"
    run "$PT_SCRIPT"

    assert_equals "0" "$status" "default run should succeed"

    BATS_TEST_COMPLETED=pass
}

@test "Command: pt run is explicit default" {
    test_info "Setting up: empty process list"

    create_mock_ps ""

    test_info "Running: pt run"
    run "$PT_SCRIPT" run

    assert_equals "0" "$status" "pt run should succeed"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# ENVIRONMENT VARIABLE TESTS
#==============================================================================

@test "Command: respects PT_DEBUG=1" {
    test_info "Setting up: PT_DEBUG=1"

    export PT_DEBUG=1

    cat > "${MOCK_BIN}/ps" << 'EOF_PS'
#!/usr/bin/env bash
if [[ "$*" == *"-eo"* ]]; then
    echo "12345 1000 7200 524288 0.0 ? bun test --watch"
fi
EOF_PS
    chmod +x "${MOCK_BIN}/ps"

    test_info "Running: pt scan with debug"
    run "$PT_SCRIPT" scan

    assert_equals "0" "$status" "scan should succeed"

    BATS_TEST_COMPLETED=pass
}
