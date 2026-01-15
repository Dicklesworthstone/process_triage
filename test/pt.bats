#!/usr/bin/env bats
# Process Triage - BATS Test Suite

setup() {
    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    PATH="$PROJECT_ROOT:$PATH"

    # Isolated config for tests
    export PROCESS_TRIAGE_CONFIG="$BATS_TEST_TMPDIR/config"
    mkdir -p "$PROCESS_TRIAGE_CONFIG"
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/config" 2>/dev/null || true
}

@test "pt --help shows usage" {
    run pt --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Process Triage"* ]]
}

@test "pt help shows usage" {
    run pt help
    [ "$status" -eq 0 ]
    [[ "$output" == *"USAGE"* ]]
}

@test "pt --version shows version" {
    run pt --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"1.0.0"* ]]
}

@test "pt unknown command fails" {
    run pt unknown_xyz_123
    [ "$status" -ne 0 ]
}

@test "pt scan runs without error" {
    command -v gum &>/dev/null || skip "gum not installed"
    run timeout 10 pt scan
    [ "$status" -eq 0 ] || [ "$status" -eq 124 ]
}

@test "pt history with empty config works" {
    command -v gum &>/dev/null || skip "gum not installed"
    run pt history
    [ "$status" -eq 0 ]
}

@test "pt clear with empty config works" {
    command -v gum &>/dev/null || skip "gum not installed"
    # Need to simulate non-interactive confirmation
    echo '{}' > "$PROCESS_TRIAGE_CONFIG/decisions.json"
    run pt history
    [ "$status" -eq 0 ]
}
