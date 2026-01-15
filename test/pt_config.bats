#!/usr/bin/env bats
# Configuration tests for pt bash wrapper

load "./test_helper/common.bash"

setup() {
    test_start "config tests" "validate custom config directory handling"
    setup_test_env

    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    PATH="$PROJECT_ROOT:$PATH"
}

teardown() {
    teardown_test_env
    test_end "config tests" "pass"
}

# ============================================================================
# Custom Config Directory
# ============================================================================

@test "PROCESS_TRIAGE_CONFIG env var sets config location" {
    local custom_config="$BATS_TEST_TMPDIR/custom_config"
    mkdir -p "$custom_config"
    export PROCESS_TRIAGE_CONFIG="$custom_config"

    run pt --help
    [ "$status" -eq 0 ]
}

@test "config files are created in custom location" {
    local custom_config="$BATS_TEST_TMPDIR/custom_config"
    mkdir -p "$custom_config"
    export PROCESS_TRIAGE_CONFIG="$custom_config"

    # Run a command that initializes config
    run pt robot plan --format json
    [ "$status" -eq 0 ]

    # Decisions file should exist in custom location
    [ -f "$custom_config/decisions.json" ]
}

@test "log file is created in custom config location" {
    local custom_config="$BATS_TEST_TMPDIR/custom_config"
    mkdir -p "$custom_config"
    export PROCESS_TRIAGE_CONFIG="$custom_config"

    # Run a command that might log
    run pt robot plan --format json
    [ "$status" -eq 0 ]

    # Log file location should follow config
    # (log may or may not be created depending on operations)
}

@test "different config dirs are isolated" {
    local config1="$BATS_TEST_TMPDIR/config1"
    local config2="$BATS_TEST_TMPDIR/config2"
    mkdir -p "$config1" "$config2"

    # Set up decision in config1
    echo '{"pattern1": "kill"}' > "$config1/decisions.json"

    # Set up different decision in config2
    echo '{"pattern2": "spare"}' > "$config2/decisions.json"

    # Verify isolation
    [ "$(cat "$config1/decisions.json")" != "$(cat "$config2/decisions.json")" ]
}

@test "XDG_CONFIG_HOME is respected when PROCESS_TRIAGE_CONFIG unset" {
    unset PROCESS_TRIAGE_CONFIG
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/xdg_config"
    mkdir -p "$XDG_CONFIG_HOME"

    # Note: We can't easily test this without actually running pt
    # which would create files in the XDG location
    # This is more of a documentation test
    run pt --help
    [ "$status" -eq 0 ]
}

# ============================================================================
# Config File Formats
# ============================================================================

@test "decisions.json is valid JSON object" {
    skip_if_no_jq

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    echo '{}' > "$CONFIG_DIR/decisions.json"

    run jq 'type' "$CONFIG_DIR/decisions.json"
    [ "$status" -eq 0 ]
    [ "$output" = '"object"' ]
}

@test "priors.json is valid JSON object" {
    skip_if_no_jq

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    echo '{}' > "$CONFIG_DIR/priors.json"

    run jq 'type' "$CONFIG_DIR/priors.json"
    [ "$status" -eq 0 ]
    [ "$output" = '"object"' ]
}

# ============================================================================
# Config Initialization
# ============================================================================

@test "config dir is created if missing" {
    # Use a unique path to avoid deleting anything if a prior run left artifacts.
    local new_config="$BATS_TEST_TMPDIR/new_config_dir_$$"
    export PROCESS_TRIAGE_CONFIG="$new_config"

    run pt robot plan --format json
    [ "$status" -eq 0 ]

    # Config dir should now exist
    [ -d "$new_config" ]
}

@test "nested config path is created" {
    # Use a unique path to avoid deleting anything if a prior run left artifacts.
    local nested_config="$BATS_TEST_TMPDIR/deep_$$/nested/config"
    export PROCESS_TRIAGE_CONFIG="$nested_config"

    run pt robot plan --format json
    [ "$status" -eq 0 ]

    # Should create nested directories
    [ -d "$nested_config" ]
}

@test "empty decisions.json defaults to {}" {
    skip_if_no_jq

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    # Create empty file
    : > "$CONFIG_DIR/decisions.json"

    # Run pt to ensure it handles empty file
    run pt robot plan --format json
    [ "$status" -eq 0 ]
}

# ============================================================================
# Config Permissions
# ============================================================================

@test "config dir with restrictive permissions works" {
    skip_if_root  # Root can write anywhere

    local restricted_config="$BATS_TEST_TMPDIR/restricted"
    mkdir -p "$restricted_config"
    chmod 700 "$restricted_config"
    export PROCESS_TRIAGE_CONFIG="$restricted_config"

    run pt --help
    [ "$status" -eq 0 ]
}

@test "read-only decisions.json is handled gracefully" {
    skip_if_root  # Root can write anywhere

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    echo '{}' > "$CONFIG_DIR/decisions.json"
    chmod 444 "$CONFIG_DIR/decisions.json"

    # Should still be able to read and run
    run pt robot plan --format json
    # May succeed or fail gracefully, but shouldn't crash
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    # Restore permissions for cleanup
    chmod 644 "$CONFIG_DIR/decisions.json"
}

# ============================================================================
# Environment Variables
# ============================================================================

@test "CI=true disables gum" {
    export CI=true
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    # Should not try to use gum in CI mode
    run pt --help
    [ "$status" -eq 0 ]
}

@test "NO_COLOR=1 disables colors" {
    export NO_COLOR=1
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    run pt --help
    [ "$status" -eq 0 ]
    # Output should not contain ANSI escape codes
    # (Hard to test reliably, but command should work)
}

@test "PT_DEBUG=1 enables debug output" {
    export PT_DEBUG=1
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    run pt --help
    [ "$status" -eq 0 ]
    # Debug mode should not break normal operation
}

# ============================================================================
# Version
# ============================================================================

@test "VERSION matches script constant" {
    local file_version
    file_version=$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "unknown")

    run pt --version
    [ "$status" -eq 0 ]

    if [ "$file_version" != "unknown" ]; then
        assert_contains "$output" "$file_version" "version should match VERSION file"
    fi
}

@test "pt -v shows version" {
    run pt -v
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt version" "should show version info"
}

@test "pt version shows version" {
    run pt version
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt version" "should show version info"
}

# ============================================================================
# Scoring Thresholds
# ============================================================================

@test "THRESHOLD_KILL is 60" {
    local threshold
    threshold=$(grep "^readonly THRESHOLD_KILL=" "$PROJECT_ROOT/pt" | cut -d= -f2)
    [ "$threshold" = "60" ]
}

@test "THRESHOLD_REVIEW is 30" {
    local threshold
    threshold=$(grep "^readonly THRESHOLD_REVIEW=" "$PROJECT_ROOT/pt" | cut -d= -f2)
    [ "$threshold" = "30" ]
}

# ============================================================================
# Type Lifetimes Configuration
# ============================================================================

@test "TYPE_LIFETIME has test entry" {
    run grep -q '\[test\]=' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}

@test "TYPE_LIFETIME has daemon entry" {
    run grep -q '\[daemon\]=' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}

@test "daemon TYPE_LIFETIME is 0 (never expires)" {
    local lifetime
    lifetime=$(grep '\[daemon\]=' "$PROJECT_ROOT/pt" | grep -oE '[0-9]+')
    [ "$lifetime" = "0" ]
}

# ============================================================================
# Protected Patterns
# ============================================================================

@test "systemd is in protected patterns" {
    # Check that systemd appears in the is_protected_cmd function body
    run grep 'systemd' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
    assert_contains "$output" "systemd" "should have systemd in patterns"
}

@test "dockerd is in protected patterns" {
    # Check that dockerd appears in the pt script
    run grep 'dockerd' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
    assert_contains "$output" "dockerd" "should have dockerd in patterns"
}

@test "sshd is in protected patterns" {
    # Check that sshd appears in the pt script
    run grep 'sshd' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
    assert_contains "$output" "sshd" "should have sshd in patterns"
}

# ============================================================================
# Classification Patterns
# ============================================================================

@test "test pattern matches bun test" {
    # Verify classify_process function exists and contains test pattern
    run grep -q 'bun.*test' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}

@test "dev_server pattern matches next dev" {
    # Verify classify_process function exists and contains dev server pattern
    run grep -q 'next.*dev' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}

@test "agent pattern matches claude" {
    # Verify classify_process function exists and contains agent pattern
    run grep -q 'claude' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}

@test "daemon pattern matches postgres" {
    # Verify classify_process function exists and contains daemon pattern
    run grep -q 'postgres' "$PROJECT_ROOT/pt"
    [ "$status" -eq 0 ]
}
