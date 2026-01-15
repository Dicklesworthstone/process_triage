#!/usr/bin/env bash
# Test helper functions for pt BATS tests
# Provides: setup/teardown, mocks, assertions, logging

#==============================================================================
# TEST LOGGING
#==============================================================================
# All test output should be detailed and debuggable

TEST_LOG_LEVEL=${TEST_LOG_LEVEL:-info}  # debug, info, warn, error

test_log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(date '+%H:%M:%S.%3N')"

    case "$level" in
        debug) [[ "$TEST_LOG_LEVEL" == "debug" ]] && echo "# [$timestamp] DEBUG: $msg" || : ;;
        info)  echo "# [$timestamp] INFO:  $msg" ;;
        warn)  echo "# [$timestamp] WARN:  $msg" >&2 ;;
        error) echo "# [$timestamp] ERROR: $msg" >&2 ;;
    esac
    return 0
}

test_debug() { test_log debug "$@"; }
test_info()  { test_log info "$@"; }
test_warn()  { test_log warn "$@"; }
test_error() { test_log error "$@"; }

# Log test start with description
# Usage: test_start "test name" "description"
test_start() {
    local test_name="$1"
    local description="$2"
    test_info "=== START: $test_name ==="
    test_info "Testing: $description"
}

# Log test completion with result
# Usage: test_end "test name" "pass|fail"
test_end() {
    local test_name="$1"
    local status="$2"
    if [[ "$status" == "pass" ]]; then
        test_info "=== PASS: $test_name ==="
    else
        test_error "=== FAIL: $test_name ==="
    fi
}

#==============================================================================
# TEST ENVIRONMENT SETUP
#==============================================================================

setup_test_env() {
    test_debug "Setting up test environment..."

    # Create isolated directories
    # Use a unique per-test directory to avoid needing cleanup (no deletions).
    local test_suffix="${BATS_TEST_NAME:-unknown}"
    test_suffix="${test_suffix//[^a-zA-Z0-9_-]/_}"
    export TEST_DIR="${BATS_TEST_TMPDIR}/test_env_${test_suffix}_$$"
    export CONFIG_DIR="${TEST_DIR}/config"
    export MOCK_BIN="${TEST_DIR}/mock_bin"
    export TEST_LOG_FILE="${TEST_DIR}/test.log"

    mkdir -p "$CONFIG_DIR" "$MOCK_BIN"

    # Initialize empty decisions file
    echo '{}' > "${CONFIG_DIR}/decisions.json"

    # Set test mode flags
    export TEST_MODE=1
    export CI=true
    export NO_COLOR=1

    test_debug "TEST_DIR=$TEST_DIR"
    test_debug "CONFIG_DIR=$CONFIG_DIR"
    test_debug "MOCK_BIN=$MOCK_BIN"

    test_info "Test environment ready"
}

teardown_test_env() {
    test_debug "Tearing down test environment..."

    # Log any test artifacts before cleanup
    if [[ -f "$TEST_LOG_FILE" ]]; then
        test_debug "Test log contents:"
        while read -r line; do
            test_debug "  $line"
        done < "$TEST_LOG_FILE"
    fi

    # Intentionally do not delete any files/directories here.
    test_debug "Leaving test artifacts at: $TEST_DIR"
}

#==============================================================================
# MOCK CREATION UTILITIES
#==============================================================================

# Create a mock command that outputs predefined text
# Usage: create_mock_command name output [exit_code]
create_mock_command() {
    local name="$1"
    local output="$2"
    local exit_code="${3:-0}"

    test_debug "Creating mock command: $name (exit=$exit_code)"
    test_debug "Mock output: ${output:0:100}..."

    cat > "${MOCK_BIN}/${name}" << 'MOCK_CMD'
#!/usr/bin/env bash
cat << 'MOCK_OUTPUT'
__MOCK_OUTPUT__
MOCK_OUTPUT
exit __MOCK_EXIT__
MOCK_CMD
    sed -i "s|__MOCK_OUTPUT__|${output//|/\\|}|g" "${MOCK_BIN}/${name}"
    sed -i "s|__MOCK_EXIT__|${exit_code}|g" "${MOCK_BIN}/${name}"
    chmod +x "${MOCK_BIN}/${name}"

    test_info "Mock '$name' created at ${MOCK_BIN}/${name}"
}

# Create mock ps command with specific process output
create_mock_ps() {
    local processes="$1"
    test_info "Creating mock ps with $(echo "$processes" | wc -l) processes"
    create_mock_command "ps" "$processes"
}

# Create mock curl that returns specific content
create_mock_curl() {
    local content="$1"
    local exit_code="${2:-0}"
    test_info "Creating mock curl (exit=$exit_code, content_len=${#content})"
    create_mock_command "curl" "$content" "$exit_code"
}

# Create mock curl that simulates redirect for version checking
create_mock_curl_redirect() {
    local final_url="$1"
    test_info "Creating mock curl redirect to: $final_url"

    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
# Mock curl that handles -w '%{url_effective}'
if [[ "$*" == *"url_effective"* ]]; then
    echo "__REDIRECT_URL__"
else
    # Default behavior
    cat /dev/null
fi
exit 0
MOCK_CURL
    sed -i "s|__REDIRECT_URL__|${final_url//|/\\|}|g" "${MOCK_BIN}/curl"
    chmod +x "${MOCK_BIN}/curl"
}

#==============================================================================
# MOCK PROCESS DATA GENERATORS
#==============================================================================

# Generate a mock process line in pt's expected format
# Usage: mock_process PID PPID AGE_SECS MEM_MB "command"
mock_process() {
    local pid="$1"
    local ppid="$2"
    local age="$3"
    local mem="$4"
    local cmd="$5"

    test_debug "mock_process: pid=$pid ppid=$ppid age=$age mem=$mem cmd='$cmd'"
    printf '%s|%s|%s|%s|%s\n' "$pid" "$ppid" "$age" "$mem" "$cmd"
}

# Pre-built scenarios
mock_ps_with_stuck_test() {
    local age="${1:-7200}"  # 2 hours default
    test_info "Generating stuck test scenario (age=$age)"
    mock_process 12345 1000 "$age" 512 "bun test --watch"
}

mock_ps_with_orphan() {
    test_info "Generating orphan process scenario"
    mock_process 23456 1 86400 256 "orphaned process"
}

mock_ps_with_dev_server() {
    local age="${1:-259200}"  # 3 days default
    test_info "Generating old dev server scenario (age=$age)"
    mock_process 34567 1000 "$age" 128 "next dev --port 3000"
}

mock_ps_with_protected() {
    test_info "Generating protected process scenario"
    mock_process 1 0 9999999 100 "/usr/lib/systemd/systemd"
}

mock_ps_with_agent_shell() {
    local age="${1:-90000}"  # ~25 hours default
    test_info "Generating agent shell scenario (age=$age)"
    mock_process 45678 1000 "$age" 200 "/bin/bash -c claude assistant"
}

# Complex scenario with multiple process types
mock_ps_mixed_scenario() {
    test_info "Generating mixed scenario with multiple process types"
    {
        mock_process 10001 1000 3601 512 "bun test --watch"           # Stuck test
        mock_process 10002 1 172800 256 "orphaned background task"    # Orphan + old
        mock_process 10003 1000 259200 128 "next dev --port 3000"     # Old dev server
        mock_process 10004 1000 90000 200 "/bin/bash -c claude"       # Agent shell
        mock_process 10005 1000 1800 64 "vim file.txt"                # Normal (recent)
        mock_process 1 0 9999999 100 "/usr/lib/systemd/systemd"       # Protected
    }
}

#==============================================================================
# ASSERTION HELPERS
#==============================================================================

# Assert score is within expected range
assert_score_range() {
    local actual="$1"
    local min="$2"
    local max="$3"
    local context="${4:-}"

    test_debug "assert_score_range: actual=$actual expected=[$min-$max] context='$context'"

    if (( actual < min || actual > max )); then
        test_error "Score out of range"
        test_error "  Expected: $min to $max"
        test_error "  Actual:   $actual"
        [[ -n "$context" ]] && test_error "  Context:  $context"
        return 1
    fi

    test_debug "Score $actual is within range [$min-$max] ✓"
    return 0
}

# Assert string contains substring
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local context="${3:-}"

    test_debug "assert_contains: looking for '$needle' in '${haystack:0:50}...'"

    if [[ "$haystack" != *"$needle"* ]]; then
        test_error "String does not contain expected substring"
        test_error "  Looking for: '$needle'"
        test_error "  In string:   '${haystack:0:200}'"
        [[ -n "$context" ]] && test_error "  Context:     $context"
        return 1
    fi

    test_debug "Found '$needle' in string ✓"
    return 0
}

# Assert string does not contain substring
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local context="${3:-}"

    test_debug "assert_not_contains: checking '$needle' absent from '${haystack:0:50}...'"

    if [[ "$haystack" == *"$needle"* ]]; then
        test_error "String contains unexpected substring"
        test_error "  Should not contain: '$needle'"
        test_error "  But found in:       '${haystack:0:200}'"
        [[ -n "$context" ]] && test_error "  Context:            $context"
        return 1
    fi

    test_debug "Confirmed '$needle' absent ✓"
    return 0
}

# Assert equality with detailed diff
assert_equals() {
    local expected="$1"
    local actual="$2"
    local context="${3:-}"

    test_debug "assert_equals: comparing values"

    if [[ "$expected" != "$actual" ]]; then
        test_error "Values not equal"
        test_error "  Expected: '$expected'"
        test_error "  Actual:   '$actual'"
        [[ -n "$context" ]] && test_error "  Context:  $context"
        return 1
    fi

    test_debug "Values match: '$expected' ✓"
    return 0
}

# Assert command succeeds
assert_success() {
    local cmd="$1"
    local context="${2:-}"

    test_debug "assert_success: running '$cmd'"

    local output exit_code
    output="$(eval "$cmd" 2>&1)"
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        test_error "Command failed (expected success)"
        test_error "  Command:   $cmd"
        test_error "  Exit code: $exit_code"
        test_error "  Output:    $output"
        [[ -n "$context" ]] && test_error "  Context:   $context"
        return 1
    fi

    test_debug "Command succeeded (exit=0) ✓"
    echo "$output"
    return 0
}

# Assert command fails
assert_fails() {
    local cmd="$1"
    local expected_exit="${2:-}"
    local context="${3:-}"

    test_debug "assert_fails: running '$cmd'"

    local output exit_code
    output="$(eval "$cmd" 2>&1)"
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        test_error "Command succeeded (expected failure)"
        test_error "  Command: $cmd"
        test_error "  Output:  $output"
        [[ -n "$context" ]] && test_error "  Context: $context"
        return 1
    fi

    if [[ -n "$expected_exit" ]] && [[ $exit_code -ne $expected_exit ]]; then
        test_error "Wrong exit code"
        test_error "  Expected: $expected_exit"
        test_error "  Actual:   $exit_code"
        return 1
    fi

    test_debug "Command failed as expected (exit=$exit_code) ✓"
    echo "$output"
    return 0
}

#==============================================================================
# SKIP HELPERS
#==============================================================================

skip_if_no_jq() {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        skip "jq not installed"
    fi
}

skip_if_no_gum() {
    if ! command -v gum &>/dev/null; then
        test_warn "Skipping: gum not installed"
        skip "gum not installed"
    fi
}

skip_if_ci() {
    if [[ -n "${CI:-}" ]]; then
        test_warn "Skipping: CI environment"
        skip "Skipped in CI environment"
    fi
}

skip_if_root() {
    if [[ $EUID -eq 0 ]]; then
        test_warn "Skipping: running as root"
        skip "Skipped when running as root"
    fi
}

#==============================================================================
# PATH MANIPULATION FOR MOCKS
#==============================================================================

use_mock_bin() {
    test_info "Injecting mock bin into PATH"
    test_debug "MOCK_BIN=$MOCK_BIN"
    export ORIGINAL_PATH="$PATH"
    export PATH="${MOCK_BIN}:${PATH}"
    test_debug "New PATH: $PATH"
}

restore_path() {
    if [[ -n "${ORIGINAL_PATH:-}" ]]; then
        test_debug "Restoring original PATH"
        export PATH="$ORIGINAL_PATH"
        unset ORIGINAL_PATH
    fi
}

#==============================================================================
# FILE COMPARISON UTILITIES
#==============================================================================

# Create a snapshot of a file for comparison
snapshot_file() {
    local file="$1"
    local snapshot_name="$2"

    if [[ -f "$file" ]]; then
        cp "$file" "${TEST_DIR}/${snapshot_name}.snapshot"
        test_debug "Created snapshot: $snapshot_name"
    else
        test_warn "Cannot snapshot: $file does not exist"
    fi
}

# Compare file with snapshot
compare_with_snapshot() {
    local file="$1"
    local snapshot_name="$2"
    local snapshot="${TEST_DIR}/${snapshot_name}.snapshot"

    if [[ ! -f "$snapshot" ]]; then
        test_error "Snapshot not found: $snapshot_name"
        return 1
    fi

    if diff -q "$file" "$snapshot" >/dev/null 2>&1; then
        test_debug "File matches snapshot: $snapshot_name ✓"
        return 0
    else
        test_error "File differs from snapshot: $snapshot_name"
        test_error "Diff:"
        while read -r line; do
            test_error "  $line"
        done < <(diff "$snapshot" "$file")
        return 1
    fi
}

#==============================================================================
# TIMING UTILITIES
#==============================================================================

# Time a command and report duration
# Usage: time_command "description" command...
time_command() {
    local description="$1"
    shift
    local cmd="$*"

    local start end duration
    start=$(date +%s%3N)
    eval "$cmd"
    local exit_code=$?
    end=$(date +%s%3N)
    duration=$((end - start))

    test_info "$description completed in ${duration}ms (exit=$exit_code)"
    return $exit_code
}
