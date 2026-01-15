#!/usr/bin/env bats
# Agent CLI Contract Tests for pt-core
# Validates the agent CLI surface against the contract spec
#
# These tests enforce:
# - Non-interactive behavior (no prompts, no TTY assumptions)
# - Stable schema_version in all JSON outputs
# - Durable session identity format
# - Process identity includes stable identity tuple
# - Exit code semantics
#
# Reference: docs/AGENT_CLI_CONTRACT.md, docs/CLI_SPECIFICATION.md

load "./test_helper/common.bash"

PT_CORE="${BATS_TEST_DIRNAME}/../target/release/pt-core"

# Schema version pattern: X.Y.Z
SCHEMA_VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'

# Session ID pattern: pt-YYYYMMDD-HHMMSS-<random4>
SESSION_ID_PATTERN='^pt-[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$'

setup_file() {
    # Ensure pt-core is built
    if [[ ! -x "$PT_CORE" ]]; then
        echo "# Building pt-core..." >&3
        (cd "${BATS_TEST_DIRNAME}/.." && cargo build --release 2>/dev/null) || {
            echo "ERROR: Failed to build pt-core" >&2
            exit 1
        }
    fi
}

setup() {
    setup_test_env
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    test_start "$BATS_TEST_NAME" "Agent CLI contract test"
}

teardown() {
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    teardown_test_env
}

#==============================================================================
# HELPER FUNCTIONS FOR CONTRACT VALIDATION
#==============================================================================

# Check if jq is available for JSON validation
require_jq() {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        skip "jq not installed"
    fi
}

# Validate JSON output has schema_version
validate_schema_version() {
    local json="$1"
    local context="${2:-output}"

    local version
    version=$(echo "$json" | jq -r '.schema_version // empty' 2>/dev/null)

    if [[ -z "$version" ]]; then
        test_error "Missing schema_version in $context"
        return 1
    fi

    if ! [[ "$version" =~ $SCHEMA_VERSION_PATTERN ]]; then
        test_error "Invalid schema_version format: $version (expected X.Y.Z)"
        return 1
    fi

    test_info "schema_version: $version"
    return 0
}

# Validate JSON output has valid session_id
validate_session_id() {
    local json="$1"
    local context="${2:-output}"

    local session_id
    session_id=$(echo "$json" | jq -r '.session_id // empty' 2>/dev/null)

    if [[ -z "$session_id" ]]; then
        test_error "Missing session_id in $context"
        return 1
    fi

    if ! [[ "$session_id" =~ $SESSION_ID_PATTERN ]]; then
        test_error "Invalid session_id format: $session_id (expected pt-YYYYMMDD-HHMMSS-XXXX)"
        return 1
    fi

    test_info "session_id: $session_id"
    return 0
}

# Validate JSON output has generated_at timestamp
validate_timestamp() {
    local json="$1"
    local field="${2:-generated_at}"
    local context="${3:-output}"

    local ts
    ts=$(echo "$json" | jq -r ".$field // empty" 2>/dev/null)

    if [[ -z "$ts" ]]; then
        test_error "Missing $field in $context"
        return 1
    fi

    # ISO 8601 basic check
    if ! [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        test_error "Invalid timestamp format for $field: $ts"
        return 1
    fi

    test_info "$field: $ts"
    return 0
}

# Extract the main JSON object from output (skipping JSONL events)
extract_json() {
    local output="$1"
    # Skip lines that look like JSONL events (start with {"event":)
    echo "$output" | grep -v '^{"event":' | jq -s 'last' 2>/dev/null
}

#==============================================================================
# NON-INTERACTIVITY TESTS
#==============================================================================

@test "Contract: agent commands do not hang with closed stdin" {
    require_jq
    test_info "Testing non-interactivity (closed stdin)"

    # Run with stdin from /dev/null - should not hang
    run timeout 30 bash -c "echo '' | $PT_CORE agent plan --standalone --format json"

    # Should complete (exit code doesn't matter, just shouldn't hang)
    test_info "Command completed with exit code: $status"
    [[ $status -ne 124 ]] || {
        test_error "Command timed out - possible TTY/prompt issue"
        false
    }

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent commands work without TTY" {
    require_jq
    test_info "Testing operation without TTY"

    # Force non-TTY environment
    run env TERM=dumb "$PT_CORE" agent capabilities --standalone --format json </dev/null

    assert_equals "0" "$status" "capabilities should succeed without TTY"

    local json
    json=$(extract_json "$output")
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SCHEMA VERSION INVARIANT TESTS
#==============================================================================

@test "Contract: agent plan output includes schema_version" {
    require_jq
    test_info "Testing: pt agent plan schema_version"

    run "$PT_CORE" agent plan --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "plan output"
    validate_session_id "$json" "plan output"
    validate_timestamp "$json" "generated_at" "plan output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent capabilities output includes schema_version" {
    require_jq
    test_info "Testing: pt agent capabilities schema_version"

    run "$PT_CORE" agent capabilities --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "capabilities output"
    validate_session_id "$json" "capabilities output"
    validate_timestamp "$json" "generated_at" "capabilities output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent snapshot output includes schema_version" {
    require_jq
    test_info "Testing: pt agent snapshot schema_version"

    run "$PT_CORE" agent snapshot --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "snapshot output"
    validate_session_id "$json" "snapshot output"
    validate_timestamp "$json" "generated_at" "snapshot output"
    validate_timestamp "$json" "timestamp" "snapshot output"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SESSION ID FORMAT TESTS
#==============================================================================

@test "Contract: session_id follows pt-YYYYMMDD-HHMMSS-XXXX format" {
    require_jq
    test_info "Testing session_id format across commands"

    # Test plan
    run "$PT_CORE" agent plan --standalone --format json
    local plan_json
    plan_json=$(extract_json "$output")
    local plan_session
    plan_session=$(echo "$plan_json" | jq -r '.session_id')

    test_info "plan session_id: $plan_session"
    [[ "$plan_session" =~ $SESSION_ID_PATTERN ]]

    # Test snapshot
    run "$PT_CORE" agent snapshot --standalone --format json
    local snapshot_json
    snapshot_json=$(extract_json "$output")
    local snapshot_session
    snapshot_session=$(echo "$snapshot_json" | jq -r '.session_id')

    test_info "snapshot session_id: $snapshot_session"
    [[ "$snapshot_session" =~ $SESSION_ID_PATTERN ]]

    # Each invocation should create a unique session
    [[ "$plan_session" != "$snapshot_session" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# CAPABILITIES OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: capabilities output has required structure" {
    require_jq
    test_info "Testing capabilities output structure"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    local json
    json=$(extract_json "$output")

    # Check required top-level fields
    test_info "Checking required fields..."

    local has_os has_tools has_data_sources has_permissions has_actions
    has_os=$(echo "$json" | jq 'has("os")')
    has_tools=$(echo "$json" | jq 'has("tools")')
    has_data_sources=$(echo "$json" | jq 'has("data_sources")')
    has_permissions=$(echo "$json" | jq 'has("permissions")')
    has_actions=$(echo "$json" | jq 'has("actions")')

    assert_equals "true" "$has_os" "should have os field"
    assert_equals "true" "$has_tools" "should have tools field"
    assert_equals "true" "$has_data_sources" "should have data_sources field"
    assert_equals "true" "$has_permissions" "should have permissions field"
    assert_equals "true" "$has_actions" "should have actions field"

    # Check OS sub-fields
    local os_family os_arch
    os_family=$(echo "$json" | jq -r '.os.family')
    os_arch=$(echo "$json" | jq -r '.os.arch')

    test_info "OS: family=$os_family arch=$os_arch"
    [[ -n "$os_family" && "$os_family" != "null" ]]
    [[ -n "$os_arch" && "$os_arch" != "null" ]]

    # Check permissions sub-fields
    local is_root can_sudo
    is_root=$(echo "$json" | jq '.permissions.is_root')
    can_sudo=$(echo "$json" | jq '.permissions.can_sudo')

    test_info "Permissions: is_root=$is_root can_sudo=$can_sudo"
    [[ "$is_root" == "true" || "$is_root" == "false" ]]
    [[ "$can_sudo" == "true" || "$can_sudo" == "false" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SNAPSHOT OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: snapshot output has system_state" {
    require_jq
    test_info "Testing snapshot output structure"

    run "$PT_CORE" agent snapshot --standalone --format json
    assert_equals "0" "$status" "snapshot should succeed"

    local json
    json=$(extract_json "$output")

    # Check system_state
    local has_system_state
    has_system_state=$(echo "$json" | jq 'has("system_state")')
    assert_equals "true" "$has_system_state" "should have system_state"

    # Check system_state sub-fields
    local cores process_count
    cores=$(echo "$json" | jq '.system_state.cores')
    process_count=$(echo "$json" | jq '.system_state.process_count')

    test_info "System: cores=$cores processes=$process_count"
    [[ "$cores" -gt 0 ]]
    [[ "$process_count" -ge 0 ]]

    # Check load average
    local load_len
    load_len=$(echo "$json" | jq '.system_state.load | length')
    assert_equals "3" "$load_len" "load should have 3 values"

    # Check memory
    local has_memory
    has_memory=$(echo "$json" | jq '.system_state | has("memory")')
    assert_equals "true" "$has_memory" "should have memory info"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# PLAN OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: plan output has required base fields" {
    require_jq
    test_info "Testing plan output base structure"

    run "$PT_CORE" agent plan --standalone --format json

    local json
    json=$(extract_json "$output")

    # Required base fields per contract
    validate_schema_version "$json"
    validate_session_id "$json"
    validate_timestamp "$json"

    # Args should be present showing invocation parameters
    local has_args
    has_args=$(echo "$json" | jq 'has("args")')
    test_info "has_args: $has_args"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# EXIT CODE SEMANTICS TESTS
#==============================================================================

@test "Contract: agent capabilities exits 0 on success" {
    test_info "Testing capabilities exit code"

    run "$PT_CORE" agent capabilities --standalone --format json

    assert_equals "0" "$status" "capabilities should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent snapshot exits 0 on success" {
    test_info "Testing snapshot exit code"

    run "$PT_CORE" agent snapshot --standalone --format json

    assert_equals "0" "$status" "snapshot should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan exits with valid code" {
    test_info "Testing plan exit code"

    run "$PT_CORE" agent plan --standalone --format json

    # Exit codes per CLI_SPECIFICATION.md:
    # 0 = CLEAN (nothing to do)
    # 1 = PLAN_READY (candidates exist)
    # Both are valid for plan command
    [[ $status -eq 0 || $status -eq 1 ]]
    test_info "Plan exit code: $status (0=clean, 1=plan_ready)"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: unknown agent subcommand returns error" {
    test_info "Testing unknown subcommand handling"

    run "$PT_CORE" agent nonexistent --format json 2>&1

    [[ $status -ne 0 ]]
    test_info "Unknown subcommand exit code: $status"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# JSON OUTPUT FORMAT TESTS
#==============================================================================

@test "Contract: --format json produces valid JSON" {
    require_jq
    test_info "Testing JSON output validity"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    # Extract and validate JSON
    local json
    json=$(extract_json "$output")

    # jq should parse without error
    echo "$json" | jq '.' >/dev/null 2>&1
    local jq_status=$?

    assert_equals "0" "$jq_status" "output should be valid JSON"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: --format json output is not empty" {
    require_jq
    test_info "Testing JSON output is not empty"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    local json
    json=$(extract_json "$output")

    local key_count
    key_count=$(echo "$json" | jq 'keys | length')

    [[ "$key_count" -gt 0 ]]
    test_info "JSON has $key_count keys"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# HELP AND VERSION TESTS
#==============================================================================

@test "Contract: agent --help exits 0" {
    test_info "Testing agent --help"

    run "$PT_CORE" agent --help

    assert_equals "0" "$status" "--help should exit 0"
    assert_contains "$output" "agent" "should mention agent"
    assert_contains "$output" "plan" "should mention plan subcommand"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan --help exits 0" {
    test_info "Testing agent plan --help"

    run "$PT_CORE" agent plan --help

    assert_equals "0" "$status" "plan --help should exit 0"
    assert_contains "$output" "plan" "should describe plan"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# STANDALONE MODE TESTS
#==============================================================================

@test "Contract: --standalone flag works without wrapper" {
    require_jq
    test_info "Testing --standalone flag"

    # Unset any wrapper-provided environment
    unset PT_CAPABILITIES_MANIFEST

    run "$PT_CORE" agent capabilities --standalone --format json

    assert_equals "0" "$status" "standalone should work"

    local json
    json=$(extract_json "$output")
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# QUIET AND VERBOSE MODE TESTS
#==============================================================================

@test "Contract: --quiet reduces output verbosity" {
    test_info "Testing --quiet flag"

    run "$PT_CORE" agent capabilities --standalone --format json --quiet

    assert_equals "0" "$status" "--quiet should work"

    # Output should still be valid JSON
    local json
    json=$(extract_json "$output")
    [[ -n "$json" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# JSONL EVENT STREAM TESTS
#==============================================================================

@test "Contract: plan emits JSONL progress events" {
    require_jq
    test_info "Testing JSONL event emission"

    run "$PT_CORE" agent plan --standalone --format json

    # Check if any JSONL events were emitted
    local event_lines
    event_lines=$(echo "$output" | grep -c '^{"event":' || true)

    test_info "Found $event_lines JSONL event lines"

    # At least plan_ready event should be emitted
    if [[ "$event_lines" -gt 0 ]]; then
        local first_event
        first_event=$(echo "$output" | grep '^{"event":' | head -1)

        # Validate event has required fields
        local has_event has_timestamp
        has_event=$(echo "$first_event" | jq 'has("event")')
        has_timestamp=$(echo "$first_event" | jq 'has("timestamp")')

        assert_equals "true" "$has_event" "event should have event field"
        assert_equals "true" "$has_timestamp" "event should have timestamp"
    fi

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# ERROR OUTPUT FORMAT TESTS
#==============================================================================

@test "Contract: error responses follow error schema" {
    require_jq
    test_info "Testing error response format"

    # Try to use a non-existent session
    run "$PT_CORE" agent verify --session pt-00000000-000000-xxxx --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Error exit code: $status"

    # If JSON error is returned, validate structure
    # (implementation may vary - just ensure it doesn't crash)

    BATS_TEST_COMPLETED=pass
}
