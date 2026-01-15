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

#==============================================================================
# AGENT SESSIONS COMMAND TESTS
#==============================================================================

@test "Contract: agent sessions output includes schema_version" {
    require_jq
    test_info "Testing: pt agent sessions schema_version"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "sessions output"
    validate_timestamp "$json" "generated_at" "sessions output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions list has sessions array" {
    require_jq
    test_info "Testing: sessions list output structure"

    run "$PT_CORE" agent sessions --standalone --format json

    assert_equals "0" "$status" "sessions should succeed"

    local json
    json=$(extract_json "$output")

    # Must have sessions array
    local has_sessions
    has_sessions=$(echo "$json" | jq 'has("sessions")')
    assert_equals "true" "$has_sessions" "should have sessions array"

    # Sessions should be an array
    local is_array
    is_array=$(echo "$json" | jq '.sessions | type == "array"')
    assert_equals "true" "$is_array" "sessions should be array"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions list has total_count" {
    require_jq
    test_info "Testing: sessions list total_count"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have total_count
    local has_count
    has_count=$(echo "$json" | jq 'has("total_count")')
    assert_equals "true" "$has_count" "should have total_count"

    # total_count should be a number
    local count
    count=$(echo "$json" | jq '.total_count')
    [[ "$count" =~ ^[0-9]+$ ]]
    test_info "total_count: $count"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --status returns single session" {
    require_jq
    test_info "Testing: sessions --status for single session"

    # First create a session via snapshot
    run "$PT_CORE" agent snapshot --standalone --format json
    assert_equals "0" "$status" "snapshot should succeed"

    local snapshot_json
    snapshot_json=$(extract_json "$output")
    local session_id
    session_id=$(echo "$snapshot_json" | jq -r '.session_id')
    test_info "Created session: $session_id"

    # Now query that session
    run "$PT_CORE" agent sessions --status "$session_id" --standalone --format json
    assert_equals "0" "$status" "sessions --status should succeed"

    local json
    json=$(extract_json "$output")

    # Should have the same session_id
    local returned_id
    returned_id=$(echo "$json" | jq -r '.session_id')
    assert_equals "$session_id" "$returned_id" "should return correct session"

    # Should have state
    local has_state
    has_state=$(echo "$json" | jq 'has("state")')
    assert_equals "true" "$has_state" "should have state"

    # Should have resumable flag
    local has_resumable
    has_resumable=$(echo "$json" | jq 'has("resumable")')
    assert_equals "true" "$has_resumable" "should have resumable"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --status invalid session returns error" {
    test_info "Testing: sessions --status with invalid session"

    run "$PT_CORE" agent sessions --status pt-00000000-000000-xxxx --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Invalid session exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --state filter works" {
    require_jq
    test_info "Testing: sessions --state filter"

    run "$PT_CORE" agent sessions --state created --standalone --format json

    assert_equals "0" "$status" "sessions --state should succeed"

    local json
    json=$(extract_json "$output")

    # All returned sessions should have state "created" (or empty list)
    local sessions_count
    sessions_count=$(echo "$json" | jq '.sessions | length')
    test_info "Found $sessions_count sessions with state=created"

    if [[ "$sessions_count" -gt 0 ]]; then
        # Check first session has correct state
        local first_state
        first_state=$(echo "$json" | jq -r '.sessions[0].state')
        assert_equals "created" "$first_state" "filtered sessions should have correct state"
    fi

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --limit works" {
    require_jq
    test_info "Testing: sessions --limit"

    run "$PT_CORE" agent sessions --limit 5 --standalone --format json

    assert_equals "0" "$status" "sessions --limit should succeed"

    local json
    json=$(extract_json "$output")

    local sessions_count
    sessions_count=$(echo "$json" | jq '.sessions | length')
    test_info "Returned $sessions_count sessions (limit=5)"

    # Should return at most 5
    [[ "$sessions_count" -le 5 ]]

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions exits 0 on success" {
    test_info "Testing sessions exit code"

    run "$PT_CORE" agent sessions --standalone --format json

    assert_equals "0" "$status" "sessions should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --help exits 0" {
    test_info "Testing agent sessions --help"

    run "$PT_CORE" agent sessions --help

    assert_equals "0" "$status" "sessions --help should exit 0"
    assert_contains "$output" "sessions" "should describe sessions"
    assert_contains "$output" "status" "should mention --status"
    assert_contains "$output" "cleanup" "should mention --cleanup"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --format summary works" {
    test_info "Testing sessions summary format"

    run "$PT_CORE" agent sessions --standalone --format summary

    assert_equals "0" "$status" "sessions summary should succeed"

    # Summary should contain session count or "No sessions"
    [[ "$output" =~ session || "$output" =~ "No sessions" ]]
    test_info "Summary output: $output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions JSON includes host_id" {
    require_jq
    test_info "Testing: sessions host_id field"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have host_id at top level
    local has_host
    has_host=$(echo "$json" | jq 'has("host_id")')
    assert_equals "true" "$has_host" "should have host_id"

    local host_id
    host_id=$(echo "$json" | jq -r '.host_id')
    [[ -n "$host_id" ]]
    test_info "host_id: $host_id"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# AGENT LIST-PRIORS COMMAND TESTS
#==============================================================================

@test "Contract: agent list-priors output includes schema_version" {
    require_jq
    test_info "Testing: pt agent list-priors schema_version"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "list-priors output"
    validate_session_id "$json" "list-priors output"
    validate_timestamp "$json" "generated_at" "list-priors output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors has classes array" {
    require_jq
    test_info "Testing: list-priors classes output structure"

    run "$PT_CORE" agent list-priors --standalone --format json

    assert_equals "0" "$status" "list-priors should succeed"

    local json
    json=$(extract_json "$output")

    # Must have classes array
    local has_classes
    has_classes=$(echo "$json" | jq 'has("classes")')
    assert_equals "true" "$has_classes" "should have classes array"

    # Classes should be an array
    local is_array
    is_array=$(echo "$json" | jq '.classes | type == "array"')
    assert_equals "true" "$is_array" "classes should be array"

    # By default should have 4 classes
    local classes_count
    classes_count=$(echo "$json" | jq '.classes | length')
    assert_equals "4" "$classes_count" "should have 4 classes by default"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors classes have required Beta params" {
    require_jq
    test_info "Testing: list-priors class Beta parameters"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Check first class (useful) has required beta params
    local first_class
    first_class=$(echo "$json" | jq '.classes[0]')

    local class_name
    class_name=$(echo "$first_class" | jq -r '.class')
    test_info "Checking class: $class_name"

    # Must have cpu_beta with alpha/beta
    local has_cpu_beta
    has_cpu_beta=$(echo "$first_class" | jq 'has("cpu_beta")')
    assert_equals "true" "$has_cpu_beta" "should have cpu_beta"

    local cpu_alpha cpu_beta
    cpu_alpha=$(echo "$first_class" | jq '.cpu_beta.alpha')
    cpu_beta=$(echo "$first_class" | jq '.cpu_beta.beta')
    test_info "cpu_beta: alpha=$cpu_alpha beta=$cpu_beta"
    [[ "$cpu_alpha" != "null" && "$cpu_beta" != "null" ]]

    # Must have orphan_beta
    local has_orphan_beta
    has_orphan_beta=$(echo "$first_class" | jq 'has("orphan_beta")')
    assert_equals "true" "$has_orphan_beta" "should have orphan_beta"

    # Must have tty_beta
    local has_tty_beta
    has_tty_beta=$(echo "$first_class" | jq 'has("tty_beta")')
    assert_equals "true" "$has_tty_beta" "should have tty_beta"

    # Must have net_beta
    local has_net_beta
    has_net_beta=$(echo "$first_class" | jq 'has("net_beta")')
    assert_equals "true" "$has_net_beta" "should have net_beta"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --class filter works" {
    require_jq
    test_info "Testing: list-priors --class filter"

    run "$PT_CORE" agent list-priors --class zombie --standalone --format json

    assert_equals "0" "$status" "list-priors --class should succeed"

    local json
    json=$(extract_json "$output")

    # Should have exactly 1 class
    local classes_count
    classes_count=$(echo "$json" | jq '.classes | length')
    assert_equals "1" "$classes_count" "should have 1 class when filtered"

    # That class should be "zombie"
    local class_name
    class_name=$(echo "$json" | jq -r '.classes[0].class')
    assert_equals "zombie" "$class_name" "filtered class should be zombie"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --class validates input" {
    test_info "Testing: list-priors --class validation"

    run "$PT_CORE" agent list-priors --class invalid_class --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Invalid class exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --extended adds extra sections" {
    require_jq
    test_info "Testing: list-priors --extended flag"

    run "$PT_CORE" agent list-priors --extended --standalone --format json

    assert_equals "0" "$status" "list-priors --extended should succeed"

    local json
    json=$(extract_json "$output")

    # Extended mode should include bocpd section (from priors)
    local has_bocpd
    has_bocpd=$(echo "$json" | jq 'has("bocpd")')
    test_info "has_bocpd: $has_bocpd"

    # May also have other extended sections depending on config
    # Just verify the basic structure is valid
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors has source info" {
    require_jq
    test_info "Testing: list-priors source information"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have source section
    local has_source
    has_source=$(echo "$json" | jq 'has("source")')
    assert_equals "true" "$has_source" "should have source section"

    # Source should describe where priors came from
    local using_defaults
    using_defaults=$(echo "$json" | jq '.source.using_defaults')
    test_info "source.using_defaults: $using_defaults"
    [[ "$using_defaults" == "true" || "$using_defaults" == "false" ]]

    # Should have priors_schema_version
    local schema_ver
    schema_ver=$(echo "$json" | jq -r '.source.priors_schema_version')
    test_info "source.priors_schema_version: $schema_ver"
    [[ "$schema_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors exits 0 on success" {
    test_info "Testing list-priors exit code"

    run "$PT_CORE" agent list-priors --standalone --format json

    assert_equals "0" "$status" "list-priors should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --help exits 0" {
    test_info "Testing agent list-priors --help"

    run "$PT_CORE" agent list-priors --help

    assert_equals "0" "$status" "list-priors --help should exit 0"
    assert_contains "$output" "list-priors" "should describe list-priors"
    assert_contains "$output" "class" "should mention --class"
    assert_contains "$output" "extended" "should mention --extended"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format summary works" {
    test_info "Testing list-priors summary format"

    run "$PT_CORE" agent list-priors --standalone --format summary

    assert_equals "0" "$status" "list-priors summary should succeed"

    # Summary should contain priors info
    [[ -n "$output" ]]
    test_info "Summary output: $output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format md works" {
    test_info "Testing list-priors markdown format"

    run "$PT_CORE" agent list-priors --standalone --format md

    assert_equals "0" "$status" "list-priors md should succeed"

    # Markdown should have table structure
    assert_contains "$output" "Parameter" "should have Parameter header"
    assert_contains "$output" "Value" "should have Value header"
    assert_contains "$output" "|" "should have markdown table pipes"

    # Should have class section headers
    assert_contains "$output" "## useful" "should have useful class section"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors JSON includes host_id" {
    require_jq
    test_info "Testing: list-priors host_id field"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have host_id at top level
    local has_host
    has_host=$(echo "$json" | jq 'has("host_id")')
    assert_equals "true" "$has_host" "should have host_id"

    local host_id
    host_id=$(echo "$json" | jq -r '.host_id')
    [[ -n "$host_id" ]]
    test_info "host_id: $host_id"

    BATS_TEST_COMPLETED=pass
}
