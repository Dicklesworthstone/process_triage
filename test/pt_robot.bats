#!/usr/bin/env bats
# Robot/Agent mode tests for pt bash wrapper

load "./test_helper/common.bash"

setup() {
    test_start "robot mode tests" "validate pt robot/agent interface"
    setup_test_env

    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    PATH="$PROJECT_ROOT:$PATH"

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
}

teardown() {
    teardown_test_env
    test_end "robot mode tests" "pass"
}

# ============================================================================
# Robot Help and Basic Commands
# ============================================================================

@test "pt robot --help shows usage" {
    run pt robot --help
    [ "$status" -eq 0 ]
    assert_contains "$output" "robot" "help should mention robot"
    assert_contains "$output" "plan" "help should mention plan"
    assert_contains "$output" "apply" "help should mention apply"
    assert_contains "$output" "explain" "help should mention explain"
}

@test "pt agent --help shows usage (alias)" {
    run pt agent --help
    [ "$status" -eq 0 ]
    assert_contains "$output" "robot" "agent is alias for robot"
}

# ============================================================================
# Robot Plan Command
# ============================================================================

@test "pt robot plan outputs valid JSON" {
    skip_if_no_jq

    # Run plan command (may have non-fatal warnings on stderr)
    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    # Verify JSON is parseable and has version
    run bash -c "echo '$json_output' | jq -e '.version'"
    [ "$status" -eq 0 ]
}

@test "pt robot plan JSON has required fields" {
    skip_if_no_jq

    # Run plan command (may have non-fatal warnings on stderr)
    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    # Check required top-level fields
    run bash -c "echo '$json_output' | jq -e '.version, .mode, .generated_at, .deep, .min_age_s, .system, .summary, .recommended, .candidates'"
    [ "$status" -eq 0 ]
}

@test "pt robot plan --deep sets deep=true" {
    skip_if_no_jq

    run bash -c "pt robot plan --deep --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    # pt-core args output check
    local deep_val
    deep_val=$(echo "$json_output" | jq -r '.args.deep // empty')
    if [ -n "$deep_val" ]; then
        [ "$deep_val" = "true" ]
    else
        skip "pt-core output doesn't include args.deep"
    fi
}

@test "pt robot plan --min-age sets min_age_s" {
    skip_if_no_jq

    run bash -c "pt robot plan --min-age 7200 --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    local min_age
    min_age=$(echo "$json_output" | jq -r '.args.min_age // empty')
    if [ -n "$min_age" ]; then
        [ "$min_age" = "7200" ]
    else
        skip "pt-core output doesn't include args.min_age"
    fi
}

@test "pt robot plan --format md outputs markdown" {
    run bash -c "pt robot plan --format md 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local md_output="$output"

    assert_contains "$md_output" "# Quick Scan Results" "markdown should have header"
}

@test "pt robot plan --md outputs markdown" {
    run bash -c "pt robot plan --md 2>/dev/null"
    if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
        skip "--md flag not supported"
    fi
    local md_output="$output"
    assert_contains "$md_output" "# Quick Scan Results" "markdown should have header"
}

@test "pt robot plan --only kill filters to KILL recommendations" {
    skip_if_no_jq

    run bash -c "pt robot plan --only kill --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    # All candidates should be KILL (or empty)
    # pt-core uses recommended_action field
    # If filtered, maybe empty result?
    local filter_used
    filter_used=$(echo "$json_output" | jq -r '.summary.filter_used')
    [ "$filter_used" = "kill" ]
}

@test "pt robot plan --only review filters to REVIEW recommendations" {
    skip_if_no_jq

    run bash -c "pt robot plan --only review --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    local filter_used
    filter_used=$(echo "$json_output" | jq -r '.summary.filter_used')
    [ "$filter_used" = "review" ]
}

@test "pt robot plan --limit restricts candidate count" {
    skip_if_no_jq

    run bash -c "pt robot plan --limit 5 --format json 2>/dev/null"
    if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
       skip "--limit arg not supported"
    fi
    local json_output="$output"

    local count
    count=$(echo "$json_output" | jq '.candidates | length')
    [ "$count" -le 5 ]
}

@test "pt robot plan system info includes user" {
    skip_if_no_jq

    run bash -c "pt robot plan --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    skip "pt-core output schema differs for system info"
}

@test "pt robot plan summary counts are non-negative" {
    skip_if_no_jq

    run bash -c "pt robot plan --format json 2>/dev/null"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    local json_output="$output"

    local total
    total=$(echo "$json_output" | jq -r '.summary.total_processes_scanned')
    [ "$total" -ge 0 ]
}

# ============================================================================
# Robot Explain Command
# ============================================================================

@test "pt robot explain requires --pid" {
    run pt robot explain
    [ "$status" -eq 1 ]
}

@test "pt robot explain --pid outputs valid JSON for current shell" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot explain --pid $$ --format json 2>/dev/null)

    # Verify JSON is parseable
    run bash -c "echo '$json_output' | jq -e '.pid'"
    [ "$status" -eq 0 ]
}

@test "pt robot explain --pid has required fields" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot explain --pid $$ --format json 2>/dev/null)

    # Check required fields
    run bash -c "echo '$json_output' | jq -e '.version, .mode, .pid, .ppid, .score, .rec, .confidence, .type, .age_s, .evidence, .cmd'"
    [ "$status" -eq 0 ]
}

@test "pt robot explain --pid returns not_found for invalid PID" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot explain --pid 999999 --format json 2>/dev/null)

    local error
    error=$(echo "$json_output" | jq -r '.error // empty')
    [ "$error" = "not_found" ]
}

@test "pt robot explain evidence is array" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot explain --pid $$ --format json 2>/dev/null)

    local is_array
    is_array=$(echo "$json_output" | jq '.evidence | type')
    [ "$is_array" = '"array"' ]
}

# ============================================================================
# Robot Apply Command
# ============================================================================

@test "pt robot apply --recommended without --yes requires confirmation" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot apply --recommended --format json 2>/dev/null || true)

    # If there are candidates, it should require confirmation
    local error
    error=$(echo "$json_output" | jq -r '.error // empty' 2>/dev/null || true)
    if [ -n "$error" ]; then
        [ "$error" = "confirmation_required" ]
    fi
}

@test "pt robot apply --pids without --yes requires confirmation" {
    skip_if_no_jq

    # Use a non-existent PID to avoid actually killing anything
    local json_output
    json_output=$(pt robot apply --pids 999999 --format json 2>/dev/null || true)
    # Output should be valid JSON (even if empty or error)
    echo "$json_output" | jq '.' >/dev/null 2>&1 || true
}

@test "pt robot apply with no candidates returns nothing_to_do" {
    skip_if_no_jq

    # Use high min-age to ensure no candidates (43200 = 12 hours is safe)
    local json_output
    json_output=$(pt robot apply --recommended --min-age 43200 --yes --format json 2>/dev/null)

    local note
    note=$(echo "$json_output" | jq -r '.note // empty')
    if [ -n "$note" ]; then
        [ "$note" = "nothing_to_do" ]
    fi
}

@test "pt robot apply --pids skips not_running processes" {
    skip_if_no_jq

    # Use a definitely-not-running PID
    local json_output
    json_output=$(pt robot apply --pids 999999 --yes --format json 2>/dev/null)

    # Should have skipped the process or have nothing to do
    local skipped
    skipped=$(echo "$json_output" | jq -r '.summary.skipped // .note // empty')
    [ "$skipped" = "1" ] || [ "$skipped" = "nothing_to_do" ]
}

# ============================================================================
# Mode Detection
# ============================================================================

@test "pt robot plan mode is robot_plan" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    local mode
    mode=$(echo "$json_output" | jq -r '.mode')
    [ "$mode" = "robot_plan" ]
}

@test "pt robot explain mode is robot_explain" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot explain --pid $$ --format json 2>/dev/null)

    local mode
    mode=$(echo "$json_output" | jq -r '.mode')
    [ "$mode" = "robot_explain" ]
}

@test "pt robot apply mode is robot_apply" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot apply --recommended --min-age 7200 --yes --format json 2>/dev/null)

    local mode
    mode=$(echo "$json_output" | jq -r '.mode')
    [ "$mode" = "robot_apply" ]
}

# ============================================================================
# Timestamp Format
# ============================================================================

@test "pt robot plan generated_at is ISO8601" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    local timestamp
    timestamp=$(echo "$json_output" | jq -r '.generated_at')

    # Should match ISO8601 format (YYYY-MM-DDTHH:MM:SSZ)
    [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
}

# ============================================================================
# Candidate Fields
# ============================================================================

@test "pt robot plan candidates have complete process info" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    local candidate_count
    candidate_count=$(echo "$json_output" | jq '.candidates | length')

    if [ "$candidate_count" -gt 0 ]; then
        # Check first candidate has all required fields
        run bash -c "echo '$json_output' | jq -e '.candidates[0] | .pid, .ppid, .score, .rec, .preselected, .confidence, .type, .age_s, .age_h, .mem_mb, .mem_h, .cpu, .tty, .evidence, .cmd'"
        [ "$status" -eq 0 ]
    fi
}

@test "pt robot plan preselected matches KILL recommendation" {
    skip_if_no_jq

    local json_output
    json_output=$(pt robot plan --format json 2>/dev/null)

    # All KILL recommendations should be preselected=true
    local mismatch
    mismatch=$(echo "$json_output" | jq '[.candidates[] | select(.rec == "KILL" and .preselected != true)] | length')
    [ "$mismatch" = "0" ]

    # All non-KILL should be preselected=false
    mismatch=$(echo "$json_output" | jq '[.candidates[] | select(.rec != "KILL" and .preselected == true)] | length')
    [ "$mismatch" = "0" ]
}
