#!/usr/bin/env bats
# Decision memory function-level tests (no mocks)

load "./test_helper/common.bash"

setup() {
    test_start "decision memory" "validate save/get/cache helpers"
    setup_test_env

    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    PATH="$PROJECT_ROOT:$PATH"

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export DECISIONS_FILE="$CONFIG_DIR/decisions.json"
    export LOG_FILE="$CONFIG_DIR/triage.log"

    # Ensure a known-good starting file
    echo '{}' > "$DECISIONS_FILE"

    # Define a minimal log function for save_decision
    log() {
        printf '%s\n' "$*" >> "$LOG_FILE"
    }
}

teardown() {
    teardown_test_env
    test_end "decision memory" "pass"
}

load_decision_functions() {
    source <(sed -n '/^load_decisions_cache()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^get_cached_decision()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^get_past_decision()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^save_decision()/,/^}/p' "$PROJECT_ROOT/pt")
}

#------------------------------------------------------------------------------
# save_decision tests
#------------------------------------------------------------------------------

@test "save_decision: creates valid JSON" {
    skip_if_no_jq
    load_decision_functions

    save_decision "test pattern" "kill"

    jq -e '.' "$DECISIONS_FILE" >/dev/null
}

@test "save_decision: stores kill decision" {
    skip_if_no_jq
    load_decision_functions

    save_decision "bun test" "kill"

    local stored
    stored=$(jq -r '."bun test"' "$DECISIONS_FILE")
    [ "$stored" = "kill" ]
}

@test "save_decision: stores spare decision" {
    skip_if_no_jq
    load_decision_functions

    save_decision "gunicorn" "spare"

    local stored
    stored=$(jq -r '.gunicorn' "$DECISIONS_FILE")
    [ "$stored" = "spare" ]
}

@test "save_decision: overwrites previous decision" {
    skip_if_no_jq
    load_decision_functions

    save_decision "pattern1" "kill"
    save_decision "pattern1" "spare"

    local stored
    stored=$(jq -r '.pattern1' "$DECISIONS_FILE")
    [ "$stored" = "spare" ]
}

@test "save_decision: handles patterns with special characters" {
    skip_if_no_jq
    load_decision_functions

    local pattern='path/to/file --flag="value"'
    save_decision "$pattern" "kill"

    jq -e '.' "$DECISIONS_FILE" >/dev/null

    local stored
    stored=$(jq -r --arg k "$pattern" '.[$k]' "$DECISIONS_FILE")
    [ "$stored" = "kill" ]
}

@test "save_decision: handles multiple patterns" {
    skip_if_no_jq
    load_decision_functions

    save_decision "pattern1" "kill"
    save_decision "pattern2" "spare"
    save_decision "pattern3" "kill"

    local count
    count=$(jq 'length' "$DECISIONS_FILE")
    [ "$count" -eq 3 ]
}

#------------------------------------------------------------------------------
# get_past_decision tests
#------------------------------------------------------------------------------

@test "get_past_decision: returns stored decision" {
    skip_if_no_jq
    load_decision_functions

    echo '{"bun test": "kill"}' > "$DECISIONS_FILE"

    local result
    result=$(get_past_decision "bun test")
    [ "$result" = "kill" ]
}

@test "get_past_decision: returns unknown for missing pattern" {
    skip_if_no_jq
    load_decision_functions

    echo '{}' > "$DECISIONS_FILE"

    local result
    result=$(get_past_decision "nonexistent")
    [ "$result" = "unknown" ]
}

#------------------------------------------------------------------------------
# Cache tests
#------------------------------------------------------------------------------

@test "load_decisions_cache + get_cached_decision: returns cached values" {
    skip_if_no_jq
    load_decision_functions

    echo '{"p1": "kill", "p2": "spare", "p3": "kill"}' > "$DECISIONS_FILE"

    DECISIONS_CACHE_FILE=""
    DECISIONS_CACHE_LOADED=false
    load_decisions_cache

    [ "$(get_cached_decision "p1")" = "kill" ]
    [ "$(get_cached_decision "p2")" = "spare" ]
    [ "$(get_cached_decision "p3")" = "kill" ]
}

@test "get_cached_decision: exact match only" {
    skip_if_no_jq
    load_decision_functions

    echo '{"bun test": "kill"}' > "$DECISIONS_FILE"

    DECISIONS_CACHE_FILE=""
    DECISIONS_CACHE_LOADED=false
    load_decisions_cache

    local result
    result=$(get_cached_decision "bun")
    [ "$result" = "unknown" ]
}

@test "get_cached_decision: returns unknown for missing" {
    skip_if_no_jq
    load_decision_functions

    echo '{}' > "$DECISIONS_FILE"

    DECISIONS_CACHE_FILE=""
    DECISIONS_CACHE_LOADED=false
    load_decisions_cache

    local result
    result=$(get_cached_decision "missing")
    [ "$result" = "unknown" ]
}

@test "decision memory: survives reload" {
    skip_if_no_jq
    load_decision_functions

    save_decision "persistent pattern" "kill"

    DECISIONS_CACHE_FILE=""
    DECISIONS_CACHE_LOADED=false
    load_decisions_cache

    [ "$(get_cached_decision "persistent pattern")" = "kill" ]
}
