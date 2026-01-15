#!/usr/bin/env bats
# Scoring + recommendation tests for bash pt (legacy engine)

load "./test_helper/common.bash"

setup() {
    test_start "scoring" "validate heuristic scoring + tiering"
    setup_test_env

    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    PATH="$PROJECT_ROOT:$PATH"

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export DECISIONS_FILE="$CONFIG_DIR/decisions.json"
    export LOG_FILE="$CONFIG_DIR/triage.log"

    # Scoring constants (keep aligned with pt)
    THRESHOLD_KILL=60
    THRESHOLD_REVIEW=30
    declare -gA TYPE_LIFETIME=(
        [test]=1800
        [dev_server]=259200
        [agent]=43200
        [shell]=3600
        [build]=7200
        [daemon]=0
        [unknown]=86400
    )
}

teardown() {
    teardown_test_env
    test_end "scoring" "pass"
}

load_scoring_functions() {
    source <(sed -n '/^is_protected_cmd()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^classify_process()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^normalize_pattern()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^get_cached_decision()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^score_process_bayesian()/,/^}/p' "$PROJECT_ROOT/pt")
}

parse_score_result() {
    local result="$1"
    IFS='|' read -r score rec confidence ptype evidence <<< "$result"
    SCORE_OUT="$score"
    REC_OUT="$rec"
    CONF_OUT="$confidence"
    PTYPE_OUT="$ptype"
    EVIDENCE_OUT="$evidence"
}

reset_decision_cache() {
    DECISIONS_CACHE_FILE="$CONFIG_DIR/decisions_cache"
    : > "$DECISIONS_CACHE_FILE"
}

#------------------------------------------------------------------------------
# Classification + protection
#------------------------------------------------------------------------------

@test "classify_process detects common patterns" {
    load_scoring_functions

    [ "$(classify_process "bun test")" = "test" ]
    [ "$(classify_process "next dev")" = "dev_server" ]
    [ "$(classify_process "claude run")" = "agent" ]
    [ "$(classify_process "zsh -c echo hi")" = "shell" ]
}

@test "protected commands are always SPARE" {
    load_scoring_functions
    reset_decision_cache

    local result
    result=$(score_process_bayesian 100 1 999999 12000 99 "?" "sshd -D" "false")
    parse_score_result "$result"

    [ "$REC_OUT" = "SPARE" ]
    [[ "$EVIDENCE_OUT" == *"protected:system_service"* ]]
}

#------------------------------------------------------------------------------
# Scoring invariants
#------------------------------------------------------------------------------

@test "orphaned process contributes strong evidence" {
    load_scoring_functions
    reset_decision_cache

    local result
    result=$(score_process_bayesian 123 1 10800 0 0 "?" "sleep 9999" "false")
    parse_score_result "$result"

    [[ "$EVIDENCE_OUT" == *"orphaned:PPID=1"* ]]
    [ "$SCORE_OUT" -gt 0 ]
}

@test "decision history boosts KILL prior to REVIEW" {
    load_scoring_functions
    reset_decision_cache

    local cmd="sleep 10"
    local pattern
    pattern=$(normalize_pattern "$cmd")
    printf '%s\t%s\n' "$pattern" "kill" > "$DECISIONS_CACHE_FILE"

    local result
    result=$(score_process_bayesian 55 2 10 0 0 "?" "$cmd" "false")
    parse_score_result "$result"

    [ "$REC_OUT" = "REVIEW" ]
    [[ "$EVIDENCE_OUT" == *"history:killed_before"* ]]
}

@test "decision history spare reduces score" {
    load_scoring_functions
    reset_decision_cache

    local cmd="bun test"
    local base
    base=$(score_process_bayesian 77 2 7200 0 0 "?" "$cmd" "false")
    parse_score_result "$base"
    local base_score="$SCORE_OUT"

    local pattern
    pattern=$(normalize_pattern "$cmd")
    printf '%s\t%s\n' "$pattern" "spare" > "$DECISIONS_CACHE_FILE"

    local spared
    spared=$(score_process_bayesian 77 2 7200 0 0 "?" "$cmd" "false")
    parse_score_result "$spared"

    [ "$SCORE_OUT" -le $((base_score - 40)) ]
    [[ "$EVIDENCE_OUT" == *"history:spared_before"* ]]
}

#------------------------------------------------------------------------------
# Recommendation tiering
#------------------------------------------------------------------------------

@test "tiering boundaries: KILL/REVIEW/SPARE" {
    load_scoring_functions
    reset_decision_cache

    # KILL: stuck test runner (age + pattern + idle)
    local kill_result
    kill_result=$(score_process_bayesian 10 2 7200 0 0 "?" "bun test" "false")
    parse_score_result "$kill_result"
    [ "$REC_OUT" = "KILL" ]

    # REVIEW: dev server idle ~22h
    local review_result
    review_result=$(score_process_bayesian 11 2 79200 0 0 "?" "next dev" "false")
    parse_score_result "$review_result"
    [ "$REC_OUT" = "REVIEW" ]

    # SPARE: short-lived unknown
    local spare_result
    spare_result=$(score_process_bayesian 12 2 1200 0 5 "?" "sleep 5" "false")
    parse_score_result "$spare_result"
    [ "$REC_OUT" = "SPARE" ]
}
