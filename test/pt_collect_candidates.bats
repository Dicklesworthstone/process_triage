#!/usr/bin/env bats
# collect_candidates integration tests with mock ps output

load "./test_helper/common.bash"

setup() {
    test_start "collect_candidates" "mock ps-based candidate filtering"
    setup_test_env

    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"

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

    use_mock_bin
}

teardown() {
    restore_path
    teardown_test_env
    test_end "collect_candidates" "pass"
}

load_collect_functions() {
    source <(sed -n '/^load_decisions_cache()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^get_cached_decision()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^normalize_pattern()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^classify_process()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^is_protected_cmd()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^score_process_bayesian()/,/^}/p' "$PROJECT_ROOT/pt")
    source <(sed -n '/^collect_candidates()/,/^}/p' "$PROJECT_ROOT/pt")
}

parse_candidate() {
    local candidate="$1"
    IFS=$'\t' read -r score pid ppid age mem cpu tty rec confidence ptype evidence cmd <<< "$candidate"
    SCORE_OUT="$score"
    PID_OUT="$pid"
    AGE_OUT="$age"
    REC_OUT="$rec"
    CMD_OUT="$cmd"
}

sanitize_candidates() {
    local filtered=()
    local entry
    for entry in "${candidates[@]}"; do
        [[ -n "$entry" ]] && filtered+=("$entry")
    done
    candidates=("${filtered[@]}")
}

@test "collect_candidates filters protected patterns and sorts by score" {
    load_collect_functions

    # Mock ps output: one high-score candidate, one lower-score, one protected
    cat > "${MOCK_BIN}/ps" << 'EOF_PS'
#!/usr/bin/env bash
cat << 'EOF_OUTPUT'
100 1 4000 10240 0.0 ? bun test
101 1 2000 20480 0.0 ? next dev
102 1 5000 20480 0.1 ? systemd
EOF_OUTPUT
EOF_PS
    chmod +x "${MOCK_BIN}/ps"

    local candidates=()
    mapfile -t candidates < <(collect_candidates 0 false)
    sanitize_candidates

    [ "${#candidates[@]}" -eq 2 ]
    parse_candidate "${candidates[0]}"
    [ "$CMD_OUT" = "bun test" ]
    [ "$REC_OUT" = "KILL" ]
    parse_candidate "${candidates[1]}"
    [ "$CMD_OUT" = "next dev" ]
}

@test "collect_candidates returns empty when only protected entries exist" {
    load_collect_functions

    cat > "${MOCK_BIN}/ps" << 'EOF_PS'
#!/usr/bin/env bash
cat << 'EOF_OUTPUT'
200 1 99999 20480 0.1 ? systemd
EOF_OUTPUT
EOF_PS
    chmod +x "${MOCK_BIN}/ps"

    local candidates=()
    mapfile -t candidates < <(collect_candidates 0 false)
    sanitize_candidates

    [ "${#candidates[@]}" -eq 0 ]
}
