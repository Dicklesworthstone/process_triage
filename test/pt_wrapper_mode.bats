#!/usr/bin/env bats

PT_SCRIPT="${BATS_TEST_DIRNAME}/../pt"

setup() {
    if [[ ! -x "$PT_SCRIPT" ]]; then
        echo "pt wrapper not found at $PT_SCRIPT" >&2
        exit 1
    fi

    export TEST_DIR="${BATS_TEST_TMPDIR}/pt_wrapper_mode_${BATS_TEST_NUMBER}_$$"
    mkdir -p "$TEST_DIR"

    export MOCK_LOG="${TEST_DIR}/mock.log"
    export MOCK_PT_CORE="${TEST_DIR}/pt-core-mock"
    cat > "$MOCK_PT_CORE" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${PT_WRAPPER_TEST_LOG:?PT_WRAPPER_TEST_LOG must be set}"

{
    printf 'PT_UI_MODE=%s\n' "${PT_UI_MODE:-}"
    printf 'ARGS=%s\n' "$*"
} > "$PT_WRAPPER_TEST_LOG"
EOF
    chmod +x "$MOCK_PT_CORE"
}

@test "wrapper: --shell sets mode and strips wrapper flag before forwarding" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --shell scan --format json

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=shell$' "$MOCK_LOG"
    grep -q '^ARGS=scan --format json$' "$MOCK_LOG"
}

@test "wrapper: --tui sets mode and strips wrapper flag before forwarding" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --tui run

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=tui$' "$MOCK_LOG"
    grep -q '^ARGS=run$' "$MOCK_LOG"
}

@test "wrapper: --shell and --tui together fail fast" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --shell --tui scan

    [ "$status" -eq 2 ]
    [[ "$output" == *"--shell and --tui cannot be used together"* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: PT_UI_MODE=tui forces tui mode" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PT_UI_MODE=tui \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=tui$' "$MOCK_LOG"
}

@test "wrapper: auto mode picks shell in CI/non-interactive contexts" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PT_UI_MODE=auto \
        CI=true \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=shell$' "$MOCK_LOG"
}

@test "wrapper: invalid PT_UI_MODE falls back to auto detection" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PT_UI_MODE=invalid_mode \
        TERM=dumb \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=shell$' "$MOCK_LOG"
}

@test "wrapper: version check still works with wrapper mode flags" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --shell --version

    [ "$status" -eq 0 ]
    [[ "$output" == *"pt 2.0.3"* ]]
    [ ! -f "$MOCK_LOG" ]
}
