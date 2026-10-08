#!/usr/bin/env bats

load "./common.bash"

@test "test helper creates env and mock command" {
    test_start "test helper creates env and mock command" "ensure setup and mocks work"
    setup_test_dirs

    [ -d "$CONFIG_DIR" ]
    [ -d "$MOCK_BIN" ]
    [ -f "$CONFIG_DIR/decisions.json" ]

    create_mock_command "hello" "world" 0
    [ -x "$MOCK_BIN/hello" ]
    run "$MOCK_BIN/hello"
    [ "$status" -eq 0 ]
    [ "$output" = "world" ]

    test_end "test helper creates env and mock command" "pass"
}

@test "test helper mock preserves literal multiline data and failing status" {
    setup_test_dirs
    local payload=$'first & | \\ $(printf unintended)\n__MOCK_EXIT__\nMOCK_OUTPUT\nlast'
    create_mock_command "literal" "$payload" 37
    run "$MOCK_BIN/literal"
    [ "$status" -eq 37 ]
    [ "$output" = "$payload" ]

    create_mock_command "empty" "" 0
    run "$MOCK_BIN/empty"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "test helper redirect preserves literal URL and default empty response" {
    setup_test_dirs
    local url='https://example.invalid/a?one=1&two=$(printf unintended)|three=__REDIRECT_URL__'
    create_mock_curl_redirect "$url"
    run "$MOCK_BIN/curl" -w '%{url_effective}'
    [ "$status" -eq 0 ]
    [ "$output" = "$url" ]
    run "$MOCK_BIN/curl" --silent https://example.invalid/
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "test helper command assertions preserve argv and reject wrong statuses" {
    local payload='literal; printf unintended'
    run assert_success "literal argument" printf '%s\n' "$payload"
    [ "$status" -eq 0 ]
    [ "$output" = "$payload" ]
    run assert_success "failure rejected" bash -c 'exit 37'
    [ "$status" -eq 1 ]
    run assert_fails 37 "expected failure" bash -c 'exit 37'
    [ "$status" -eq 0 ]
    run assert_fails 36 "wrong status rejected" bash -c 'exit 37'
    [ "$status" -eq 1 ]
    run assert_fails 37 "success rejected" true
    [ "$status" -eq 1 ]
    run assert_success "missing command"
    [ "$status" -eq 2 ]
    run assert_fails 37 "missing command"
    [ "$status" -eq 2 ]
    run assert_fails invalid "invalid status" true
    [ "$status" -eq 2 ]
}

@test "test helper timing preserves argv and actual failing exit" {
    setup_test_dirs
    local payload='literal; printf unintended'
    run time_command "literal argument" bash -c \
        'printf "%s\n" "$1" > "$2"; exit 37' -- "$payload" "$TEST_DIR/timed-output"
    [ "$status" -eq 37 ]
    [ "$(cat "$TEST_DIR/timed-output")" = "$payload" ]
    [[ "$output" =~ completed\ in\ [0-9]+ms\ \(exit=37\) ]]
    run time_command "missing command"
    [ "$status" -eq 2 ]
}

@test "test helper full environment refuses missing core without compiling" {
    export PT_CORE_PATH="$BATS_TEST_TMPDIR/absent-core-$$"
    run setup_test_env
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required pt-core binary is not an executable file"* ]]
    [[ "$output" == *"Build through RCH before BATS"* ]]
    export PT_CORE_PATH="$BATS_TEST_TMPDIR"
    run setup_test_env
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required pt-core binary is not an executable file"* ]]
}

@test "test helper selects prebuilt release and CI override without rewriting fixtures" {
    setup_test_dirs
    unset PT_CORE_PATH PT_CORE
    export PROJECT_ROOT="$TEST_DIR/prebuilt-project"
    mkdir -p "$PROJECT_ROOT/target/release"
    # These executable fixtures prove selection only, never native core behavior.
    create_mock_command "core_fixture" "fixture-only" 0
    cp "$MOCK_BIN/core_fixture" "$PROJECT_ROOT/target/release/pt-core"
    setup_test_env
    [ "$PT_CORE_PATH" = "$PROJECT_ROOT/target/release/pt-core" ]
    [ ! -e "$PROJECT_ROOT/target/debug" ]
    cmp "$MOCK_BIN/core_fixture" "$PROJECT_ROOT/target/release/pt-core"

    unset PT_CORE_PATH
    export PT_CORE="$MOCK_BIN/core_fixture"
    setup_test_env
    [ "$PT_CORE_PATH" = "$MOCK_BIN/core_fixture" ]

    export PT_CORE_PATH="$TEST_DIR/explicit-missing"
    run setup_test_env
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required pt-core binary is not an executable file"* ]]
}
