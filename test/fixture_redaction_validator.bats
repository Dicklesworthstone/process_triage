#!/usr/bin/env bats

setup() {
    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    export PROJECT_ROOT
}

@test "Fixture redaction verification passes" {
    local fixtures=(
        "$PROJECT_ROOT/test/fixtures/config"
        "$PROJECT_ROOT/test/fixtures/pt-core"
        "$PROJECT_ROOT/test/fixtures/manifest_examples"
        "$PROJECT_ROOT/test/fixtures/capabilities"
        "$PROJECT_ROOT/test/fixtures/output"
    )

    for fixture in "${fixtures[@]}"; do
        run "$PROJECT_ROOT/scripts/verify_fixture_redaction.py" "$fixture"
        [ "$status" -eq 0 ]
    done
}
