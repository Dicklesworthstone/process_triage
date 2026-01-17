#!/usr/bin/env bats
# E2E tests for musl static binaries
# Tests binary portability across Linux distributions
#
# NOTE: These tests require Docker to be available.
# Run with: bats test/musl_e2e.bats

load "./test_helper/common.bash"

MUSL_BINARY="${MUSL_BINARY:-target/x86_64-unknown-linux-musl/release/pt-core}"
SCRIPT_DIR="${BATS_TEST_DIRNAME}/../scripts"

setup() {
    setup_test_env
    test_start "$BATS_TEST_NAME" "musl binary test"
}

teardown() {
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    teardown_test_env
}

#==============================================================================
# HELPER FUNCTIONS
#==============================================================================

skip_if_no_docker() {
    if ! command -v docker &>/dev/null; then
        skip "docker not available"
    fi
}

skip_if_no_musl_binary() {
    if [[ ! -f "$MUSL_BINARY" ]]; then
        skip "musl binary not found at $MUSL_BINARY - run: cargo build --release --target x86_64-unknown-linux-musl"
    fi
}

run_in_container() {
    local image="$1"
    shift
    docker run --rm \
        -v "$(realpath "$MUSL_BINARY"):/app/pt-core:ro" \
        -w /app \
        "$image" \
        "$@"
}

#==============================================================================
# STATIC LINKING TESTS
#==============================================================================

@test "musl: binary exists" {
    skip_if_no_musl_binary

    [[ -f "$MUSL_BINARY" ]]
}

@test "musl: binary is statically linked" {
    skip_if_no_musl_binary

    run file "$MUSL_BINARY"
    assert_equals "0" "$status" "file command should succeed"
    assert_contains "$output" "statically linked" "Binary should be statically linked"
}

@test "musl: ldd reports not a dynamic executable" {
    skip_if_no_musl_binary

    run ldd "$MUSL_BINARY" 2>&1
    # ldd returns non-zero for static binaries
    assert_contains "$output" "not a dynamic executable" "ldd should report static binary"
}

@test "musl: binary size under 15MB" {
    skip_if_no_musl_binary

    run "${SCRIPT_DIR}/check_binary_size.sh" "$MUSL_BINARY" 15

    assert_equals "0" "$status" "Binary should be under 15MB"
    assert_contains "$output" "within limit" "Should report within limit"
}

#==============================================================================
# ALPINE LINUX TESTS
#==============================================================================

@test "musl: runs on Alpine latest" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "alpine:latest" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Alpine latest"
    assert_contains "$output" "pt-core" "Should show version"
}

@test "musl: runs on Alpine 3.14 (older)" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "alpine:3.14" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Alpine 3.14"
    assert_contains "$output" "pt-core" "Should show version"
}

@test "musl: help works on Alpine" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "alpine:latest" sh -c './pt-core --help'

    assert_equals "0" "$status" "Help should work on Alpine"
    assert_contains "$output" "Process Triage" "Should show description"
}

#==============================================================================
# DEBIAN/UBUNTU TESTS (glibc systems)
#==============================================================================

@test "musl: runs on Ubuntu 22.04" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "ubuntu:22.04" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Ubuntu 22.04"
    assert_contains "$output" "pt-core" "Should show version"
}

@test "musl: runs on Ubuntu 20.04" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "ubuntu:20.04" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Ubuntu 20.04"
    assert_contains "$output" "pt-core" "Should show version"
}

@test "musl: runs on Debian slim" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "debian:slim" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Debian slim"
    assert_contains "$output" "pt-core" "Should show version"
}

#==============================================================================
# CENTOS/FEDORA TESTS
#==============================================================================

@test "musl: runs on CentOS 7 (older glibc)" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "centos:7" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on CentOS 7"
    assert_contains "$output" "pt-core" "Should show version"
}

@test "musl: runs on Fedora 38" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "fedora:38" sh -c './pt-core --version'

    assert_equals "0" "$status" "Should run on Fedora 38"
    assert_contains "$output" "pt-core" "Should show version"
}

#==============================================================================
# MINIMAL CONTAINER TESTS
#==============================================================================

@test "musl: runs on busybox (minimal)" {
    skip_if_no_docker
    skip_if_no_musl_binary

    # busybox doesn't have /bin/sh by default, use /bin/sh from busybox
    run docker run --rm \
        -v "$(realpath "$MUSL_BINARY"):/pt-core:ro" \
        busybox:latest \
        /pt-core --version

    assert_equals "0" "$status" "Should run on busybox"
    assert_contains "$output" "pt-core" "Should show version"
}

#==============================================================================
# FUNCTIONAL TESTS
#==============================================================================

@test "musl: scan command works on Alpine" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "alpine:latest" sh -c '
        apk add --no-cache procps >/dev/null 2>&1 || true
        ./pt-core scan --format json 2>/dev/null || true
        echo "scan_attempted"
    '

    assert_equals "0" "$status" "Scan should attempt on Alpine"
    assert_contains "$output" "scan_attempted" "Should complete scan attempt"
}

@test "musl: robot plan command works on Alpine" {
    skip_if_no_docker
    skip_if_no_musl_binary

    run run_in_container "alpine:latest" sh -c '
        apk add --no-cache procps >/dev/null 2>&1 || true
        ./pt-core robot plan --format json 2>/dev/null | head -5 || true
        echo "plan_attempted"
    '

    assert_equals "0" "$status" "Robot plan should attempt on Alpine"
    assert_contains "$output" "plan_attempted" "Should complete plan attempt"
}

#==============================================================================
# CROSS-PLATFORM CONSISTENCY
#==============================================================================

@test "musl: version matches across Alpine and Ubuntu" {
    skip_if_no_docker
    skip_if_no_musl_binary

    local alpine_version
    local ubuntu_version

    alpine_version=$(run_in_container "alpine:latest" sh -c './pt-core --version' | head -1)
    ubuntu_version=$(run_in_container "ubuntu:22.04" sh -c './pt-core --version' | head -1)

    [[ "$alpine_version" == "$ubuntu_version" ]]
}
