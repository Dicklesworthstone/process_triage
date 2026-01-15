#!/usr/bin/env bats
# E2E self-update tests for pt
# Verifies update check, download, checksum validation, and script validation.

load "./test_helper/common.bash"

PT_SCRIPT="${BATS_TEST_DIRNAME}/../pt"

setup_file() {
    if [[ ! -x "$PT_SCRIPT" ]]; then
        echo "ERROR: pt script not found at $PT_SCRIPT" >&2
        exit 1
    fi
}

setup() {
    setup_test_env

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    export PT_TEST_SCRIPT="${TEST_DIR}/pt_test_copy"
    cp "$PT_SCRIPT" "$PT_TEST_SCRIPT"
    chmod +x "$PT_TEST_SCRIPT"
}

teardown() {
    restore_path
    teardown_test_env
}

read_version() {
    local script="$1"
    local version
    version=$(sed -n 's/^readonly VERSION="\([^"]*\)".*/\1/p' "$script" | head -n1)
    if [[ -z "$version" ]]; then
        version=$(sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$script" | head -n1)
    fi
    printf '%s' "$version"
}

write_mock_curl_update() {
    local latest_url="$1"
    local checksum="$2"
    local payload_path="$3"

    cat > "${MOCK_BIN}/curl" << EOF
#!/usr/bin/env bash
set -e

latest_url="${latest_url}"
checksum="${checksum}"
payload_path="${payload_path}"

out_file=""
want_effective=false
url=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            out_file="$2"
            shift 2
            ;;
        -w)
            if [[ "$2" == *"url_effective"* ]]; then
                want_effective=true
            fi
            shift 2
            ;;
        http*)
            url="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [[ "$want_effective" == "true" ]]; then
    echo "$latest_url"
    exit 0
fi

if [[ "$url" == *".sha256" ]]; then
    echo "$checksum  pt"
    exit 0
fi

if [[ "$url" == */pt ]]; then
    if [[ -n "$out_file" ]]; then
        cat "$payload_path" > "$out_file"
    else
        cat "$payload_path"
    fi
    exit 0
fi

exit 1
EOF
    chmod +x "${MOCK_BIN}/curl"
}

#==============================================================================
# VERSION CHECKING TESTS
#==============================================================================

@test "E2E Update: --check detects newer version available" {
    test_start "E2E Update: check detects newer" "verify update availability detection"

    local current_version
    current_version=$(read_version "$PT_TEST_SCRIPT")
    test_info "Current version: $current_version"

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v99.0.0" "deadbeef" "$PT_TEST_SCRIPT"
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --check 2>&1"

    assert_equals "0" "$status" "pt update --check should succeed"
    assert_contains "$output" "Update available" "Should report update"
    assert_contains "$output" "99.0.0" "Should show latest version"

    test_end "E2E Update: check detects newer" "pass"
}

@test "E2E Update: --check shows already up to date" {
    test_start "E2E Update: check up to date" "verify latest version detection"

    local current_version
    current_version=$(read_version "$PT_TEST_SCRIPT")
    test_info "Current version: $current_version"

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v${current_version}" "deadbeef" "$PT_TEST_SCRIPT"
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --check 2>&1"

    assert_equals "0" "$status" "pt update --check should succeed"
    assert_contains "$output" "Already running latest version" "Should report up-to-date"

    test_end "E2E Update: check up to date" "pass"
}

@test "E2E Update: handles network failure gracefully" {
    test_start "E2E Update: network failure" "verify update check failure handling"

    create_mock_command "curl" "" 1
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --check 2>&1"

    if [[ $status -eq 0 ]]; then
        test_error "Expected non-zero status for network failure"
        test_end "E2E Update: network failure" "fail"
        return 1
    fi

    assert_contains "$output" "Could not check for updates" "Should report check failure"

    test_end "E2E Update: network failure" "pass"
}

#==============================================================================
# UPDATE FLOW TESTS
#==============================================================================

@test "E2E Update: full update flow with mocks" {
    test_start "E2E Update: full flow" "verify download, checksum, validation, replace"

    local mock_new_script="${TEST_DIR}/mock_new_pt"
    cat > "$mock_new_script" << 'EOF_SCRIPT'
#!/usr/bin/env bash
# Process Triage mock
VERSION="99.0.0"
echo "Process Triage mock"
EOF_SCRIPT

    local checksum
    if command -v sha256sum &>/dev/null; then
        checksum=$(sha256sum "$mock_new_script" | cut -d' ' -f1)
    else
        checksum=$(shasum -a 256 "$mock_new_script" | cut -d' ' -f1)
    fi

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v99.0.0" "$checksum" "$mock_new_script"
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --force 2>&1"

    assert_equals "0" "$status" "pt update --force should succeed"
    assert_contains "$output" "Updated to pt v99.0.0" "Should report update success"

    local new_version
    new_version=$(read_version "$PT_TEST_SCRIPT")
    assert_equals "99.0.0" "$new_version" "Script should be replaced with new version"

    test_end "E2E Update: full flow" "pass"
}

@test "E2E Update: rejects mismatched checksum" {
    test_start "E2E Update: checksum mismatch" "verify checksum validation failure"

    local mock_new_script="${TEST_DIR}/mock_bad_checksum"
    cat > "$mock_new_script" << 'EOF_SCRIPT'
#!/usr/bin/env bash
# Process Triage mock
VERSION="99.0.0"
echo "Process Triage mock"
EOF_SCRIPT

    local wrong_checksum="0000000000000000000000000000000000000000000000000000000000000000"

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v99.0.0" "$wrong_checksum" "$mock_new_script"
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --force 2>&1"

    if [[ $status -eq 0 ]]; then
        test_error "Expected failure on checksum mismatch"
        test_end "E2E Update: checksum mismatch" "fail"
        return 1
    fi

    assert_contains "$output" "Checksum mismatch" "Should report checksum mismatch"

    test_end "E2E Update: checksum mismatch" "pass"
}

@test "E2E Update: rejects invalid bash syntax" {
    test_start "E2E Update: invalid syntax" "verify validation rejects bad script"

    local bad_script="${TEST_DIR}/bad_syntax"
    cat > "$bad_script" << 'EOF_SCRIPT'
#!/usr/bin/env bash
# Process Triage mock
VERSION="99.0.0"
if [[ true ]]; then
    echo "missing fi"
EOF_SCRIPT

    local checksum
    if command -v sha256sum &>/dev/null; then
        checksum=$(sha256sum "$bad_script" | cut -d' ' -f1)
    else
        checksum=$(shasum -a 256 "$bad_script" | cut -d' ' -f1)
    fi

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v99.0.0" "$checksum" "$bad_script"
    use_mock_bin

    run bash -c "\"$PT_TEST_SCRIPT\" update --force 2>&1"

    if [[ $status -eq 0 ]]; then
        test_error "Expected failure on invalid syntax"
        test_end "E2E Update: invalid syntax" "fail"
        return 1
    fi

    assert_contains "$output" "Script validation failed" "Should report validation failure"

    test_end "E2E Update: invalid syntax" "pass"
}

#==============================================================================
# PERMISSION HANDLING TESTS
#==============================================================================

@test "E2E Update: detects unwritable installation directory" {
    test_start "E2E Update: unwritable dir" "verify permission errors are handled"

    skip_if_root

    local readonly_dir="${TEST_DIR}/readonly"
    mkdir -p "$readonly_dir"

    local ro_script="${readonly_dir}/pt"
    cp "$PT_TEST_SCRIPT" "$ro_script"
    chmod +x "$ro_script"

    chmod 555 "$readonly_dir"

    write_mock_curl_update "https://github.com/user/repo/releases/tag/v99.0.0" "deadbeef" "$PT_TEST_SCRIPT"
    use_mock_bin

    run bash -c "\"$ro_script\" update --force 2>&1"

    chmod 755 "$readonly_dir"

    if [[ $status -eq 0 ]]; then
        test_error "Expected failure when directory is not writable"
        test_end "E2E Update: unwritable dir" "fail"
        return 1
    fi

    assert_contains "$output" "Cannot write" "Should report permission issue"

    test_end "E2E Update: unwritable dir" "pass"
}
