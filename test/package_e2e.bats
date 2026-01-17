#!/usr/bin/env bats
# E2E tests for package distribution (Homebrew/Scoop)
# Tests formula generation, manifest generation, and validation

load "./test_helper/common.bash"

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../scripts/package"
PT_CORE="${BATS_TEST_DIRNAME}/../target/debug/pt-core"

setup() {
    setup_test_env
    test_start "$BATS_TEST_NAME" "Package distribution test"

    # Create test directories
    export PACKAGE_TEST_DIR="${TEST_DIR}/packages"
    mkdir -p "$PACKAGE_TEST_DIR"

    # Create mock checksums file for testing
    export MOCK_CHECKSUMS="${PACKAGE_TEST_DIR}/checksums.sha256"
    cat > "$MOCK_CHECKSUMS" << 'EOF'
deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678  pt-core-linux-x86_64-1.0.0.tar.gz
cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678  pt-core-linux-aarch64-1.0.0.tar.gz
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  pt-core-macos-x86_64-1.0.0.tar.gz
abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  pt-core-macos-aarch64-1.0.0.tar.gz
EOF
}

teardown() {
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    teardown_test_env
}

#==============================================================================
# FORMULA TEMPLATE TESTS
#==============================================================================

@test "Package: Homebrew formula template exists" {
    test_start "Package: formula template" "verify template exists"

    [[ -f "${SCRIPT_DIR}/pt.rb.template" ]]

    test_end "Package: formula template" "pass"
}

@test "Package: Homebrew formula template has placeholders" {
    test_start "Package: formula placeholders" "verify placeholders"

    run cat "${SCRIPT_DIR}/pt.rb.template"

    assert_equals "0" "$status" "Should read template"
    assert_contains "$output" "{{VERSION}}" "Should have VERSION placeholder"
    assert_contains "$output" "{{SHA256_" "Should have SHA256 placeholders"

    test_end "Package: formula placeholders" "pass"
}

#==============================================================================
# MANIFEST TEMPLATE TESTS
#==============================================================================

@test "Package: Scoop manifest template exists" {
    test_start "Package: manifest template" "verify template exists"

    [[ -f "${SCRIPT_DIR}/pt.json.template" ]]

    test_end "Package: manifest template" "pass"
}

@test "Package: Scoop manifest template is valid JSON structure" {
    test_start "Package: manifest json" "verify JSON structure"

    # Template has placeholders, so we need to replace them first
    local temp_manifest="${PACKAGE_TEST_DIR}/temp.json"
    sed -e 's/{{VERSION}}/1.0.0/g' \
        -e 's/{{SHA256_LINUX_X86_64}}/deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678/g' \
        "${SCRIPT_DIR}/pt.json.template" > "$temp_manifest"

    run jq . "$temp_manifest"

    assert_equals "0" "$status" "Should be valid JSON after substitution"

    test_end "Package: manifest json" "pass"
}

#==============================================================================
# GENERATION SCRIPT TESTS
#==============================================================================

@test "Package: generate_packages.sh exists and is executable" {
    test_start "Package: gen script exists" "verify script"

    [[ -x "${SCRIPT_DIR}/generate_packages.sh" ]]

    test_end "Package: gen script exists" "pass"
}

@test "Package: generate_packages.sh generates valid formula" {
    test_start "Package: gen formula" "verify formula generation"

    run "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "$MOCK_CHECKSUMS" "$PACKAGE_TEST_DIR"

    assert_equals "0" "$status" "Script should succeed"

    # Check formula was created
    [[ -f "${PACKAGE_TEST_DIR}/pt.rb" ]]

    # Check formula has correct version
    run cat "${PACKAGE_TEST_DIR}/pt.rb"
    assert_contains "$output" 'version "1.0.0"' "Should have correct version"

    # Check SHA256 was substituted
    assert_contains "$output" "deadbeef" "Should have substituted SHA256"

    test_end "Package: gen formula" "pass"
}

@test "Package: generate_packages.sh generates valid manifest" {
    test_start "Package: gen manifest" "verify manifest generation"

    run "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "$MOCK_CHECKSUMS" "$PACKAGE_TEST_DIR"

    assert_equals "0" "$status" "Script should succeed"

    # Check manifest was created
    [[ -f "${PACKAGE_TEST_DIR}/pt.json" ]]

    # Check manifest is valid JSON
    run jq . "${PACKAGE_TEST_DIR}/pt.json"
    assert_equals "0" "$status" "Manifest should be valid JSON"

    # Check version was substituted
    run jq -r '.version' "${PACKAGE_TEST_DIR}/pt.json"
    assert_equals "1.0.0" "$output" "Should have correct version"

    test_end "Package: gen manifest" "pass"
}

@test "Package: generate_packages.sh fails on missing checksums" {
    test_start "Package: gen missing checksums" "verify error handling"

    run "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "/nonexistent/checksums" "$PACKAGE_TEST_DIR"

    assert_not_equals "0" "$status" "Should fail with missing checksums"

    test_end "Package: gen missing checksums" "pass"
}

#==============================================================================
# VALIDATION SCRIPT TESTS
#==============================================================================

@test "Package: test_manifest.sh exists and is executable" {
    test_start "Package: test script exists" "verify test script"

    [[ -x "${SCRIPT_DIR}/test_manifest.sh" ]]

    test_end "Package: test script exists" "pass"
}

@test "Package: test_manifest.sh validates generated manifest" {
    test_start "Package: validate manifest" "verify validation"

    # Generate manifest first
    "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "$MOCK_CHECKSUMS" "$PACKAGE_TEST_DIR"

    # Run validation
    run "${SCRIPT_DIR}/test_manifest.sh" "${PACKAGE_TEST_DIR}/pt.json"

    assert_equals "0" "$status" "Validation should pass"
    assert_contains "$output" "PASS" "Should show PASS messages"

    test_end "Package: validate manifest" "pass"
}

@test "Package: test_manifest.sh fails on invalid JSON" {
    test_start "Package: validate invalid" "verify invalid detection"

    # Create invalid manifest
    echo "not valid json" > "${PACKAGE_TEST_DIR}/invalid.json"

    run "${SCRIPT_DIR}/test_manifest.sh" "${PACKAGE_TEST_DIR}/invalid.json"

    assert_not_equals "0" "$status" "Should fail on invalid JSON"
    assert_contains "$output" "FAIL" "Should show FAIL message"

    test_end "Package: validate invalid" "pass"
}

#==============================================================================
# FORMULA VALIDATION TESTS
#==============================================================================

@test "Package: Generated formula has valid Ruby syntax" {
    skip_if_no_ruby

    test_start "Package: formula ruby" "verify Ruby syntax"

    # Generate formula first
    "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "$MOCK_CHECKSUMS" "$PACKAGE_TEST_DIR"

    run ruby -c "${PACKAGE_TEST_DIR}/pt.rb"

    assert_equals "0" "$status" "Ruby syntax should be valid"

    test_end "Package: formula ruby" "pass"
}

@test "Package: Generated formula has all platform configurations" {
    test_start "Package: formula platforms" "verify platform configs"

    # Generate formula first
    "${SCRIPT_DIR}/generate_packages.sh" "1.0.0" "$MOCK_CHECKSUMS" "$PACKAGE_TEST_DIR"

    run cat "${PACKAGE_TEST_DIR}/pt.rb"

    # Check for platform blocks
    assert_contains "$output" "on_macos" "Should have macOS block"
    assert_contains "$output" "on_linux" "Should have Linux block"
    assert_contains "$output" "on_arm" "Should have ARM config"
    assert_contains "$output" "on_intel" "Should have Intel config"

    test_end "Package: formula platforms" "pass"
}

#==============================================================================
# HELPER FUNCTIONS
#==============================================================================

skip_if_no_ruby() {
    if ! command -v ruby &>/dev/null; then
        skip "ruby not available"
    fi
}
