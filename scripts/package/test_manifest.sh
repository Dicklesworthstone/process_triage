#!/usr/bin/env bash
# Test script for validating Scoop manifest
# Usage: ./test_manifest.sh <manifest_path>

set -euo pipefail

MANIFEST_PATH="${1:-dist/packages/pt.json}"

log() {
    local level="$1"
    shift
    echo "[$level] $*"
}

test_json_syntax() {
    log "TEST" "Checking JSON syntax..."

    if ! jq . "$MANIFEST_PATH" > /dev/null 2>&1; then
        log "FAIL" "Invalid JSON syntax"
        jq . "$MANIFEST_PATH"
        return 1
    fi

    log "PASS" "JSON syntax OK"
}

test_required_fields() {
    log "TEST" "Checking required fields..."

    local required_fields=(
        "version"
        "description"
        "homepage"
        "license"
        "architecture"
    )

    local missing=()
    for field in "${required_fields[@]}"; do
        if ! jq -e ".$field" "$MANIFEST_PATH" > /dev/null 2>&1; then
            missing+=("$field")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "FAIL" "Missing required fields: ${missing[*]}"
        return 1
    fi

    log "PASS" "All required fields present"
}

test_architecture() {
    log "TEST" "Checking architecture configuration..."

    # Check 64bit architecture
    if ! jq -e '.architecture."64bit".url' "$MANIFEST_PATH" > /dev/null 2>&1; then
        log "FAIL" "Missing 64bit URL"
        return 1
    fi

    if ! jq -e '.architecture."64bit".hash' "$MANIFEST_PATH" > /dev/null 2>&1; then
        log "FAIL" "Missing 64bit hash"
        return 1
    fi

    log "PASS" "Architecture configuration OK"
}

test_hash_format() {
    log "TEST" "Checking hash format..."

    local hash
    hash=$(jq -r '.architecture."64bit".hash' "$MANIFEST_PATH")

    if [[ ! "$hash" =~ ^[a-f0-9]{64}$ ]]; then
        log "FAIL" "Invalid SHA256 hash format: $hash"
        return 1
    fi

    log "PASS" "SHA256 hash format OK"
}

test_url_format() {
    log "TEST" "Checking URL format..."

    local url
    url=$(jq -r '.architecture."64bit".url' "$MANIFEST_PATH")

    if [[ ! "$url" =~ ^https://github\.com/ ]]; then
        log "WARN" "URL not from GitHub: $url"
    fi

    if [[ ! "$url" =~ /releases/download/ ]]; then
        log "WARN" "URL not a release download: $url"
    fi

    log "PASS" "URL format checked"
}

test_autoupdate() {
    log "TEST" "Checking autoupdate configuration..."

    if ! jq -e '.autoupdate' "$MANIFEST_PATH" > /dev/null 2>&1; then
        log "WARN" "No autoupdate configuration (optional)"
        return 0
    fi

    if ! jq -e '.checkver' "$MANIFEST_PATH" > /dev/null 2>&1; then
        log "WARN" "No checkver configuration (recommended with autoupdate)"
    fi

    log "PASS" "Autoupdate configuration present"
}

run_tests() {
    if [[ ! -f "$MANIFEST_PATH" ]]; then
        log "ERROR" "Manifest not found: $MANIFEST_PATH"
        exit 1
    fi

    log "INFO" "Testing manifest: $MANIFEST_PATH"
    echo

    local failed=0

    test_json_syntax || ((failed++))
    test_required_fields || ((failed++))
    test_architecture || ((failed++))
    test_hash_format || ((failed++))
    test_url_format || ((failed++))
    test_autoupdate || true  # Don't count as failure

    echo
    if [[ $failed -eq 0 ]]; then
        log "SUCCESS" "All tests passed"
        exit 0
    else
        log "FAILURE" "$failed test(s) failed"
        exit 1
    fi
}

run_tests
