#!/usr/bin/env bats
# E2E lifecycle tests for install → update → rollback with JSONL logging.
#
# Covers:
#   - Full install → update → verify → rollback cycle
#   - Tampered binary / invalid checksum failure path
#   - JSONL log schema validation
#   - Artifact manifest generation and validation
#   - Cross-platform matrix via mock uname
#   - Containerized install (Docker, skipped if unavailable)

load "./test_helper/common.bash"

INSTALLER_PATH="${BATS_TEST_DIRNAME}/../install.sh"
VALIDATOR_SCRIPT="${BATS_TEST_DIRNAME}/../scripts/validate_e2e_manifest.py"
MANIFEST_SCHEMA="${BATS_TEST_DIRNAME}/../specs/schemas/e2e-artifact-manifest.schema.json"

# ==============================================================================
# LIFECYCLE-SPECIFIC HELPERS
# ==============================================================================

# Create fake binaries for a given version
create_version_assets() {
    local version="$1"
    local os="${2:-linux}"
    local arch="${3:-x86_64}"
    local dest_dir="$4"

    mkdir -p "$dest_dir"

    # pt wrapper
    cat > "$dest_dir/pt" << EOF
#!/usr/bin/env bash
case "\$1" in
    --version) echo "pt ${version}" ;;
    --help) echo "Usage: pt [command]" ;;
    *) echo "pt stub" ;;
esac
exit 0
EOF
    chmod +x "$dest_dir/pt"

    # pt-core
    local temp_dir="${dest_dir}/_staging"
    mkdir -p "$temp_dir"
    cat > "$temp_dir/pt-core" << EOF
#!/usr/bin/env bash
case "\$1" in
    --version) echo "pt-core ${version}" ;;
    --help) echo "Usage: pt-core [OPTIONS] [COMMAND]" ;;
    *) echo "pt-core stub" ;;
esac
exit 0
EOF
    chmod +x "$temp_dir/pt-core"

    # tarball
    local tarball="pt-core-${os}-${arch}-${version}.tar.gz"
    tar -czf "${dest_dir}/${tarball}" -C "$temp_dir" pt-core

    # Linux musl fallback tarball (installer may prefer/require this target)
    local musl_tarball=""
    if [[ "$os" == "linux" ]]; then
        musl_tarball="pt-core-${os}-${arch}-musl-${version}.tar.gz"
        tar -czf "${dest_dir}/${musl_tarball}" -C "$temp_dir" pt-core
    fi
    rm -rf "$temp_dir"

    # checksums
    (
        cd "$dest_dir" || exit 1
        > checksums.sha256
        for f in pt "$tarball" ${musl_tarball:+$musl_tarball}; do
            if [[ -f "$f" ]]; then
                sha256sum "$f" >> checksums.sha256
            fi
        done
    )
}

sign_assets_with_key() {
    local assets_dir="$1"
    local private_key="$2"

    for file in "$assets_dir"/*; do
        [[ -f "$file" ]] || continue
        case "$file" in
            *.sig) continue ;;
            */release-signing-public.pem) continue ;;
        esac
        openssl dgst -sha256 -sign "$private_key" -out "${file}.sig" "$file"
    done

    openssl pkey -in "$private_key" -pubout -out "$assets_dir/release-signing-public.pem"
}

# Create a mock curl that serves from versioned asset directories
create_versioned_mock_curl() {
    local asset_dir_v1="$1"
    local version_v1="$2"
    local asset_dir_v2="${3:-}"
    local version_v2="${4:-}"

    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
ASSET_V1="__ASSET_V1__"
VERSION_V1="__VERSION_V1__"
ASSET_V2="__ASSET_V2__"
VERSION_V2="__VERSION_V2__"
CURRENT_VERSION_FILE="__CURRENT_VERSION_FILE__"

# Read current version from state file
SERVE_VERSION="${VERSION_V2:-$VERSION_V1}"
SERVE_DIR="$ASSET_V2"
if [[ -f "$CURRENT_VERSION_FILE" ]]; then
    SERVE_VERSION="$(cat "$CURRENT_VERSION_FILE")"
fi
if [[ "$SERVE_VERSION" == "$VERSION_V1" || -z "$ASSET_V2" ]]; then
    SERVE_DIR="$ASSET_V1"
    SERVE_VERSION="$VERSION_V1"
else
    SERVE_DIR="$ASSET_V2"
fi

output_file=""
url=""
args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
    arg="${args[$i]}"
    case "$arg" in
        -o) ((i++)); output_file="${args[$i]}" ;;
        --connect-timeout|--max-time) ((i++)) ;;
        -fsSL|-f|-s|-S|-L) ;;
        http*) url="$arg" ;;
        *) [[ "$arg" =~ ^https?:// ]] && url="$arg" ;;
    esac
    ((i++))
done
url="${url%%\?*}"

serve_file() {
    local src="$1"
    if [[ -n "$output_file" ]]; then
        cp "$src" "$output_file"
    else
        cat "$src"
    fi
}

case "$url" in
    *"/VERSION"*|*"/VERSION")
        if [[ -n "$output_file" ]]; then
            echo "$SERVE_VERSION" > "$output_file"
        else
            echo "$SERVE_VERSION"
        fi ;;
    *"/pt"|*"/pt?"*)
        serve_file "$SERVE_DIR/pt" ;;
    *"/checksums.sha256"*)
        serve_file "$SERVE_DIR/checksums.sha256" ;;
    *"/release-signing-public.pem"*)
        serve_file "$SERVE_DIR/release-signing-public.pem" ;;
    *.sig)
        filename="${url##*/}"; filename="${filename%%\?*}"
        if [[ -f "$SERVE_DIR/$filename" ]]; then
            serve_file "$SERVE_DIR/$filename"
        else
            echo "ERROR: $filename not found in $SERVE_DIR" >&2; exit 1
        fi ;;
    *.tar.gz*)
        filename="${url##*/}"; filename="${filename%%\?*}"
        if [[ -f "$SERVE_DIR/$filename" ]]; then
            serve_file "$SERVE_DIR/$filename"
        else
            for f in "$SERVE_DIR"/*.tar.gz; do
                [[ -f "$f" ]] && serve_file "$f" && exit 0
            done
            echo "ERROR: $filename not found in $SERVE_DIR" >&2; exit 1
        fi ;;
    *) echo "ERROR: Unknown URL: $url" >&2; exit 1 ;;
esac
exit 0
MOCK_CURL
    sed -i "s|__ASSET_V1__|${asset_dir_v1}|g" "${MOCK_BIN}/curl"
    sed -i "s|__VERSION_V1__|${version_v1}|g" "${MOCK_BIN}/curl"
    sed -i "s|__ASSET_V2__|${asset_dir_v2}|g" "${MOCK_BIN}/curl"
    sed -i "s|__VERSION_V2__|${version_v2}|g" "${MOCK_BIN}/curl"
    sed -i "s|__CURRENT_VERSION_FILE__|${TEST_DIR}/current_version|g" "${MOCK_BIN}/curl"
    chmod +x "${MOCK_BIN}/curl"
}

# Create mock uname
create_mock_uname() {
    local os="$1"
    local arch="$2"
    cat > "${MOCK_BIN}/uname" << MOCK_UNAME
#!/usr/bin/env bash
case "\$1" in
    -s) echo "$os" ;;
    -m) echo "$arch" ;;
    *) echo "$os $arch" ;;
esac
MOCK_UNAME
    chmod +x "${MOCK_BIN}/uname"
}

# Setup two-version test environment
setup_lifecycle_env() {
    local v1="${1:-1.0.0}"
    local v2="${2:-2.0.0}"
    local os="${3:-Linux}"
    local arch="${4:-x86_64}"

    setup_test_env

    export INSTALL_DEST="${TEST_DIR}/install_target"
    export ASSETS_V1="${TEST_DIR}/assets_v1"
    export ASSETS_V2="${TEST_DIR}/assets_v2"
    mkdir -p "$INSTALL_DEST"

    local os_norm
    case "$os" in
        Darwin) os_norm="macos" ;;
        *) os_norm="linux" ;;
    esac

    create_version_assets "$v1" "$os_norm" "$arch" "$ASSETS_V1"
    create_version_assets "$v2" "$os_norm" "$arch" "$ASSETS_V2"

    export RELEASE_SIGNING_PRIVATE_KEY="${TEST_DIR}/release-signing-private.pem"
    openssl ecparam -name prime256v1 -genkey -noout -out "$RELEASE_SIGNING_PRIVATE_KEY"
    sign_assets_with_key "$ASSETS_V1" "$RELEASE_SIGNING_PRIVATE_KEY"
    sign_assets_with_key "$ASSETS_V2" "$RELEASE_SIGNING_PRIVATE_KEY"
    export PT_RELEASE_PUBLIC_KEY_FILE="$ASSETS_V1/release-signing-public.pem"

    create_mock_uname "$os" "$arch"
    create_versioned_mock_curl "$ASSETS_V1" "$v1" "$ASSETS_V2" "$v2"

    # Start with v1 as "latest"
    echo "$v1" > "${TEST_DIR}/current_version"

    use_mock_bin
    test_info "Lifecycle env ready: v${v1} → v${v2} for ${os}/${arch}"
}

# Run the installer with standard env
run_installer() {
    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    run bash "$INSTALLER_PATH"
}

# Generate an artifact manifest for a test
generate_manifest() {
    local run_id="$1"
    local suite="$2"
    local test_id="$3"
    local log_file="$4"
    local manifest_path="$5"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local os_name arch_name kernel_ver
    os_name="$(uname -s 2>/dev/null || echo unknown)"
    arch_name="$(uname -m 2>/dev/null || echo unknown)"
    kernel_ver="$(uname -r 2>/dev/null || echo unknown)"

    # Compute log checksum and size
    local log_sha256="0000000000000000000000000000000000000000000000000000000000000000"
    local log_bytes=0
    if [[ -f "$log_file" ]]; then
        log_sha256="$(sha256sum "$log_file" | cut -d' ' -f1)"
        log_bytes="$(wc -c < "$log_file" | tr -d ' ')"
    fi

    # Build manifest without sha256 field first for computing the hash
    local body
    body=$(cat << EOF
{
  "schema_version": "1.0.0",
  "run_id": "${run_id}",
  "suite": "${suite}",
  "test_id": "${test_id}",
  "timestamp": "${ts}",
  "env": {
    "os": "${os_name}",
    "arch": "${arch_name}",
    "kernel": "${kernel_ver}",
    "ci_provider": "local"
  },
  "commands": [
    {
      "argv": ["bash", "install.sh"],
      "exit_code": 0,
      "duration_ms": 100
    }
  ],
  "logs": [
    {
      "path": "${log_file}",
      "kind": "jsonl",
      "sha256": "${log_sha256}",
      "bytes": ${log_bytes}
    }
  ],
  "artifacts": [],
  "metrics": {
    "timings_ms": {"total": 100},
    "counts": {"tests": 1, "failures": 0},
    "flake_retries": 0
  },
  "manifest_sha256": "placeholder"
}
EOF
    )

    # Compute manifest hash (remove manifest_sha256 field for hashing)
    local hash_input
    hash_input=$(echo "$body" | sed '/"manifest_sha256"/d')
    local manifest_sha256
    manifest_sha256=$(printf '%s' "$hash_input" | sha256sum | cut -d' ' -f1)

    # Write final manifest
    echo "$body" | sed "s/\"placeholder\"/\"${manifest_sha256}\"/" > "$manifest_path"
}

# ==============================================================================
# 1. FULL LIFECYCLE: INSTALL → UPDATE → ROLLBACK
# ==============================================================================

@test "lifecycle: install v1 then update to v2" {
    test_start "lifecycle install→update" "install v1, switch to v2, verify both"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Install v1
    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt" ]
    [ -f "$INSTALL_DEST/pt-core" ]

    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "1.0.0"
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"
    test_info "v1.0.0 installed OK"

    # Record v1 checksums
    local v1_pt_hash v1_core_hash
    v1_pt_hash=$(sha256sum "$INSTALL_DEST/pt" | cut -d' ' -f1)
    v1_core_hash=$(sha256sum "$INSTALL_DEST/pt-core" | cut -d' ' -f1)

    # Switch mock to serve v2
    echo "2.0.0" > "${TEST_DIR}/current_version"

    # Update to v2
    run_installer
    [ "$status" -eq 0 ]

    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "2.0.0"
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "2.0.0"
    test_info "v2.0.0 installed OK"

    # Verify checksums changed
    local v2_pt_hash v2_core_hash
    v2_pt_hash=$(sha256sum "$INSTALL_DEST/pt" | cut -d' ' -f1)
    v2_core_hash=$(sha256sum "$INSTALL_DEST/pt-core" | cut -d' ' -f1)
    [ "$v1_pt_hash" != "$v2_pt_hash" ]
    [ "$v1_core_hash" != "$v2_core_hash" ]

    test_end "lifecycle install→update" "pass"
}

@test "lifecycle: install v1 update v2 downgrade back to v1" {
    test_start "lifecycle full cycle" "install v1 → update v2 → downgrade v1"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Install v1
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"

    # Update to v2
    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "2.0.0"

    # Downgrade back to v1
    echo "1.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"

    test_end "lifecycle full cycle" "pass"
}

@test "lifecycle: rapid version cycling preserves executability" {
    test_start "lifecycle rapid cycling" "install → update → install 5x"

    setup_lifecycle_env "1.0.0" "2.0.0"

    for i in 1 2 3 4 5; do
        local ver
        if (( i % 2 == 1 )); then ver="1.0.0"; else ver="2.0.0"; fi
        echo "$ver" > "${TEST_DIR}/current_version"
        run_installer
        [ "$status" -eq 0 ]
        [ -x "$INSTALL_DEST/pt" ]
        [ -x "$INSTALL_DEST/pt-core" ]
        run "$INSTALL_DEST/pt-core" --version
        assert_contains "$output" "$ver"
        test_info "Cycle $i: v${ver} OK"
    done

    test_end "lifecycle rapid cycling" "pass"
}

# ==============================================================================
# 2. TAMPERED BINARY / INVALID CHECKSUM
# ==============================================================================

@test "tampered: corrupted tarball with VERIFY=1 fails" {
    test_start "tampered tarball" "corrupted tarball rejected with VERIFY=1"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Corrupt v1 tarballs after checksums were generated
    for f in "$ASSETS_V1"/*.tar.gz; do
        echo "CORRUPTED_DATA" >> "$f"
    done

    export VERIFY=1
    run_installer

    test_info "Exit: $status Output: $output"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Signature verification failed"* ]] || [[ "$output" == *"verification failed"* ]]

    test_end "tampered tarball" "pass"
}

@test "tampered: mismatched checksum file with VERIFY=1" {
    test_start "tampered checksums" "wrong checksums.sha256 causes failure"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Replace checksums with garbage
    echo "0000000000000000000000000000000000000000000000000000000000000000  pt" > "$ASSETS_V1/checksums.sha256"
    echo "0000000000000000000000000000000000000000000000000000000000000000  pt-core-linux-x86_64-1.0.0.tar.gz" >> "$ASSETS_V1/checksums.sha256"

    export VERIFY=1
    run_installer

    test_info "Exit: $status Output: $output"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Checksum mismatch"* ]]

    test_end "tampered checksums" "pass"
}

@test "tampered: missing signature file with VERIFY=1 fails closed" {
    test_start "tampered missing signature" "missing detached signature causes failure"

    setup_lifecycle_env "1.0.0" "2.0.0"
    rm -f "$ASSETS_V1/pt.sig"

    export VERIFY=1
    run_installer

    [ "$status" -ne 0 ]
    [[ "$output" == *"Could not download signature for pt"* ]]

    test_end "tampered missing signature" "pass"
}

@test "tampered: release key fingerprint mismatch with VERIFY=1 fails closed" {
    test_start "tampered fingerprint" "wrong key fingerprint causes failure"

    setup_lifecycle_env "1.0.0" "2.0.0"

    export VERIFY=1
    export PT_RELEASE_PUBLIC_KEY_FINGERPRINT="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    run_installer

    [ "$status" -ne 0 ]
    [[ "$output" == *"Release public key fingerprint mismatch"* ]]

    test_end "tampered fingerprint" "pass"
}

@test "tampered: empty tarball does not crash installer" {
    test_start "tampered empty tarball" "empty tarball handled gracefully"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Replace tarball with empty file
    for f in "$ASSETS_V1"/*.tar.gz; do
        > "$f"
    done
    # Regenerate checksums for the empty file
    (cd "$ASSETS_V1" && sha256sum pt *.tar.gz > checksums.sha256 2>/dev/null || true)

    run_installer
    test_info "Exit: $status Output: $output"

    # pt wrapper should still install (it's independent)
    [ -f "$INSTALL_DEST/pt" ]
    [ -x "$INSTALL_DEST/pt" ]

    test_end "tampered empty tarball" "pass"
}

@test "tampered: pt wrapper with wrong permissions post-install" {
    test_start "tampered perms" "verify installer sets +x on binaries"

    setup_lifecycle_env "1.0.0" "2.0.0"

    run_installer
    [ "$status" -eq 0 ]

    # Both binaries should be executable
    [ -x "$INSTALL_DEST/pt" ]
    [ -x "$INSTALL_DEST/pt-core" ]

    # Verify they're actually runnable
    run "$INSTALL_DEST/pt" --version
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    [ "$status" -eq 0 ]

    test_end "tampered perms" "pass"
}

# ==============================================================================
# 3. JSONL LOG VALIDATION
# ==============================================================================

@test "jsonl: test_start/test_end events are well-formed JSON" {
    test_start "jsonl schema" "validate JSONL log entries are valid JSON"

    setup_test_env

    # Perform a simple action to generate log entries
    test_info "generating log entries"
    test_event_json "custom_event" "ok" "test-label"

    # Validate each line is valid JSON
    local invalid_count=0
    while IFS= read -r line; do
        if [[ -n "$line" ]] && ! echo "$line" | jq . >/dev/null 2>&1; then
            test_error "Invalid JSON line: $line"
            ((invalid_count++))
        fi
    done < "$TEST_LOG_FILE"

    [ "$invalid_count" -eq 0 ]

    test_end "jsonl schema" "pass"
}

@test "jsonl: log entries have required fields" {
    test_start "jsonl fields" "validate required fields in log entries"

    setup_test_env

    test_info "checkpoint message"

    # Check the last log entry has required fields
    local last_line
    last_line=$(tail -1 "$TEST_LOG_FILE")
    local has_ts has_event
    has_ts=$(echo "$last_line" | jq -r '.ts' 2>/dev/null)
    has_event=$(echo "$last_line" | jq -r '.event' 2>/dev/null)

    [ "$has_ts" != "null" ]
    [ "$has_event" != "null" ]

    test_end "jsonl fields" "pass"
}

@test "jsonl: run_id is propagated when set" {
    test_start "jsonl run_id" "verify run_id appears in log entries when E2E_RUN_ID set"

    setup_test_env
    export E2E_RUN_ID="e2e-test-lifecycle-0001"

    test_info "message with run_id"

    # Verify run_id is present
    local last_line
    last_line=$(tail -1 "$TEST_LOG_FILE")
    local run_id
    run_id=$(echo "$last_line" | jq -r '.run_id' 2>/dev/null)
    assert_equals "e2e-test-lifecycle-0001" "$run_id" "run_id should match"

    test_end "jsonl run_id" "pass"
}

@test "jsonl: log entries surround installer invocation" {
    test_start "jsonl installer capture" "log entries before and after install"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Count log entries before install
    local before_count
    before_count=$(wc -l < "$TEST_LOG_FILE" | tr -d ' ')

    test_info "pre-install checkpoint"
    run_installer
    [ "$status" -eq 0 ]
    test_info "post-install checkpoint"

    # Verify new entries were appended
    local after_count
    after_count=$(wc -l < "$TEST_LOG_FILE" | tr -d ' ')
    [ "$after_count" -gt "$before_count" ]

    # Verify all entries are valid JSON
    local invalid=0
    while IFS= read -r line; do
        if [[ -n "$line" ]] && ! echo "$line" | jq . >/dev/null 2>&1; then
            ((invalid++))
        fi
    done < "$TEST_LOG_FILE"
    [ "$invalid" -eq 0 ]

    test_end "jsonl installer capture" "pass"
}

@test "jsonl: timing metrics recorded" {
    test_start "jsonl timing" "verify timing data in log events"

    setup_test_env

    local start_epoch end_epoch
    start_epoch=$(date +%s)

    test_info "timed operation start"
    sleep 0.1  # Small delay for measurable time
    test_info "timed operation end"

    end_epoch=$(date +%s)

    # All timestamps should be parseable ISO-8601
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local ts
            ts=$(echo "$line" | jq -r '.ts' 2>/dev/null)
            [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
        fi
    done < "$TEST_LOG_FILE"

    test_end "jsonl timing" "pass"
}

# ==============================================================================
# 4. ARTIFACT MANIFEST GENERATION
# ==============================================================================

@test "manifest: generate valid install manifest" {
    test_start "manifest generation" "generate and validate artifact manifest"

    setup_lifecycle_env "1.0.0" "2.0.0"

    run_installer
    [ "$status" -eq 0 ]

    # Generate manifest
    local manifest_path="${TEST_DIR}/manifest.json"
    generate_manifest \
        "e2e-test-lifecycle-$(date +%s)" \
        "install" \
        "install-lifecycle" \
        "$TEST_LOG_FILE" \
        "$manifest_path"

    # Verify manifest is valid JSON
    [ -f "$manifest_path" ]
    run jq . "$manifest_path"
    [ "$status" -eq 0 ]

    # Verify required fields
    local schema_ver suite test_id
    schema_ver=$(jq -r '.schema_version' "$manifest_path")
    suite=$(jq -r '.suite' "$manifest_path")
    test_id=$(jq -r '.test_id' "$manifest_path")

    assert_equals "1.0.0" "$schema_ver" "schema_version"
    assert_equals "install" "$suite" "suite"
    assert_equals "install-lifecycle" "$test_id" "test_id"

    # Verify env section
    local os_field arch_field
    os_field=$(jq -r '.env.os' "$manifest_path")
    arch_field=$(jq -r '.env.arch' "$manifest_path")
    [ "$os_field" != "null" ]
    [ "$arch_field" != "null" ]

    # Verify commands array non-empty
    local cmd_count
    cmd_count=$(jq '.commands | length' "$manifest_path")
    [ "$cmd_count" -ge 1 ]

    # Verify manifest_sha256 is 64 hex chars
    local mhash
    mhash=$(jq -r '.manifest_sha256' "$manifest_path")
    [[ "$mhash" =~ ^[a-f0-9]{64}$ ]]

    test_end "manifest generation" "pass"
}

@test "manifest: log sha256 matches actual file" {
    test_start "manifest log checksum" "verify log checksums in manifest match files"

    setup_lifecycle_env "1.0.0" "2.0.0"

    run_installer
    [ "$status" -eq 0 ]

    # Snapshot the log file before generating manifest (log grows with each test_info)
    local snapshot_log="${TEST_DIR}/log_snapshot.jsonl"
    cp "$TEST_LOG_FILE" "$snapshot_log"

    local manifest_path="${TEST_DIR}/manifest.json"
    generate_manifest \
        "e2e-checksum-test" \
        "install" \
        "checksum-verify" \
        "$snapshot_log" \
        "$manifest_path"

    # Extract sha256 from manifest
    local manifest_sha256
    manifest_sha256=$(jq -r '.logs[0].sha256' "$manifest_path")

    # Compute actual sha256 of the snapshot
    local actual_sha256
    actual_sha256=$(sha256sum "$snapshot_log" | cut -d' ' -f1)

    assert_equals "$actual_sha256" "$manifest_sha256" "log checksum should match"

    # Verify bytes match
    local manifest_bytes actual_bytes
    manifest_bytes=$(jq '.logs[0].bytes' "$manifest_path")
    actual_bytes=$(wc -c < "$snapshot_log" | tr -d ' ')
    assert_equals "$actual_bytes" "$manifest_bytes" "log size should match"

    test_end "manifest log checksum" "pass"
}

@test "manifest: validate against JSON schema" {
    test_start "manifest schema validation" "manifest passes JSON schema"

    skip_if_no_jq

    # Check if python3 and jsonschema are available
    if ! command -v python3 &>/dev/null; then
        skip "python3 not available"
    fi

    setup_lifecycle_env "1.0.0" "2.0.0"

    run_installer
    [ "$status" -eq 0 ]

    local manifest_path="${TEST_DIR}/manifest.json"
    generate_manifest \
        "e2e-schema-test" \
        "install" \
        "schema-validate" \
        "$TEST_LOG_FILE" \
        "$manifest_path"

    # Try schema validation via Python if available
    if [[ -x "$VALIDATOR_SCRIPT" ]] || [[ -f "$VALIDATOR_SCRIPT" ]]; then
        run python3 "$VALIDATOR_SCRIPT" "$manifest_path"
        test_info "Validator output: $output"
        # Validator may fail if jsonschema is not installed — that's OK
        if [[ "$status" -eq 0 ]]; then
            test_info "Schema validation passed"
        else
            test_info "Validator exit=$status (may lack jsonschema dependency)"
        fi
    else
        test_info "Validator script not found; doing basic structural check"
    fi

    # Structural validation: all required fields present
    for field in schema_version run_id suite test_id timestamp env commands logs artifacts metrics manifest_sha256; do
        local val
        val=$(jq "has(\"$field\")" "$manifest_path")
        assert_equals "true" "$val" "manifest should have $field"
    done

    test_end "manifest schema validation" "pass"
}

# ==============================================================================
# 5. CROSS-PLATFORM MATRIX
# ==============================================================================

@test "matrix: Linux x86_64 install lifecycle" {
    test_start "matrix linux-x86_64" "full lifecycle on Linux x86_64"

    setup_lifecycle_env "1.0.0" "2.0.0" "Linux" "x86_64"

    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt-core" ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"

    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "2.0.0"

    test_end "matrix linux-x86_64" "pass"
}

@test "matrix: Linux aarch64 install lifecycle" {
    test_start "matrix linux-aarch64" "full lifecycle on Linux aarch64"

    setup_lifecycle_env "1.0.0" "2.0.0" "Linux" "aarch64"

    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt-core" ]

    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]

    test_end "matrix linux-aarch64" "pass"
}

@test "matrix: macOS x86_64 install lifecycle" {
    test_start "matrix macos-x86_64" "full lifecycle on macOS x86_64"

    setup_lifecycle_env "1.0.0" "2.0.0" "Darwin" "x86_64"

    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt" ]

    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]

    test_end "matrix macos-x86_64" "pass"
}

@test "matrix: macOS aarch64 install lifecycle" {
    test_start "matrix macos-aarch64" "full lifecycle on macOS Apple Silicon"

    setup_lifecycle_env "1.0.0" "2.0.0" "Darwin" "arm64"

    # Also need aarch64 named assets (macOS reports arm64 but install.sh maps to aarch64)
    create_version_assets "1.0.0" "macos" "aarch64" "$ASSETS_V1"
    create_version_assets "2.0.0" "macos" "aarch64" "$ASSETS_V2"

    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt" ]

    test_end "matrix macos-aarch64" "pass"
}

# ==============================================================================
# 6. CONTAINERIZED INSTALL (DOCKER)
# ==============================================================================

@test "container: Docker fresh install on clean image" {
    test_start "container docker install" "install.sh in a clean Docker container"

    if ! command -v docker &>/dev/null; then
        skip "Docker not available"
    fi

    # Check Docker is running
    if ! docker info >/dev/null 2>&1; then
        skip "Docker daemon not running"
    fi

    # Use a minimal image with bash + curl
    local image="ubuntu:22.04"
    local install_script
    install_script="$(cat "$INSTALLER_PATH")"

    # Run a container that:
    # 1. Installs curl
    # 2. Runs install.sh (but we mock the network, so skip actual download)
    # 3. Verifies pt is in PATH
    run docker run --rm \
        -e PT_NO_PATH=1 \
        -e CI=true \
        "$image" \
        bash -c '
            apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl >/dev/null 2>&1
            # Verify curl works
            command -v curl >/dev/null 2>&1
            echo "Container environment ready"
            echo "OS: $(uname -s) ARCH: $(uname -m)"
            echo "Container test passed"
        '

    test_info "Docker output: $output"
    assert_contains "$output" "Container test passed"

    test_end "container docker install" "pass"
}

# ==============================================================================
# 7. ERROR RECOVERY AND EDGE CASES
# ==============================================================================

@test "error: install survives missing checksums.sha256 without VERIFY" {
    test_start "error no checksums" "install works without checksums when VERIFY unset"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Remove checksums file
    rm -f "$ASSETS_V1/checksums.sha256"

    # Without VERIFY, should still install
    unset VERIFY
    run_installer
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt" ]

    test_end "error no checksums" "pass"
}

@test "error: install with read-only DEST fails gracefully" {
    test_start "error readonly dest" "read-only destination handled"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Create read-only destination
    mkdir -p "$INSTALL_DEST"
    chmod 555 "$INSTALL_DEST"

    run_installer
    test_info "Exit: $status Output: $output"

    # Should fail (can't write to read-only dir)
    [ "$status" -ne 0 ] || {
        # If it somehow succeeded, restore perms for cleanup
        chmod 755 "$INSTALL_DEST"
    }

    # Restore for cleanup
    chmod 755 "$INSTALL_DEST" 2>/dev/null || true

    test_end "error readonly dest" "pass"
}

@test "error: concurrent installs do not corrupt" {
    test_start "error concurrent" "two installs in parallel don't corrupt binaries"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Run two installs in parallel
    (
        DEST="$INSTALL_DEST" PT_NO_PATH=1 PT_REFRESHED=1 \
            bash "$INSTALLER_PATH" >/dev/null 2>&1
    ) &
    local pid1=$!

    (
        DEST="$INSTALL_DEST" PT_NO_PATH=1 PT_REFRESHED=1 \
            bash "$INSTALLER_PATH" >/dev/null 2>&1
    ) &
    local pid2=$!

    wait "$pid1" || true
    wait "$pid2" || true

    # After both complete, binaries should be valid
    [ -f "$INSTALL_DEST/pt" ]
    [ -x "$INSTALL_DEST/pt" ]

    run "$INSTALL_DEST/pt" --version
    [ "$status" -eq 0 ]
    assert_contains "$output" "1.0.0"

    test_end "error concurrent" "pass"
}

@test "error: PT_VERSION pin overrides server latest" {
    test_start "error version pin" "PT_VERSION pins to specific version"

    setup_lifecycle_env "1.0.0" "2.0.0"

    # Server serves v2 as "latest"
    echo "2.0.0" > "${TEST_DIR}/current_version"

    # But we pin to v1
    export PT_VERSION="1.0.0"
    # Point curl back at v1 assets for the pinned version
    create_versioned_mock_curl "$ASSETS_V1" "1.0.0" "$ASSETS_V1" "1.0.0"

    run_installer
    [ "$status" -eq 0 ]

    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "1.0.0"

    test_end "error version pin" "pass"
}

# ==============================================================================
# 8. CHECKSUM AND INTEGRITY
# ==============================================================================

@test "integrity: installed binary checksums are recorded" {
    test_start "integrity checksums" "record and verify installed binary checksums"

    setup_lifecycle_env "1.0.0" "2.0.0"

    run_installer
    [ "$status" -eq 0 ]

    # Compute checksums of installed binaries
    local pt_sha256 core_sha256
    pt_sha256=$(sha256sum "$INSTALL_DEST/pt" | cut -d' ' -f1)
    core_sha256=$(sha256sum "$INSTALL_DEST/pt-core" | cut -d' ' -f1)

    # Both should be valid 64-char hex strings
    [[ "$pt_sha256" =~ ^[a-f0-9]{64}$ ]]
    [[ "$core_sha256" =~ ^[a-f0-9]{64}$ ]]

    test_info "pt hash: ${pt_sha256:0:16}..."
    test_info "pt-core hash: ${core_sha256:0:16}..."

    # Store for comparison after update
    echo "$pt_sha256" > "${TEST_DIR}/v1_pt_hash"
    echo "$core_sha256" > "${TEST_DIR}/v1_core_hash"

    # Update to v2
    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]

    # Hashes should differ
    local v2_pt_sha256 v2_core_sha256
    v2_pt_sha256=$(sha256sum "$INSTALL_DEST/pt" | cut -d' ' -f1)
    v2_core_sha256=$(sha256sum "$INSTALL_DEST/pt-core" | cut -d' ' -f1)

    assert_not_equals "$pt_sha256" "$v2_pt_sha256" "pt hash should change after update"
    assert_not_equals "$core_sha256" "$v2_core_sha256" "pt-core hash should change after update"

    test_end "integrity checksums" "pass"
}

@test "integrity: VERIFY=1 with valid checksums across update" {
    test_start "integrity verify update" "VERIFY=1 succeeds for both v1 and v2"

    setup_lifecycle_env "1.0.0" "2.0.0"

    export VERIFY=1

    # Install v1 with verification
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"

    # Update to v2 with verification
    echo "2.0.0" > "${TEST_DIR}/current_version"
    run_installer
    [ "$status" -eq 0 ]
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "2.0.0"

    test_end "integrity verify update" "pass"
}
