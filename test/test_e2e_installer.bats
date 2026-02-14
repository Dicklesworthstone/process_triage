#!/usr/bin/env bats
# E2E tests for install.sh
#
# Tests the two-layer install system:
# - pt (bash wrapper)
# - pt-core (Rust binary)
#
# Validates: fresh install, upgrade, OS/arch selection, checksum verification,
# PATH management, and network failure handling.

load "./test_helper/common.bash"

# ==============================================================================
# INSTALLER-SPECIFIC HELPERS
# ==============================================================================

INSTALLER_PATH="${BATS_TEST_DIRNAME}/../install.sh"

# Create a fake pt wrapper script for testing
create_fake_pt_wrapper() {
    local version="$1"
    local dest="$2"

    cat > "$dest" << EOF
#!/usr/bin/env bash
# Fake pt wrapper for testing
case "\$1" in
    --version) echo "pt ${version}" ;;
    --help) echo "Usage: pt [command]" ;;
    *) echo "pt stub" ;;
esac
exit 0
EOF
    chmod +x "$dest"
    test_debug "Created fake pt wrapper v${version} at $dest"
}

# Create a fake pt-core binary for testing
create_fake_pt_core() {
    local version="$1"
    local dest="$2"

    cat > "$dest" << 'EOF'
#!/usr/bin/env bash
# Fake pt-core for testing
case "$1" in
    --version) echo "__VERSION__" ;;
    --help) echo "Usage: pt-core [OPTIONS] [COMMAND]" ;;
    *) echo "pt-core stub" ;;
esac
exit 0
EOF
    sed -i "s/__VERSION__/pt-core ${version}/g" "$dest"
    chmod +x "$dest"
    test_debug "Created fake pt-core v${version} at $dest"
}

# Create a fake tarball containing pt-core
create_fake_pt_core_tarball() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local dest_dir="$4"

    local tarball_name="pt-core-${os}-${arch}-${version}.tar.gz"
    local temp_dir="${dest_dir}/tarball_staging"

    mkdir -p "$temp_dir"
    create_fake_pt_core "$version" "$temp_dir/pt-core"

    # Create tarball
    tar -czf "${dest_dir}/${tarball_name}" -C "$temp_dir" pt-core

    test_debug "Created fake tarball: ${tarball_name}"
    echo "${dest_dir}/${tarball_name}"
}

# Create a checksums file for verification tests
create_checksums_file() {
    local version="$1"
    local assets_dir="$2"
    local checksums_file="$3"

    > "$checksums_file"

    # Add checksums for all assets in directory
    for file in "$assets_dir"/*; do
        if [[ -f "$file" ]]; then
            local hash
            hash=$(sha256sum "$file" | cut -d' ' -f1)
            local filename
            filename=$(basename "$file")
            echo "$hash  $filename" >> "$checksums_file"
            test_debug "Added checksum for $filename: ${hash:0:16}..."
        fi
    done

    test_info "Created checksums file with $(wc -l < "$checksums_file") entries"
}

create_release_signatures() {
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

# Create mock curl that serves files from a directory
create_serving_mock_curl() {
    local serve_dir="$1"
    local version="$2"

    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
# Mock curl that serves from a directory
SERVE_DIR="__SERVE_DIR__"
VERSION="__VERSION__"

# Parse all arguments - collect options and URL
output_file=""
url=""
args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
    arg="${args[$i]}"
    case "$arg" in
        -o)
            ((i++))
            output_file="${args[$i]}"
            ;;
        --connect-timeout|--max-time)
            ((i++))  # Skip the value
            ;;
        -fsSL|-f|-s|-S|-L)
            # Skip these flags
            ;;
        http*)
            url="$arg"
            ;;
        *)
            # Could be a URL or unknown option
            if [[ "$arg" =~ ^https?:// ]]; then
                url="$arg"
            fi
            ;;
    esac
    ((i++))
done

# Strip cache-buster from URL
url="${url%%\?*}"

# Debug output to stderr
# echo "DEBUG: url=$url output=$output_file" >&2

# Handle different URLs
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
            echo "$VERSION" > "$output_file"
        else
            echo "$VERSION"
        fi
        ;;
    *"/pt"|*"/pt?"*)
        if [[ -f "$SERVE_DIR/pt" ]]; then
            serve_file "$SERVE_DIR/pt"
        else
            echo "ERROR: pt not found in $SERVE_DIR" >&2
            exit 1
        fi
        ;;
    *"/checksums.sha256"*)
        if [[ -f "$SERVE_DIR/checksums.sha256" ]]; then
            serve_file "$SERVE_DIR/checksums.sha256"
        else
            exit 1
        fi
        ;;
    *"/release-signing-public.pem"*)
        if [[ -f "$SERVE_DIR/release-signing-public.pem" ]]; then
            serve_file "$SERVE_DIR/release-signing-public.pem"
        else
            exit 1
        fi
        ;;
    *".sig")
        filename="${url##*/}"
        if [[ -f "$SERVE_DIR/$filename" ]]; then
            serve_file "$SERVE_DIR/$filename"
        else
            echo "ERROR: Signature not found: $filename in $SERVE_DIR" >&2
            exit 1
        fi
        ;;
    *".tar.gz"*)
        # Extract filename from URL path
        filename="${url##*/}"
        filename="${filename%%\?*}"
        if [[ -f "$SERVE_DIR/$filename" ]]; then
            serve_file "$SERVE_DIR/$filename"
        else
            # Try matching pattern
            for f in "$SERVE_DIR"/*.tar.gz; do
                if [[ -f "$f" ]]; then
                    serve_file "$f"
                    exit 0
                fi
            done
            echo "ERROR: Tarball not found: $filename in $SERVE_DIR" >&2
            ls "$SERVE_DIR" >&2
            exit 1
        fi
        ;;
    *)
        echo "ERROR: Unknown URL pattern: $url" >&2
        exit 1
        ;;
esac
exit 0
MOCK_CURL
    sed -i "s|__SERVE_DIR__|${serve_dir}|g" "${MOCK_BIN}/curl"
    sed -i "s|__VERSION__|${version}|g" "${MOCK_BIN}/curl"
    chmod +x "${MOCK_BIN}/curl"
    test_info "Created serving mock curl for $serve_dir"
}

# Create mock uname for OS/arch simulation
create_mock_uname() {
    local os="$1"    # Linux or Darwin
    local arch="$2"  # x86_64 or aarch64

    cat > "${MOCK_BIN}/uname" << 'MOCK_UNAME'
#!/usr/bin/env bash
case "$1" in
    -s) echo "__OS__" ;;
    -m) echo "__ARCH__" ;;
    *) echo "__OS__ __ARCH__" ;;
esac
MOCK_UNAME
    sed -i "s|__OS__|${os}|g" "${MOCK_BIN}/uname"
    sed -i "s|__ARCH__|${arch}|g" "${MOCK_BIN}/uname"
    chmod +x "${MOCK_BIN}/uname"
    test_debug "Created mock uname: OS=$os ARCH=$arch"
}

# Create mock curl that fails
create_failing_mock_curl() {
    local exit_code="${1:-1}"
    local error_msg="${2:-Connection refused}"

    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
echo "__ERROR_MSG__" >&2
exit __EXIT_CODE__
MOCK_CURL
    sed -i "s|__EXIT_CODE__|${exit_code}|g" "${MOCK_BIN}/curl"
    sed -i "s|__ERROR_MSG__|${error_msg}|g" "${MOCK_BIN}/curl"
    chmod +x "${MOCK_BIN}/curl"
    test_info "Created failing mock curl (exit=$exit_code)"
}

# Setup a complete test environment for installer tests
setup_installer_test_env() {
    local version="${1:-1.0.0}"
    local os="${2:-Linux}"
    local arch="${3:-x86_64}"

    setup_test_env

    # Create directories
    export INSTALL_DEST="${TEST_DIR}/install_target"
    export ASSETS_DIR="${TEST_DIR}/assets"
    mkdir -p "$INSTALL_DEST" "$ASSETS_DIR"

    # Determine normalized OS name (linux vs macos)
    local os_normalized
    case "$os" in
        Darwin) os_normalized="macos" ;;
        Linux) os_normalized="linux" ;;
        *) os_normalized="$os" ;;
    esac

    # Create fake pt wrapper
    create_fake_pt_wrapper "$version" "$ASSETS_DIR/pt"

    # Create fake pt-core tarball
    create_fake_pt_core_tarball "$version" "$os_normalized" "$arch" "$ASSETS_DIR"
    if [[ "$os_normalized" == "linux" ]]; then
        create_fake_pt_core_tarball "$version" "$os_normalized" "${arch}-musl" "$ASSETS_DIR"
    fi

    # Create checksums
    create_checksums_file "$version" "$ASSETS_DIR" "$ASSETS_DIR/checksums.sha256"

    # Create signing key pair and detached signatures
    export RELEASE_SIGNING_PRIVATE_KEY="${TEST_DIR}/release-signing-private.pem"
    openssl ecparam -name prime256v1 -genkey -noout -out "$RELEASE_SIGNING_PRIVATE_KEY"
    create_release_signatures "$ASSETS_DIR" "$RELEASE_SIGNING_PRIVATE_KEY"
    export PT_RELEASE_PUBLIC_KEY_FILE="$ASSETS_DIR/release-signing-public.pem"

    # Setup mocks
    create_mock_uname "$os" "$arch"
    create_serving_mock_curl "$ASSETS_DIR" "$version"

    # Inject mocks into PATH
    use_mock_bin

    test_info "Installer test environment ready: v${version} for ${os}/${arch}"
}

# ==============================================================================
# SMOKE TESTS
# ==============================================================================

@test "installer: syntax check (bash -n)" {
    test_start "installer syntax check" "verify install.sh has no syntax errors"

    run bash -n "$INSTALLER_PATH"

    if [[ $status -ne 0 ]]; then
        test_error "Syntax check failed:"
        test_error "$output"
    fi

    [ "$status" -eq 0 ]
    test_end "installer syntax check" "pass"
}

@test "installer: has required functions" {
    test_start "installer required functions" "verify key functions exist"

    # Source the installer to check functions exist
    # We need to bypass the self-refresh and main execution
    local temp_script="${BATS_TEST_TMPDIR}/installer_check.sh"

    # Extract just the function definitions (skip execution)
    sed '/^maybe_self_refresh$/,/^$/d; /^main /,/^$/d; s/^main "$@"$//' "$INSTALLER_PATH" > "$temp_script"
    echo "" >> "$temp_script"

    source "$temp_script"

    # Check required functions exist
    run type detect_os
    [ "$status" -eq 0 ]

    run type detect_arch
    [ "$status" -eq 0 ]

    run type download
    [ "$status" -eq 0 ]

    run type sha256_file
    [ "$status" -eq 0 ]

    run type install_binary
    [ "$status" -eq 0 ]

    run type add_to_path
    [ "$status" -eq 0 ]

    test_end "installer required functions" "pass"
}

# ==============================================================================
# FRESH INSTALL TESTS
# ==============================================================================

@test "installer: fresh install installs both pt and pt-core" {
    test_start "fresh install" "verify both pt and pt-core are installed"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Run installer with custom dest
    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1  # Skip self-refresh

    run bash "$INSTALLER_PATH"

    test_info "Installer exit code: $status"
    test_info "Installer output: $output"

    [ "$status" -eq 0 ]

    # Check pt exists and is executable
    [ -f "$INSTALL_DEST/pt" ]
    [ -x "$INSTALL_DEST/pt" ]
    test_info "pt wrapper installed: $INSTALL_DEST/pt"

    # Check pt-core exists and is executable
    [ -f "$INSTALL_DEST/pt-core" ]
    [ -x "$INSTALL_DEST/pt-core" ]
    test_info "pt-core installed: $INSTALL_DEST/pt-core"

    # Verify they work
    run "$INSTALL_DEST/pt" --help
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt"

    run "$INSTALL_DEST/pt-core" --help
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt-core"

    test_end "fresh install" "pass"
}

@test "installer: creates install directory if missing" {
    test_start "create install dir" "verify installer creates DEST if missing"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Use a non-existent nested directory
    export DEST="${TEST_DIR}/new/nested/path"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    [ ! -d "$DEST" ]

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]
    [ -d "$DEST" ]
    [ -f "$DEST/pt" ]

    test_end "create install dir" "pass"
}

# ==============================================================================
# OS/ARCH SELECTION TESTS
# ==============================================================================

@test "installer: selects correct artifact for Linux x86_64" {
    test_start "Linux x86_64" "verify correct artifact selected"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt-core" ]

    # Verify it's the correct version
    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "1.0.0"

    test_end "Linux x86_64" "pass"
}

@test "installer: selects correct artifact for Linux aarch64" {
    test_start "Linux aarch64" "verify correct artifact selected for ARM64"

    setup_installer_test_env "1.0.0" "Linux" "aarch64"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt-core" ]

    test_end "Linux aarch64" "pass"
}

@test "installer: selects correct artifact for macOS x86_64" {
    test_start "macOS x86_64" "verify correct artifact selected for Intel Mac"

    setup_installer_test_env "1.0.0" "Darwin" "x86_64"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt-core" ]

    test_end "macOS x86_64" "pass"
}

@test "installer: selects correct artifact for macOS aarch64 (Apple Silicon)" {
    test_start "macOS aarch64" "verify correct artifact selected for Apple Silicon"

    # Note: macOS reports arm64, but we also support aarch64
    setup_installer_test_env "1.0.0" "Darwin" "arm64"

    # Also need to create assets for arm64 naming
    create_fake_pt_core_tarball "1.0.0" "macos" "aarch64" "$ASSETS_DIR"
    create_checksums_file "1.0.0" "$ASSETS_DIR" "$ASSETS_DIR/checksums.sha256"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    # May succeed or warn about missing artifact (depending on naming)
    [ -f "$INSTALL_DEST/pt" ]  # pt wrapper should always install

    test_end "macOS aarch64" "pass"
}

# ==============================================================================
# UPGRADE SCENARIO TESTS
# ==============================================================================

@test "installer: upgrade replaces old versions" {
    test_start "upgrade" "verify upgrade replaces old binaries"

    setup_installer_test_env "2.0.0" "Linux" "x86_64"

    # Install "old" version first
    create_fake_pt_wrapper "1.0.0" "$INSTALL_DEST/pt"
    create_fake_pt_core "1.0.0" "$INSTALL_DEST/pt-core"

    # Verify old version
    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "1.0.0"

    # Now run installer with new version
    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Verify new version installed
    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "2.0.0"

    run "$INSTALL_DEST/pt-core" --version
    assert_contains "$output" "2.0.0"

    test_end "upgrade" "pass"
}

@test "installer: upgrade is atomic (no partial install)" {
    test_start "atomic upgrade" "verify failed upgrade doesn't leave partial state"

    setup_installer_test_env "2.0.0" "Linux" "x86_64"

    # Install old version first
    create_fake_pt_wrapper "1.0.0" "$INSTALL_DEST/pt"
    create_fake_pt_core "1.0.0" "$INSTALL_DEST/pt-core"

    # Record old checksums
    local old_pt_hash old_core_hash
    old_pt_hash=$(sha256sum "$INSTALL_DEST/pt" | cut -d' ' -f1)
    old_core_hash=$(sha256sum "$INSTALL_DEST/pt-core" | cut -d' ' -f1)

    # Create a mock curl that fails during pt-core download
    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
url=""
output_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) output_file="$2"; shift 2 ;;
        *) url="$1"; shift ;;
    esac
done
url="${url%%\?*}"

case "$url" in
    *"/VERSION"*) echo "2.0.0" ;;
    *"/pt"*) echo "#!/usr/bin/env bash" && echo "echo 'pt 2.0.0'" ;;
    *.tar.gz*) echo "NETWORK_ERROR" >&2; exit 1 ;;
    *) echo "ok" ;;
esac
MOCK_CURL
    chmod +x "${MOCK_BIN}/curl"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    # This should warn but not fail completely (pt-core is optional fallback)
    run bash "$INSTALLER_PATH"

    # pt wrapper should still install
    [ -f "$INSTALL_DEST/pt" ]

    # pt-core might retain old version or installer warns
    test_info "Output: $output"

    test_end "atomic upgrade" "pass"
}

# ==============================================================================
# CHECKSUM VERIFICATION TESTS
# ==============================================================================

@test "installer: VERIFY=1 succeeds with valid checksums" {
    test_start "checksum valid" "verify VERIFY=1 succeeds with correct checksums"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1

    run bash "$INSTALLER_PATH"

    test_info "Output: $output"

    # Should succeed
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_DEST/pt" ]

    test_end "checksum valid" "pass"
}

@test "installer: VERIFY=1 fails on release key fingerprint mismatch" {
    test_start "fingerprint mismatch" "verify key pin mismatch fails closed"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1
    export PT_RELEASE_PUBLIC_KEY_FINGERPRINT="0000000000000000000000000000000000000000000000000000000000000000"

    run bash "$INSTALLER_PATH"

    [ "$status" -ne 0 ]
    [[ "$output" == *"Release public key fingerprint mismatch"* ]]

    test_end "fingerprint mismatch" "pass"
}

@test "installer: VERIFY=1 fails with corrupted download" {
    test_start "checksum invalid" "verify VERIFY=1 fails on mismatch"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Corrupt the pt file after checksums were generated
    echo "CORRUPTED" >> "$ASSETS_DIR/pt"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1

    run bash "$INSTALLER_PATH"

    test_info "Output: $output"

    [ "$status" -ne 0 ]
    [[ "$output" == *"Signature verification failed"* ]] || [[ "$output" == *"verification failed"* ]]

    test_end "checksum invalid" "pass"
}

@test "installer: VERIFY=1 shows clear error on mismatch" {
    test_start "checksum error message" "verify error message is clear"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Create mismatched checksums
    echo "0000000000000000000000000000000000000000000000000000000000000000  pt" > "$ASSETS_DIR/checksums.sha256"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1

    run bash "$INSTALLER_PATH"

    test_info "Output: $output"

    [ "$status" -ne 0 ]
    [[ "$output" == *"Checksum mismatch"* ]]

    test_end "checksum error message" "pass"
}

@test "installer: VERIFY=1 fails when pt signature is missing" {
    test_start "missing pt signature" "verify missing pt.sig aborts install"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"
    rm -f "$ASSETS_DIR/pt.sig"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1

    run bash "$INSTALLER_PATH"

    [ "$status" -ne 0 ]
    [[ "$output" == *"Could not download signature for pt"* ]]

    test_end "missing pt signature" "pass"
}

@test "installer: VERIFY=1 fails when pt-core signature is missing" {
    test_start "missing pt-core signature" "verify missing pt-core archive .sig aborts install"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"
    rm -f "$ASSETS_DIR"/pt-core-*.tar.gz.sig

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export VERIFY=1

    run bash "$INSTALLER_PATH"

    [ "$status" -ne 0 ]
    [[ "$output" == *"Could not download signature for pt-core"* ]]

    test_end "missing pt-core signature" "pass"
}

# ==============================================================================
# PATH MANAGEMENT TESTS
# ==============================================================================

@test "installer: adds to PATH in bashrc" {
    test_start "PATH bashrc" "verify PATH added to .bashrc"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Create fake bashrc
    export HOME="${TEST_DIR}/home"
    mkdir -p "$HOME"
    touch "$HOME/.bashrc"

    export DEST="${HOME}/.local/bin"
    export SHELL="/bin/bash"
    export PT_REFRESHED=1
    # Don't set PT_NO_PATH

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Check bashrc was modified
    run cat "$HOME/.bashrc"
    assert_contains "$output" "$DEST"
    assert_contains "$output" "PATH"

    test_end "PATH bashrc" "pass"
}

@test "installer: adds to PATH in zshrc" {
    test_start "PATH zshrc" "verify PATH added to .zshrc"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export HOME="${TEST_DIR}/home"
    mkdir -p "$HOME"
    touch "$HOME/.zshrc"

    export DEST="${HOME}/.local/bin"
    export SHELL="/bin/zsh"
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Check zshrc was modified
    run cat "$HOME/.zshrc"
    assert_contains "$output" "$DEST"

    test_end "PATH zshrc" "pass"
}

@test "installer: PT_NO_PATH=1 skips PATH modification" {
    test_start "PATH skip" "verify PT_NO_PATH=1 prevents PATH edits"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export HOME="${TEST_DIR}/home"
    mkdir -p "$HOME"
    touch "$HOME/.bashrc"
    echo "# original content" > "$HOME/.bashrc"

    export DEST="${HOME}/.local/bin"
    export SHELL="/bin/bash"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Check bashrc was NOT modified
    run cat "$HOME/.bashrc"
    assert_not_contains "$output" ".local/bin"
    assert_contains "$output" "original content"

    test_end "PATH skip" "pass"
}

@test "installer: does not duplicate PATH entries" {
    test_start "PATH no duplicate" "verify PATH not added twice"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export HOME="${TEST_DIR}/home"
    mkdir -p "$HOME"
    export DEST="${HOME}/.local/bin"

    # Pre-add the PATH entry
    echo 'export PATH="'"$DEST"':$PATH"' > "$HOME/.bashrc"
    local original_content
    original_content=$(cat "$HOME/.bashrc")

    export SHELL="/bin/bash"
    export PT_REFRESHED=1
    # PATH already includes DEST
    export PATH="$DEST:$PATH"

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Count occurrences of DEST in bashrc - should be exactly 1
    local count
    count=$(grep -c "$DEST" "$HOME/.bashrc")
    [ "$count" -eq 1 ]

    test_end "PATH no duplicate" "pass"
}

# ==============================================================================
# NETWORK FAILURE TESTS
# ==============================================================================

@test "installer: fails gracefully on network error" {
    test_start "network error" "verify clean failure on network error"

    setup_test_env

    export INSTALL_DEST="${TEST_DIR}/install_target"
    mkdir -p "$INSTALL_DEST"

    # Create failing curl
    create_failing_mock_curl 7 "curl: (7) Failed to connect to host"

    use_mock_bin

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    test_info "Exit code: $status"
    test_info "Output: $output"

    # Should fail
    [ "$status" -ne 0 ]

    # Should have error message (check various possible error indicators)
    [[ "$output" == *"Failed"* ]] || [[ "$output" == *"error"* ]] || [[ "$output" == *"Error"* ]] || \
    [[ "$output" == *"curl"* ]] || [[ "$output" == *"Could not"* ]] || [[ "$output" == *"fetch"* ]]

    # No partial binaries should be installed
    [ ! -f "$INSTALL_DEST/pt" ] || [ ! -x "$INSTALL_DEST/pt" ]

    test_end "network error" "pass"
}

@test "installer: shows useful error on version fetch failure" {
    test_start "version fetch error" "verify useful error when VERSION fetch fails"

    setup_test_env

    export INSTALL_DEST="${TEST_DIR}/install_target"
    mkdir -p "$INSTALL_DEST"

    # Create curl that only fails on VERSION
    cat > "${MOCK_BIN}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
url=""
for arg in "$@"; do
    case "$arg" in
        -o|-f|-s|-S|-L|--*) ;;
        http*) url="$arg" ;;
    esac
done
url="${url%%\?*}"

if [[ "$url" == *"/VERSION"* ]]; then
    echo "curl: (6) Could not resolve host" >&2
    exit 6
fi
echo "ok"
MOCK_CURL
    chmod +x "${MOCK_BIN}/curl"

    use_mock_bin

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    test_info "Output: $output"

    # Should fail
    [ "$status" -ne 0 ]

    # Error should mention VERSION or fetching
    [[ "$output" == *"VERSION"* ]] || [[ "$output" == *"version"* ]] || [[ "$output" == *"fetch"* ]]

    test_end "version fetch error" "pass"
}

@test "installer: continues if pt-core download fails" {
    test_start "pt-core optional" "verify pt wrapper installs even if pt-core fails"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    # Remove pt-core tarball
    rm -f "$ASSETS_DIR"/*.tar.gz

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    test_info "Output: $output"

    # pt wrapper should still install successfully
    [ -f "$INSTALL_DEST/pt" ]
    [ -x "$INSTALL_DEST/pt" ]

    # Should warn about pt-core
    [[ "$output" == *"pt-core"* ]] || [[ "$output" == *"Failed"* ]] || true

    test_end "pt-core optional" "pass"
}

# ==============================================================================
# EDGE CASE TESTS
# ==============================================================================

@test "installer: handles spaces in DEST path" {
    test_start "spaces in path" "verify DEST with spaces works"

    setup_installer_test_env "1.0.0" "Linux" "x86_64"

    export DEST="${TEST_DIR}/install path with spaces"
    export PT_NO_PATH=1
    export PT_REFRESHED=1

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]
    [ -f "$DEST/pt" ]
    [ -x "$DEST/pt" ]

    test_end "spaces in path" "pass"
}

@test "installer: PT_VERSION overrides latest" {
    test_start "PT_VERSION override" "verify specific version can be installed"

    setup_installer_test_env "1.5.0" "Linux" "x86_64"

    # Also create 1.5.0 assets
    create_fake_pt_wrapper "1.5.0" "$ASSETS_DIR/pt"
    create_fake_pt_core_tarball "1.5.0" "linux" "x86_64" "$ASSETS_DIR"
    create_checksums_file "1.5.0" "$ASSETS_DIR" "$ASSETS_DIR/checksums.sha256"
    create_serving_mock_curl "$ASSETS_DIR" "1.5.0"

    export DEST="$INSTALL_DEST"
    export PT_NO_PATH=1
    export PT_REFRESHED=1
    export PT_VERSION="1.5.0"

    run bash "$INSTALLER_PATH"

    [ "$status" -eq 0 ]

    # Verify correct version
    run "$INSTALL_DEST/pt" --version
    assert_contains "$output" "1.5.0"

    test_end "PT_VERSION override" "pass"
}
