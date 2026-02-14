#!/usr/bin/env bash
#
# install.sh - Process Triage (pt) Installer
#
# One-liner installation:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/master/install.sh | bash
#
# Environment variables:
#   DEST        - Custom install directory (default: ~/.local/bin)
#   PT_SYSTEM   - Set to 1 for system-wide install (/usr/local/bin)
#   PT_VERSION  - Install specific version (default: latest)
#   PT_NO_PATH  - Set to 1 to skip PATH modification
#   VERIFY      - Set to 1 to enforce signature + checksum verification
#   PT_RELEASE_PUBLIC_KEY_FILE - Optional PEM public key file for signature verification
#   PT_RELEASE_PUBLIC_KEY_PEM  - Optional PEM public key content for signature verification
#   PT_CORE_VERSION - Install specific pt-core version (default: same as PT_VERSION)
#
set -euo pipefail

readonly GITHUB_REPO="Dicklesworthstone/process_triage"
readonly RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/master"
readonly RELEASES_URL="https://github.com/${GITHUB_REPO}/releases"

# Minimal downloader for early bootstrapping (stdout).
fetch_stdout() {
    local url="$1"

    if command -v curl &>/dev/null; then
        curl -fsSL --connect-timeout 10 --max-time 120 "$url"
    elif command -v wget &>/dev/null; then
        wget -q --timeout=10 -O - "$url"
    else
        printf 'Neither curl nor wget available\n' >&2
        return 1
    fi
}

# ==============================================================================
# Self-Refresh: Re-download when piped to avoid CDN cache issues
# ==============================================================================

maybe_self_refresh() {
    # Only refresh if being piped AND not already refreshed
    if [[ -p /dev/stdin ]] && [[ -z "${PT_REFRESHED:-}" ]]; then
        export PT_REFRESHED=1
        # Re-execute with cache-busted URL
        exec bash <(fetch_stdout "${RAW_URL}/install.sh?cb=$(date +%s)")
    fi
}

maybe_self_refresh

# ==============================================================================
# Logging
# ==============================================================================

log_info() {
    printf '\033[0;34mi\033[0m %s\n' "$*" >&2
}

log_success() {
    printf '\033[0;32m✓\033[0m %s\n' "$*" >&2
}

log_error() {
    printf '\033[0;31m✗\033[0m %s\n' "$*" >&2
}

log_step() {
    printf '\033[0;36m→\033[0m %s\n' "$*" >&2
}

log_warn() {
    printf '\033[0;33m⚠\033[0m %s\n' "$*" >&2
}

# ==============================================================================
# Platform Detection
# ==============================================================================

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')

    case "$os" in
        linux)
            echo "linux"
            ;;
        darwin)
            echo "macos"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            log_error "pt-core supports Linux and macOS only"
            return 1
            ;;
    esac
}

detect_arch() {
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            log_error "pt-core supports x86_64 and aarch64 only"
            return 1
            ;;
    esac
}

# Build artifact name for pt-core binary
# Format: pt-core-{os}-{arch}-{version}.tar.gz
get_pt_core_artifact_name() {
    local version="$1"
    local os arch

    os=$(detect_os) || return 1
    arch=$(detect_arch) || return 1

    echo "pt-core-${os}-${arch}-${version}.tar.gz"
}

# ==============================================================================
# Utilities
# ==============================================================================

# Cross-platform mktemp (Linux GNU vs macOS BSD)
mktemp_dir() {
    local dir

    # Try GNU style first (Linux)
    dir=$(mktemp -d 2>/dev/null) && { echo "$dir"; return 0; }

    # BSD style with -t (macOS)
    dir=$(mktemp -d -t pt 2>/dev/null) && { echo "$dir"; return 0; }

    # BSD style with explicit template
    dir=$(mktemp -d -t pt.XXXXXXXXXX 2>/dev/null) && { echo "$dir"; return 0; }

    # Manual fallback
    dir="/tmp/pt.$$.$(date +%s)"
    mkdir -p "$dir" && { echo "$dir"; return 0; }

    log_error "Failed to create temporary directory"
    return 1
}

# Append cache-buster to URL to bypass CDN caching
append_cache_buster() {
    local url="$1"
    local timestamp
    timestamp=$(date +%s)

    if [[ "$url" == *"?"* ]]; then
        echo "${url}&cb=${timestamp}"
    else
        echo "${url}?cb=${timestamp}"
    fi
}

# Download file using curl or wget
download() {
    local url="$1"
    local output="$2"

    if command -v curl &>/dev/null; then
        curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q --timeout=10 -O "$output" "$url"
    else
        log_error "Neither curl nor wget available"
        log_error "Install curl: apt install curl (or brew install curl)"
        return 1
    fi
}

# Cross-platform SHA256
sha256_file() {
    local file="$1"

    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    elif command -v openssl &>/dev/null; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        log_warn "No SHA256 tool available"
        return 1
    fi
}

# ==============================================================================
# Version Detection
# ==============================================================================

get_latest_version() {
    local version_url
    version_url=$(append_cache_buster "${RAW_URL}/VERSION")

    local version
    version=$(fetch_stdout "$version_url" 2>/dev/null | tr -d '[:space:]') || {
        log_error "Could not fetch VERSION file"
        log_error "URL: ${RAW_URL}/VERSION"
        return 1
    }

    # Validate version format (semver-like)
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
        log_error "Invalid version format: $version"
        return 1
    fi

    echo "$version"
}

get_installed_version() {
    local install_path="$1"

    if [[ ! -x "$install_path" ]]; then
        echo ""
        return 0
    fi

    # Extract version from installed script
    local version
    version=$("$install_path" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
    echo "${version:-unknown}"
}

# Detect if system uses musl libc (Alpine, etc.)
# Returns: 0 if musl, 1 if glibc or unknown
detect_musl() {
    # Check for Alpine Linux
    if [[ -f /etc/alpine-release ]]; then
        return 0
    fi

    # Check ldd output for musl
    if command -v ldd &>/dev/null; then
        if ldd --version 2>&1 | grep -qi musl; then
            return 0
        fi
    fi

    # Check /lib for musl-libc
    if [[ -f /lib/ld-musl-x86_64.so.1 ]] || [[ -f /lib/ld-musl-aarch64.so.1 ]]; then
        return 0
    fi

    return 1
}

# Detect platform (OS + architecture + libc) for artifact naming
# Returns: linux-x86_64, linux-x86_64-musl, linux-aarch64, macos-x86_64, etc.
detect_platform() {
    local arch; arch=$(uname -m)
    local os; os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local suffix=""

    case "$arch" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)
            log_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    case "$os" in
        linux)
            # Check for musl-based system
            if detect_musl; then
                suffix="-musl"
                log_info "Detected musl-based system (using static binary)"
            fi
            ;;
        darwin) os="macos" ;;
        *)
            log_error "Unsupported OS: $os"
            return 1
            ;;
    esac

    echo "${os}-${arch}${suffix}"
}

# Get artifact name with optional musl fallback
# On glibc systems, first try glibc build, then musl as fallback
get_artifact_with_fallback() {
    local version="$1"
    local platform="$2"

    # Primary artifact name
    echo "pt-core-${platform}-${version}.tar.gz"
}

# Try to get musl fallback artifact name (for glibc version mismatch)
get_musl_fallback() {
    local version="$1"
    local platform="$2"

    # Only applicable for Linux glibc builds
    if [[ "$platform" == linux-x86_64 ]]; then
        echo "pt-core-linux-x86_64-musl-${version}.tar.gz"
    elif [[ "$platform" == linux-aarch64 ]]; then
        echo "pt-core-linux-aarch64-musl-${version}.tar.gz"
    else
        echo ""
    fi
}

# ==============================================================================
# Verification (optional)
# ==============================================================================

# Download the consolidated checksums file from release
download_checksums() {
    local version="$1"
    local output="$2"

    local checksum_url="${RELEASES_URL}/download/v${version}/checksums.sha256"

    download "$checksum_url" "$output" 2>/dev/null || {
        log_error "Could not download checksums file"
        log_error "URL: $checksum_url"
        return 1
    }
}

# Look up expected checksum for a file from checksums.sha256
lookup_checksum() {
    local checksums_file="$1"
    local filename="$2"

    if [[ ! -f "$checksums_file" ]]; then
        return 1
    fi

    # Format: "hash  filename" (two spaces)
    grep -E "^[a-f0-9]{64}  ${filename}$" "$checksums_file" | cut -d' ' -f1
}

verify_download() {
    local file="$1"
    local version="$2"

    if [[ "${VERIFY:-}" != "1" ]]; then
        return 0  # Verification not requested
    fi

    log_step "Verifying checksum..."

    # Download expected checksum
    local checksum_url="${RELEASES_URL}/download/v${version}/pt.sha256"
    local expected

    expected=$(fetch_stdout "$checksum_url" 2>/dev/null) || {
        log_error "Could not download checksum file"
        log_error "URL: $checksum_url"
        return 1
    }

    # Extract hash (format: "hash  filename" or just "hash")
    expected="${expected%% *}"
    if [[ -z "$expected" ]]; then
        log_error "Checksum file was empty or malformed: $checksum_url"
        return 1
    fi

    # Compute actual
    local actual
    actual=$(sha256_file "$file") || {
        log_error "Could not compute checksum (no SHA256 tool available)"
        return 1
    }

    # Compare
    if [[ "$expected" == "$actual" ]]; then
        log_success "Checksum verified: ${actual:0:16}..."
        return 0
    else
        log_error "Checksum mismatch!"
        log_error "Expected: $expected"
        log_error "Actual:   $actual"
        log_error ""
        log_error "The downloaded file may be corrupted or tampered with."
        log_error "Please report this issue if it persists."
        return 1
    fi
}

# Verify a file against checksums.sha256 file
verify_file_checksum() {
    local file="$1"
    local filename="$2"
    local checksums_file="$3"

    if [[ "${VERIFY:-}" != "1" ]]; then
        return 0  # Verification not requested
    fi

    log_step "Verifying ${filename} checksum..."

    local expected
    expected=$(lookup_checksum "$checksums_file" "$filename") || {
        log_error "No checksum found for ${filename} in ${checksums_file}"
        return 1
    }

    if [[ -z "$expected" ]]; then
        log_error "Checksum not found for ${filename} in ${checksums_file}"
        return 1
    fi

    local actual
    actual=$(sha256_file "$file") || {
        log_error "Could not compute checksum (no SHA256 tool available)"
        return 1
    }

    if [[ "$expected" == "$actual" ]]; then
        log_success "${filename} checksum verified: ${actual:0:16}..."
        return 0
    else
        log_error "Checksum mismatch for ${filename}!"
        log_error "Expected: $expected"
        log_error "Actual:   $actual"
        return 1
    fi
}

ensure_openssl_for_signatures() {
    if ! command -v openssl &>/dev/null; then
        log_error "OpenSSL is required for signature verification (VERIFY=1)."
        log_error "Install OpenSSL and retry."
        return 1
    fi
}

resolve_release_public_key() {
    local version="$1"
    local output="$2"

    if [[ -n "${PT_RELEASE_PUBLIC_KEY_FILE:-}" ]]; then
        if [[ ! -f "${PT_RELEASE_PUBLIC_KEY_FILE}" ]]; then
            log_error "PT_RELEASE_PUBLIC_KEY_FILE does not exist: ${PT_RELEASE_PUBLIC_KEY_FILE}"
            return 1
        fi
        cp "${PT_RELEASE_PUBLIC_KEY_FILE}" "$output" || {
            log_error "Failed to copy public key from PT_RELEASE_PUBLIC_KEY_FILE"
            return 1
        }
    elif [[ -n "${PT_RELEASE_PUBLIC_KEY_PEM:-}" ]]; then
        printf '%s\n' "${PT_RELEASE_PUBLIC_KEY_PEM}" > "$output"
    else
        local key_url="${RELEASES_URL}/download/v${version}/release-signing-public.pem"
        download "$key_url" "$output" || {
            log_error "Could not download trusted public key for v${version}"
            log_error "URL: ${key_url}"
            log_error "Set PT_RELEASE_PUBLIC_KEY_FILE or PT_RELEASE_PUBLIC_KEY_PEM to provide a trusted key."
            return 1
        }
    fi

    if ! openssl pkey -pubin -in "$output" -noout >/dev/null 2>&1; then
        log_error "Invalid public key PEM for release signature verification"
        return 1
    fi
}

download_signature() {
    local version="$1"
    local artifact_name="$2"
    local output="$3"

    local sig_url="${RELEASES_URL}/download/v${version}/${artifact_name}.sig"
    download "$sig_url" "$output" || {
        log_error "Could not download signature for ${artifact_name}"
        log_error "URL: ${sig_url}"
        return 1
    }
}

verify_file_signature() {
    local file_path="$1"
    local artifact_name="$2"
    local version="$3"
    local pubkey_file="$4"
    local sig_output="$5"

    log_step "Verifying ${artifact_name} signature..."
    download_signature "$version" "$artifact_name" "$sig_output" || return 1

    if openssl dgst -sha256 -verify "$pubkey_file" -signature "$sig_output" "$file_path" >/dev/null 2>&1; then
        log_success "${artifact_name} signature verified"
        return 0
    fi

    log_error "Signature verification failed for ${artifact_name}"
    return 1
}

# ==============================================================================
# Installation
# ==============================================================================

# Atomically install a binary with optional backup of existing version
# Uses rename (mv) for atomicity - either the install completes or it doesn't
install_binary() {
    local source_file="$1"
    local dest_dir="$2"
    local binary_name="$3"
    local dest_file="${dest_dir}/${binary_name}"

    # Create destination directory if needed
    if [[ ! -d "$dest_dir" ]]; then
        log_step "Creating directory: $dest_dir"
        mkdir -p "$dest_dir"
    fi

    # Check for existing installation and create backup
    local current_version=""
    if [[ -f "$dest_file" ]]; then
        if [[ "$binary_name" == "pt" ]]; then
            current_version=$(get_installed_version "$dest_file")
            if [[ -n "$current_version" && "$current_version" != "unknown" ]]; then
                log_info "Current $binary_name version: $current_version"
            fi
        fi

        # Create backup of existing binary for rollback
        local backup_file="${dest_file}.bak"
        if ! cp "$dest_file" "$backup_file" 2>/dev/null; then
            log_error "Failed to back up existing ${binary_name} to ${backup_file}"
            log_error "Aborting install to preserve rollback safety"
            return 1
        fi
        log_info "Backed up existing ${binary_name} to ${backup_file}"
    fi

    # Make source executable before moving
    chmod +x "$source_file"

    # Atomic install using rename (mv)
    # On the same filesystem, mv is atomic; we ensure this by copying to dest_dir first
    local temp_dest="${dest_file}.new"
    cp "$source_file" "$temp_dest" || {
        log_error "Failed to copy ${binary_name} to destination"
        return 1
    }
    chmod +x "$temp_dest"

    # Atomic rename
    mv "$temp_dest" "$dest_file" || {
        log_error "Failed to install ${binary_name} (atomic rename failed)"
        rm -f "$temp_dest" 2>/dev/null
        return 1
    }

    log_success "Installed: $dest_file"
}

# ==============================================================================
# PATH Management
# ==============================================================================

detect_shell() {
    local shell_name

    # Check $SHELL environment variable
    shell_name="${SHELL##*/}"

    # Validate it's a known shell
    case "$shell_name" in
        bash|zsh|fish|sh)
            echo "$shell_name"
            ;;
        *)
            # Fallback: check what's running
            if [[ -n "${BASH_VERSION:-}" ]]; then
                echo "bash"
            elif [[ -n "${ZSH_VERSION:-}" ]]; then
                echo "zsh"
            else
                echo "bash"  # Default assumption
            fi
            ;;
    esac
}

get_shell_config() {
    local shell_name="$1"

    case "$shell_name" in
        bash)
            # Prefer .bashrc for interactive, .bash_profile for login
            if [[ -f "$HOME/.bashrc" ]]; then
                echo "$HOME/.bashrc"
            elif [[ -f "$HOME/.bash_profile" ]]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.bashrc"  # Create it
            fi
            ;;
        zsh)
            echo "$HOME/.zshrc"
            ;;
        fish)
            echo "$HOME/.config/fish/config.fish"
            ;;
        *)
            echo "$HOME/.profile"
            ;;
    esac
}

add_to_path() {
    local install_dir="$1"

    # Check if already in PATH
    if [[ ":$PATH:" == *":$install_dir:"* ]]; then
        log_info "$install_dir already in PATH"
        return 0
    fi

    # Detect shell and config file
    local shell_name config_file
    shell_name=$(detect_shell)
    config_file=$(get_shell_config "$shell_name")

    log_step "Adding $install_dir to PATH in $config_file"

    # Create directory for fish config if needed
    if [[ "$shell_name" == "fish" ]]; then
        mkdir -p "${config_file%/*}"
    fi

    # Prepare PATH export line
    local path_line
    case "$shell_name" in
        fish)
            path_line="set -gx PATH \"$install_dir\" \$PATH"
            ;;
        *)
            path_line="export PATH=\"$install_dir:\$PATH\""
            ;;
    esac

    # Check if already added (avoid duplicates)
    if [[ -f "$config_file" ]] && grep -qF "$install_dir" "$config_file" 2>/dev/null; then
        log_info "PATH already configured in $config_file"
        return 0
    fi

    # Add to config
    {
        echo ""
        echo "# Added by pt installer"
        echo "$path_line"
    } >> "$config_file"

    log_success "Added to $config_file"
    log_info "Run 'source $config_file' or start a new terminal to use pt."
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    log_step "Installing pt (Process Triage)..."

    # Determine version to install
    local version="${PT_VERSION:-}"
    if [[ -z "$version" ]]; then
        log_step "Detecting latest version..."
        version=$(get_latest_version) || exit 1
    fi
    log_info "Version: $version"

    # Determine pt-core version (may differ from pt wrapper version)
    local core_version="${PT_CORE_VERSION:-$version}"
    if [[ "$core_version" != "$version" ]]; then
        log_info "pt-core version: $core_version (decoupled from wrapper)"
    fi

    # Determine install location
    local dest="${DEST:-$HOME/.local/bin}"
    if [[ "${PT_SYSTEM:-}" == "1" ]]; then
        dest="/usr/local/bin"
        # Check for root/sudo for system install
        if [[ ! -w "$dest" ]] && [[ "$(id -u)" != "0" ]]; then
            log_error "System-wide install requires root privileges"
            log_error "Run with: sudo PT_SYSTEM=1 bash <(curl -fsSL ...)"
            exit 1
        fi
    fi

    log_info "Install directory: $dest"

    # Create temp directory
    local temp_dir
    temp_dir=$(mktemp_dir)
    trap 'rm -rf "${temp_dir:-}"' EXIT

    # Download consolidated checksums file (for verification)
    local wrapper_checksums_file="$temp_dir/checksums-wrapper.sha256"
    local core_checksums_file="$temp_dir/checksums-core.sha256"
    local wrapper_pubkey_file="$temp_dir/release-signing-wrapper.pem"
    local core_pubkey_file="$temp_dir/release-signing-core.pem"
    if [[ "${VERIFY:-}" == "1" ]]; then
        ensure_openssl_for_signatures || exit 1

        log_step "Resolving trusted public key..."
        if ! resolve_release_public_key "$version" "$wrapper_pubkey_file"; then
            log_error "Installation aborted: could not load trusted key for wrapper version v${version}"
            exit 1
        fi

        if [[ "$core_version" == "$version" ]]; then
            cp "$wrapper_pubkey_file" "$core_pubkey_file"
        else
            if ! resolve_release_public_key "$core_version" "$core_pubkey_file"; then
                log_error "Installation aborted: could not load trusted key for pt-core version v${core_version}"
                exit 1
            fi
        fi

        log_step "Downloading checksums..."
        if ! download_checksums "$version" "$wrapper_checksums_file"; then
            log_error "Installation aborted: wrapper checksums are required when VERIFY=1"
            exit 1
        fi
        log_success "Downloaded wrapper checksums.sha256"

        if [[ "$core_version" == "$version" ]]; then
            core_checksums_file="$wrapper_checksums_file"
        else
            if ! download_checksums "$core_version" "$core_checksums_file"; then
                log_error "Installation aborted: pt-core checksums are required when VERIFY=1"
                exit 1
            fi
            log_success "Downloaded pt-core checksums.sha256"
        fi
    fi

    # Download pt wrapper script
    log_step "Downloading pt wrapper..."
    local download_url
    local downloaded_wrapper=false
    local release_url="${RELEASES_URL}/download/v${version}/pt"
    local tag_url="https://raw.githubusercontent.com/${GITHUB_REPO}/v${version}/pt"
    local master_url="${RAW_URL}/pt"

    download_url=$(append_cache_buster "$release_url")
    if download "$download_url" "$temp_dir/pt"; then
        downloaded_wrapper=true
    else
        download_url=$(append_cache_buster "$tag_url")
        if download "$download_url" "$temp_dir/pt"; then
            downloaded_wrapper=true
        fi
    fi

    if [[ "$downloaded_wrapper" != "true" ]]; then
        if [[ "${VERIFY:-}" == "1" ]]; then
            log_error "Failed to download pt wrapper from release or tag with VERIFY=1."
            log_error "Refusing insecure fallback to master while verification is enabled."
            exit 1
        else
            log_warn "Falling back to master pt wrapper (unverified)."
        fi
        download_url=$(append_cache_buster "$master_url")
        download "$download_url" "$temp_dir/pt" || {
            log_error "Failed to download pt wrapper"
            exit 1
        }
    fi

    # Verify pt wrapper if requested
    if [[ "${VERIFY:-}" == "1" ]]; then
        if ! verify_file_signature \
            "$temp_dir/pt" \
            "pt" \
            "$version" \
            "$wrapper_pubkey_file" \
            "$temp_dir/pt.sig"; then
            log_error "Installation aborted: pt wrapper signature verification failed"
            exit 1
        fi

        if ! verify_file_checksum "$temp_dir/pt" "pt" "$wrapper_checksums_file"; then
            log_error "Installation aborted: pt wrapper checksum verification failed"
            exit 1
        fi
    fi

    # Download and verify pt-core
    local target
    local core_installed=false
    if target=$(detect_platform); then
        log_step "Downloading pt-core (${target})..."
        local archive_name="pt-core-${target}-${core_version}.tar.gz"
        local core_url="${RELEASES_URL}/download/v${core_version}/${archive_name}"
        local download_success=false

        if download "$core_url" "$temp_dir/$archive_name"; then
            download_success=true
        else
            # Try musl fallback for Linux glibc systems
            local musl_fallback
            musl_fallback=$(get_musl_fallback "$core_version" "$target")
            if [[ -n "$musl_fallback" ]]; then
                log_info "Trying musl static binary as fallback..."
                local musl_url="${RELEASES_URL}/download/v${core_version}/${musl_fallback}"
                if download "$musl_url" "$temp_dir/$musl_fallback"; then
                    archive_name="$musl_fallback"
                    download_success=true
                    log_success "Using musl static binary (works on any Linux)"
                fi
            fi
        fi

        if [[ "$download_success" == "true" ]]; then
            # Verify pt-core archive if requested
            if [[ "${VERIFY:-}" == "1" ]]; then
                if ! verify_file_signature \
                    "$temp_dir/$archive_name" \
                    "$archive_name" \
                    "$core_version" \
                    "$core_pubkey_file" \
                    "$temp_dir/${archive_name}.sig"; then
                    log_error "Installation aborted: pt-core signature verification failed"
                    exit 1
                fi

                if ! verify_file_checksum "$temp_dir/$archive_name" "$archive_name" "$core_checksums_file"; then
                    log_error "Installation aborted: pt-core checksum verification failed"
                    exit 1
                fi
            fi

            # Extract pt-core binary from archive
            if tar -xzf "$temp_dir/$archive_name" -C "$temp_dir" pt-core 2>/dev/null || \
               tar -xzf "$temp_dir/$archive_name" -C "$temp_dir" 2>/dev/null; then
                if [[ -f "$temp_dir/pt-core" ]]; then
                    if install_binary "$temp_dir/pt-core" "$dest" "pt-core"; then
                        core_installed=true
                    fi
                else
                    log_warn "pt-core binary not found in archive"
                fi
            else
                log_warn "Failed to extract pt-core from archive"
            fi
        else
            log_warn "Failed to download pt-core binary for $target"
            log_warn "You may need to build from source: cargo install --path crates/pt-core"
        fi
    else
        log_warn "Skipping pt-core (unsupported architecture)"
    fi

    # Install pt wrapper
    if ! install_binary "$temp_dir/pt" "$dest" "pt"; then
        log_error "Failed to install pt wrapper"
        exit 1
    fi

    # Add to PATH if needed and not disabled
    if [[ "${PT_NO_PATH:-}" != "1" ]]; then
        add_to_path "$dest"
    else
        log_info "Skipping PATH modification (PT_NO_PATH=1)"
        if [[ ":$PATH:" != *":$dest:"* ]]; then
            log_info "Add manually: export PATH=\"$dest:\$PATH\""
        fi
    fi

    echo ""
    log_success "pt v${version} installed successfully!"
    if [[ "$core_installed" == "true" ]]; then
        log_success "pt-core v${core_version} installed successfully!"
    else
        log_warn "pt-core was not installed. Some features may be unavailable."
        log_warn "To build from source: cargo install --path crates/pt-core"
    fi
    log_info "Run 'pt --help' to get started."
}

main "$@"
