#!/usr/bin/env bash
#
# install.sh - Process Triage (pt) Installer
#
# One-liner installation:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
#
# Environment variables:
#   DEST        - Custom install directory (default: ~/.local/bin)
#   PT_SYSTEM   - Set to 1 for system-wide install (/usr/local/bin)
#   PT_VERSION  - Install specific version (default: latest)
#   PT_NO_PATH  - Set to 1 to skip PATH modification
#   VERIFY      - Set to 1 to enable checksum verification
#
set -euo pipefail

readonly GITHUB_REPO="Dicklesworthstone/process_triage"
readonly RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
readonly RELEASES_URL="https://github.com/${GITHUB_REPO}/releases"

# ==============================================================================
# Self-Refresh: Re-download when piped to avoid CDN cache issues
# ==============================================================================

maybe_self_refresh() {
    # Only refresh if being piped AND not already refreshed
    if [[ -p /dev/stdin ]] && [[ -z "${PT_REFRESHED:-}" ]]; then
        export PT_REFRESHED=1
        # Re-execute with cache-busted URL
        exec bash <(curl -fsSL "${RAW_URL}/install.sh?cb=$(date +%s)")
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
    version=$(curl -fsSL --connect-timeout 5 "$version_url" 2>/dev/null | tr -d '[:space:]') || {
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

detect_arch() {
    local arch; arch=$(uname -m)
    local os; os=$(uname -s | tr '[:upper:]' '[:lower:]')

    case "$arch" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)
            return 1
            ;;
    esac

    case "$os" in
        linux) ;;
        darwin) os="macos" ;;
        *)
            return 1
            ;;
    esac

    echo "${os}-${arch}"
}

# ==============================================================================
# Verification (optional)
# ==============================================================================

# Download the consolidated checksums file from release
download_checksums() {
    local version="$1"
    local output="$2"

    local checksum_url="${RELEASES_URL}/download/v${version}/checksums.sha256"

    curl -fsSL --connect-timeout 5 "$checksum_url" -o "$output" 2>/dev/null || {
        log_warn "Could not download checksums file"
        log_warn "URL: $checksum_url"
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

    expected=$(curl -fsSL --connect-timeout 5 "$checksum_url" 2>/dev/null) || {
        log_warn "Could not download checksum file"
        log_warn "URL: $checksum_url"
        log_warn ""
        log_warn "Checksums may not be available for this version."
        log_warn "Proceeding without verification."
        return 0
    }

    # Extract hash (format: "hash  filename" or just "hash")
    expected="${expected%% *}"

    # Compute actual
    local actual
    actual=$(sha256_file "$file") || {
        log_warn "Could not compute checksum (no SHA256 tool)"
        log_warn "Skipping verification"
        return 0
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
        log_warn "No checksum found for ${filename}"
        log_warn "Proceeding without verification"
        return 0
    }

    if [[ -z "$expected" ]]; then
        log_warn "Checksum not found for ${filename}"
        return 0
    fi

    local actual
    actual=$(sha256_file "$file") || {
        log_warn "Could not compute checksum (no SHA256 tool)"
        return 0
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

# ==============================================================================
# Installation
# ==============================================================================

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

    # Check for existing installation
    local current_version=""
    if [[ -f "$dest_file" ]]; then
        if [[ "$binary_name" == "pt" ]]; then
            current_version=$(get_installed_version "$dest_file")
            if [[ -n "$current_version" && "$current_version" != "unknown" ]]; then
                log_info "Current $binary_name version: $current_version"
            fi
        fi
    fi

    # Copy file
    cp "$source_file" "$dest_file"
    chmod +x "$dest_file"

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

    # Create temp directory
    local temp_dir
    temp_dir=$(mktemp_dir)
    trap 'rm -rf "$temp_dir"' EXIT

    # Download pt script
    log_step "Downloading pt wrapper..."
    local download_url
    download_url=$(append_cache_buster "${RAW_URL}/pt")
    download "$download_url" "$temp_dir/pt" || {
        log_error "Failed to download pt"
        exit 1
    }

    # Verify if requested
    if ! verify_download "$temp_dir/pt" "$version"; then
        log_error "Installation aborted due to verification failure"
        exit 1
    fi

    # Download pt-core
    local target
    if target=$(detect_arch); then
        log_step "Downloading pt-core (${target})..."
        local core_url="${RELEASES_URL}/download/v${version}/pt-core-${target}"
        if download "$core_url" "$temp_dir/pt-core"; then
            install_binary "$temp_dir/pt-core" "$dest" "pt-core"
        else
            log_warn "Failed to download pt-core binary for $target"
            log_warn "You may need to install Rust and run: cargo install pt-core"
        fi
    else
        log_warn "Skipping pt-core (unsupported architecture)"
    fi

    # Install pt wrapper
    install_binary "$temp_dir/pt" "$dest" "pt"

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
    log_info "Run 'pt help' to get started."
}

main "$@"
