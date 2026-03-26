#!/usr/bin/env bash
#
# install.sh - Process Triage (pt) Installer
#
# One-line install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh?$(date +%s)" | bash
#
# One-line install (stable URL):
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
#
# Common options:
#   --version 2.0.5        Install a specific release
#   --dest ~/.local/bin    Install into a custom directory
#   --system               Install into /usr/local/bin
#   --easy-mode            Update shell PATH files automatically
#   --verify               Enforce checksum + signature verification
#   --from-source          Build pt-core from source
#   --offline FILE         Install from a local pt-core tarball
#                          Version inferred from bundle name or local VERSION file
#   --quiet                Suppress non-error output
#   --no-gum               Disable gum formatting
#   --force                Reinstall even if target version is already present
#   --no-configure         Skip agent auto-configuration and skill install
#   --emit-skill-payload   Print the canonical skill SKILL.md to stdout and exit
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-process_triage}"
GITHUB_REPO="${OWNER}/${REPO}"
RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
RELEASES_URL="https://github.com/${GITHUB_REPO}/releases"
API_URL="https://api.github.com/repos/${GITHUB_REPO}"

DEST_DEFAULT="$HOME/.local/bin"
DEST="${DEST:-$DEST_DEFAULT}"
VERSION="${PT_VERSION:-}"
CORE_VERSION="${PT_CORE_VERSION:-}"
SYSTEM=0
EASY_MODE=0
QUIET=0
NO_GUM=0
FORCE_INSTALL=0
FROM_SOURCE=0
VERIFY=0
NO_CONFIGURE=0
NO_VERIFY=0
VERIFY_SELF=0
EMIT_SKILL_PAYLOAD=0
OFFLINE_BUNDLE=""
LOCK_ROOT="/tmp/pt-install.lock.d"
LOCK_HELD=0
TEMP_DIR=""
HAS_GUM=0
WSL=0
OS=""
ARCH=""
TARGET=""
PLATFORM=""
PROXY_ARGS=()
DOWNLOADED_ARTIFACT=""
INSTALLED_WRAPPER_VERSION=""
INSTALLED_CORE_VERSION=""
SUMMARY_LINES=()
AGENT_LINES=()
BACKUP_LINES=()

CLAUDE_STATUS="skipped"
CODEX_STATUS="skipped"
COPILOT_STATUS="skipped"
CURSOR_STATUS="skipped"
WINDSURF_STATUS="skipped"
GEMINI_STATUS="skipped"
CLAUDE_SKILL_STATUS="skipped"
CODEX_SKILL_STATUS="skipped"

DEFAULT_RELEASE_PUBLIC_KEY_FINGERPRINT=""

strip_ansi() {
    sed $'s/\033\\[[0-9;]*m//g'
}

detect_gum() {
    if command -v gum >/dev/null 2>&1 && [[ -t 1 ]] && [[ "$NO_GUM" -eq 0 ]]; then
        HAS_GUM=1
    fi
}

info() {
    [[ "$QUIET" -eq 1 ]] && return 0
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style --foreground 39 "→ $*"
    else
        printf '\033[0;34m→\033[0m %s\n' "$*"
    fi
}

ok() {
    [[ "$QUIET" -eq 1 ]] && return 0
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style --foreground 42 "✓ $*"
    else
        printf '\033[0;32m✓\033[0m %s\n' "$*"
    fi
}

warn() {
    [[ "$QUIET" -eq 1 ]] && return 0
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style --foreground 214 "⚠ $*"
    else
        printf '\033[1;33m⚠\033[0m %s\n' "$*"
    fi
}

err() {
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style --foreground 196 "✗ $*" >&2
    else
        printf '\033[0;31m✗\033[0m %s\n' "$*" >&2
    fi
}

run_with_spinner() {
    local title="$1"
    shift
    if [[ "$HAS_GUM" -eq 1 && "$QUIET" -eq 0 ]]; then
        gum spin --spinner dot --title "$title" -- "$@"
    else
        info "$title"
        "$@"
    fi
}

draw_box() {
    local color="$1"
    shift
    local lines=("$@")
    local max_width=0
    local line stripped len pad

    for line in "${lines[@]}"; do
        stripped=$(printf '%b' "$line" | strip_ansi)
        len=${#stripped}
        [[ "$len" -gt "$max_width" ]] && max_width="$len"
    done

    local border=""
    local inner_width=$((max_width + 4))
    local i
    for ((i = 0; i < inner_width; i++)); do
        border+="═"
    done

    printf "\033[%sm╔%s╗\033[0m\n" "$color" "$border"
    for line in "${lines[@]}"; do
        stripped=$(printf '%b' "$line" | strip_ansi)
        len=${#stripped}
        pad=$((max_width - len))
        printf "\033[%sm║\033[0m  %b%*s  \033[%sm║\033[0m\n" "$color" "$line" "$pad" "" "$color"
    done
    printf "\033[%sm╚%s╝\033[0m\n" "$color" "$border"
}

show_header() {
    [[ "$QUIET" -eq 1 ]] && return 0
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style \
            --border normal \
            --border-foreground 39 \
            --padding "0 1" \
            --margin "1 0" \
            "$(gum style --foreground 42 --bold 'pt installer')" \
            "$(gum style --foreground 245 'Safety-first process triage with signed releases and agent integration')"
    else
        echo ""
        draw_box "0;36" \
            "\033[1;32mpt installer\033[0m" \
            "Safety-first process triage with signed releases and agent integration"
        echo ""
    fi
}

usage() {
    cat <<'EOF'
Process Triage installer

Usage:
  bash install.sh [options]

Options:
  --version <ver>      Install a specific version
  --dest <dir>         Install directory (default: ~/.local/bin)
  --system             Install to /usr/local/bin
  --easy-mode          Update shell PATH files automatically
  --verify             Require checksum + signature verification
  --verify-self        Run post-install diagnostics
  --from-source        Build pt-core from source
  --offline <file>     Install pt-core from a local tarball
                       Version inferred from bundle name or local VERSION file
  --force              Reinstall even if already at target version
  --quiet              Suppress non-error output
  --no-gum             Disable gum formatting
  --no-configure       Skip agent init + skill install
  --no-verify          Disable checksum/signature verification
  --emit-skill-payload Print the canonical skill SKILL.md to stdout and exit
  -h, --help           Show help

Environment:
  PT_VERSION                              Version override
  PT_CORE_VERSION                         pt-core version override
  PT_SYSTEM=1                             System install shortcut
  PT_NO_PATH=1                            Skip PATH updates
  VERIFY=1                                Require verification
  PT_RELEASE_PUBLIC_KEY_FILE              PEM file for release verification
  PT_RELEASE_PUBLIC_KEY_PEM               PEM contents for release verification
  PT_RELEASE_PUBLIC_KEY_FINGERPRINT       Expected SHA-256 fingerprint
  PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE  File containing expected fingerprint
  HTTP_PROXY / HTTPS_PROXY / NO_PROXY     Proxy support
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                [[ -n "${2:-}" ]] || { err "--version requires a value"; exit 1; }
                VERSION="$2"
                shift 2
                ;;
            --dest)
                [[ -n "${2:-}" ]] || { err "--dest requires a value"; exit 1; }
                DEST="$2"
                shift 2
                ;;
            --system)
                SYSTEM=1
                shift
                ;;
            --easy-mode)
                EASY_MODE=1
                shift
                ;;
            --verify)
                VERIFY=1
                shift
                ;;
            --verify-self)
                VERIFY_SELF=1
                shift
                ;;
            --from-source)
                FROM_SOURCE=1
                shift
                ;;
            --offline)
                [[ -n "${2:-}" ]] || { err "--offline requires a file path"; exit 1; }
                OFFLINE_BUNDLE="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL=1
                shift
                ;;
            --quiet)
                QUIET=1
                shift
                ;;
            --no-gum)
                NO_GUM=1
                shift
                ;;
            --no-configure)
                NO_CONFIGURE=1
                shift
                ;;
            --no-verify)
                NO_VERIFY=1
                shift
                ;;
            --emit-skill-payload)
                EMIT_SKILL_PAYLOAD=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ "${PT_SYSTEM:-0}" == "1" ]]; then
        SYSTEM=1
    fi
    if [[ "${VERIFY:-0}" == "1" ]]; then
        VERIFY=1
    fi
    if [[ "$NO_VERIFY" -eq 1 ]]; then
        VERIFY=0
    fi
}

setup_proxy() {
    PROXY_ARGS=()
    if [[ -n "${HTTPS_PROXY:-}" ]]; then
        PROXY_ARGS=(--proxy "$HTTPS_PROXY")
    elif [[ -n "${HTTP_PROXY:-}" ]]; then
        PROXY_ARGS=(--proxy "$HTTP_PROXY")
    fi
}

fetch_stdout() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 10 --max-time 120 "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O - "$url"
    else
        err "Neither curl nor wget is available"
        return 1
    fi
}

download() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 10 --max-time 120 "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
    else
        err "Neither curl nor wget is available"
        return 1
    fi
}

append_cache_buster() {
    local url="$1"
    local ts
    ts=$(date +%s)
    if [[ "$url" == *"?"* ]]; then
        printf '%s&cb=%s\n' "$url" "$ts"
    else
        printf '%s?cb=%s\n' "$url" "$ts"
    fi
}

infer_version_from_text() {
    local text="$1"
    if [[ "$text" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

infer_version_from_offline_bundle() {
    local bundle_path="$1"
    infer_version_from_text "$(basename "$bundle_path")"
}

resolve_local_version_file() {
    local candidate=""

    if [[ -f "./VERSION" ]]; then
        candidate="$(tr -d '[:space:]' < ./VERSION)"
        infer_version_from_text "$candidate" && return 0
    fi

    if [[ -f "$(dirname "$0")/VERSION" ]]; then
        candidate="$(tr -d '[:space:]' < "$(dirname "$0")/VERSION")"
        infer_version_from_text "$candidate" && return 0
    fi

    return 1
}

copy_local_verification_file() {
    local output="$1"
    shift
    local candidate
    for candidate in "$@"; do
        [[ -n "$candidate" && -f "$candidate" ]] || continue
        cp "$candidate" "$output"
        return 0
    done
    return 1
}

prepare_offline_release_public_key() {
    local output="$1"
    local script_dir
    script_dir="$(dirname "$0")"

    if [[ -n "${PT_RELEASE_PUBLIC_KEY_FILE:-}" ]]; then
        cp "${PT_RELEASE_PUBLIC_KEY_FILE}" "$output"
    elif [[ -n "${PT_RELEASE_PUBLIC_KEY_PEM:-}" ]]; then
        printf '%s\n' "${PT_RELEASE_PUBLIC_KEY_PEM}" > "$output"
    elif ! copy_local_verification_file \
        "$output" \
        "./release-signing-public.pem" \
        "${script_dir}/release-signing-public.pem" \
        "$(dirname "$OFFLINE_BUNDLE")/release-signing-public.pem"; then
        err "Offline verification requires a local release-signing-public.pem"
        err "Provide PT_RELEASE_PUBLIC_KEY_FILE/PT_RELEASE_PUBLIC_KEY_PEM or place the PEM beside install.sh, the current directory, or the offline bundle"
        return 1
    fi

    openssl pkey -pubin -in "$output" -noout >/dev/null 2>&1 || {
        err "Invalid release public key PEM"
        return 1
    }

    local expected actual
    expected="$(resolve_expected_key_fingerprint || true)"
    if [[ -n "$expected" ]]; then
        actual="$(openssl pkey -pubin -in "$output" -outform der 2>/dev/null | sha256_stdin)"
        actual="$(normalize_fingerprint "$actual")"
        if [[ "$actual" != "$expected" ]]; then
            err "Release public key fingerprint mismatch"
            return 1
        fi
        ok "Release public key fingerprint verified: ${actual:0:16}..."
    else
        warn "No release public key fingerprint pin configured"
    fi
}

prepare_offline_checksums() {
    local output="$1"
    local script_dir
    script_dir="$(dirname "$0")"

    if ! copy_local_verification_file \
        "$output" \
        "./checksums.sha256" \
        "${script_dir}/checksums.sha256" \
        "$(dirname "$OFFLINE_BUNDLE")/checksums.sha256"; then
        err "Offline verification requires a local checksums.sha256"
        err "Place checksums.sha256 beside install.sh, the current directory, or the offline bundle"
        return 1
    fi
}

verify_file_signature_offline() {
    local file_path="$1"
    local artifact_name="$2"
    local pubkey_file="$3"
    local sig_output="$4"
    shift 4

    copy_local_verification_file "$sig_output" "$@" || {
        err "Offline verification requires a local signature for ${artifact_name}"
        return 1
    }

    if openssl dgst -sha256 -verify "$pubkey_file" -signature "$sig_output" "$file_path" >/dev/null 2>&1; then
        ok "${artifact_name} signature verified"
        return 0
    fi
    err "Signature verification failed for ${artifact_name}"
    return 1
}

cleanup() {
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    if [[ "$LOCK_HELD" -eq 1 && -d "$LOCK_ROOT" ]]; then
        rm -rf "$LOCK_ROOT"
    fi
}

create_temp_dir() {
    TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t pt.XXXXXXXX 2>/dev/null)"
    if [[ -z "$TEMP_DIR" || ! -d "$TEMP_DIR" ]]; then
        err "Failed to create temporary directory"
        exit 1
    fi
    trap cleanup EXIT
}

maybe_self_refresh() {
    if [[ -p /dev/stdin && -z "${PT_REFRESHED:-}" && -z "$OFFLINE_BUNDLE" ]]; then
        export PT_REFRESHED=1
        exec bash <(fetch_stdout "$(append_cache_buster "${RAW_URL}/install.sh")") "$@"
    fi
}

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        arm64|aarch64) ARCH="aarch64" ;;
        *)
            err "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    if [[ "$OS" == "linux" && -f /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        WSL=1
        warn "WSL detected; continuing with Linux install"
    fi

    case "$OS" in
        linux)
            if [[ -f /etc/alpine-release ]] || (command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl); then
                PLATFORM="linux-${ARCH}-musl"
            else
                PLATFORM="linux-${ARCH}"
            fi
            ;;
        darwin)
            PLATFORM="macos-${ARCH}"
            ;;
        *)
            err "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case "$PLATFORM" in
        linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
        linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
        linux-x86_64-musl) TARGET="x86_64-unknown-linux-musl" ;;
        linux-aarch64-musl) TARGET="aarch64-unknown-linux-musl" ;;
        macos-x86_64) TARGET="x86_64-apple-darwin" ;;
        macos-aarch64) TARGET="aarch64-apple-darwin" ;;
        *)
            warn "No prebuilt for ${PLATFORM}; will fall back to source"
            FROM_SOURCE=1
            ;;
    esac
}

resolve_version() {
    if [[ -n "$VERSION" ]]; then
        return 0
    fi

    if [[ -n "$OFFLINE_BUNDLE" ]]; then
        VERSION="$(infer_version_from_offline_bundle "$OFFLINE_BUNDLE" || true)"
        if [[ -z "$VERSION" ]]; then
            VERSION="$(resolve_local_version_file || true)"
        fi
        if [[ -z "$VERSION" ]]; then
            err "Offline mode requires --version or a versioned bundle filename"
            err "Example: pt-core-linux-x86_64-2.0.5.tar.gz"
            exit 1
        fi
        return 0
    fi

    local latest=""
    latest="$(fetch_stdout "${API_URL}/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null || true)"
    latest="${latest#v}"
    if [[ -z "$latest" ]]; then
        latest="$(
            curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 10 --max-time 20 -o /dev/null -w '%{url_effective}' \
                "${RELEASES_URL}/latest" 2>/dev/null \
                | sed -E 's|.*/tag/v?([0-9]+\.[0-9]+\.[0-9]+)$|\1|' \
                || true
        )"
    fi
    if [[ -z "$latest" ]]; then
        latest="$(fetch_stdout "$(append_cache_buster "${RAW_URL}/VERSION")" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$latest" ]]; then
        err "Could not resolve latest version"
        exit 1
    fi
    VERSION="$latest"
}

resolve_core_version() {
    if [[ -z "$CORE_VERSION" ]]; then
        CORE_VERSION="$VERSION"
    fi
}

artifact_name_for_platform() {
    local version="$1"
    local platform="$2"
    printf 'pt-core-%s-%s.tar.gz\n' "$platform" "$version"
}

wrapper_urls() {
    printf '%s\n' \
        "${RELEASES_URL}/download/v${VERSION}/pt" \
        "https://raw.githubusercontent.com/${GITHUB_REPO}/v${VERSION}/pt" \
        "${RAW_URL}/pt"
}

core_urls() {
    local artifact
    artifact="$(artifact_name_for_platform "$CORE_VERSION" "$PLATFORM")"
    printf '%s\n' \
        "${RELEASES_URL}/download/v${CORE_VERSION}/${artifact}"
    if [[ "$PLATFORM" == linux-x86_64 ]]; then
        printf '%s\n' "${RELEASES_URL}/download/v${CORE_VERSION}/pt-core-linux-x86_64-musl-${CORE_VERSION}.tar.gz"
    elif [[ "$PLATFORM" == linux-aarch64 ]]; then
        printf '%s\n' "${RELEASES_URL}/download/v${CORE_VERSION}/pt-core-linux-aarch64-musl-${CORE_VERSION}.tar.gz"
    fi
}

download_first_available() {
    local output="$1"
    shift
    local url
    for url in "$@"; do
        [[ -z "$url" ]] && continue
        if download "$url" "$output" 2>/dev/null; then
            DOWNLOADED_ARTIFACT="$(basename "$url")"
            return 0
        fi
    done
    return 1
}

check_disk_space() {
    local install_parent
    install_parent="$(dirname "$DEST")"
    mkdir -p "$install_parent"
    local available
    available=$(df -Pk "$install_parent" | awk 'NR==2 {print $4}')
    if [[ -n "$available" && "$available" -lt 10240 ]]; then
        err "At least 10MB of free space is required in $install_parent"
        exit 1
    fi
}

check_write_permissions() {
    local install_parent
    install_parent="$(dirname "$DEST")"
    mkdir -p "$install_parent"
    if [[ ! -w "$install_parent" ]] && [[ "$SYSTEM" -eq 0 ]]; then
        err "Install directory is not writable: $install_parent"
        exit 1
    fi
}

check_network() {
    if [[ -n "$OFFLINE_BUNDLE" || "$FROM_SOURCE" -eq 1 ]]; then
        info "Skipping network preflight"
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        warn "curl not found; skipping network preflight"
        return 0
    fi
    local url
    url="${RELEASES_URL}/download/v${VERSION}/pt"
    if ! curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 3 --max-time 5 -o /dev/null "$url"; then
        warn "Network preflight failed for $url"
    fi
}

get_installed_version() {
    local bin="$1"
    [[ -x "$bin" ]] || return 0
    "$bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

check_existing_install() {
    INSTALLED_WRAPPER_VERSION="$(get_installed_version "$DEST/pt")"
    INSTALLED_CORE_VERSION="$(get_installed_version "$DEST/pt-core")"
    if [[ -n "$INSTALLED_WRAPPER_VERSION" ]]; then
        info "Existing pt version: ${INSTALLED_WRAPPER_VERSION}"
    fi
    if [[ -n "$INSTALLED_CORE_VERSION" ]]; then
        info "Existing pt-core version: ${INSTALLED_CORE_VERSION}"
    fi
}

preflight_checks() {
    info "Running preflight checks"
    check_disk_space
    check_write_permissions
    check_existing_install
    check_network
}

acquire_lock() {
    if mkdir "$LOCK_ROOT" 2>/dev/null; then
        LOCK_HELD=1
        printf '%s\n' "$$" > "${LOCK_ROOT}/pid"
        return 0
    fi

    if [[ -f "${LOCK_ROOT}/pid" ]]; then
        local existing_pid
        existing_pid="$(cat "${LOCK_ROOT}/pid" 2>/dev/null || true)"
        if [[ -n "$existing_pid" ]] && ! kill -0 "$existing_pid" 2>/dev/null; then
            rm -rf "$LOCK_ROOT"
            if mkdir "$LOCK_ROOT" 2>/dev/null; then
                LOCK_HELD=1
                printf '%s\n' "$$" > "${LOCK_ROOT}/pid"
                return 0
            fi
            # Another process grabbed the lock between rm and mkdir
        fi
    fi

    err "Another pt installer appears to be running (${LOCK_ROOT})"
    exit 1
}

sha256_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        return 1
    fi
}

sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 | awk '{print $NF}'
    else
        return 1
    fi
}

normalize_fingerprint() {
    local value="$1"
    value="${value//[[:space:]]/}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    [[ "$value" =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s\n' "$value"
}

resolve_expected_key_fingerprint() {
    local expected=""
    if [[ -n "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT:-}" ]]; then
        expected="$PT_RELEASE_PUBLIC_KEY_FINGERPRINT"
    elif [[ -n "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE:-}" && -f "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE}" ]]; then
        expected="$(head -n1 "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE}" | awk '{print $1}')"
    elif [[ -n "$DEFAULT_RELEASE_PUBLIC_KEY_FINGERPRINT" ]]; then
        expected="$DEFAULT_RELEASE_PUBLIC_KEY_FINGERPRINT"
    fi

    [[ -z "$expected" ]] && return 0
    normalize_fingerprint "$expected"
}

resolve_release_public_key() {
    local version="$1"
    local output="$2"

    if [[ -n "${PT_RELEASE_PUBLIC_KEY_FILE:-}" ]]; then
        cp "${PT_RELEASE_PUBLIC_KEY_FILE}" "$output"
    elif [[ -n "${PT_RELEASE_PUBLIC_KEY_PEM:-}" ]]; then
        printf '%s\n' "${PT_RELEASE_PUBLIC_KEY_PEM}" > "$output"
    elif ! download "${RELEASES_URL}/download/v${version}/release-signing-public.pem" "$output" 2>/dev/null; then
        err "Release v${version} does not publish release-signing-public.pem"
        err "Use PT_RELEASE_PUBLIC_KEY_FILE/PT_RELEASE_PUBLIC_KEY_PEM or install without --verify"
        return 1
    fi

    openssl pkey -pubin -in "$output" -noout >/dev/null 2>&1 || {
        err "Invalid release public key PEM"
        return 1
    }

    local expected actual
    expected="$(resolve_expected_key_fingerprint || true)"
    if [[ -n "$expected" ]]; then
        actual="$(openssl pkey -pubin -in "$output" -outform der 2>/dev/null | sha256_stdin)"
        actual="$(normalize_fingerprint "$actual")"
        if [[ "$actual" != "$expected" ]]; then
            err "Release public key fingerprint mismatch"
            return 1
        fi
        ok "Release public key fingerprint verified: ${actual:0:16}..."
    else
        warn "No release public key fingerprint pin configured"
    fi
}

download_checksums() {
    local version="$1"
    local output="$2"
    if ! download "${RELEASES_URL}/download/v${version}/checksums.sha256" "$output" 2>/dev/null; then
        err "Release v${version} does not publish checksums.sha256"
        err "Install without --verify or provide local verification materials in offline mode"
        return 1
    fi
}

lookup_checksum() {
    local checksums_file="$1"
    local filename="$2"
    grep -E "^[a-f0-9]{64}  ${filename}$" "$checksums_file" | awk '{print $1}'
}

verify_file_checksum() {
    local file="$1"
    local filename="$2"
    local checksums_file="$3"
    local expected actual

    expected="$(lookup_checksum "$checksums_file" "$filename" || true)"
    [[ -n "$expected" ]] || {
        err "No checksum found for ${filename}"
        return 1
    }
    actual="$(sha256_file "$file")" || {
        err "Could not compute checksum"
        return 1
    }
    if [[ "$actual" != "$expected" ]]; then
        err "Checksum mismatch for ${filename}"
        err "Expected: $expected"
        err "Actual:   $actual"
        return 1
    fi
    ok "${filename} checksum verified: ${actual:0:16}..."
}

verify_file_signature() {
    local file_path="$1"
    local artifact_name="$2"
    local version="$3"
    local pubkey_file="$4"
    local sig_output="$5"

    if ! download "${RELEASES_URL}/download/v${version}/${artifact_name}.sig" "$sig_output" 2>/dev/null; then
        err "Release v${version} does not publish ${artifact_name}.sig"
        err "Install without --verify or publish the matching signature sidecar"
        return 1
    fi
    if openssl dgst -sha256 -verify "$pubkey_file" -signature "$sig_output" "$file_path" >/dev/null 2>&1; then
        ok "${artifact_name} signature verified"
        return 0
    fi
    err "Signature verification failed for ${artifact_name}"
    return 1
}

best_effort_sigstore_verify() {
    local file_path="$1"
    local artifact_name="$2"
    if ! command -v cosign >/dev/null 2>&1; then
        warn "cosign not found; skipping Sigstore verification for ${artifact_name}"
        return 0
    fi
    warn "No Sigstore bundle published for ${artifact_name}; skipping cosign verification"
}

install_binary() {
    local source_file="$1"
    local dest_dir="$2"
    local binary_name="$3"
    local backup_file=""
    local dest_file="${dest_dir}/${binary_name}"
    local temp_dest="${dest_file}.new"

    mkdir -p "$dest_dir"
    if [[ -f "$dest_file" ]]; then
        backup_file="${dest_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$dest_file" "$backup_file"
        BACKUP_LINES+=("${binary_name} backup: ${backup_file}")
    fi

    install -m 0755 "$source_file" "$temp_dest"
    mv "$temp_dest" "$dest_file"
    ok "Installed ${dest_file}"
}

extract_core_archive() {
    local archive="$1"
    local extract_dir="$2"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir" pt-core 2>/dev/null || tar -xzf "$archive" -C "$extract_dir"
}

path_line_for_shell() {
    local install_dir="$1"
    local shell_name="$2"
    case "$shell_name" in
        fish)
            printf 'if not contains "%s" $PATH\n    set -gx PATH "%s" $PATH\nend\n' "$install_dir" "$install_dir"
            ;;
        *)
            printf 'case ":$PATH:" in\n  *:"%s":*) ;;\n  *) export PATH="%s:$PATH" ;;\nesac\n' "$install_dir" "$install_dir"
            ;;
    esac
}

append_path_snippet() {
    local file="$1"
    local shell_name="$2"
    local install_dir="$3"
    local marker="# process_triage installer PATH"

    [[ -f "$file" ]] || : > "$file"
    if grep -Fq "$marker" "$file" 2>/dev/null; then
        return 0
    fi

    {
        printf '\n%s\n' "$marker"
        path_line_for_shell "$install_dir" "$shell_name"
    } >> "$file"
}

maybe_add_path() {
    local install_dir="$1"

    if [[ "${PT_NO_PATH:-0}" == "1" ]]; then
        info "Skipping PATH changes (PT_NO_PATH=1)"
        return 0
    fi

    if [[ ":$PATH:" == *":${install_dir}:"* ]]; then
        info "${install_dir} already in PATH"
        return 0
    fi

    if [[ "$EASY_MODE" -eq 1 ]]; then
        append_path_snippet "$HOME/.zshenv" "zsh" "$install_dir"
        append_path_snippet "$HOME/.profile" "sh" "$install_dir"
        append_path_snippet "$HOME/.bashrc" "bash" "$install_dir"
        ok "Added ${install_dir} to shell PATH config"
    else
        warn "Add ${install_dir} to PATH to use pt"
        warn "Hint: run with --easy-mode to update your shell rc files"
    fi
}

install_completions_for_shell() {
    local shell_name="$1"
    local target=""
    case "$shell_name" in
        bash)
            target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/pt"
            ;;
        zsh)
            target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_pt"
            ;;
        fish)
            target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/pt.fish"
            ;;
        *)
            return 0
            ;;
    esac
    mkdir -p "$(dirname "$target")"
    "$DEST/pt" completions "$shell_name" > "$target"
    ok "Installed ${shell_name} completions"
}

maybe_install_completions() {
    [[ -x "$DEST/pt" ]] || return 0
    install_completions_for_shell "bash" || true
    install_completions_for_shell "zsh" || true
    install_completions_for_shell "fish" || true
}

agent_present() {
    local agent="$1"
    case "$agent" in
        claude)
            [[ -d "$HOME/.claude" ]] || command -v claude >/dev/null 2>&1
            ;;
        codex)
            [[ -d "$HOME/.codex" ]] || command -v codex >/dev/null 2>&1
            ;;
        copilot)
            command -v copilot >/dev/null 2>&1
            ;;
        cursor)
            [[ -d "$HOME/.cursor" ]] || [[ -d "$HOME/.config/Cursor" ]] || [[ -d "$HOME/Library/Application Support/Cursor" ]]
            ;;
        windsurf)
            [[ -d "$HOME/.codeium/windsurf" ]] || [[ -d "$HOME/.config/Windsurf" ]]
            ;;
        gemini)
            [[ -d "$HOME/.gemini" ]] || command -v gemini >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

run_agent_init_for() {
    local agent="$1"
    local status_var="$2"
    if ! agent_present "$agent"; then
        printf -v "$status_var" '%s' "skipped"
        return 0
    fi
    if "$DEST/pt-core" agent init --yes --agent "$agent" --format summary >/dev/null 2>&1; then
        printf -v "$status_var" '%s' "configured"
    else
        printf -v "$status_var" '%s' "failed"
    fi
}

skill_payload() {
    cat <<'EOF'
---
name: process-triage
description: >-
  Triage system processes with the `pt` wrapper and choose safe remediation.
  Use when diagnosing runaway processes, comparing `pt scan` and `pt deep-scan`,
  or using `pt agent` plan/apply workflows.
---

# process-triage

Use `pt` as the user-facing command and `pt help` for wrapper-aware help.

Core workflows:
- `pt scan --format json`
- `pt deep-scan --format json`
- `pt agent plan`
- `pt agent explain`
- `pt agent apply`

Safety:
- Never kill automatically without explicit user approval
- Prefer `pt agent` over legacy `pt robot`
- Use structured output for agent automation
EOF
}

install_skill_dir() {
    local base_dir="$1"
    local status_var="$2"
    local skill_dir="${base_dir}/process-triage"

    mkdir -p "$skill_dir"
    skill_payload > "${skill_dir}/SKILL.md"
    printf -v "$status_var" '%s' "inline"
}

maybe_configure_agents() {
    if [[ "$NO_CONFIGURE" -eq 1 || ! -x "$DEST/pt-core" ]]; then
        return 0
    fi

    run_agent_init_for "claude" CLAUDE_STATUS
    run_agent_init_for "codex" CODEX_STATUS
    run_agent_init_for "copilot" COPILOT_STATUS
    run_agent_init_for "cursor" CURSOR_STATUS
    run_agent_init_for "windsurf" WINDSURF_STATUS
    if agent_present "gemini"; then
        GEMINI_STATUS="unsupported"
    fi

    if [[ -d "$HOME/.claude" || "$CLAUDE_STATUS" == "configured" ]]; then
        install_skill_dir "$HOME/.claude/skills" CLAUDE_SKILL_STATUS
    fi
    if [[ -d "$HOME/.codex" || "$CODEX_STATUS" == "configured" ]]; then
        install_skill_dir "$HOME/.codex/skills" CODEX_SKILL_STATUS
    fi
}

maybe_build_from_source() {
    local source_dir="${TEMP_DIR}/src"
    local git_ref="v${VERSION}"
    local wrapper_path="${TEMP_DIR}/pt"
    local core_path="${TEMP_DIR}/pt-core"

    command -v git >/dev/null 2>&1 || {
        err "git is required for --from-source"
        exit 1
    }
    command -v cargo >/dev/null 2>&1 || {
        err "cargo is required for --from-source"
        exit 1
    }

    run_with_spinner "Cloning source" git clone --depth 1 --branch "$git_ref" "https://github.com/${GITHUB_REPO}.git" "$source_dir"
    run_with_spinner "Building pt-core from source" bash -lc "cd '$source_dir' && cargo build --release -p pt-core"

    cp "${source_dir}/pt" "$wrapper_path"
    cp "${source_dir}/target/release/pt-core" "$core_path"
}

verify_existing_install_short_circuit() {
    if [[ "$FORCE_INSTALL" -eq 1 ]]; then
        return 1
    fi
    if [[ "${INSTALLED_WRAPPER_VERSION:-}" == "$VERSION" && "${INSTALLED_CORE_VERSION:-}" == "$CORE_VERSION" ]]; then
        ok "pt ${VERSION} is already installed"
        maybe_add_path "$DEST"
        maybe_install_completions
        maybe_configure_agents
        if [[ "$VERIFY_SELF" -eq 1 ]]; then
            "$DEST/pt" --version >/dev/null
            "$DEST/pt" scan --format json >/dev/null 2>/dev/null || true
        fi
        show_final_summary
        exit 0
    fi
    return 1
}

prepare_release_verification() {
    local version="$1"
    local pubkey_file="$2"
    local checksums_file="$3"

    resolve_release_public_key "$version" "$pubkey_file"
    download_checksums "$version" "$checksums_file"
}

prepare_offline_verification() {
    local wrapper_source="$1"
    local core_bundle="$2"
    local wrapper_sig_output="$3"
    local core_sig_output="$4"
    local wrapper_name
    local core_name
    local script_dir
    script_dir="$(dirname "$0")"
    wrapper_name="$(basename "$wrapper_source")"
    core_name="$(basename "$core_bundle")"

    prepare_offline_release_public_key "$wrapper_pubkey"
    cp "$wrapper_pubkey" "$core_pubkey"
    prepare_offline_checksums "$wrapper_checksums"
    cp "$wrapper_checksums" "$core_checksums"

    verify_file_signature_offline \
        "$wrapper_source" \
        "$wrapper_name" \
        "$wrapper_pubkey" \
        "$wrapper_sig_output" \
        "./${wrapper_name}.sig" \
        "${script_dir}/${wrapper_name}.sig" \
        "$(dirname "$wrapper_source")/${wrapper_name}.sig"

    verify_file_signature_offline \
        "$core_bundle" \
        "$core_name" \
        "$core_pubkey" \
        "$core_sig_output" \
        "${core_bundle}.sig" \
        "$(dirname "$core_bundle")/${core_name}.sig"
}

download_wrapper() {
    local output="$1"
    local urls=()
    mapfile -t urls < <(wrapper_urls)
    download_first_available "$output" "${urls[@]}" || {
        err "Failed to download pt wrapper"
        exit 1
    }
}

download_core_archive() {
    local output="$1"
    local urls=()
    mapfile -t urls < <(core_urls)
    download_first_available "$output" "${urls[@]}" || return 1
    return 0
}

show_agent_scan_notice() {
    [[ "$NO_CONFIGURE" -eq 1 || "$QUIET" -eq 1 ]] && return 0
    if [[ "$HAS_GUM" -eq 1 ]]; then
        gum style \
            --border normal \
            --border-foreground 244 \
            --padding "0 1" \
            "$(gum style --foreground 212 --bold 'Agent scan')" \
            "$(gum style --foreground 247 'Looking for installed coding agents and optional skills')"
    else
        draw_box "0;36" \
            "Agent scan" \
            "Looking for installed coding agents and optional skills"
    fi
}

show_final_summary() {
    local lines=(
        "Installed pt ${VERSION} to ${DEST}"
        "Installed pt-core ${CORE_VERSION} to ${DEST}"
    )

    [[ "$CLAUDE_STATUS" != "skipped" ]] && AGENT_LINES+=("Claude Code: ${CLAUDE_STATUS}")
    [[ "$CODEX_STATUS" != "skipped" ]] && AGENT_LINES+=("Codex CLI: ${CODEX_STATUS}")
    [[ "$COPILOT_STATUS" != "skipped" ]] && AGENT_LINES+=("GitHub Copilot CLI: ${COPILOT_STATUS}")
    [[ "$CURSOR_STATUS" != "skipped" ]] && AGENT_LINES+=("Cursor: ${CURSOR_STATUS}")
    [[ "$WINDSURF_STATUS" != "skipped" ]] && AGENT_LINES+=("Windsurf: ${WINDSURF_STATUS}")
    [[ "$GEMINI_STATUS" != "skipped" ]] && AGENT_LINES+=("Gemini CLI: ${GEMINI_STATUS}")
    [[ "$CLAUDE_SKILL_STATUS" != "skipped" ]] && AGENT_LINES+=("Claude skill: ${CLAUDE_SKILL_STATUS}")
    [[ "$CODEX_SKILL_STATUS" != "skipped" ]] && AGENT_LINES+=("Codex skill: ${CODEX_SKILL_STATUS}")

    lines+=("${AGENT_LINES[@]}")
    lines+=("${BACKUP_LINES[@]}")
    lines+=("Run: pt --help")
    lines+=("Uninstall: rm -f ${DEST}/pt ${DEST}/pt-core")
    lines+=("If you enabled PATH updates, remove the '# process_triage installer PATH' block from your shell files to revert them.")

    echo ""
    if [[ "$HAS_GUM" -eq 1 && "$QUIET" -eq 0 ]]; then
        gum style --border double --border-foreground 42 --padding "1 2" "${lines[@]}"
    else
        draw_box "0;32" "${lines[@]}"
    fi
}

main() {
    parse_args "$@"
    if [[ "$EMIT_SKILL_PAYLOAD" -eq 1 ]]; then
        skill_payload
        return 0
    fi
    setup_proxy
    detect_gum
    maybe_self_refresh "$@"
    show_header

    if [[ "$SYSTEM" -eq 1 ]]; then
        DEST="/usr/local/bin"
    fi

    detect_platform
    resolve_version
    resolve_core_version
    create_temp_dir
    preflight_checks
    if verify_existing_install_short_circuit; then
        return 0
    fi
    acquire_lock

    local wrapper_file="${TEMP_DIR}/pt"
    local core_archive="${TEMP_DIR}/pt-core.tar.gz"
    local core_extract_dir="${TEMP_DIR}/core"
    local core_binary="${TEMP_DIR}/core/pt-core"
    local wrapper_checksums="${TEMP_DIR}/wrapper-checksums.sha256"
    local core_checksums="${TEMP_DIR}/core-checksums.sha256"
    local wrapper_pubkey="${TEMP_DIR}/wrapper-release.pem"
    local core_pubkey="${TEMP_DIR}/core-release.pem"
    local wrapper_source=""

    if [[ "$VERIFY" -eq 1 && -z "$OFFLINE_BUNDLE" ]]; then
        prepare_release_verification "$VERSION" "$wrapper_pubkey" "$wrapper_checksums"
        if [[ "$CORE_VERSION" == "$VERSION" ]]; then
            cp "$wrapper_pubkey" "$core_pubkey"
            cp "$wrapper_checksums" "$core_checksums"
        else
            prepare_release_verification "$CORE_VERSION" "$core_pubkey" "$core_checksums"
        fi
    fi

    if [[ -n "$OFFLINE_BUNDLE" ]]; then
        if [[ ! -f "$OFFLINE_BUNDLE" ]]; then
            err "Offline bundle not found: $OFFLINE_BUNDLE"
            exit 1
        fi
        cp "$OFFLINE_BUNDLE" "$core_archive"
        if [[ -f "./pt" ]]; then
            wrapper_source="./pt"
            cp ./pt "$wrapper_file"
        elif [[ -f "$(dirname "$0")/pt" ]]; then
            wrapper_source="$(dirname "$0")/pt"
            cp "$(dirname "$0")/pt" "$wrapper_file"
        else
            err "Offline mode requires a local pt wrapper beside install.sh or in the current directory"
            exit 1
        fi
    elif [[ "$FROM_SOURCE" -eq 1 ]]; then
        maybe_build_from_source
    else
        run_with_spinner "Downloading pt wrapper" download_wrapper "$wrapper_file"
        if ! run_with_spinner "Downloading pt-core archive" download_core_archive "$core_archive"; then
            warn "Prebuilt pt-core download failed; falling back to source build"
            FROM_SOURCE=1
            maybe_build_from_source
        fi
    fi

    if [[ "$FROM_SOURCE" -ne 1 && "$VERIFY" -eq 1 ]]; then
        if [[ -n "$OFFLINE_BUNDLE" ]]; then
            prepare_offline_verification "$wrapper_source" "$OFFLINE_BUNDLE" "${TEMP_DIR}/pt.sig" "${TEMP_DIR}/$(basename "$OFFLINE_BUNDLE").sig"
            verify_file_checksum "$wrapper_file" "pt" "$wrapper_checksums"
            verify_file_checksum "$core_archive" "$(basename "$OFFLINE_BUNDLE")" "$core_checksums"
        else
            verify_file_signature "$wrapper_file" "pt" "$VERSION" "$wrapper_pubkey" "${TEMP_DIR}/pt.sig"
            verify_file_checksum "$wrapper_file" "pt" "$wrapper_checksums"
            best_effort_sigstore_verify "$wrapper_file" "pt"

            verify_file_signature "$core_archive" "$DOWNLOADED_ARTIFACT" "$CORE_VERSION" "$core_pubkey" "${TEMP_DIR}/${DOWNLOADED_ARTIFACT}.sig"
            verify_file_checksum "$core_archive" "$DOWNLOADED_ARTIFACT" "$core_checksums"
            best_effort_sigstore_verify "$core_archive" "$DOWNLOADED_ARTIFACT"
        fi
    fi

    if [[ "$FROM_SOURCE" -ne 1 ]]; then
        extract_core_archive "$core_archive" "$core_extract_dir"
    fi

    if [[ "$FROM_SOURCE" -eq 1 ]]; then
        core_binary="${TEMP_DIR}/pt-core"
    fi

    [[ -f "$wrapper_file" ]] || {
        err "Wrapper file missing after acquisition"
        exit 1
    }
    [[ -f "$core_binary" ]] || {
        err "pt-core binary missing after acquisition"
        exit 1
    }

    install_binary "$wrapper_file" "$DEST" "pt"
    install_binary "$core_binary" "$DEST" "pt-core"

    maybe_add_path "$DEST"
    maybe_install_completions
    show_agent_scan_notice
    maybe_configure_agents

    if [[ "$VERIFY_SELF" -eq 1 ]]; then
        run_with_spinner "Running post-install verification" bash -lc "'$DEST/pt' --version >/dev/null && '$DEST/pt-core' --version >/dev/null && '$DEST/pt' scan --format json >/dev/null 2>/dev/null"
    fi

    show_final_summary
}

main "$@"
