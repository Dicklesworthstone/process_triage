#!/usr/bin/env bash
# Generate Homebrew formula and Scoop manifest from templates
# Usage: ./generate_packages.sh <version> <checksums_file> <output_dir>
#
# The checksums file should contain lines like:
#   <sha256>  pt-core-linux-x86_64-<version>.tar.gz
#   <sha256>  pt-core-linux-aarch64-<version>.tar.gz
#   <sha256>  pt-core-macos-x86_64-<version>.tar.gz
#   <sha256>  pt-core-macos-aarch64-<version>.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 <version> <checksums_file> <output_dir>"
    echo ""
    echo "Arguments:"
    echo "  version        Release version (e.g., 1.0.0)"
    echo "  checksums_file Path to checksums.sha256 file"
    echo "  output_dir     Directory to write generated files"
    exit 1
}

log_info() {
    echo "[INFO] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

extract_sha256() {
    local checksums_file="$1"
    local pattern="$2"

    local sha256
    sha256=$(grep -E "$pattern" "$checksums_file" | awk '{print $1}' | head -1)

    if [[ -z "$sha256" ]]; then
        log_error "Could not find checksum for pattern: $pattern"
        return 1
    fi

    echo "$sha256"
}

generate_formula() {
    local version="$1"
    local checksums_file="$2"
    local output_file="$3"

    log_info "Generating Homebrew formula for version $version"

    # Extract checksums for each platform
    local sha_linux_x86_64 sha_linux_aarch64 sha_macos_x86_64 sha_macos_aarch64

    sha_linux_x86_64=$(extract_sha256 "$checksums_file" "pt-core-linux-x86_64")
    sha_linux_aarch64=$(extract_sha256 "$checksums_file" "pt-core-linux-aarch64")
    sha_macos_x86_64=$(extract_sha256 "$checksums_file" "pt-core-macos-x86_64")
    sha_macos_aarch64=$(extract_sha256 "$checksums_file" "pt-core-macos-aarch64")

    log_info "  Linux x86_64:  ${sha_linux_x86_64:0:16}..."
    log_info "  Linux aarch64: ${sha_linux_aarch64:0:16}..."
    log_info "  macOS x86_64:  ${sha_macos_x86_64:0:16}..."
    log_info "  macOS aarch64: ${sha_macos_aarch64:0:16}..."

    # Generate formula from template
    sed -e "s/{{VERSION}}/${version}/g" \
        -e "s/{{SHA256_LINUX_X86_64}}/${sha_linux_x86_64}/g" \
        -e "s/{{SHA256_LINUX_AARCH64}}/${sha_linux_aarch64}/g" \
        -e "s/{{SHA256_MACOS_X86_64}}/${sha_macos_x86_64}/g" \
        -e "s/{{SHA256_MACOS_AARCH64}}/${sha_macos_aarch64}/g" \
        "${SCRIPT_DIR}/pt.rb.template" > "$output_file"

    log_info "  Formula written to: $output_file"
}

generate_manifest() {
    local version="$1"
    local checksums_file="$2"
    local output_file="$3"

    log_info "Generating Scoop manifest for version $version"

    # For Scoop, we currently only support Windows via WSL2/Linux x86_64
    # Windows native binaries would need separate cross-compilation
    local sha_linux_x86_64
    sha_linux_x86_64=$(extract_sha256 "$checksums_file" "pt-core-linux-x86_64")

    log_info "  Linux x86_64: ${sha_linux_x86_64:0:16}..."

    # Generate manifest from template
    sed -e "s/{{VERSION}}/${version}/g" \
        -e "s/{{SHA256_LINUX_X86_64}}/${sha_linux_x86_64}/g" \
        "${SCRIPT_DIR}/pt.json.template" > "$output_file"

    log_info "  Manifest written to: $output_file"
}

validate_formula() {
    local formula_file="$1"

    log_info "Validating Homebrew formula syntax"

    if command -v ruby &>/dev/null; then
        if ruby -c "$formula_file" &>/dev/null; then
            log_info "  Ruby syntax: OK"
        else
            log_error "  Ruby syntax: FAILED"
            ruby -c "$formula_file"
            return 1
        fi
    else
        log_info "  Ruby not available, skipping syntax check"
    fi
}

validate_manifest() {
    local manifest_file="$1"

    log_info "Validating Scoop manifest JSON"

    if command -v jq &>/dev/null; then
        if jq . "$manifest_file" &>/dev/null; then
            log_info "  JSON syntax: OK"
        else
            log_error "  JSON syntax: FAILED"
            jq . "$manifest_file"
            return 1
        fi
    else
        log_info "  jq not available, skipping syntax check"
    fi
}

main() {
    if [[ $# -lt 3 ]]; then
        usage
    fi

    local version="$1"
    local checksums_file="$2"
    local output_dir="$3"

    # Validate inputs
    if [[ ! -f "$checksums_file" ]]; then
        log_error "Checksums file not found: $checksums_file"
        exit 1
    fi

    # Create output directory
    mkdir -p "$output_dir"

    # Generate formula and manifest
    local formula_file="${output_dir}/pt.rb"
    local manifest_file="${output_dir}/pt.json"

    generate_formula "$version" "$checksums_file" "$formula_file"
    generate_manifest "$version" "$checksums_file" "$manifest_file"

    # Validate generated files
    validate_formula "$formula_file"
    validate_manifest "$manifest_file"

    log_info "Package generation complete!"
    log_info ""
    log_info "Generated files:"
    log_info "  Homebrew formula: $formula_file"
    log_info "  Scoop manifest:   $manifest_file"

    # Output JSON for GitHub Actions
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "formula_path=$formula_file" >> "$GITHUB_OUTPUT"
        echo "manifest_path=$manifest_file" >> "$GITHUB_OUTPUT"
    fi
}

main "$@"
