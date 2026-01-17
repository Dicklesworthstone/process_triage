#!/usr/bin/env bash
# Check binary size and report
# Usage: ./check_binary_size.sh <binary_path> [max_size_mb]
#
# Exit codes:
#   0 - Binary size is within limits
#   1 - Binary size exceeds limit
#   2 - Invalid arguments

set -euo pipefail

BINARY_PATH="${1:-}"
MAX_SIZE_MB="${2:-15}"

usage() {
    echo "Usage: $0 <binary_path> [max_size_mb]"
    echo ""
    echo "Arguments:"
    echo "  binary_path  Path to the binary to check"
    echo "  max_size_mb  Maximum size in MB (default: 15)"
    echo ""
    echo "Example:"
    echo "  $0 target/release/pt-core 15"
    exit 2
}

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARN] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

check_binary() {
    local binary="$1"
    local max_mb="$2"

    if [[ ! -f "$binary" ]]; then
        log_error "Binary not found: $binary"
        exit 2
    fi

    # Get size in bytes
    local size_bytes
    size_bytes=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)

    # Convert to MB
    local size_mb
    size_mb=$((size_bytes / 1024 / 1024))
    local size_kb
    size_kb=$((size_bytes / 1024))

    # Calculate max bytes
    local max_bytes
    max_bytes=$((max_mb * 1024 * 1024))

    # Output JSON for machine parsing
    cat << EOF
{
  "binary": "$binary",
  "size_bytes": $size_bytes,
  "size_kb": $size_kb,
  "size_mb": $size_mb,
  "max_mb": $max_mb,
  "max_bytes": $max_bytes,
  "within_limit": $([ "$size_bytes" -le "$max_bytes" ] && echo "true" || echo "false")
}
EOF

    echo ""
    log_info "Binary: $binary"
    log_info "Size: ${size_mb}MB (${size_kb}KB / ${size_bytes} bytes)"
    log_info "Limit: ${max_mb}MB (${max_bytes} bytes)"

    if [[ "$size_bytes" -gt "$max_bytes" ]]; then
        log_warn "Binary size (${size_mb}MB) exceeds limit (${max_mb}MB)"
        return 1
    fi

    log_info "✓ Binary size is within limit"
    return 0
}

analyze_sections() {
    local binary="$1"

    echo ""
    log_info "Section analysis:"

    if command -v size &>/dev/null; then
        size "$binary" 2>/dev/null || true
    fi

    if command -v bloaty &>/dev/null; then
        echo ""
        log_info "Bloaty analysis (top 10 contributors):"
        bloaty -d sections "$binary" 2>/dev/null | head -15 || true
    fi
}

check_linking() {
    local binary="$1"

    echo ""
    log_info "Link analysis:"

    # Check file type
    file "$binary"

    # Check if statically linked (musl)
    if ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
        log_info "✓ Binary is statically linked"
    elif ldd "$binary" 2>&1 | grep -q "statically linked"; then
        log_info "✓ Binary is statically linked"
    else
        log_info "Binary is dynamically linked"
        echo "Linked libraries:"
        ldd "$binary" 2>/dev/null | head -10 || true
    fi
}

main() {
    if [[ -z "$BINARY_PATH" ]]; then
        usage
    fi

    check_binary "$BINARY_PATH" "$MAX_SIZE_MB"
    local result=$?

    # Additional analysis if verbose
    if [[ "${VERBOSE:-}" == "1" ]]; then
        analyze_sections "$BINARY_PATH"
        check_linking "$BINARY_PATH"
    fi

    exit $result
}

main
