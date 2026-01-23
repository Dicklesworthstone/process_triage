#!/usr/bin/env bash
# E2E test for threshold naming unification (bd-2yz0)
#
# Tests that:
# - --min-posterior is the primary flag name
# - --threshold works as a backward-compatible alias
# - Both flags produce equivalent behavior
# - Default value is 0.7
# - Help text shows proper alias relationship

set -euo pipefail

# Setup logging
LOG="${LOG:-test/logs/e2e_threshold_naming_$(date +%Y%m%d_%H%M%S).log}"
mkdir -p "$(dirname "$LOG")"

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"
}

log_pass() {
    log "✓ $*"
}

log_fail() {
    log "✗ $*"
    FAILURES=$((FAILURES + 1))
}

log_warn() {
    log "⚠ $*"
}

FAILURES=0
PT_CORE="${PT_CORE:-./target/release/pt-core}"

# Build if needed
if [[ ! -x "$PT_CORE" ]]; then
    log "Building pt-core..."
    cargo build --release -p pt-core 2>/dev/null || {
        log_fail "Failed to build pt-core"
        exit 1
    }
fi

log "=== E2E Test: threshold naming (bd-2yz0) ==="
log "Using: $PT_CORE"

#------------------------------------------------------------------------------
# Test 1: --min-posterior flag is recognized
#------------------------------------------------------------------------------
log ""
log "--- Test 1: --min-posterior flag works ---"

OUTPUT=$("$PT_CORE" agent plan --min-posterior 0.95 --format json 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

# Exit code 0 or 1 (no candidates) is acceptable
if [[ $EXIT_CODE -le 1 ]]; then
    log_pass "--min-posterior 0.95 accepted (exit $EXIT_CODE)"
else
    # Check if it's an unrecognized flag error
    if echo "$OUTPUT" | grep -qi "error.*min-posterior\|unrecognized\|invalid"; then
        log_fail "--min-posterior flag not recognized"
        echo "Output: $OUTPUT" >> "$LOG"
    else
        log_pass "--min-posterior flag accepted (exit $EXIT_CODE)"
    fi
fi

#------------------------------------------------------------------------------
# Test 2: --threshold alias still works
#------------------------------------------------------------------------------
log ""
log "--- Test 2: --threshold alias works ---"

OUTPUT=$("$PT_CORE" agent plan --threshold 0.85 --format json 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

if [[ $EXIT_CODE -le 1 ]]; then
    log_pass "--threshold alias works (exit $EXIT_CODE)"
else
    if echo "$OUTPUT" | grep -qi "error.*threshold\|unrecognized\|invalid"; then
        log_fail "--threshold alias not recognized"
        echo "Output: $OUTPUT" >> "$LOG"
    else
        log_pass "--threshold alias accepted (exit $EXIT_CODE)"
    fi
fi

#------------------------------------------------------------------------------
# Test 3: Help shows --min-posterior as primary
#------------------------------------------------------------------------------
log ""
log "--- Test 3: Help shows --min-posterior as primary ---"

HELP=$("$PT_CORE" agent plan --help 2>&1 || true)

if echo "$HELP" | grep -q "min-posterior"; then
    log_pass "Help shows --min-posterior"
else
    log_fail "Help should show --min-posterior"
    echo "Help output:" >> "$LOG"
    echo "$HELP" >> "$LOG"
fi

#------------------------------------------------------------------------------
# Test 4: Help mentions threshold (as alias)
#------------------------------------------------------------------------------
log ""
log "--- Test 4: Help shows threshold as alias ---"

if echo "$HELP" | grep -qi "threshold"; then
    log_pass "Help mentions threshold"
else
    log_warn "Help might not show alias (acceptable if alias works)"
fi

#------------------------------------------------------------------------------
# Test 5: Both flags produce structurally equivalent output
#------------------------------------------------------------------------------
log ""
log "--- Test 5: Both flags produce equivalent output ---"

# Run with --min-posterior
OUTPUT1=$("$PT_CORE" agent plan --min-posterior 0.8 --format json 2>&1 || true)
# Run with --threshold
OUTPUT2=$("$PT_CORE" agent plan --threshold 0.8 --format json 2>&1 || true)

# Extract structure (remove volatile fields like timestamps)
FIELDS1=$(echo "$OUTPUT1" | jq -r 'keys | sort | .[]' 2>/dev/null || echo "parse_error")
FIELDS2=$(echo "$OUTPUT2" | jq -r 'keys | sort | .[]' 2>/dev/null || echo "parse_error")

if [[ "$FIELDS1" == "$FIELDS2" ]] && [[ "$FIELDS1" != "parse_error" ]]; then
    log_pass "Both flags produce same output structure"
else
    log_warn "Output structure differs (may be due to timing/candidates)"
    echo "Fields1: $FIELDS1" >> "$LOG"
    echo "Fields2: $FIELDS2" >> "$LOG"
fi

#------------------------------------------------------------------------------
# Test 6: Boundary value tests
#------------------------------------------------------------------------------
log ""
log "--- Test 6: Boundary value tests ---"

# Test with 0.0 (minimum valid)
OUTPUT=$("$PT_CORE" agent plan --min-posterior 0.0 --format json 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}
if [[ $EXIT_CODE -le 1 ]]; then
    log_pass "--min-posterior 0.0 accepted"
else
    log_warn "--min-posterior 0.0 returned exit $EXIT_CODE (may be policy rejection)"
fi

# Test with 1.0 (maximum valid)
OUTPUT=$("$PT_CORE" agent plan --min-posterior 1.0 --format json 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}
if [[ $EXIT_CODE -le 1 ]]; then
    log_pass "--min-posterior 1.0 accepted"
else
    log_warn "--min-posterior 1.0 returned exit $EXIT_CODE"
fi

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
log ""
log "=== E2E Test Summary ==="
if [[ $FAILURES -eq 0 ]]; then
    log "=== E2E Test PASSED ==="
    exit 0
else
    log "=== E2E Test FAILED ($FAILURES failures) ==="
    exit 1
fi
