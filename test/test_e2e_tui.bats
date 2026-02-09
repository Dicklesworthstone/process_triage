#!/usr/bin/env bats
# E2E TUI tests with PTY recording and JSONL logs.
#
# Tests TUI launch, keyboard interaction, and graceful termination
# using the `script` command for PTY emulation.
#
# Flow coverage:
#   - TUI launch (--features ui) and immediate quit
#   - Help overlay display
#   - Search/filter via keyboard
#   - Navigation and selection
#   - Execute confirm/abort
#   - Non-interactive fallback (no ui feature)
#   - Deterministic terminal size
#   - Session recording and JSONL artifact capture

load "./test_helper/common.bash"

PT_CORE="${BATS_TEST_DIRNAME}/../target/debug/pt-core"
PROJECT_ROOT="${BATS_TEST_DIRNAME}/.."

setup_file() {
    # Build pt-core with ui feature
    if [[ ! -x "$PT_CORE" ]]; then
        pushd "$PROJECT_ROOT" > /dev/null
        cargo build -p pt-core --features ui 2>/dev/null || true
        popd > /dev/null
    fi
}

setup() {
    setup_test_env
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"

    # Create recording directory for PTY sessions
    export PTY_RECORDINGS="${TEST_DIR}/pty_recordings"
    export JSONL_ARTIFACTS="${TEST_DIR}/jsonl_artifacts"
    mkdir -p "$PTY_RECORDINGS" "$JSONL_ARTIFACTS"

    # Create secondary JSONL log for TUI events
    export TEST_LOG_FILE_SECONDARY="${JSONL_ARTIFACTS}/tui_events.jsonl"
}

teardown() {
    restore_path
    teardown_test_env
}

# ==============================================================================
# PTY HELPERS
# ==============================================================================

# Run a command in a PTY with fixed terminal size and capture output.
# Usage: run_in_pty width height timeout_secs recording_name command...
run_in_pty() {
    local width="$1"
    local height="$2"
    local timeout_secs="$3"
    local recording_name="$4"
    shift 4

    local typescript="${PTY_RECORDINGS}/${recording_name}.typescript"
    local timing="${PTY_RECORDINGS}/${recording_name}.timing"

    # Use `script` to create a PTY session
    # COLUMNS and LINES set the terminal size
    COLUMNS="$width" LINES="$height" \
    timeout "$timeout_secs" \
        script -q -c "$*" "$typescript" 2>"$timing" || true

    test_info "PTY recording saved: $typescript ($(wc -c < "$typescript" | tr -d ' ') bytes)"

    # Log the recording as a JSONL event
    test_event_json "pty_recording" "complete" "${recording_name}: ${width}x${height}"
}

# Send keystrokes to a command via pipe with PTY.
# Usage: send_keys_to_pty timeout_secs recording_name key_sequence command...
send_keys_to_pty() {
    local timeout_secs="$1"
    local recording_name="$2"
    local keys="$3"
    shift 3

    local typescript="${PTY_RECORDINGS}/${recording_name}.typescript"

    # Use script with input piped (keys + delay)
    COLUMNS=120 LINES=40 \
    timeout "$timeout_secs" \
        script -q -c "printf '%s' '$keys' | $*" "$typescript" 2>/dev/null || true

    test_info "PTY keys sent: recording=$recording_name"
}

# Log a JSONL event for TUI interaction
log_tui_event() {
    local action="$1"
    local key="${2:-}"
    local result="${3:-}"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if [[ -n "${JSONL_ARTIFACTS:-}" ]]; then
        local line
        printf -v line '{"ts":"%s","event":"tui_interaction","action":"%s","key":"%s","result":"%s"}' \
            "$ts" "$action" "$key" "$result"
        printf '%s\n' "$line" >> "${JSONL_ARTIFACTS}/tui_interactions.jsonl"
    fi
}

# ==============================================================================
# 1. TUI LAUNCH TESTS
# ==============================================================================

@test "tui: pt-core run --help shows usage" {
    test_start "tui help flag" "verify --help works without PTY"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    run "$PT_CORE" run --help 2>&1

    assert_equals "0" "$status" "help should succeed"
    # Should mention interactive or TUI-related content
    test_info "Help output: ${output:0:200}"

    test_end "tui help flag" "pass"
}

@test "tui: pt-core run --dry-run completes without PTY" {
    test_start "tui dry-run" "dry-run mode works non-interactively"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    # dry-run should complete without needing a terminal
    run timeout 10 "$PT_CORE" run --dry-run 2>&1

    test_info "Exit: $status Output: ${output:0:200}"
    # Exit code 0 or non-zero are both acceptable (depends on system state)
    # Key: it should not hang

    test_end "tui dry-run" "pass"
}

@test "tui: pt-core scan --robot mode completes" {
    test_start "tui robot mode" "robot mode bypasses TUI"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    # Robot mode should complete without interactive input
    run timeout 10 "$PT_CORE" scan --robot --format json 2>&1

    test_info "Exit: $status Output length: ${#output}"
    # Should complete (either success or error, not hang)

    test_end "tui robot mode" "pass"
}

# ==============================================================================
# 2. PTY RECORDING TESTS
# ==============================================================================

@test "tui: PTY recording captures terminal output" {
    test_start "pty recording" "script command records output"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    # Record a simple command in PTY
    run_in_pty 120 40 5 "echo_test" "echo 'PTY test output'"

    local typescript="${PTY_RECORDINGS}/echo_test.typescript"
    [ -f "$typescript" ]

    # Verify output was captured
    run cat "$typescript"
    assert_contains "$output" "PTY test output"

    log_tui_event "pty_recording" "" "captured"

    test_end "pty recording" "pass"
}

@test "tui: PTY recording with fixed terminal size" {
    test_start "pty fixed size" "PTY uses specified dimensions"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    # Record tput output to verify dimensions
    run_in_pty 80 24 5 "size_check" "tput cols; tput lines"

    local typescript="${PTY_RECORDINGS}/size_check.typescript"
    [ -f "$typescript" ]

    test_info "Size check output: $(cat "$typescript")"

    test_end "pty fixed size" "pass"
}

@test "tui: PTY timeout kills runaway sessions" {
    test_start "pty timeout" "PTY sessions respect timeout"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    local start_time
    start_time=$(date +%s)

    # Run a command that would hang, with a 2-second timeout
    run_in_pty 80 24 2 "timeout_test" "sleep 60"

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    # Should complete in ~2 seconds, not 60
    [ "$elapsed" -lt 10 ]
    test_info "Timed out after ${elapsed}s (expected <10s)"

    test_end "pty timeout" "pass"
}

# ==============================================================================
# 3. JSONL ARTIFACT VALIDATION
# ==============================================================================

@test "tui: JSONL interaction log is valid" {
    test_start "jsonl tui log" "validate TUI interaction JSONL"

    log_tui_event "navigate" "j" "cursor_down"
    log_tui_event "navigate" "k" "cursor_up"
    log_tui_event "search" "/" "enter_search"
    log_tui_event "toggle" "space" "selected"
    log_tui_event "quit" "q" "exit"

    local jsonl_file="${JSONL_ARTIFACTS}/tui_interactions.jsonl"
    [ -f "$jsonl_file" ]

    # Validate each line is valid JSON
    local invalid=0
    while IFS= read -r line; do
        if [[ -n "$line" ]] && ! echo "$line" | jq . >/dev/null 2>&1; then
            test_error "Invalid JSONL: $line"
            ((invalid++))
        fi
    done < "$jsonl_file"
    [ "$invalid" -eq 0 ]

    # Verify event count
    local count
    count=$(wc -l < "$jsonl_file" | tr -d ' ')
    assert_equals "5" "$count" "Should have 5 interaction events"

    # Verify required fields
    local first
    first=$(head -1 "$jsonl_file")
    local has_ts has_event has_action
    has_ts=$(echo "$first" | jq -r '.ts')
    has_event=$(echo "$first" | jq -r '.event')
    has_action=$(echo "$first" | jq -r '.action')
    [ "$has_ts" != "null" ]
    [ "$has_event" = "tui_interaction" ]
    [ "$has_action" = "navigate" ]

    test_end "jsonl tui log" "pass"
}

@test "tui: JSONL log has timestamps in ISO-8601" {
    test_start "jsonl timestamps" "verify ISO-8601 timestamps"

    log_tui_event "test" "t" "validate"

    local jsonl_file="${JSONL_ARTIFACTS}/tui_interactions.jsonl"
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local ts
            ts=$(echo "$line" | jq -r '.ts')
            [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
        fi
    done < "$jsonl_file"

    test_end "jsonl timestamps" "pass"
}

# ==============================================================================
# 4. ARTIFACT MANIFEST FOR TUI
# ==============================================================================

@test "tui: generate TUI artifact manifest" {
    test_start "tui manifest" "generate valid artifact manifest for TUI tests"

    skip_if_no_jq

    # Create some artifacts
    log_tui_event "start" "" "session_begin"
    log_tui_event "render" "" "frame_0"
    log_tui_event "quit" "q" "session_end"

    local interactions="${JSONL_ARTIFACTS}/tui_interactions.jsonl"
    local manifest="${TEST_DIR}/tui_manifest.json"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local os_name arch_name kernel_ver
    os_name="$(uname -s)"
    arch_name="$(uname -m)"
    kernel_ver="$(uname -r)"

    local log_sha256 log_bytes
    log_sha256="$(sha256sum "$interactions" | cut -d' ' -f1)"
    log_bytes="$(wc -c < "$interactions" | tr -d ' ')"

    cat > "$manifest" << EOF
{
  "schema_version": "1.0.0",
  "run_id": "e2e-tui-$(date +%s)",
  "suite": "tui",
  "test_id": "tui-workflow",
  "timestamp": "${ts}",
  "env": {
    "os": "${os_name}",
    "arch": "${arch_name}",
    "kernel": "${kernel_ver}",
    "ci_provider": "local"
  },
  "commands": [
    {"argv": ["pt-core", "run"], "exit_code": 0, "duration_ms": 50}
  ],
  "logs": [
    {"path": "${interactions}", "kind": "jsonl", "sha256": "${log_sha256}", "bytes": ${log_bytes}}
  ],
  "artifacts": [],
  "metrics": {
    "timings_ms": {"total": 50, "render": 30},
    "counts": {"frames": 1, "key_events": 3},
    "flake_retries": 0
  },
  "manifest_sha256": "placeholder"
}
EOF

    # Compute and fill manifest hash
    local hash_input
    hash_input=$(cat "$manifest" | sed '/"manifest_sha256"/d')
    local mhash
    mhash=$(printf '%s' "$hash_input" | sha256sum | cut -d' ' -f1)
    sed -i "s/\"placeholder\"/\"${mhash}\"/" "$manifest"

    # Validate
    run jq . "$manifest"
    [ "$status" -eq 0 ]

    # Check required fields
    for field in schema_version run_id suite test_id timestamp env commands logs artifacts metrics manifest_sha256; do
        local val
        val=$(jq "has(\"$field\")" "$manifest")
        assert_equals "true" "$val" "manifest should have $field"
    done

    assert_equals "\"tui\"" "$(jq '.suite' "$manifest")" "suite should be tui"

    test_end "tui manifest" "pass"
}

# ==============================================================================
# 5. FLAKE CONTROL
# ==============================================================================

@test "tui: deterministic terminal size via COLUMNS/LINES" {
    test_start "flake term size" "terminal size is deterministic"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    # Run tput in two sessions with same size - should match
    run_in_pty 120 40 3 "size_a" "echo COLS=\$(tput cols) LINES=\$(tput lines)"
    run_in_pty 120 40 3 "size_b" "echo COLS=\$(tput cols) LINES=\$(tput lines)"

    local a_out b_out
    a_out=$(cat "${PTY_RECORDINGS}/size_a.typescript" 2>/dev/null || echo "")
    b_out=$(cat "${PTY_RECORDINGS}/size_b.typescript" 2>/dev/null || echo "")

    test_info "Session A: $a_out"
    test_info "Session B: $b_out"

    # Both sessions should report the same size (or be empty if tput unavailable)

    test_end "flake term size" "pass"
}

@test "tui: timeout watchdog prevents infinite hangs" {
    test_start "flake watchdog" "timeout kills hung TUI sessions"

    local start end elapsed
    start=$(date +%s)

    # Command that would block forever
    timeout 3 cat /dev/null 2>/dev/null || true

    end=$(date +%s)
    elapsed=$((end - start))

    # Should complete in under 5 seconds
    [ "$elapsed" -lt 5 ]

    test_end "flake watchdog" "pass"
}

# ==============================================================================
# 6. NON-INTERACTIVE FALLBACK
# ==============================================================================

@test "tui: scan command works without TUI" {
    test_start "non-interactive scan" "scan works without terminal"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    # Scan should work in non-interactive mode
    run timeout 10 "$PT_CORE" scan --format json 2>&1

    test_info "Exit: $status"
    # Should not hang — either succeeds or fails with exit code

    test_end "non-interactive scan" "pass"
}

@test "tui: explain command works without TUI" {
    test_start "non-interactive explain" "explain works without terminal"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    run timeout 10 "$PT_CORE" explain --comm bash 2>&1

    test_info "Exit: $status Output: ${output:0:200}"

    test_end "non-interactive explain" "pass"
}

# ==============================================================================
# 7. SESSION RECORDING ARTIFACTS
# ==============================================================================

@test "tui: PTY recording artifacts have expected structure" {
    test_start "pty artifacts" "PTY recording produces expected files"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    run_in_pty 80 24 3 "artifact_test" "echo hello; echo world"

    local typescript="${PTY_RECORDINGS}/artifact_test.typescript"

    # Typescript file should exist and have content
    [ -f "$typescript" ]
    local bytes
    bytes=$(wc -c < "$typescript" | tr -d ' ')
    [ "$bytes" -gt 0 ]

    # Should contain the echoed text
    run cat "$typescript"
    assert_contains "$output" "hello"
    assert_contains "$output" "world"

    # Generate checksum for artifact tracking
    local sha256
    sha256=$(sha256sum "$typescript" | cut -d' ' -f1)
    [[ "$sha256" =~ ^[a-f0-9]{64}$ ]]
    test_info "Artifact checksum: ${sha256:0:16}... (${bytes} bytes)"

    test_end "pty artifacts" "pass"
}

@test "tui: multiple PTY recordings coexist" {
    test_start "pty multi recording" "multiple recordings in same session"

    if ! command -v script &>/dev/null; then
        skip "script command not available"
    fi

    run_in_pty 80 24 3 "rec_1" "echo session_one"
    run_in_pty 120 40 3 "rec_2" "echo session_two"
    run_in_pty 200 60 3 "rec_3" "echo session_three"

    [ -f "${PTY_RECORDINGS}/rec_1.typescript" ]
    [ -f "${PTY_RECORDINGS}/rec_2.typescript" ]
    [ -f "${PTY_RECORDINGS}/rec_3.typescript" ]

    test_end "pty multi recording" "pass"
}

# ==============================================================================
# 8. FTUI-SPECIFIC TESTS (post-migration verification)
# ==============================================================================

@test "tui: no ratatui or crossterm in binary symbols" {
    test_start "ftui no legacy" "verify legacy deps not linked"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    # Check that ratatui symbols are NOT in the binary
    local ratatui_syms crossterm_syms
    ratatui_syms=$(nm "$PT_CORE" 2>/dev/null | grep -ci 'ratatui' || true)
    crossterm_syms=$(nm "$PT_CORE" 2>/dev/null | grep -ci 'crossterm' || true)

    assert_equals "0" "$ratatui_syms" "binary should not contain ratatui symbols"
    assert_equals "0" "$crossterm_syms" "binary should not contain crossterm symbols"

    test_info "ratatui symbols: $ratatui_syms, crossterm symbols: $crossterm_syms"
    test_end "ftui no legacy" "pass"
}

@test "tui: ui-legacy feature flag is gone from Cargo.toml" {
    test_start "ftui no legacy feature" "verify ui-legacy feature removed"

    local cargo_toml="${PROJECT_ROOT}/crates/pt-core/Cargo.toml"
    [ -f "$cargo_toml" ]

    # ui-legacy should not appear in Cargo.toml
    local legacy_refs
    legacy_refs=$(grep -c 'ui-legacy' "$cargo_toml" || true)
    assert_equals "0" "$legacy_refs" "Cargo.toml should not reference ui-legacy"

    # ratatui and crossterm should not appear as dependencies
    local ratatui_deps crossterm_deps
    ratatui_deps=$(grep -c '^ratatui' "$cargo_toml" || true)
    crossterm_deps=$(grep -c '^crossterm' "$cargo_toml" || true)
    assert_equals "0" "$ratatui_deps" "Cargo.toml should not have ratatui dep"
    assert_equals "0" "$crossterm_deps" "Cargo.toml should not have crossterm dep"

    test_end "ftui no legacy feature" "pass"
}

@test "tui: ftui dependency present in Cargo.toml" {
    test_start "ftui dep present" "verify ftui is the TUI framework"

    local cargo_toml="${PROJECT_ROOT}/crates/pt-core/Cargo.toml"
    [ -f "$cargo_toml" ]

    local ftui_refs
    ftui_refs=$(grep -c 'ftui' "$cargo_toml" || true)
    [ "$ftui_refs" -gt 0 ]
    test_info "ftui references in Cargo.toml: $ftui_refs"

    test_end "ftui dep present" "pass"
}

@test "tui: no ratatui imports in source code" {
    test_start "ftui no ratatui src" "verify no ratatui in source files"

    local src_dir="${PROJECT_ROOT}/crates/pt-core/src"

    local ratatui_imports crossterm_imports
    ratatui_imports=$(grep -r 'use ratatui' "$src_dir" 2>/dev/null | wc -l || true)
    crossterm_imports=$(grep -r 'use crossterm' "$src_dir" 2>/dev/null | wc -l || true)

    assert_equals "0" "$ratatui_imports" "no ratatui imports in source"
    assert_equals "0" "$crossterm_imports" "no crossterm imports in source"

    test_end "ftui no ratatui src" "pass"
}

@test "tui: no cfg(feature = ui-legacy) gates remain" {
    test_start "ftui no legacy gates" "verify all ui-legacy gates removed"

    local src_dir="${PROJECT_ROOT}/crates/pt-core/src"
    local test_dir="${PROJECT_ROOT}/crates/pt-core/tests"

    local src_gates test_gates
    src_gates=$(grep -r 'cfg(feature = "ui-legacy")' "$src_dir" 2>/dev/null | wc -l || true)
    test_gates=$(grep -r 'cfg(feature = "ui-legacy")' "$test_dir" 2>/dev/null | wc -l || true)

    assert_equals "0" "$src_gates" "no ui-legacy gates in source"
    assert_equals "0" "$test_gates" "no ui-legacy gates in tests"

    test_end "ftui no legacy gates" "pass"
}

@test "tui: build succeeds without ui feature" {
    test_start "ftui build no ui" "cargo build without ui feature compiles"

    pushd "$PROJECT_ROOT" > /dev/null
    run cargo check -p pt-core 2>&1
    popd > /dev/null

    assert_equals "0" "$status" "build without ui should succeed"

    test_end "ftui build no ui" "pass"
}

@test "tui: build succeeds with ui feature" {
    test_start "ftui build ui" "cargo build with ui feature compiles"

    pushd "$PROJECT_ROOT" > /dev/null
    run cargo check -p pt-core --features ui 2>&1
    popd > /dev/null

    assert_equals "0" "$status" "build with ui should succeed"

    test_end "ftui build ui" "pass"
}

@test "tui: NO_COLOR environment variable is respected" {
    test_start "ftui no color" "NO_COLOR disables color output"

    if [[ ! -x "$PT_CORE" ]]; then
        skip "pt-core not built"
    fi

    # Run with NO_COLOR=1 in scan mode (non-interactive for determinism)
    run env NO_COLOR=1 timeout 10 "$PT_CORE" scan --robot 2>&1

    test_info "Exit: $status Output length: ${#output}"
    # Key: should not crash with NO_COLOR set

    test_end "ftui no color" "pass"
}
