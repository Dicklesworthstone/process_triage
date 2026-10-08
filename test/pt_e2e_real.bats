#!/usr/bin/env bats
# Real-system E2E tests for pt (no mocks), with detailed logging.

load "./test_helper/common.bash"

setup() {
    setup_test_env

    local test_file_dir
    test_file_dir="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$test_file_dir")"
    PATH="$PROJECT_ROOT:$PATH"

    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export ARTIFACT_DIR="$TEST_DIR/artifacts"
    export ARTIFACT_LOG_DIR="$ARTIFACT_DIR/logs"
    export ARTIFACT_STDOUT_DIR="$ARTIFACT_DIR/stdout"
    export ARTIFACT_STDERR_DIR="$ARTIFACT_DIR/stderr"
    export ARTIFACT_PLANS_DIR="$ARTIFACT_DIR/plans"
    export ARTIFACT_SNAPSHOTS_DIR="$ARTIFACT_DIR/snapshots"
    export ARTIFACT_TELEMETRY_DIR="$ARTIFACT_DIR/telemetry"
    mkdir -p \
        "$ARTIFACT_DIR" \
        "$ARTIFACT_LOG_DIR" \
        "$ARTIFACT_STDOUT_DIR" \
        "$ARTIFACT_STDERR_DIR" \
        "$ARTIFACT_PLANS_DIR" \
        "$ARTIFACT_SNAPSHOTS_DIR" \
        "$ARTIFACT_TELEMETRY_DIR"

    if [[ -z "${TEST_LOG_FILE:-}" ]]; then
        export TEST_LOG_FILE="$ARTIFACT_LOG_DIR/pt_e2e_real.jsonl"
    else
        export TEST_LOG_FILE_SECONDARY="$ARTIFACT_LOG_DIR/pt_e2e_real.jsonl"
    fi

    test_start "real e2e" "pt CLI real-system E2E with artifacts"
    test_info "Artifacts: $ARTIFACT_DIR"
}

teardown() {
    teardown_test_env
    if [[ -n "${BATS_TEST_COMPLETED:-}" ]]; then
        test_end "real e2e" "pass"
    else
        test_end "real e2e" "fail"
    fi
}

# ----------------------------------------------------------------------------
# Local helpers
# ----------------------------------------------------------------------------

command_exists() {
    command -v "$1" &>/dev/null
}

redact_output() {
    sed -E \
        -e 's/(AKIA[0-9A-Z]{16})/[REDACTED]/g' \
        -e 's/(ghp_[A-Za-z0-9]{20,})/[REDACTED]/g' \
        -e 's/(sk-[A-Za-z0-9_-]{10,})/[REDACTED]/g' \
        -e 's/(password=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(--password=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(--token[[:space:]]+)[^[:space:]]+/\1[REDACTED]/g'
}

assert_no_secret() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    local pattern="AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{10,}|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY"
    if command_exists "rg"; then
        if rg -n "$pattern" "$file"; then
            test_error "Secret-like pattern found in artifact: $file"
            return 1
        fi
    elif grep -E -n "$pattern" "$file"; then
        test_error "Secret-like pattern found in artifact: $file"
        return 1
    fi
    return 0
}

log_json_event() {
    local event="$1"
    local status="$2"
    local cmd="$3"
    local out_file="$4"
    local err_file="$5"
    local line_count="$6"

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local cmd_esc
    local out_esc
    local err_esc
    local run_id_esc
    local run_id_field
    cmd_esc=$(escape_json "$cmd")
    out_esc=$(escape_json "$out_file")
    err_esc=$(escape_json "$err_file")
    run_id_field=""
    if [[ -n "${E2E_RUN_ID:-}" ]]; then
        run_id_esc=$(escape_json "$E2E_RUN_ID")
        run_id_field=",\"run_id\":\"${run_id_esc}\""
    fi

    printf '{"ts":"%s","event":"%s","status":%s,"cmd":"%s","stdout":"%s","stderr":"%s","lines":%s%s}\n' \
        "$ts" \
        "$event" \
        "$status" \
        "$cmd_esc" \
        "$out_esc" \
        "$err_esc" \
        "$line_count" \
        "$run_id_field" \
        >> "$TEST_LOG_FILE"
}

escape_json() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

run_cmd_with_artifacts() {
    local name="$1"
    local cmd="$2"
    local out_file="$ARTIFACT_STDOUT_DIR/${name}.stdout"
    local err_file="$ARTIFACT_STDERR_DIR/${name}.stderr"

    local full_cmd
    printf -v full_cmd '%s 2> %q' "$cmd" "$err_file"
    run bash -c "$full_cmd"

    printf "%s" "$output" | redact_output > "$out_file"
    if [[ -f "$err_file" ]]; then
        local redacted_err
        redacted_err=$(redact_output < "$err_file")
        printf "%s" "$redacted_err" > "$err_file"
    fi
    assert_no_secret "$out_file"
    assert_no_secret "$err_file"

    local line_count
    line_count=$(printf "%s" "$output" | wc -l | tr -d ' ')

    log_json_event "$name" "$status" "$cmd" "$out_file" "$err_file" "$line_count"
}

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

@test "pt --help (real)" {
    run_cmd_with_artifacts "help" "pt --help"
    [ "$status" -eq 0 ]
    assert_contains "$output" "Process Triage" "help should mention Process Triage"
}

@test "pt --version (real)" {
    run_cmd_with_artifacts "version" "pt --version"
    [ "$status" -eq 0 ]
    assert_contains "$output" "pt " "version output should include prefix"
}

@test "pt query sessions (real)" {
    run_cmd_with_artifacts "query_sessions" "pt -f json query sessions --limit 1"
    [ "$status" -eq 0 ]
}

@test "pt scan (real)" {
    skip_if_no_gum
    if ! command_exists "timeout"; then
        test_warn "Skipping: timeout not installed"
        skip "timeout not installed"
    fi

    run_cmd_with_artifacts "scan" "timeout 10 pt scan"

    if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
        fail "pt scan failed with status $status"
    fi
}

@test "mux-pane plan visibility and protected services (real, paired binaries)" {
    # Explicit live-host acceptance: ordinary CI lacks both the mux layout and
    # the independently built incumbent. A skip supplies no acceptance evidence.
    [[ -n "${PT_PANE_BASELINE_BIN:-}" && -n "${PT_PANE_SUBJECT_PID:-}" && -n "${PT_PANE_CONTROL_PIDS:-}" ]] ||
        skip "requires incumbent binary, live pane subject and protected controls"
    [[ -x "$PT_PANE_BASELINE_BIN" ]]
    command_exists python3
    export PROCESS_TRIAGE_RETENTION=off
    run python3 - "$ARTIFACT_SNAPSHOTS_DIR/pane_subjects.json" <<'PY'
import json
import os
import sys
from pathlib import Path

pids = [int(os.environ['PT_PANE_SUBJECT_PID'])]
pids += [int(pid) for pid in os.environ['PT_PANE_CONTROL_PIDS'].split(',')]
rows = {}
uptime = float(Path('/proc/uptime').read_text().split()[0])
ticks = os.sysconf('SC_CLK_TCK')
for pid in pids:
    proc = Path('/proc') / str(pid)
    stat = (proc / 'stat').read_text()
    fields = stat[stat.rfind(')') + 1:].split()
    rows[str(pid)] = {
        'birth_ticks': int(fields[19]), 'ppid': int(fields[1]),
        'sid': int(fields[3]), 'tty': int(fields[4]),
        'uids': next(line for line in (proc / 'status').read_text().splitlines()
                     if line.startswith('Uid:')),
        'exe': str((proc / 'exe').readlink()),
        'argv': (proc / 'cmdline').read_bytes().decode().split('\0'),
        'comm': (proc / 'comm').read_text().strip(),
        'cgroup': (proc / 'cgroup').read_text().strip(),
        'elapsed_seconds': uptime - int(fields[19]) / ticks,
    }
assert rows[str(pids[0])]['elapsed_seconds'] >= 3600, 'pane subject must exceed the age floor'
Path(sys.argv[1]).write_text(json.dumps(rows))
PY
    printf '%s\n' "$output" > "$ARTIFACT_LOG_DIR/pane_witness_capture.txt"
    [[ "$status" -eq 0 ]] || test_error "$output"
    [[ "$status" -eq 0 ]]
    local name binary command
    for name in baseline fixed; do
        binary="$PT_CORE_PATH"
        [[ "$name" != baseline ]] || binary="$PT_PANE_BASELINE_BIN"
        printf -v command 'PROCESS_TRIAGE_DATA=%q %q agent plan --format json --min-posterior 0 --max-candidates 1000' \
            "$DATA_DIR/$name" "$binary"
        run_cmd_with_artifacts "pane_$name" "$command"
        [[ "$status" -eq 0 || "$status" -eq 1 ]]
    done

    run python3 - "$ARTIFACT_STDOUT_DIR/pane_baseline.stdout" "$ARTIFACT_STDOUT_DIR/pane_fixed.stdout" \
        "$ARTIFACT_SNAPSHOTS_DIR/pane_subjects.json" <<'PY'
import json
import os
import sys
from pathlib import Path

baseline, fixed, recorded = [json.loads(Path(path).read_text()) for path in sys.argv[1:]]
run_id = os.environ.get('E2E_RUN_ID', 'pane-manual')
subject = int(os.environ['PT_PANE_SUBJECT_PID'])
controls = {int(pid) for pid in os.environ['PT_PANE_CONTROL_PIDS'].split(',')}
old = {int(row['pid']): row for row in baseline['candidates']}
new = {int(row['pid']): row for row in fixed['candidates']}
assert subject not in old, 'incumbent unexpectedly evaluates the pane subject'
assert subject in new, 'fixed plan still hides the pane subject'
assert not controls.intersection(new), 'fixed plan exposes protected service controls'
protected = fixed['summary']['protected_by_pid']
assert all(str(pid) in protected for pid in controls), 'control absence must be caused by protection'
assert fixed['summary']['protected_by_rule']['builtin.agent_coordination'] > 0
assert new[subject]['supervisor'].get('type') != 'systemd'
assert new[subject]['supervisor'].get('supervisor_command') is None
assert fixed['args']['effective_min_age'] == baseline['args']['effective_min_age'] == 3600

# Bind the externally chosen live subjects to their raw placement. Nothing here
# recreates the classifier or supplies synthetic process rows to the executable.
for pid in [subject, *sorted(controls)]:
    proc = Path('/proc') / str(pid)
    stat = (proc / 'stat').read_text()
    fields = stat[stat.rfind(')') + 1:].split()
    current = {
        'birth_ticks': int(fields[19]), 'ppid': int(fields[1]),
        'sid': int(fields[3]), 'tty': int(fields[4]),
        'uids': next(line for line in (proc / 'status').read_text().splitlines()
                     if line.startswith('Uid:')),
        'exe': str((proc / 'exe').readlink()),
        'argv': (proc / 'cmdline').read_bytes().decode().split('\0'),
        'comm': (proc / 'comm').read_text().strip(),
        'cgroup': (proc / 'cgroup').read_text().strip(),
    }
    expected = {key: value for key, value in recorded[str(pid)].items()
                if key != 'elapsed_seconds'}
    assert current == expected, f'live identity or placement changed for {pid}'
    print(json.dumps({'run_id': run_id, 'pid': pid, **recorded[str(pid)]}))
control_names = {recorded[str(pid)]['comm'] for pid in controls}
assert {'frankenterm-mux', 'rchd', 'dbus-daemon', 'am'}.issubset(control_names)
for pid in controls:
    if recorded[str(pid)]['comm'] == 'am':
        assert protected[str(pid)] == 'builtin.agent_coordination', 'live am needs builtin protection'
print(json.dumps({'run_id': run_id, 'baseline_summary': baseline['summary'], 'fixed_summary': fixed['summary'],
                  'new_candidate_pids': sorted(new.keys() - old.keys()),
                  'removed_candidate_pids': sorted(old.keys() - new.keys()),
                  'protected_controls': len(controls), 'control_false_positives': 0,
                  'new_kill_recommendations': sum(row['recommended_action'] == 'kill'
                      for pid, row in new.items() if pid not in old)}))
print(json.dumps({'run_id': run_id, 'event': 'pane_acceptance', 'status': 'PASS',
                  'message': 'native read-only pane visibility and protected controls'}))
PY
    printf '%s\n' "$output" > "$ARTIFACT_LOG_DIR/pane_comparison_output.txt"
    [[ "$status" -eq 0 ]] || test_error "$output"
    [[ "$status" -eq 0 ]]
    printf '%s\n' "$output" > "$ARTIFACT_LOG_DIR/pane_comparison.jsonl"
    test_info "$output"
}
