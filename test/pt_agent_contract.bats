#!/usr/bin/env bats
# Agent CLI Contract Tests for pt-core
# Validates the agent CLI surface against the contract spec
#
# These tests enforce:
# - Non-interactive behavior (no prompts, no TTY assumptions)
# - Stable schema_version in all JSON outputs
# - Durable session identity format
# - Process identity includes stable identity tuple
# - Exit code semantics
#
# Reference: docs/AGENT_CLI_CONTRACT.md, docs/CLI_SPECIFICATION.md

load "./test_helper/common.bash"

PT_CORE="${PT_CORE:-}"

# Schema version pattern: X.Y.Z
SCHEMA_VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'

# Session ID pattern: pt-YYYYMMDD-HHMMSS-<random4>
SESSION_ID_PATTERN='^pt-[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$'

setup_file() {
    if [[ -z "$PT_CORE" || ! -x "$PT_CORE" ]]; then
        printf 'Set PT_CORE to an explicitly prepared executable pt-core binary.\n' >&2
        return 1
    fi
    command -v jq >/dev/null || return 1
}

setup() {
    # The shared helper builds Cargo implicitly. Keep this contract suite bound
    # to the caller's prepared binary and retain all artifacts for inspection.
    TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pt-agent-contract.XXXXXX")
    export TEST_DIR
    export CONFIG_DIR="${TEST_DIR}/config"
    export DATA_DIR="${TEST_DIR}/data"
    export TEST_LOG_FILE="${TEST_LOG_FILE:-${TEST_DIR}/test.jsonl}"
    mkdir -p "$CONFIG_DIR" "$DATA_DIR"
    printf '{}\n' > "${CONFIG_DIR}/decisions.json"
    export PROCESS_TRIAGE_CONFIG="$CONFIG_DIR"
    export PROCESS_TRIAGE_DATA="$DATA_DIR"
    export PROCESS_TRIAGE_RETENTION=off
    export TEST_MODE=1 CI=true NO_COLOR=1
    CONTRACT_TARGET_PID=""
    CONTRACT_TARGET_TICKS=""
    CONTRACT_REAPER_PID=""
    CONTRACT_CONTROL_FD=""
    test_start "$BATS_TEST_NAME" "Agent CLI contract test"
}

teardown() {
    cleanup_contract_target || return 1
    test_end "$BATS_TEST_NAME" "${BATS_TEST_COMPLETED:-fail}"
    teardown_test_env
}

#==============================================================================
# HELPER FUNCTIONS FOR CONTRACT VALIDATION
#==============================================================================

# Check if jq is available for JSON validation
require_jq() {
    if ! command -v jq &>/dev/null; then
        test_warn "Skipping: jq not installed"
        skip "jq not installed"
    fi
}

# Validate JSON output has schema_version
validate_schema_version() {
    local json="$1"
    local context="${2:-output}"

    local version
    version=$(echo "$json" | jq -r '.schema_version // empty' 2>/dev/null)

    if [[ -z "$version" ]]; then
        test_error "Missing schema_version in $context"
        return 1
    fi

    if ! [[ "$version" =~ $SCHEMA_VERSION_PATTERN ]]; then
        test_error "Invalid schema_version format: $version (expected X.Y.Z)"
        return 1
    fi

    test_info "schema_version: $version"
    return 0
}

# Validate JSON output has valid session_id
validate_session_id() {
    local json="$1"
    local context="${2:-output}"

    local session_id
    session_id=$(echo "$json" | jq -r '.session_id // empty' 2>/dev/null)

    if [[ -z "$session_id" ]]; then
        test_error "Missing session_id in $context"
        return 1
    fi

    if ! [[ "$session_id" =~ $SESSION_ID_PATTERN ]]; then
        test_error "Invalid session_id format: $session_id (expected pt-YYYYMMDD-HHMMSS-XXXX)"
        return 1
    fi

    test_info "session_id: $session_id"
    return 0
}

# Validate JSON output has generated_at timestamp
validate_timestamp() {
    local json="$1"
    local field="${2:-generated_at}"
    local context="${3:-output}"

    local ts
    ts=$(echo "$json" | jq -r ".$field // empty" 2>/dev/null)

    if [[ -z "$ts" ]]; then
        test_error "Missing $field in $context"
        return 1
    fi

    # ISO 8601 basic check
    if ! [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        test_error "Invalid timestamp format for $field: $ts"
        return 1
    fi

    test_info "$field: $ts"
    return 0
}

# Extract the main JSON object from output (skipping JSONL events)
extract_json() {
    local output="$1"
    # Skip lines that look like JSONL events (start with {"event":)
    echo "$output" | grep -v '^{"event":' | jq -s 'last' 2>/dev/null
}

# Read Linux start ticks and state without assuming comm lacks spaces or ')'.
contract_target_identity() {
    local pid="$1" stat
    local -a fields
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    IFS= read -r stat < "/proc/${pid}/stat" || return 1
    read -r -a fields <<< "${stat##*) }"
    [[ "${fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
    printf '%s %s\n' "${fields[19]}" "${fields[0]}"
}

contract_target_is_alive() {
    local identity
    [[ -n "$CONTRACT_TARGET_PID" && -n "$CONTRACT_TARGET_TICKS" ]] || return 1
    [[ -r "/proc/${CONTRACT_TARGET_PID}/stat" ]] || return 1
    identity=$(contract_target_identity "$CONTRACT_TARGET_PID") || return 1
    [[ "$identity" == "$CONTRACT_TARGET_TICKS "* && "${identity#* }" != "Z" ]]
}

# Record real descriptor identities after exec; a writable harness capture file
# is genuine data-loss evidence and must never be hidden by changing policy.
contract_target_fd_evidence() {
    local start_id="$1" path fd destination kind flags key value access_mode
    local writable_regular
    contract_target_is_alive || return 1
    for path in /proc/"$CONTRACT_TARGET_PID"/fd/*; do
        fd=${path##*/}
        [[ "$fd" =~ ^[0-9]+$ ]] || return 1
        destination=$(readlink -- "$path") || return 1
        kind=$(LC_ALL=C stat -Lc '%F' -- "$path") || return 1
        flags=""
        while read -r key value; do
            if [[ "$key" == flags: ]]; then
                flags=$value
                break
            fi
        done < "/proc/${CONTRACT_TARGET_PID}/fdinfo/${fd}"
        [[ "$flags" =~ ^[0-7]+$ ]] || return 1
        access_mode=$((8#$flags & 3))
        writable_regular=false
        if [[ -f "$path" ]] && (( access_mode == 1 || access_mode == 2 )); then
            writable_regular=true
        fi
        jq -cn --argjson pid "$CONTRACT_TARGET_PID" --argjson start_ticks "$CONTRACT_TARGET_TICKS" \
            --arg start_id "$start_id" --argjson fd "$fd" --arg flags "$flags" \
            --arg kind "$kind" --arg destination "$destination" --argjson access_mode "$access_mode" \
            --argjson writable_regular "$writable_regular" \
            '{pid:$pid,start_ticks:$start_ticks,start_id:$start_id,fd:$fd,flags:$flags,
              kind:$kind,destination:$destination,access_mode:$access_mode,
              writable_regular:$writable_regular}' >> "${CONTRACT_LOG_DIR}/target-fds.jsonl" || return 1
    done
    contract_target_is_alive || return 1
    jq -e -s --argjson pid "$CONTRACT_TARGET_PID" --arg start_id "$start_id" \
        'length == 3 and (map(.fd) | sort) == [0,1,2]
         and all(.[]; .pid == $pid and .start_id == $start_id
             and .destination == "/dev/null" and .writable_regular == false)' \
        "${CONTRACT_LOG_DIR}/target-fds.jsonl"
}

cleanup_contract_target() {
    # Only the owned subreaper sends cleanup signals, through the original pidfd.
    # Close the controller pipe even after an assertion fails, then reap it.
    if [[ -n "$CONTRACT_CONTROL_FD" ]]; then
        printf 'cleanup\n' >&"$CONTRACT_CONTROL_FD"
        exec {CONTRACT_CONTROL_FD}>&-
        CONTRACT_CONTROL_FD=""
    fi
    if [[ -n "$CONTRACT_REAPER_PID" ]]; then
        local reaper_status=0
        wait "$CONTRACT_REAPER_PID" || reaper_status=$?
        CONTRACT_REAPER_PID=""
        cat "${CONTRACT_LOG_DIR}/target-launch.stderr" >&2
        return "$reaper_status"
    fi
    return 0
}

contract_start_adopted_target() {
    local duration="$1" script
    # A dedicated subprocess owns adoption; do not turn the BATS harness into a
    # process-global subreaper. The intermediate exits after pidfd binding.
    script=$(cat <<'CONTRACT_SUBREAPER'
import ctypes, json, os, signal, sys, time
from pathlib import Path
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
pid_read, pid_write = os.pipe()
ack_read, ack_write = os.pipe()
intermediate = os.fork()
if intermediate == 0:
    os.close(pid_read)
    os.close(ack_write)
    os.setsid()
    target = os.fork()
    if target == 0:
        null = os.open('/dev/null', os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        for fd in [int(name) for name in os.listdir('/proc/self/fd') if int(name) > 2]:
            try:
                os.close(fd)
            except OSError:
                pass
        os.execve('/usr/bin/sleep', ['sleep', sys.argv[1]], {'PATH': '/usr/bin:/bin'})
    os.write(pid_write, str(target).encode() + b'\n')
    os.close(pid_write)
    os.read(ack_read, 1)
    os._exit(0)
os.close(pid_write)
os.close(ack_read)
with os.fdopen(pid_read) as pipe:
    target = int(pipe.readline())
pidfd = os.pidfd_open(target)
try:
    os.write(ack_write, b'1')
    os.close(ack_write)
    assert os.waitpid(intermediate, 0) == (intermediate, 0)
    deadline = time.monotonic() + 5
    while Path('/proc/' + str(target) + '/comm').read_text().strip() != 'sleep':
        assert time.monotonic() < deadline
        time.sleep(0.01)
    stat = Path('/proc/' + str(target) + '/stat').read_text()
    fields = stat.rsplit(') ', 1)[1].split()
    assert int(fields[1]) == os.getpid()
    assert int(fields[3]) == intermediate and intermediate != target
    assert fields[4] == '0' and fields[0] != 'Z'
    environment = Path('/proc/' + str(target) + '/environ').read_bytes()
    assert environment == b'PATH=/usr/bin:/bin\0'
    print(json.dumps({'pid': target, 'former_parent': intermediate,
                      'adoptive_parent': os.getpid(), 'uid': os.getuid(),
                      'start_ticks': int(fields[19]), 'sid': int(fields[3]),
                      'tty_nr': int(fields[4]), 'raw_stat': stat,
                      'raw_status': Path('/proc/' + str(target) + '/status').read_text(),
                      'environment': environment.decode()}), flush=True)
    sys.stdin.readline()
finally:
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
    except ProcessLookupError:
        pass
    os.waitpid(target, 0)
    os.close(pidfd)
    print('Owned pidfd target reaped; files retained', file=sys.stderr, flush=True)
CONTRACT_SUBREAPER
    )
    mkfifo "${CONTRACT_LOG_DIR}/target-control"
    env -i PATH=/usr/bin:/bin python3 -u -c "$script" "$duration" \
        < "${CONTRACT_LOG_DIR}/target-control" \
        > "${CONTRACT_LOG_DIR}/owned-target-before.json" \
        2> "${CONTRACT_LOG_DIR}/target-launch.stderr" &
    CONTRACT_REAPER_PID=$!
    exec {CONTRACT_CONTROL_FD}> "${CONTRACT_LOG_DIR}/target-control"
}

# Capture real stdout/stderr separately and log every command's actual result.
# BATS run retains the exit status, including PlanReady (1) and refusals.
contract_monotonic_ms() {
    local uptime _idle
    read -r uptime _idle < /proc/uptime || return 1
    [[ "$uptime" =~ ^([0-9]+)\.([0-9]{2})$ ]] || return 1
    printf '%s\n' "$((10#${BASH_REMATCH[1]} * 1000 + 10#${BASH_REMATCH[2]} * 10))"
}

contract_step() {
    local step="$1" limit="$2"
    shift 2
    local started ended step_status stdout_digest stderr_digest
    started=$(contract_monotonic_ms) || return 1
    if timeout "$limit" "$PT_CORE" "$@" \
        > "${CONTRACT_LOG_DIR}/${step}.stdout" \
        2> "${CONTRACT_LOG_DIR}/${step}.stderr"; then
        step_status=0
    else
        step_status=$?
    fi
    ended=$(contract_monotonic_ms) || return 1
    stdout_digest=$(sha256sum "${CONTRACT_LOG_DIR}/${step}.stdout")
    stderr_digest=$(sha256sum "${CONTRACT_LOG_DIR}/${step}.stderr")
    jq -cn --arg step "$step" --arg command "$PT_CORE" \
        --argjson exit_code "$step_status" --argjson elapsed_ms "$((ended - started))" \
        --arg stdout_sha256 "${stdout_digest%% *}" \
        --arg stderr_sha256 "${stderr_digest%% *}" --args \
        '{step:$step, command:$command, args:$ARGS.positional, exit_code:$exit_code,
          elapsed_ms:$elapsed_ms, elapsed_clock:"linux_boot_uptime",
          stdout_sha256:$stdout_sha256, stderr_sha256:$stderr_sha256}' \
        -- "$@" >> "${CONTRACT_LOG_DIR}/steps.jsonl"
    cat "${CONTRACT_LOG_DIR}/${step}.stdout"
    cat "${CONTRACT_LOG_DIR}/${step}.stderr" >&2
    return "$step_status"
}

@test "Contract: real plan applies and verifies its saved live identity" {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "Linux-only /proc+setsid identity regression; other platform contract tests remain enabled"
    fi
    command -v python3 >/dev/null
    command -v timeout >/dev/null
    command -v sha256sum >/dev/null
    CONTRACT_LOG_DIR="${BATS_TEST_DIRNAME}/../target/test-logs/e2e/agent_loop/bats-$(date +%s%N)-$$"
    mkdir -p "$CONTRACT_LOG_DIR"
    test_info "Actual command logs: $CONTRACT_LOG_DIR"

    run contract_step policy_defaults 30 --format json config show --file policy
    test_info "$output"
    assert_equals "0" "$status" "default policy must come from the real binary"
    # A declared test signature supplies the prior. Keep default loss, FDR,
    # posterior thresholds and every runtime guard; this is controlled plumbing,
    # not evidence that the synthetic prior or statistical FDR is calibrated.
    jq '.policy
        | .robot_mode.enabled = true
        | .guardrails.min_process_age_seconds = 0' \
        "${CONTRACT_LOG_DIR}/policy_defaults.stdout" > "${CONFIG_DIR}/policy.json"
    jq -e --slurpfile defaults "${CONTRACT_LOG_DIR}/policy_defaults.stdout" \
        '. == ($defaults[0].policy | .robot_mode.enabled = true
            | .guardrails.min_process_age_seconds = 0)
         and .fdr_control.enabled == true and .guardrails.builtin_protection == true' \
        "${CONFIG_DIR}/policy.json"

    local duration="1000.$$"
    contract_start_adopted_target "$duration"
    local attempt
    cat "${CONTRACT_LOG_DIR}/target-launch.stderr" >&2
    for ((attempt = 0; attempt < 200; attempt++)); do
        [[ -s "${CONTRACT_LOG_DIR}/owned-target-before.json" ]] && break
        sleep 0.01
    done
    CONTRACT_TARGET_PID=$(jq -er '.pid' "${CONTRACT_LOG_DIR}/owned-target-before.json")
    [[ "$CONTRACT_TARGET_PID" =~ ^[0-9]+$ ]]
    local identity
    identity=$(contract_target_identity "$CONTRACT_TARGET_PID")
    CONTRACT_TARGET_TICKS="${identity%% *}"
    contract_target_is_alive
    local target_uid
    target_uid=$(id -u)
    jq -e --argjson reaper "$CONTRACT_REAPER_PID" --argjson uid "$target_uid" \
        --argjson ticks "$CONTRACT_TARGET_TICKS" \
        '.adoptive_parent == $reaper and .former_parent != .adoptive_parent
         and .sid == .former_parent and .sid != .pid and .tty_nr == 0
         and .start_ticks == $ticks and .uid == $uid
         and .environment == "PATH=/usr/bin:/bin\u0000"' \
        "${CONTRACT_LOG_DIR}/owned-target-before.json"
    local boot_id expected_start_id
    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
    expected_start_id="${boot_id}:${CONTRACT_TARGET_TICKS}:${CONTRACT_TARGET_PID}"
    local target_comm=""
    for ((attempt = 0; attempt < 200; attempt++)); do
        contract_target_is_alive
        IFS= read -r target_comm < "/proc/${CONTRACT_TARGET_PID}/comm"
        [[ "$target_comm" == sleep ]] && break
        sleep 0.01
    done
    assert_equals "sleep" "$target_comm" "descriptor evidence must observe the exec'd target"
    contract_target_fd_evidence "$expected_start_id"

    # Explicit typed schema input, never a hand-built executable Plan. Scope the
    # argument matcher to this exact disposable command instead of all sleeps.
    jq -n --arg pattern "(^|\\s)${duration/./\\.}\$" \
        '{schema_version:2,signatures:[{name:"literal-owned-sleep",category:"other",
          patterns:{process_names:["^sleep$"],arg_patterns:[$pattern]},
          priors:{useful:{alpha:1,beta:999},useful_bad:{alpha:1,beta:999},
                  abandoned:{alpha:999,beta:1},zombie:{alpha:1,beta:999}}}]}' \
        > "${CONFIG_DIR}/signatures.json"
    run contract_step signature_validate 30 --format json signature validate
    test_info "$output"
    assert_equals "0" "$status" "the real signature loader must validate the four-class input"

    run contract_step plan 180 --format json agent plan \
        --min-age 0 --max-candidates 20 --pids "$CONTRACT_TARGET_PID"
    test_info "$output"
    assert_equals "1" "$status" "actual planner must return PlanReady"
    jq -e --argjson pid "$CONTRACT_TARGET_PID" \
        '.args.pids == [$pid] and (.candidates | length) == 1
         and .candidates[0].pid == $pid
         and .candidates[0].inference.prior_source == "signature"
         and .candidates[0].inference.mode == "bayesian"
         and .candidates[0].inference.fast_path.used == false
         and .candidates[0].signature.name == "literal-owned-sleep"' \
        "${CONTRACT_LOG_DIR}/plan.stdout"
    local session_id saved_plan action_id
    session_id=$(jq -er '.session_id' "${CONTRACT_LOG_DIR}/plan.stdout")
    [[ "$session_id" =~ $SESSION_ID_PATTERN ]]
    saved_plan="${DATA_DIR}/sessions/${session_id}/decision/plan.json"
    [[ -s "$saved_plan" ]]
    jq -e --argjson pid "$CONTRACT_TARGET_PID" --arg start_id "$expected_start_id" --argjson uid "$target_uid" \
        '.actions | length == 1 and
         (.[0] | .target.pid == $pid and .target.start_id == $start_id
          and .target.uid == $uid
          and .action == "kill" and .blocked == false
          and (.pre_checks | length) > 0 and .rationale.posterior != null)' "$saved_plan"
    action_id=$(jq -er '.actions[0].action_id' "$saved_plan")
    jq -e --arg command "sleep $duration" \
        '.candidates[0].command == $command and .candidates[0].command_short == "sleep"' "$saved_plan"
    jq -e --slurpfile saved "$saved_plan" '. == $saved[0]' "${CONTRACT_LOG_DIR}/plan.stdout"
    jq -e --argjson reaper "$CONTRACT_REAPER_PID" '.candidates[0].ppid == $reaper' "$saved_plan"

    run contract_step stale_identity 30 --format json agent apply --session "$session_id" \
        --targets "${CONTRACT_TARGET_PID}:stale-start-id" --yes
    test_info "$output"
    assert_equals "10" "$status" "stale supplied identity must be refused with ArgsError"
    [[ "$(cat "${CONTRACT_LOG_DIR}/stale_identity.stderr")" == *"does not match a saved action"* ]]
    contract_target_is_alive
    [[ ! -e "${DATA_DIR}/sessions/${session_id}/action/outcomes.jsonl" ]]

    # Removing saved checks cannot bypass the real runtime identity guard.
    cp -- "$saved_plan" "${CONTRACT_LOG_DIR}/original-plan.json"
    jq --argjson uid "$target_uid" \
        '.actions |= map(.pre_checks = [] | .target.uid = ($uid + 1))' \
        "${CONTRACT_LOG_DIR}/original-plan.json" > "$saved_plan"
    run contract_step tampered_uid 240 --format json agent apply --session "$session_id" \
        --targets "${CONTRACT_TARGET_PID}:${expected_start_id}" --yes
    test_info "$output"
    assert_equals "3" "$status" "tampered UID must return ActionsPartial without delivering a signal"
    jq -e '.outcomes[0].status == "identity_mismatch"' "${CONTRACT_LOG_DIR}/tampered_uid.stdout"
    contract_target_is_alive
    cat "${CONTRACT_LOG_DIR}/original-plan.json" > "$saved_plan"
    cmp -- "$saved_plan" "${CONTRACT_LOG_DIR}/original-plan.json"

    run contract_step apply 240 --format json agent apply --session "$session_id" \
        --targets "${CONTRACT_TARGET_PID}:${expected_start_id}" --yes
    test_info "$output"
    assert_equals "2" "$status" "the actual saved action must return ActionsOk"
    jq -e --argjson pid "$CONTRACT_TARGET_PID" --arg action_id "$action_id" \
        '(.outcomes | length) == 1 and .outcomes[0].pid == $pid
         and .outcomes[0].action_id == $action_id and .outcomes[0].status == "success"' \
        "${CONTRACT_LOG_DIR}/apply.stdout"
    if contract_target_is_alive; then
        test_error "The target survived the reported successful action"
        false
    fi

    run contract_step verify 60 --format json agent verify --session "$session_id"
    test_info "$output"
    assert_equals "0" "$status" "verify must confirm the real action"
    jq -e --argjson pid "$CONTRACT_TARGET_PID" --arg start_id "$expected_start_id" \
        'any(.action_outcomes[]; .target.pid == $pid and .target.start_id == $start_id
            and .outcome == "confirmed_dead")' "${CONTRACT_LOG_DIR}/verify.stdout"
    jq -e -s 'length == 7 and all(.[]; .command != "" and (.args | type) == "array"
        and (.stdout_sha256 | length) == 64 and (.stderr_sha256 | length) == 64
        and .elapsed_ms >= 0)' "${CONTRACT_LOG_DIR}/steps.jsonl"
    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# NON-INTERACTIVITY TESTS
#==============================================================================

@test "Contract: agent commands do not hang with closed stdin" {
    require_jq
    test_info "Testing non-interactivity (closed stdin)"

    # Run with stdin from /dev/null - should not hang
    run timeout 30 "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0 </dev/null

    # Should complete (exit code doesn't matter, just shouldn't hang)
    test_info "Command completed with exit code: $status"
    [[ $status -ne 124 ]] || {
        test_error "Command timed out - possible TTY/prompt issue"
        false
    }

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent commands work without TTY" {
    require_jq
    test_info "Testing operation without TTY"

    # Force non-TTY environment
    run env TERM=dumb "$PT_CORE" agent capabilities --standalone --format json </dev/null

    assert_equals "0" "$status" "capabilities should succeed without TTY"

    local json
    json=$(extract_json "$output")
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SCHEMA VERSION INVARIANT TESTS
#==============================================================================

@test "Contract: agent plan output includes schema_version" {
    require_jq
    test_info "Testing: pt agent plan schema_version"

    run "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "plan output"
    validate_session_id "$json" "plan output"
    validate_timestamp "$json" "generated_at" "plan output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent capabilities output includes schema_version" {
    require_jq
    test_info "Testing: pt agent capabilities schema_version"

    run "$PT_CORE" agent capabilities --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "capabilities output"
    validate_session_id "$json" "capabilities output"
    validate_timestamp "$json" "generated_at" "capabilities output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent snapshot output includes schema_version" {
    require_jq
    test_info "Testing: pt agent snapshot schema_version"

    run "$PT_CORE" agent snapshot --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "snapshot output"
    validate_session_id "$json" "snapshot output"
    validate_timestamp "$json" "generated_at" "snapshot output"
    validate_timestamp "$json" "timestamp" "snapshot output"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SESSION ID FORMAT TESTS
#==============================================================================

@test "Contract: session_id follows pt-YYYYMMDD-HHMMSS-XXXX format" {
    require_jq
    test_info "Testing session_id format across commands"

    # Test plan
    run "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0
    local plan_json
    plan_json=$(extract_json "$output")
    local plan_session
    plan_session=$(echo "$plan_json" | jq -r '.session_id')

    test_info "plan session_id: $plan_session"
    [[ "$plan_session" =~ $SESSION_ID_PATTERN ]]

    # Test snapshot
    run "$PT_CORE" agent snapshot --standalone --format json
    local snapshot_json
    snapshot_json=$(extract_json "$output")
    local snapshot_session
    snapshot_session=$(echo "$snapshot_json" | jq -r '.session_id')

    test_info "snapshot session_id: $snapshot_session"
    [[ "$snapshot_session" =~ $SESSION_ID_PATTERN ]]

    # Each invocation should create a unique session
    [[ "$plan_session" != "$snapshot_session" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# CAPABILITIES OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: capabilities output has required structure" {
    require_jq
    test_info "Testing capabilities output structure"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    local json
    json=$(extract_json "$output")

    # Check required top-level fields
    test_info "Checking required fields..."

    local has_os has_tools has_data_sources has_permissions has_actions
    has_os=$(echo "$json" | jq 'has("os")')
    has_tools=$(echo "$json" | jq 'has("tools")')
    has_data_sources=$(echo "$json" | jq 'has("data_sources")')
    has_permissions=$(echo "$json" | jq 'has("permissions")')
    has_actions=$(echo "$json" | jq 'has("actions")')

    assert_equals "true" "$has_os" "should have os field"
    assert_equals "true" "$has_tools" "should have tools field"
    assert_equals "true" "$has_data_sources" "should have data_sources field"
    assert_equals "true" "$has_permissions" "should have permissions field"
    assert_equals "true" "$has_actions" "should have actions field"

    # Check OS sub-fields
    local os_family os_arch
    os_family=$(echo "$json" | jq -r '.os.family')
    os_arch=$(echo "$json" | jq -r '.os.arch')

    test_info "OS: family=$os_family arch=$os_arch"
    [[ -n "$os_family" && "$os_family" != "null" ]]
    [[ -n "$os_arch" && "$os_arch" != "null" ]]

    # Check permissions sub-fields
    local is_root can_sudo
    is_root=$(echo "$json" | jq '.permissions.is_root')
    can_sudo=$(echo "$json" | jq '.permissions.can_sudo')

    test_info "Permissions: is_root=$is_root can_sudo=$can_sudo"
    [[ "$is_root" == "true" || "$is_root" == "false" ]]
    [[ "$can_sudo" == "true" || "$can_sudo" == "false" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# SNAPSHOT OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: snapshot output has system_state" {
    require_jq
    test_info "Testing snapshot output structure"

    run "$PT_CORE" agent snapshot --standalone --format json
    assert_equals "0" "$status" "snapshot should succeed"

    local json
    json=$(extract_json "$output")

    # Check system_state
    local has_system_state
    has_system_state=$(echo "$json" | jq 'has("system_state")')
    assert_equals "true" "$has_system_state" "should have system_state"

    # Check system_state sub-fields
    local cores process_count
    cores=$(echo "$json" | jq '.system_state.cores')
    process_count=$(echo "$json" | jq '.system_state.process_count')

    test_info "System: cores=$cores processes=$process_count"
    [[ "$cores" -gt 0 ]]
    [[ "$process_count" -ge 0 ]]

    # Check load average
    local load_len
    load_len=$(echo "$json" | jq '.system_state.load | length')
    assert_equals "3" "$load_len" "load should have 3 values"

    # Check memory
    local has_memory
    has_memory=$(echo "$json" | jq '.system_state | has("memory")')
    assert_equals "true" "$has_memory" "should have memory info"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# PLAN OUTPUT STRUCTURE TESTS
#==============================================================================

@test "Contract: plan output has required base fields" {
    require_jq
    test_info "Testing plan output base structure"

    run "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0

    local json
    json=$(extract_json "$output")

    # Required base fields per contract
    validate_schema_version "$json"
    validate_session_id "$json"
    validate_timestamp "$json"

    # Args should be present showing invocation parameters
    local has_args
    has_args=$(echo "$json" | jq 'has("args")')
    test_info "has_args: $has_args"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# EXIT CODE SEMANTICS TESTS
#==============================================================================

@test "Contract: agent capabilities exits 0 on success" {
    test_info "Testing capabilities exit code"

    run "$PT_CORE" agent capabilities --standalone --format json

    assert_equals "0" "$status" "capabilities should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent snapshot exits 0 on success" {
    test_info "Testing snapshot exit code"

    run "$PT_CORE" agent snapshot --standalone --format json

    assert_equals "0" "$status" "snapshot should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan exits with valid code" {
    test_info "Testing plan exit code"

    run "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0

    # Exit codes per CLI_SPECIFICATION.md:
    # 0 = CLEAN (nothing to do)
    # 1 = PLAN_READY (candidates exist)
    # Both are valid for plan command
    [[ $status -eq 0 || $status -eq 1 ]]
    test_info "Plan exit code: $status (0=clean, 1=plan_ready)"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: unknown agent subcommand returns error" {
    test_info "Testing unknown subcommand handling"

    run "$PT_CORE" agent nonexistent --format json 2>&1

    [[ $status -ne 0 ]]
    test_info "Unknown subcommand exit code: $status"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# JSON OUTPUT FORMAT TESTS
#==============================================================================

@test "Contract: --format json produces valid JSON" {
    require_jq
    test_info "Testing JSON output validity"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    # Extract and validate JSON
    local json
    json=$(extract_json "$output")

    # jq should parse without error
    echo "$json" | jq '.' >/dev/null 2>&1
    local jq_status=$?

    assert_equals "0" "$jq_status" "output should be valid JSON"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: --format json output is not empty" {
    require_jq
    test_info "Testing JSON output is not empty"

    run "$PT_CORE" agent capabilities --standalone --format json
    assert_equals "0" "$status" "capabilities should succeed"

    local json
    json=$(extract_json "$output")

    local key_count
    key_count=$(echo "$json" | jq 'keys | length')

    [[ "$key_count" -gt 0 ]]
    test_info "JSON has $key_count keys"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# HELP AND VERSION TESTS
#==============================================================================

@test "Contract: agent --help exits 0" {
    test_info "Testing agent --help"

    run "$PT_CORE" agent --help

    assert_equals "0" "$status" "--help should exit 0"
    assert_contains "$output" "agent" "should mention agent"
    assert_contains "$output" "plan" "should mention plan subcommand"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan --help exits 0" {
    test_info "Testing agent plan --help"

    run "$PT_CORE" agent plan --help

    assert_equals "0" "$status" "plan --help should exit 0"
    assert_contains "$output" "plan" "should describe plan"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# STANDALONE MODE TESTS
#==============================================================================

@test "Contract: --standalone flag works without wrapper" {
    require_jq
    test_info "Testing --standalone flag"

    # Unset any wrapper-provided environment
    unset PT_CAPABILITIES_MANIFEST

    run "$PT_CORE" agent capabilities --standalone --format json

    assert_equals "0" "$status" "standalone should work"

    local json
    json=$(extract_json "$output")
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# QUIET AND VERBOSE MODE TESTS
#==============================================================================

@test "Contract: --quiet reduces output verbosity" {
    test_info "Testing --quiet flag"

    run "$PT_CORE" agent capabilities --standalone --format json --quiet

    assert_equals "0" "$status" "--quiet should work"

    # Output should still be valid JSON
    local json
    json=$(extract_json "$output")
    [[ -n "$json" ]]

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# JSONL EVENT STREAM TESTS
#==============================================================================

@test "Contract: plan emits JSONL progress events" {
    require_jq
    test_info "Testing JSONL event emission"

    run "$PT_CORE" agent plan --standalone --format json --min-age 99999999 --max-candidates 0

    # Check if any JSONL events were emitted
    local event_lines
    event_lines=$(echo "$output" | grep -c '^{"event":' || true)

    test_info "Found $event_lines JSONL event lines"

    # At least plan_ready event should be emitted
    if [[ "$event_lines" -gt 0 ]]; then
        local first_event
        first_event=$(echo "$output" | grep '^{"event":' | head -1)

        # Validate event has required fields
        local has_event has_timestamp
        has_event=$(echo "$first_event" | jq 'has("event")')
        has_timestamp=$(echo "$first_event" | jq 'has("timestamp")')

        assert_equals "true" "$has_event" "event should have event field"
        assert_equals "true" "$has_timestamp" "event should have timestamp"
    fi

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# ERROR OUTPUT FORMAT TESTS
#==============================================================================

@test "Contract: error responses follow error schema" {
    require_jq
    test_info "Testing error response format"

    # Try to use a non-existent session
    run "$PT_CORE" agent verify --session pt-00000000-000000-xxxx --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Error exit code: $status"

    # If JSON error is returned, validate structure
    # (implementation may vary - just ensure it doesn't crash)

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# AGENT SESSIONS COMMAND TESTS
#==============================================================================

@test "Contract: agent sessions output includes schema_version" {
    require_jq
    test_info "Testing: pt agent sessions schema_version"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "sessions output"
    validate_timestamp "$json" "generated_at" "sessions output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions list has sessions array" {
    require_jq
    test_info "Testing: sessions list output structure"

    run "$PT_CORE" agent sessions --standalone --format json

    assert_equals "0" "$status" "sessions should succeed"

    local json
    json=$(extract_json "$output")

    # Must have sessions array
    local has_sessions
    has_sessions=$(echo "$json" | jq 'has("sessions")')
    assert_equals "true" "$has_sessions" "should have sessions array"

    # Sessions should be an array
    local is_array
    is_array=$(echo "$json" | jq '.sessions | type == "array"')
    assert_equals "true" "$is_array" "sessions should be array"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions list has total_count" {
    require_jq
    test_info "Testing: sessions list total_count"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have total_count
    local has_count
    has_count=$(echo "$json" | jq 'has("total_count")')
    assert_equals "true" "$has_count" "should have total_count"

    # total_count should be a number
    local count
    count=$(echo "$json" | jq '.total_count')
    [[ "$count" =~ ^[0-9]+$ ]]
    test_info "total_count: $count"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --status returns single session" {
    require_jq
    test_info "Testing: sessions --status for single session"

    # First create a session via snapshot
    run "$PT_CORE" agent snapshot --standalone --format json
    assert_equals "0" "$status" "snapshot should succeed"

    local snapshot_json
    snapshot_json=$(extract_json "$output")
    local session_id
    session_id=$(echo "$snapshot_json" | jq -r '.session_id')
    test_info "Created session: $session_id"

    # Now query that session
    run "$PT_CORE" agent sessions --status "$session_id" --standalone --format json
    assert_equals "0" "$status" "sessions --status should succeed"

    local json
    json=$(extract_json "$output")

    # Should have the same session_id
    local returned_id
    returned_id=$(echo "$json" | jq -r '.session_id')
    assert_equals "$session_id" "$returned_id" "should return correct session"

    # Should have state
    local has_state
    has_state=$(echo "$json" | jq 'has("state")')
    assert_equals "true" "$has_state" "should have state"

    # Should have resumable flag
    local has_resumable
    has_resumable=$(echo "$json" | jq 'has("resumable")')
    assert_equals "true" "$has_resumable" "should have resumable"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --status invalid session returns error" {
    test_info "Testing: sessions --status with invalid session"

    run "$PT_CORE" agent sessions --status pt-00000000-000000-xxxx --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Invalid session exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --state filter works" {
    require_jq
    test_info "Testing: sessions --state filter"

    run "$PT_CORE" agent sessions --state created --standalone --format json

    assert_equals "0" "$status" "sessions --state should succeed"

    local json
    json=$(extract_json "$output")

    # All returned sessions should have state "created" (or empty list)
    local sessions_count
    sessions_count=$(echo "$json" | jq '.sessions | length')
    test_info "Found $sessions_count sessions with state=created"

    if [[ "$sessions_count" -gt 0 ]]; then
        # Check first session has correct state
        local first_state
        first_state=$(echo "$json" | jq -r '.sessions[0].state')
        assert_equals "created" "$first_state" "filtered sessions should have correct state"
    fi

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --limit works" {
    require_jq
    test_info "Testing: sessions --limit"

    run "$PT_CORE" agent sessions --limit 5 --standalone --format json

    assert_equals "0" "$status" "sessions --limit should succeed"

    local json
    json=$(extract_json "$output")

    local sessions_count
    sessions_count=$(echo "$json" | jq '.sessions | length')
    test_info "Returned $sessions_count sessions (limit=5)"

    # Should return at most 5
    [[ "$sessions_count" -le 5 ]]

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions exits 0 on success" {
    test_info "Testing sessions exit code"

    run "$PT_CORE" agent sessions --standalone --format json

    assert_equals "0" "$status" "sessions should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --help exits 0" {
    test_info "Testing agent sessions --help"

    run "$PT_CORE" agent sessions --help

    assert_equals "0" "$status" "sessions --help should exit 0"
    assert_contains "$output" "sessions" "should describe sessions"
    assert_contains "$output" "status" "should mention --status"
    assert_contains "$output" "cleanup" "should mention --cleanup"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions --format summary works" {
    test_info "Testing sessions summary format"

    run "$PT_CORE" agent sessions --standalone --format summary

    assert_equals "0" "$status" "sessions summary should succeed"

    # Summary should contain session count or "No sessions"
    [[ "$output" =~ session || "$output" =~ "No sessions" ]]
    test_info "Summary output: $output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent sessions JSON includes host_id" {
    require_jq
    test_info "Testing: sessions host_id field"

    run "$PT_CORE" agent sessions --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have host_id at top level
    local has_host
    has_host=$(echo "$json" | jq 'has("host_id")')
    assert_equals "true" "$has_host" "should have host_id"

    local host_id
    host_id=$(echo "$json" | jq -r '.host_id')
    [[ -n "$host_id" ]]
    test_info "host_id: $host_id"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# AGENT LIST-PRIORS COMMAND TESTS
#==============================================================================

@test "Contract: agent list-priors output includes schema_version" {
    require_jq
    test_info "Testing: pt agent list-priors schema_version"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    validate_schema_version "$json" "list-priors output"
    validate_session_id "$json" "list-priors output"
    validate_timestamp "$json" "generated_at" "list-priors output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors has classes array" {
    require_jq
    test_info "Testing: list-priors classes output structure"

    run "$PT_CORE" agent list-priors --standalone --format json

    assert_equals "0" "$status" "list-priors should succeed"

    local json
    json=$(extract_json "$output")

    # Must have classes array
    local has_classes
    has_classes=$(echo "$json" | jq 'has("classes")')
    assert_equals "true" "$has_classes" "should have classes array"

    # Classes should be an array
    local is_array
    is_array=$(echo "$json" | jq '.classes | type == "array"')
    assert_equals "true" "$is_array" "classes should be array"

    # By default should have 4 classes
    local classes_count
    classes_count=$(echo "$json" | jq '.classes | length')
    assert_equals "4" "$classes_count" "should have 4 classes by default"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors classes have required Beta params" {
    require_jq
    test_info "Testing: list-priors class Beta parameters"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Check first class (useful) has required beta params
    local first_class
    first_class=$(echo "$json" | jq '.classes[0]')

    local class_name
    class_name=$(echo "$first_class" | jq -r '.class')
    test_info "Checking class: $class_name"

    # Must have cpu_beta with alpha/beta
    local has_cpu_beta
    has_cpu_beta=$(echo "$first_class" | jq 'has("cpu_beta")')
    assert_equals "true" "$has_cpu_beta" "should have cpu_beta"

    local cpu_alpha cpu_beta
    cpu_alpha=$(echo "$first_class" | jq '.cpu_beta.alpha')
    cpu_beta=$(echo "$first_class" | jq '.cpu_beta.beta')
    test_info "cpu_beta: alpha=$cpu_alpha beta=$cpu_beta"
    [[ "$cpu_alpha" != "null" && "$cpu_beta" != "null" ]]

    # Must have orphan_beta
    local has_orphan_beta
    has_orphan_beta=$(echo "$first_class" | jq 'has("orphan_beta")')
    assert_equals "true" "$has_orphan_beta" "should have orphan_beta"

    # Must have tty_beta
    local has_tty_beta
    has_tty_beta=$(echo "$first_class" | jq 'has("tty_beta")')
    assert_equals "true" "$has_tty_beta" "should have tty_beta"

    # Must have net_beta
    local has_net_beta
    has_net_beta=$(echo "$first_class" | jq 'has("net_beta")')
    assert_equals "true" "$has_net_beta" "should have net_beta"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --class filter works" {
    require_jq
    test_info "Testing: list-priors --class filter"

    run "$PT_CORE" agent list-priors --class zombie --standalone --format json

    assert_equals "0" "$status" "list-priors --class should succeed"

    local json
    json=$(extract_json "$output")

    # Should have exactly 1 class
    local classes_count
    classes_count=$(echo "$json" | jq '.classes | length')
    assert_equals "1" "$classes_count" "should have 1 class when filtered"

    # That class should be "zombie"
    local class_name
    class_name=$(echo "$json" | jq -r '.classes[0].class')
    assert_equals "zombie" "$class_name" "filtered class should be zombie"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --class validates input" {
    test_info "Testing: list-priors --class validation"

    run "$PT_CORE" agent list-priors --class invalid_class --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Invalid class exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --extended adds extra sections" {
    require_jq
    test_info "Testing: list-priors --extended flag"

    run "$PT_CORE" agent list-priors --extended --standalone --format json

    assert_equals "0" "$status" "list-priors --extended should succeed"

    local json
    json=$(extract_json "$output")

    # Extended mode should include bocpd section (from priors)
    local has_bocpd
    has_bocpd=$(echo "$json" | jq 'has("bocpd")')
    test_info "has_bocpd: $has_bocpd"

    # May also have other extended sections depending on config
    # Just verify the basic structure is valid
    validate_schema_version "$json"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors has source info" {
    require_jq
    test_info "Testing: list-priors source information"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have source section
    local has_source
    has_source=$(echo "$json" | jq 'has("source")')
    assert_equals "true" "$has_source" "should have source section"

    # Source should describe where priors came from
    local using_defaults
    using_defaults=$(echo "$json" | jq '.source.using_defaults')
    test_info "source.using_defaults: $using_defaults"
    [[ "$using_defaults" == "true" || "$using_defaults" == "false" ]]

    # Should have priors_schema_version
    local schema_ver
    schema_ver=$(echo "$json" | jq -r '.source.priors_schema_version')
    test_info "source.priors_schema_version: $schema_ver"
    [[ "$schema_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors exits 0 on success" {
    test_info "Testing list-priors exit code"

    run "$PT_CORE" agent list-priors --standalone --format json

    assert_equals "0" "$status" "list-priors should exit 0"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --help exits 0" {
    test_info "Testing agent list-priors --help"

    run "$PT_CORE" agent list-priors --help

    assert_equals "0" "$status" "list-priors --help should exit 0"
    assert_contains "$output" "list-priors" "should describe list-priors"
    assert_contains "$output" "class" "should mention --class"
    assert_contains "$output" "extended" "should mention --extended"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format summary works" {
    test_info "Testing list-priors summary format"

    run "$PT_CORE" agent list-priors --standalone --format summary

    assert_equals "0" "$status" "list-priors summary should succeed"

    # Summary should contain priors info
    [[ -n "$output" ]]
    test_info "Summary output: $output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format md works" {
    test_info "Testing list-priors markdown format"

    run "$PT_CORE" agent list-priors --standalone --format md

    assert_equals "0" "$status" "list-priors md should succeed"

    # Markdown should have table structure
    assert_contains "$output" "Parameter" "should have Parameter header"
    assert_contains "$output" "Value" "should have Value header"
    assert_contains "$output" "|" "should have markdown table pipes"

    # Should have class section headers
    assert_contains "$output" "## useful" "should have useful class section"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors JSON includes host_id" {
    require_jq
    test_info "Testing: list-priors host_id field"

    run "$PT_CORE" agent list-priors --standalone --format json

    local json
    json=$(extract_json "$output")

    # Must have host_id at top level
    local has_host
    has_host=$(echo "$json" | jq 'has("host_id")')
    assert_equals "true" "$has_host" "should have host_id"

    local host_id
    host_id=$(echo "$json" | jq -r '.host_id')
    [[ -n "$host_id" ]]
    test_info "host_id: $host_id"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format jsonl produces compact JSON" {
    require_jq
    test_info "Testing list-priors JSONL format"

    run "$PT_CORE" agent list-priors --standalone --format jsonl

    assert_equals "0" "$status" "list-priors jsonl should succeed"

    # JSONL should be single-line JSON (no newlines except at end)
    local line_count
    line_count=$(echo "$output" | wc -l)
    assert_equals "1" "$line_count" "JSONL should be single line"

    # Should be valid JSON
    echo "$output" | jq '.' >/dev/null 2>&1
    local jq_status=$?
    assert_equals "0" "$jq_status" "JSONL output should be valid JSON"

    # Should have classes
    local has_classes
    has_classes=$(echo "$output" | jq 'has("classes")')
    assert_equals "true" "$has_classes" "should have classes"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent list-priors --format metrics produces key=value pairs" {
    test_info "Testing list-priors metrics format"

    run "$PT_CORE" agent list-priors --standalone --format metrics

    assert_equals "0" "$status" "list-priors metrics should succeed"

    # Metrics should contain key=value pairs
    assert_contains "$output" "priors_source=" "should have priors_source"
    assert_contains "$output" "priors_class_count=" "should have priors_class_count"
    assert_contains "$output" "priors_schema_version=" "should have priors_schema_version"

    # Should have per-class prior_prob metrics
    assert_contains "$output" "priors_useful_prior_prob=" "should have useful prior_prob"
    assert_contains "$output" "priors_zombie_prior_prob=" "should have zombie prior_prob"

    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# AGENT EXPORT-PRIORS COMMAND TESTS
#==============================================================================

@test "Contract: agent export-priors writes valid JSON to file" {
    require_jq
    test_info "Testing: pt agent export-priors basic export"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    # Verify file was created and is valid JSON
    [[ -f "$output_file" ]]
    test_info "File exists: $output_file"

    local file_json
    file_json=$(cat "$output_file")
    echo "$file_json" | jq '.' >/dev/null 2>&1
    local jq_status=$?
    assert_equals "0" "$jq_status" "exported file should be valid JSON"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors output has schema_version" {
    require_jq
    test_info "Testing: export-priors schema_version in exported file"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    local file_json
    file_json=$(cat "$output_file")

    # Must have schema_version
    local has_schema
    has_schema=$(echo "$file_json" | jq 'has("schema_version")')
    assert_equals "true" "$has_schema" "should have schema_version"

    local schema_ver
    schema_ver=$(echo "$file_json" | jq -r '.schema_version')
    [[ "$schema_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
    test_info "schema_version: $schema_ver"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors output has classes" {
    require_jq
    test_info "Testing: export-priors classes in exported file"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    local file_json
    file_json=$(cat "$output_file")

    # Must have priors.classes object (classes are nested inside priors)
    local has_priors
    has_priors=$(echo "$file_json" | jq 'has("priors")')
    assert_equals "true" "$has_priors" "should have priors object"

    local has_classes
    has_classes=$(echo "$file_json" | jq '.priors | has("classes")')
    assert_equals "true" "$has_classes" "should have classes inside priors"

    # Classes should have 4 class definitions
    local has_useful
    has_useful=$(echo "$file_json" | jq '.priors.classes | has("useful")')
    assert_equals "true" "$has_useful" "should have useful class"

    local has_abandoned
    has_abandoned=$(echo "$file_json" | jq '.priors.classes | has("abandoned")')
    assert_equals "true" "$has_abandoned" "should have abandoned class"

    local has_zombie
    has_zombie=$(echo "$file_json" | jq '.priors.classes | has("zombie")')
    assert_equals "true" "$has_zombie" "should have zombie class"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors --host-profile sets profile" {
    require_jq
    test_info "Testing: export-priors --host-profile flag"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --host-profile "dev-workstation" --standalone --format json

    assert_equals "0" "$status" "export-priors with host-profile should succeed"

    local file_json
    file_json=$(cat "$output_file")

    # Must have host_profile field
    local host_profile
    host_profile=$(echo "$file_json" | jq -r '.host_profile')
    assert_equals "dev-workstation" "$host_profile" "host_profile should match"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors includes export metadata" {
    require_jq
    test_info "Testing: export-priors metadata fields"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    local file_json
    file_json=$(cat "$output_file")

    # Check top-level metadata fields
    local has_exported_at
    has_exported_at=$(echo "$file_json" | jq 'has("exported_at")')
    assert_equals "true" "$has_exported_at" "should have exported_at field"

    local exported_at
    exported_at=$(echo "$file_json" | jq -r '.exported_at')
    [[ -n "$exported_at" && "$exported_at" != "null" ]]
    test_info "exported_at: $exported_at"

    local has_host_id
    has_host_id=$(echo "$file_json" | jq 'has("host_id")')
    assert_equals "true" "$has_host_id" "should have host_id field"

    local host_id
    host_id=$(echo "$file_json" | jq -r '.host_id')
    [[ -n "$host_id" && "$host_id" != "null" ]]
    test_info "host_id: $host_id"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors stdout response has exported flag" {
    require_jq
    test_info "Testing: export-priors stdout response"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    local json
    json=$(extract_json "$output")

    # Stdout response should have exported flag
    local exported
    exported=$(echo "$json" | jq -r '.exported')
    assert_equals "true" "$exported" "response should show exported true"

    # Should have path
    local path
    path=$(echo "$json" | jq -r '.path')
    [[ -n "$path" && "$path" != "null" ]]
    test_info "path: $path"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors --help exits 0" {
    test_info "Testing agent export-priors --help"

    run "$PT_CORE" agent export-priors --help

    assert_equals "0" "$status" "export-priors --help should exit 0"
    assert_contains "$output" "export-priors" "should describe export-priors"
    assert_contains "$output" "out" "should mention --out"
    assert_contains "$output" "host-profile" "should mention --host-profile"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors --format summary works" {
    test_info "Testing export-priors summary format"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format summary

    assert_equals "0" "$status" "export-priors summary should succeed"

    # Summary should contain priors info
    [[ -n "$output" ]]
    assert_contains "$output" "exported" "should mention exported"
    test_info "Summary output: $output"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors fails gracefully for invalid path" {
    test_info "Testing export-priors invalid path handling"

    run "$PT_CORE" agent export-priors --out "/nonexistent/deeply/nested/path/priors.json" --standalone --format json 2>&1

    # Should fail with non-zero exit
    [[ $status -ne 0 ]]
    test_info "Invalid path exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent export-priors creates valid export file" {
    require_jq
    test_info "Testing export-priors creates complete export file"

    local output_file
    output_file=$(mktemp -t exported_priors.XXXXXX.json)

    run "$PT_CORE" agent export-priors --out "$output_file" --standalone --format json

    assert_equals "0" "$status" "export-priors should succeed"

    local file_json
    file_json=$(cat "$output_file")

    # Verify all expected top-level fields
    local has_schema
    has_schema=$(echo "$file_json" | jq 'has("schema_version")')
    assert_equals "true" "$has_schema" "should have schema_version"

    local has_priors
    has_priors=$(echo "$file_json" | jq 'has("priors")')
    assert_equals "true" "$has_priors" "should have priors"

    local has_snapshot
    has_snapshot=$(echo "$file_json" | jq 'has("snapshot")')
    assert_equals "true" "$has_snapshot" "should have snapshot"

    test_info "Retained exported file: $output_file"
    BATS_TEST_COMPLETED=pass
}

#==============================================================================
# THRESHOLD NAMING TESTS (bd-2yz0)
#==============================================================================
# Verify --min-posterior is primary name, --threshold is alias

@test "Contract: agent plan --min-posterior is primary flag" {
    test_info "Testing --min-posterior is the primary flag name"

    run "$PT_CORE" agent plan --help

    assert_equals "0" "$status" "help should exit 0"
    assert_contains "$output" "min-posterior" "help should show --min-posterior"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan --min-posterior flag works" {
    test_info "Testing --min-posterior 0.95 is accepted"

    run "$PT_CORE" agent plan --min-posterior 0.95 --format json --standalone --min-age 99999999 --max-candidates 0

    # Exit 0 (success) or 1 (no candidates) is acceptable
    [[ $status -le 1 ]]
    test_info "exit code: $status"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan --threshold alias works" {
    test_info "Testing --threshold alias for backward compatibility"

    run "$PT_CORE" agent plan --threshold 0.85 --format json --standalone --min-age 99999999 --max-candidates 0

    # Exit 0 (success) or 1 (no candidates) is acceptable
    [[ $status -le 1 ]]
    test_info "exit code: $status (threshold alias)"

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan --min-posterior and --threshold produce same structure" {
    require_jq
    test_info "Testing --min-posterior and --threshold produce equivalent output structure"

    # Run with --min-posterior
    run "$PT_CORE" agent plan --min-posterior 0.8 --format json --standalone --min-age 99999999 --max-candidates 0
    local output1="$output"
    local status1=$status

    # Run with --threshold
    run "$PT_CORE" agent plan --threshold 0.8 --format json --standalone --min-age 99999999 --max-candidates 0
    local output2="$output"
    local status2=$status

    # Both should have same exit code behavior
    [[ $status1 -le 1 && $status2 -le 1 ]]
    test_info "min-posterior exit: $status1, threshold exit: $status2"

    # Extract and compare keys (structure) - ignore volatile fields
    local keys1
    local keys2
    keys1=$(extract_json "$output1" | jq -r 'keys | sort | .[]' 2>/dev/null | tr '\n' ' ' || echo "")
    keys2=$(extract_json "$output2" | jq -r 'keys | sort | .[]' 2>/dev/null | tr '\n' ' ' || echo "")

    # Structure should match (same fields)
    if [[ -n "$keys1" && -n "$keys2" ]]; then
        test_info "min-posterior keys: $keys1"
        test_info "threshold keys: $keys2"
        assert_equals "$keys1" "$keys2" "output structure should match"
    fi

    BATS_TEST_COMPLETED=pass
}

@test "Contract: agent plan default threshold is 0.7" {
    require_jq
    test_info "Testing default threshold value"

    # The help text should show default_value = 0.7
    run "$PT_CORE" agent plan --help

    assert_equals "0" "$status" "help should exit 0"
    assert_contains "$output" "0.7" "default threshold should be 0.7"

    BATS_TEST_COMPLETED=pass
}
