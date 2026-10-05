#!/usr/bin/env bats

PT_SCRIPT="${BATS_TEST_DIRNAME}/../pt"

setup() {
    if [[ ! -x "$PT_SCRIPT" ]]; then
        echo "pt wrapper not found at $PT_SCRIPT" >&2
        exit 1
    fi

    export TEST_DIR="${BATS_TEST_TMPDIR}/pt_wrapper_mode_${BATS_TEST_NUMBER}_$$"
    mkdir -p "$TEST_DIR"

    export MOCK_LOG="${TEST_DIR}/mock.log"
    export MOCK_BIN_DIR="${TEST_DIR}/mock-bin"
    mkdir -p "$MOCK_BIN_DIR"
    export MOCK_PT_CORE="${TEST_DIR}/pt-core-mock"
    export PT_WRAPPER_VERSION
    PT_WRAPPER_VERSION="$(sed -n 's/^readonly VERSION="\([^"]*\)".*/\1/p' "$PT_SCRIPT" | head -n1)"
    if [[ -z "$PT_WRAPPER_VERSION" ]]; then
        echo "failed to parse wrapper version from $PT_SCRIPT" >&2
        exit 1
    fi
    cat > "$MOCK_PT_CORE" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${PT_WRAPPER_TEST_LOG:?PT_WRAPPER_TEST_LOG must be set}"

{
    printf 'PT_UI_MODE=%s\n' "${PT_UI_MODE:-}"
    printf 'CORE_PATH=%s\n' "${BASH_SOURCE[0]}"
    printf 'ARGS=%s\n' "$*"
    printf 'ARG=%s\n' "$@"
} > "$PT_WRAPPER_TEST_LOG"
EOF
    chmod +x "$MOCK_PT_CORE"
}

@test "wrapper: obsolete --shell is forwarded unchanged for core validation" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --shell scan --format json

    [ "$status" -eq 0 ]
    grep -q '^ARGS=--shell scan --format json$' "$MOCK_LOG"
}

@test "wrapper: obsolete --tui is forwarded unchanged for core validation" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --tui run

    [ "$status" -eq 0 ]
    grep -q '^ARGS=--tui run$' "$MOCK_LOG"
}

@test "wrapper: obsolete UI flags are never consumed by the wrapper" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --shell --tui scan

    [ "$status" -eq 0 ]
    grep -q '^ARGS=--shell --tui scan$' "$MOCK_LOG"
}

@test "wrapper: inherited environment passes through without selecting UI mode" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PT_UI_MODE=tui \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=tui$' "$MOCK_LOG"
    grep -q '^ARGS=scan$' "$MOCK_LOG"
}

@test "wrapper: CI and noninteractive input do not synthesize PT_UI_MODE" {
    run env -u PT_UI_MODE \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        CI=true \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=$' "$MOCK_LOG"
}

@test "wrapper: PT_UI_MODE is not interpreted or rewritten" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PT_UI_MODE=invalid_mode \
        TERM=dumb \
        "$PT_SCRIPT" scan

    [ "$status" -eq 0 ]
    grep -q '^PT_UI_MODE=invalid_mode$' "$MOCK_LOG"
}

@test "wrapper: deep alias rewrites to deep-scan before forwarding" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" deep --format json

    [ "$status" -eq 0 ]
    grep -q '^ARGS=deep-scan --format json$' "$MOCK_LOG"
}

@test "wrapper: scan deep rewrites to deep-scan before forwarding" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" scan deep --format json

    [ "$status" -eq 0 ]
    grep -q '^ARGS=deep-scan --format json$' "$MOCK_LOG"
}

@test "wrapper: history reads decision memory without forwarding to pt-core" {
    local config_dir="${TEST_DIR}/config"
    mkdir -p "$config_dir"
    cat > "${config_dir}/decisions.json" << 'EOF'
{"bun test --watch":"kill","vim":"spare"}
EOF

    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PROCESS_TRIAGE_CONFIG="$config_dir" \
        "$PT_SCRIPT" history

    [ "$status" -eq 0 ]
    [[ "$output" == *"Decision history (2 patterns)"* ]]
    [[ "$output" == *"kill: 1"* ]]
    [[ "$output" == *$'kill=1 spare=0\tbun test --watch'* ]]
    [[ "$output" == *$'kill=0 spare=1\tvim'* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: history counts pt-core decision store entries once per verdict" {
    local config_dir="${TEST_DIR}/config"
    mkdir -p "$config_dir"
    # `pt-core agent label` stores each verdict at exact/standard/broad levels.
    cat > "${config_dir}/decisions.json" << 'EOF'
{"exact|node|jest --watch tests/":{"kill":2,"spare":1},"standard|node|jest --watch":{"kill":2,"spare":1,"last":"spare"},"broad|node|":{"kill":2,"spare":1}}
EOF

    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        PROCESS_TRIAGE_CONFIG="$config_dir" \
        "$PT_SCRIPT" history

    [ "$status" -eq 0 ]
    [[ "$output" == *"Decision history (1 patterns)"* ]]
    [[ "$output" == *"kill: 2"* ]]
    [[ "$output" == *"spare: 1"* ]]
    [[ "$output" == *$'kill=2 spare=1\tnode|jest --watch'* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: clear empties decision memory without forwarding to pt-core" {
    local config_dir="${TEST_DIR}/config"
    mkdir -p "$config_dir"
    cat > "${config_dir}/decisions.json" << 'EOF'
{"pattern1":"kill","pattern2":"spare"}
EOF

    run bash -lc "printf 'y\n' | env PT_CORE_PATH='$MOCK_PT_CORE' PT_WRAPPER_TEST_LOG='$MOCK_LOG' PROCESS_TRIAGE_CONFIG='$config_dir' '$PT_SCRIPT' clear"

    [ "$status" -eq 0 ]
    [[ "$output" == *"Cleared 2 decisions."* ]]
    grep -q '^{}$' "${config_dir}/decisions.json"
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: clear with a scope forgets only matching patterns" {
    local config_dir="${TEST_DIR}/config"
    mkdir -p "$config_dir"
    cat > "${config_dir}/decisions.json" << 'EOF'
{"exact|node|jest --watch tests/":{"kill":2,"spare":0},"standard|node|jest --watch":{"kill":2,"spare":0},"broad|node|":{"kill":2,"spare":0},"standard|vim|":{"kill":0,"spare":1}}
EOF

    run bash -lc "printf 'y\n' | env PT_CORE_PATH='$MOCK_PT_CORE' PT_WRAPPER_TEST_LOG='$MOCK_LOG' PROCESS_TRIAGE_CONFIG='$config_dir' '$PT_SCRIPT' clear node"

    [ "$status" -eq 0 ]
    # Counted as `pt history` lists patterns (one verdict is stored at three levels),
    # but every level of a matching pattern is forgotten.
    [[ "$output" == *'Cleared 1 decision matching "node".'* ]]
    [ "$(jq -c 'keys' "${config_dir}/decisions.json")" = '["standard|vim|"]' ]

    # Declining the confirmation changes nothing.
    run bash -lc "printf 'n\n' | env PT_CORE_PATH='$MOCK_PT_CORE' PT_WRAPPER_TEST_LOG='$MOCK_LOG' PROCESS_TRIAGE_CONFIG='$config_dir' '$PT_SCRIPT' clear vim"
    [ "$status" -eq 1 ]
    [ "$(jq -c 'keys' "${config_dir}/decisions.json")" = '["standard|vim|"]' ]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: top-level help shows wrapper-only commands and flags" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" help

    [ "$status" -eq 0 ]
    [[ "$output" == *"Process Triage wrapper for pt-core"* ]]
    [[ "$output" == *"history"* ]]
    [[ "$output" == *"clear"* ]]
    [[ "$output" != *"--shell"* ]]
    [[ "$output" != *"--tui"* ]]
    [[ "$output" == *"daemon"* ]]
    [ "$(printf '%s\n' "$output" | grep -c '^  update ')" -eq 1 ]
    [[ "$output" == *"pt help <subcommand>"* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: --help uses wrapper-aware top-level help" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --help

    [ "$status" -eq 0 ]
    [[ "$output" == *"Process Triage wrapper for pt-core"* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: help with subcommand still forwards to pt-core" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" help query

    [ "$status" -eq 0 ]
    grep -q '^ARGS=help query$' "$MOCK_LOG"
}

@test "wrapper: version reports both halves after leading global options" {
    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --config "${TEST_DIR}/config --tui" --format json --quiet --version

    [ "$status" -eq 0 ]
    # Same contract as the CI install check: first line "pt version X.Y.Z",
    # second line names the pt-core engine the wrapper will run.
    [[ "${lines[0]}" == "pt version ${PT_WRAPPER_VERSION}" ]]
    [[ "${lines[1]}" == *"($MOCK_PT_CORE)"* ]]
    # pt-core is only asked for its own version, not the unrelated global options.
    grep -q '^ARGS=--version$' "$MOCK_LOG"
}

@test "wrapper: version-looking option values and subcommand arguments remain untouched" {
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" --config --version scan
    [ "$status" -eq 0 ]
    grep -q '^ARGS=--config --version scan$' "$MOCK_LOG"
    [[ "$output" != *"pt version"* ]]

    local subcommand_log="${TEST_DIR}/subcommand-version.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$subcommand_log" \
        "$PT_SCRIPT" agent plan --label --version
    [ "$status" -eq 0 ]
    grep -q '^ARGS=agent plan --label --version$' "$subcommand_log"
    [[ "$output" != *"pt version"* ]]

    local equals_log="${TEST_DIR}/equals-version.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$equals_log" \
        "$PT_SCRIPT" --config=--version --format=json -V
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == "pt version ${PT_WRAPPER_VERSION}" ]]
    grep -q '^ARGS=--version$' "$equals_log"
}

@test "wrapper: short clusters report both versions without stealing attached format values" {
    local args index=0
    for args in '-qV' '-vvvv --version' '-vqfjson --version'; do
        index=$((index + 1))
        local log="${TEST_DIR}/cluster-${index}.log"
        # shellcheck disable=SC2086  # fixture contains separate literal CLI arguments
        run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$log" "$PT_SCRIPT" $args
        [ "$status" -eq 0 ]
        [[ "${lines[0]}" == "pt version ${PT_WRAPPER_VERSION}" ]]
        [[ "${lines[1]}" == *"($MOCK_PT_CORE)"* ]]
        grep -q '^ARGS=--version$' "$log"
    done

    local attached_log="${TEST_DIR}/attached-format-value.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$attached_log" \
        "$PT_SCRIPT" -qf--version scan
    [ "$status" -eq 0 ]
    grep -q '^ARGS=-qf--version scan$' "$attached_log"
    [[ "$output" != *"pt version"* ]]

    local separate_log="${TEST_DIR}/separate-format-value.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$separate_log" \
        "$PT_SCRIPT" -qf --version scan
    [ "$status" -eq 0 ]
    grep -q '^ARGS=-qf --version scan$' "$separate_log"
    [[ "$output" != *"pt version"* ]]
}

@test "wrapper: update enforces VERIFY=1 for installer invocation" {
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${@: -1}" == */releases/latest ]]; then
  printf '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
  exit 0
fi

# Return an installer script to stdout. The script fails unless VERIFY=1.
cat <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail
# Like the published installers (<= v2.1.0), which reset VERIFY=0 at startup:
# only the --verify argument turns verification on.
if [[ " $* " != *" --verify "* ]]; then
  echo "VERIFY missing" >&2
  exit 44
fi
exit 0
INSTALLER
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"

    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PATH="${MOCK_BIN_DIR}:$PATH" \
        "$PT_SCRIPT" update

    [ "$status" -eq 0 ]
    [[ "$output" == *"Updating Process Triage to v"* ]]
}

@test "wrapper: update resolves latest version and fetches matching installer" {
    local curl_log="${TEST_DIR}/curl.log"

    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${PT_CURL_LOG:?PT_CURL_LOG must be set}"
url="${@: -1}"
printf '%s\n' "$url" >> "$PT_CURL_LOG"

if [[ "$url" == *"/releases/latest" ]]; then
  printf '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
  exit 0
fi

if [[ "$url" == *"/v9.9.9/install.sh" ]]; then
  cat <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail
# Like the published installers (<= v2.1.0), which reset VERIFY=0 at startup:
# only the --verify argument turns verification on.
if [[ " $* " != *" --verify "* ]]; then
  echo "VERIFY missing" >&2
  exit 44
fi
exit 0
INSTALLER
  exit 0
fi

echo "unexpected url: $url" >&2
exit 31
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"

    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_CURL_LOG="$curl_log" \
        PATH="${MOCK_BIN_DIR}:$PATH" \
        "$PT_SCRIPT" update

    [ "$status" -eq 0 ]
    grep -qx 'https://api.github.com/repos/Dicklesworthstone/process_triage/releases/latest' "$curl_log"
    grep -q '/v9.9.9/install.sh' "$curl_log"
    [ "$(wc -l < "$curl_log")" -eq 2 ]
}

@test "wrapper: update rejects unsafe release metadata without invoking an installer" {
    local curl_log="${TEST_DIR}/curl.log"

    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${PT_CURL_LOG:?PT_CURL_LOG must be set}"
url="${@: -1}"
printf '%s\n' "$url" >> "$PT_CURL_LOG"

if [[ "$url" == *"/releases/latest" ]]; then
  printf '{"tag_name":"v9.9.9;injected","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
  exit 0
fi

echo "unexpected url: $url" >&2
exit 31
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"

    run env \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_WRAPPER_VERSION="$PT_WRAPPER_VERSION" \
        PT_CURL_LOG="$curl_log" \
        PATH="${MOCK_BIN_DIR}:$PATH" \
        "$PT_SCRIPT" update

    [ "$status" -eq 1 ]
    [[ "$output" == *"invalid published release tag"* ]]
    [[ "$output" != *"Updating Process Triage"* ]]
    grep -qx 'https://api.github.com/repos/Dicklesworthstone/process_triage/releases/latest' "$curl_log"
    [ "$(wc -l < "$curl_log")" -eq 1 ]
}

@test "wrapper: malformed draft prerelease and missing publication metadata fail closed" {
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${@: -1}" >> "$PT_CURL_LOG"
printf '%s\n' "$PT_RELEASE_METADATA"
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"

    local metadata index=0
    for metadata in \
        'not-json' \
        '{"tag_name":"v9.9.9","draft":true,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}' \
        '{"tag_name":"v9.9.9","draft":false,"prerelease":true,"published_at":"2026-10-01T00:00:00Z"}' \
        '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":null}' \
        '{"tag_name":999,"draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}'; do
        index=$((index + 1))
        local log="${TEST_DIR}/metadata-${index}.log"
        run env PT_RELEASE_METADATA="$metadata" PT_CURL_LOG="$log" \
            PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
        [ "$status" -eq 1 ]
        [[ "$output" == *"invalid published release metadata"* ]]
        [[ "$output" != *"Updating Process Triage"* ]]
        [ "$(wc -l < "$log")" -eq 1 ]
        grep -qx 'https://api.github.com/repos/Dicklesworthstone/process_triage/releases/latest' "$log"
    done
}

@test "wrapper: release metadata network failure is not a verification failure" {
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "${@: -1}" >> "$PT_CURL_LOG"
printf 'curl: (22) HTTP 403 API rate limit\n' >&2
exit 22
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"
    local log="${TEST_DIR}/metadata-network.log"
    run env PT_CURL_LOG="$log" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
    [ "$status" -eq 1 ]
    [[ "$output" == *"could not fetch published release metadata"* ]]
    [[ "$output" == *"HTTP 403 API rate limit"* ]]
    [[ "$output" != *"verif"* ]]
    [ "$(wc -l < "$log")" -eq 1 ]
}

@test "wrapper: update clearly requires jq before any installer is downloaded" {
    ln -s /bin/bash "${MOCK_BIN_DIR}/bash"
    ln -s /usr/bin/dirname "${MOCK_BIN_DIR}/dirname"
    run env PATH="$MOCK_BIN_DIR" "$PT_SCRIPT" update
    [ "$status" -eq 1 ]
    [[ "$output" == *"jq is required to read published release metadata"* ]]
    [[ "$output" != *"Updating Process Triage"* ]]
}

@test "wrapper: wget fallback reads published metadata and preserves signed installer arguments" {
    local tool
    for tool in bash dirname jq mktemp cat env; do
        ln -s "$(command -v "$tool")" "${MOCK_BIN_DIR}/${tool}"
    done
    cat > "${MOCK_BIN_DIR}/wget" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
printf '%s\n' "$url" >> "$PT_DOWNLOAD_LOG"
if [[ "$url" == */releases/latest ]]; then
  [[ " $* " == *" --header=Accept: application/vnd.github+json "* ]] || exit 32
  printf '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
elif [[ "$url" == */v9.9.9/install.sh ]]; then
  cat <<'INSTALLER'
#!/usr/bin/env bash
printf 'INSTALLER_ARGS=%s\nINSTALLER_VERIFY=%s\n' "$*" "$VERIFY" >> "$PT_INSTALLER_LOG"
[[ "$*" == --verify && "$VERIFY" == 1 ]] || exit 44
INSTALLER
else
  exit 31
fi
EOF
    chmod +x "${MOCK_BIN_DIR}/wget"
    local download_log="${TEST_DIR}/wget.log" installer_log="${TEST_DIR}/wget-installer.log"
    run env PT_DOWNLOAD_LOG="$download_log" PT_INSTALLER_LOG="$installer_log" \
        PATH="$MOCK_BIN_DIR" TMPDIR="$TEST_DIR" "$PT_SCRIPT" update
    [ "$status" -eq 0 ]
    [ "$(wc -l < "$download_log")" -eq 2 ]
    grep -qx 'https://api.github.com/repos/Dicklesworthstone/process_triage/releases/latest' "$download_log"
    grep -qx 'https://raw.githubusercontent.com/Dicklesworthstone/process_triage/v9.9.9/install.sh' "$download_log"
    grep -qx 'INSTALLER_ARGS=--verify' "$installer_log"
    grep -qx 'INSTALLER_VERIFY=1' "$installer_log"
}

@test "wrapper: update keeps the exact published tag and retains its invoked installer" {
    local log="${TEST_DIR}/exact-tag.log"
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
printf '%s\n' "$url" >> "$PT_CURL_LOG"
if [[ "$url" == */releases/latest ]]; then
  printf '{"tag_name":"9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
elif [[ "$url" == */9.9.9/install.sh ]]; then
  printf '#!/usr/bin/env bash\nprintf "retained installer invoked\\n"\n'
else
  exit 31
fi
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"
    run env PT_CURL_LOG="$log" TMPDIR="$TEST_DIR" PATH="${MOCK_BIN_DIR}:$PATH" \
        "$PT_SCRIPT" update
    [ "$status" -eq 0 ]
    [[ "$output" == *"retained installer invoked"* ]]
    grep -qx 'https://raw.githubusercontent.com/Dicklesworthstone/process_triage/9.9.9/install.sh' "$log"
    local -a installers=("${TEST_DIR}"/pt-install.*)
    [ "${#installers[@]}" -eq 1 ]
    [ -f "${installers[0]}" ]
    grep -q 'retained installer invoked' "${installers[0]}"
    [ "$(wc -l < "$log")" -eq 2 ]
}

# Mock curl serving an installer that records its args and fails verification, like
# a real installer facing an unsigned release.
write_unsigned_release_curl() {
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
if [[ "$url" == *"/releases/latest" ]]; then
  printf '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
  exit 0
fi
cat <<'INSTALLER'
#!/usr/bin/env bash
printf 'INSTALLER_ARGS=%s\n' "$*" >> "$PT_INSTALLER_LOG"
printf 'INSTALLER_VERIFY=%s\n' "${VERIFY:-}" >> "$PT_INSTALLER_LOG"
printf 'INSTALLER_PIN=%s\n' "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT:-}" >> "$PT_INSTALLER_LOG"
printf 'INSTALLER_PIN_FILE=%s\n' "${PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE:-}" >> "$PT_INSTALLER_LOG"
if [[ " $* " == *" --verify "* ]]; then
  echo "Release v9.9.9 does not publish release-signing-public.pem" >&2
  exit 1
fi
exit 0
INSTALLER
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"
}

@test "wrapper: update fails closed on an unverifiable release and says how to override" {
    write_unsigned_release_curl
    local log="${TEST_DIR}/installer.log"

    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_INSTALLER_LOG="$log" \
        PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update

    [ "$status" -ne 0 ]
    # The installer's own reason is shown; the wrapper does not guess another one.
    [[ "$output" == *"does not publish release-signing-public.pem"* ]]
    [[ "$output" == *"installer exited with status 1"* ]]
    [[ "$output" == *"pt update --no-verify"* ]]
    grep -q '^INSTALLER_ARGS=--verify$' "$log"
    grep -q '^INSTALLER_VERIFY=1$' "$log"
}

@test "wrapper: explicit --verify preserves the signed installer refusal" {
    write_unsigned_release_curl
    local log="${TEST_DIR}/installer-explicit-verify.log"
    run env PT_INSTALLER_LOG="$log" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update --verify
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not publish release-signing-public.pem"* ]]
    grep -q '^INSTALLER_ARGS=--verify$' "$log"
    grep -q '^INSTALLER_VERIFY=1$' "$log"
}

@test "wrapper: update hands the installer the pinned release key fingerprints" {
    write_unsigned_release_curl
    local log="${TEST_DIR}/installer.log"
    local pins
    pins="$(sed -n 's/^readonly TRUSTED_RELEASE_KEY_FINGERPRINTS="\(.*\)"$/\1/p' "$PT_SCRIPT")"
    [[ "$pins" == *"b5084da80f9652304307fa7c3f965ee7840d3815fd863c2b40f4524e00e2e4ee"* ]]

    run env -u PT_RELEASE_PUBLIC_KEY_FINGERPRINT PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_INSTALLER_LOG="$log" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
    grep -qx "INSTALLER_PIN=${pins}" "$log"

    # An explicit fingerprint in the environment is passed through unchanged.
    log="${TEST_DIR}/installer-explicit-pin.log"
    run env PT_RELEASE_PUBLIC_KEY_FINGERPRINT="abc123" PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_INSTALLER_LOG="$log" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
    grep -qx "INSTALLER_PIN=abc123" "$log"

    # So is a fingerprint file: the wrapper must not add a
    # PT_RELEASE_PUBLIC_KEY_FINGERPRINT, which the installer would prefer.
    log="${TEST_DIR}/installer-pin-file.log"
    run env -u PT_RELEASE_PUBLIC_KEY_FINGERPRINT \
        PT_RELEASE_PUBLIC_KEY_FINGERPRINT_FILE="${TEST_DIR}/pins.txt" \
        PT_CORE_PATH="$MOCK_PT_CORE" \
        PT_INSTALLER_LOG="$log" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
    grep -qx "INSTALLER_PIN=" "$log"
    grep -qx "INSTALLER_PIN_FILE=${TEST_DIR}/pins.txt" "$log"
}

@test "wrapper: update --no-verify is an explicit, warned opt-out" {
    write_unsigned_release_curl
    local log="${TEST_DIR}/installer.log"

    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_INSTALLER_LOG="$log" \
        PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update --no-verify

    [ "$status" -eq 0 ]
    [[ "$output" == *"WITHOUT signature/checksum verification"* ]]
    grep -q '^INSTALLER_ARGS=--no-verify$' "$log"
    grep -q '^INSTALLER_VERIFY=0$' "$log"
}

@test "wrapper: update subcommands pass through to pt-core backup management" {
    for sub in "list-backups" "rollback 2.0.5 --force"; do
        local log="${TEST_DIR}/backup-${sub%% *}.log"
        # shellcheck disable=SC2086
        run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$log" \
            "$PT_SCRIPT" update $sub
        [ "$status" -eq 0 ]
        grep -q "^ARGS=update ${sub}$" "$log"
    done
}

@test "wrapper: update rejects unknown options instead of ignoring them" {
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" update --yolo
    [ "$status" -eq 2 ]
    [[ "$output" == *"unknown update option '--yolo'"* ]]
}

@test "wrapper: runs under bash 3.2 (macOS /bin/bash) with no arguments" {
    # Bare `pt` expanded an empty array under `set -u`, which is an "unbound
    # variable" error in bash 3.2, before pt-core ever ran.
    if ! /bin/bash -c '[[ ${BASH_VERSINFO[0]} -eq 3 ]]' 2>/dev/null; then
        skip "/bin/bash is not bash 3.x on this host"
    fi
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        /bin/bash "$PT_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q '^ARGS=$' "$MOCK_LOG"

    local version_log="${TEST_DIR}/version.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$version_log" \
        /bin/bash "$PT_SCRIPT" --version
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == "pt version ${PT_WRAPPER_VERSION}" ]]
}

# A copy of the wrapper in its own directory with a HOME and PATH where no pt-core
# exists, so a pt-core installed on the test host cannot be found.
isolated_wrapper() {
    local dir="${TEST_DIR}/isolated"
    mkdir -p "$dir" "${TEST_DIR}/home"
    cp "$PT_SCRIPT" "$dir/pt"
    chmod +x "$dir/pt"
    printf '%s\n' "$dir/pt"
}

@test "wrapper: wrapper commands work without pt-core (update is the repair path)" {
    local pt
    pt="$(isolated_wrapper)"
    local -a env_args=(env -u PT_CORE_PATH HOME="${TEST_DIR}/home" PATH="/usr/bin:/bin"
        PROCESS_TRIAGE_CONFIG="${TEST_DIR}/no-config")

    run "${env_args[@]}" "$pt" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Process Triage wrapper for pt-core"* ]]

    run "${env_args[@]}" "$pt" history
    [ "$status" -eq 0 ]
    [[ "$output" == *"No decision history."* ]]

    run "${env_args[@]}" "$pt" clear
    [ "$status" -eq 0 ]
    [[ "$output" == *"Decision history already empty."* ]]
    [ ! -e "${TEST_DIR}/no-config" ]

    run "${env_args[@]}" "$pt" --version
    [ "$status" -eq 0 ]
    [[ "${lines[0]}" == "pt version ${PT_WRAPPER_VERSION}" ]]
    [[ "${lines[1]}" == "pt-core not found" ]]

    run "${env_args[@]}" "$pt" scan
    [ "$status" -eq 1 ]
    [[ "$output" == *"'pt-core' binary not found"* ]]

    write_unsigned_release_curl
    local installer_log="${TEST_DIR}/missing-core-installer.log"
    run env -u PT_CORE_PATH HOME="${TEST_DIR}/home" PATH="${MOCK_BIN_DIR}:/usr/bin:/bin" \
        PT_INSTALLER_LOG="$installer_log" "$pt" update
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not publish release-signing-public.pem"* ]]
    [[ "$output" != *"binary not found"* ]]
    grep -q '^INSTALLER_ARGS=--verify$' "$installer_log"
}

@test "wrapper: a symlinked wrapper finds pt-core next to its real location" {
    # From-source install: `ln -s "$(pwd)/pt" ~/.local/bin/pt` must run the repo's
    # target/release/pt-core, not whatever pt-core is installed elsewhere.
    local repo="${TEST_DIR}/repo" bin="${TEST_DIR}/bin"
    mkdir -p "${repo}/target/release" "$bin" "${TEST_DIR}/home/.local/bin"
    cp "$PT_SCRIPT" "${repo}/pt"
    chmod +x "${repo}/pt"
    cp "$MOCK_PT_CORE" "${repo}/target/release/pt-core"
    cp "$MOCK_PT_CORE" "${TEST_DIR}/home/.local/bin/pt-core"
    ln -s ../repo/pt "${bin}/pt-link"
    ln -s pt-link "${bin}/pt"

    run env -u PT_CORE_PATH HOME="${TEST_DIR}/home" PATH="/usr/bin:/bin" \
        PT_WRAPPER_TEST_LOG="$MOCK_LOG" "${bin}/pt" scan --format json
    [ "$status" -eq 0 ]
    grep -q '^ARGS=scan --format json$' "$MOCK_LOG"
    grep -qx "CORE_PATH=${repo}/target/release/pt-core" "$MOCK_LOG"
}

@test "wrapper: history does not create the config directory" {
    local config_dir="${TEST_DIR}/never-created"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PROCESS_TRIAGE_CONFIG="$config_dir" \
        "$PT_SCRIPT" history
    [ "$status" -eq 0 ]
    [[ "$output" == *"No decision history."* ]]
    [ ! -e "$config_dir" ]
}

@test "wrapper: clear TEXT matches patterns, never the level prefix" {
    local config_dir="${TEST_DIR}/config"
    mkdir -p "$config_dir"
    cat > "${config_dir}/decisions.json" << 'EOF'
{"exact|^node$|x\\.js":{"kill":1,"spare":0},"standard|node|.*x.js":{"kill":1,"spare":0}}
EOF
    # "act" is in "exact|", not in any pattern.
    run bash -lc "printf 'y\n' | env PT_CORE_PATH='$MOCK_PT_CORE' PROCESS_TRIAGE_CONFIG='$config_dir' '$PT_SCRIPT' clear act"
    [ "$status" -eq 0 ]
    [[ "$output" == *'No decisions match "act".'* ]]
    [ "$(jq 'length' "${config_dir}/decisions.json")" = "2" ]
}

@test "wrapper: --shell/--tui after the command are passed on, not swallowed" {
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" agent plan --label --tui
    [ "$status" -eq 0 ]
    grep -q '^ARGS=agent plan --label --tui$' "$MOCK_LOG"
    local value_log="${TEST_DIR}/label-space.log"
    run env PT_CORE_PATH="$MOCK_PT_CORE" PT_WRAPPER_TEST_LOG="$value_log" \
        "$PT_SCRIPT" agent plan --label '--shell with spaces'
    [ "$status" -eq 0 ]
    grep -qx 'ARG=--shell with spaces' "$value_log"
}

@test "wrapper: an unusable PT_CORE_PATH is an error, not a silent fallback" {
    run env PT_CORE_PATH="${TEST_DIR}/missing-pt-core" PT_WRAPPER_TEST_LOG="$MOCK_LOG" \
        "$PT_SCRIPT" scan
    [ "$status" -eq 1 ]
    [[ "$output" == *"PT_CORE_PATH=${TEST_DIR}/missing-pt-core is not an executable file"* ]]
    [ ! -f "$MOCK_LOG" ]
    local nonexecutable="${TEST_DIR}/nonexecutable-pt-core"
    printf '#!/usr/bin/env bash\n' > "$nonexecutable"
    chmod 644 "$nonexecutable"
    run env PT_CORE_PATH="$nonexecutable" PT_WRAPPER_TEST_LOG="$MOCK_LOG" "$PT_SCRIPT" scan
    [ "$status" -eq 1 ]
    [[ "$output" == *"is not an executable file"* ]]
    [ ! -f "$MOCK_LOG" ]
}

@test "wrapper: update rejects extra arguments after --no-verify" {
    run env PT_CORE_PATH="$MOCK_PT_CORE" "$PT_SCRIPT" update --no-verify --force
    [ "$status" -eq 2 ]
    [[ "$output" == *"unexpected arguments to 'pt update'"* ]]
}

@test "wrapper: update reports a download failure as such, not as a verification failure" {
    cat > "${MOCK_BIN_DIR}/curl" << 'EOF'
#!/usr/bin/env bash
url="${@: -1}"
if [[ "$url" == *"/releases/latest" ]]; then
  printf '{"tag_name":"v9.9.9","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z"}\n'
  exit 0
fi
echo "curl: (22) The requested URL returned error: 404" >&2
exit 22
EOF
    chmod +x "${MOCK_BIN_DIR}/curl"

    run env PT_CORE_PATH="$MOCK_PT_CORE" PATH="${MOCK_BIN_DIR}:$PATH" "$PT_SCRIPT" update
    [ "$status" -eq 1 ]
    [[ "$output" == *"could not download the v9.9.9 installer"* ]]
    [[ "$output" != *"verif"* ]]
}
