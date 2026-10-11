#!/usr/bin/env bats
# install.sh must run under /bin/bash 3.2, the shell a `curl | bash` user gets
# on stock macOS. It runs with `set -u`, where bash < 4.4 treats an empty array
# expanded as "${name[@]}" as unbound (the installer died at its first curl
# call when no proxy was set), and bash 3.2 has no mapfile/readarray.

INSTALLER="$BATS_TEST_DIRNAME/../install.sh"

@test "install.sh guards every array expansion (bash 3.2 + set -u)" {
    bare=$(grep -nE '(^|[^+])"\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\}"' "$INSTALLER" \
        | grep -vE '\$\{(BASH_SOURCE|BASH_LINENO|FUNCNAME|PIPESTATUS|BASH_REMATCH)\[@\]\}' || true)
    if [ -n "$bare" ]; then
        echo "bare array expansions; use \${name[@]+\"\${name[@]}\"}:"
        echo "$bare"
        return 1
    fi
}

@test "install.sh uses no bash 4 builtins missing from bash 3.2" {
    if grep -nE '^[^#]*\b(mapfile|readarray)\b' "$INSTALLER"; then
        return 1
    fi
}
