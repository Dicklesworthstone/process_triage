#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)

"$root_dir/scripts/gen_manpages.sh"

# Ensure generated man pages are committed
if ! git diff --exit-code "$root_dir/docs/man" >/dev/null; then
  echo "Man pages are out of date. Run scripts/gen_manpages.sh and commit changes." >&2
  git diff --stat "$root_dir/docs/man" >&2
  exit 1
fi

# Best-effort rendering check
if command -v groff >/dev/null 2>&1; then
  for page in "$root_dir"/docs/man/*.[15]; do
    groff -man -Tutf8 "$page" >/dev/null
  done
fi
