#!/usr/bin/env bash
set -euo pipefail

SESSION_ID="$(pt agent plan --format json | jq -r '.session_id')"

if [[ -z "${SESSION_ID}" || "${SESSION_ID}" == "null" ]]; then
  echo "failed to create session" >&2
  exit 1
fi

pt agent verify --session "${SESSION_ID}" --format summary
pt agent apply --session "${SESSION_ID}" --recommended --dry-run --format summary
