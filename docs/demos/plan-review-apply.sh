#!/usr/bin/env bash
set -euo pipefail

PT_COMMAND="${PT_CORE:-pt}"
if ! command -v "$PT_COMMAND" >/dev/null; then
  printf 'pt executable not found: %s\n' "$PT_COMMAND" >&2
  exit 1
fi
command -v jq >/dev/null

plan_args=(agent plan --format json)
if [[ -n "${PT_PLAN_PIDS:-}" ]]; then
  plan_args+=(--pids "$PT_PLAN_PIDS")
fi
if [[ -n "${PT_PLAN_MIN_AGE:-}" ]]; then
  plan_args+=(--min-age "$PT_PLAN_MIN_AGE")
fi
if [[ -n "${PT_PLAN_MIN_POSTERIOR:-}" ]]; then
  plan_args+=(--min-posterior "$PT_PLAN_MIN_POSTERIOR")
fi

# PlanReady (1) is a successful plan with candidates. Preserve other failures.
if PLAN_JSON=$("$PT_COMMAND" "${plan_args[@]}"); then
  plan_status=0
else
  plan_status=$?
fi
if [[ "$plan_status" -ne 0 && "$plan_status" -ne 1 ]]; then
  printf 'agent plan failed with exit %s\n' "$plan_status" >&2
  exit "$plan_status"
fi

SESSION_ID=$(printf '%s\n' "$PLAN_JSON" | jq -er '.session_id')

if [[ -z "${SESSION_ID}" || "${SESSION_ID}" == "null" ]]; then
  printf 'failed to create session\n' >&2
  exit 1
fi

printf 'Review the recorded candidates and planned actions:\n'
printf '%s\n' "$PLAN_JSON" | jq '{session_id, summary, candidates, actions}'
printf 'Simulate the reviewed plan; no action will execute:\n'
if "$PT_COMMAND" agent apply --session "$SESSION_ID" --recommended --dry-run --format summary; then
  apply_status=0
else
  apply_status=$?
fi
if [[ "$apply_status" -ne 0 && "$apply_status" -ne 2 ]]; then
  printf 'agent apply dry-run failed with exit %s\n' "$apply_status" >&2
  exit "$apply_status"
fi

printf 'Verify recorded executions; a simulation has no executed actions:\n'
if VERIFY_JSON=$("$PT_COMMAND" agent verify --session "$SESSION_ID" --format json); then
  verify_status=0
else
  verify_status=$?
fi
printf '%s\n' "$VERIFY_JSON" | jq .
printf 'agent verify returned exit %s\n' "$verify_status"
if [[ "$verify_status" -eq 0 ]]; then
  exit 0
fi

exit "$verify_status"
