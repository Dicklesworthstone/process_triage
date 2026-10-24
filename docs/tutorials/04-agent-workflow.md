# Tutorial 04: Agent Workflow (Plan, Explain, Apply, Verify)

Goal: Run pt in a structured, automation-friendly way without taking unsafe actions.

Every step works on one session: the plan creates it, the other commands name it.

```bash
# Plan only: candidates, evidence and recommended actions
pt agent plan --format json > /tmp/pt-plan.json
SESSION=$(jq -r .session_id /tmp/pt-plan.json)

# Why a process scored the way it did
pt agent explain --session "$SESSION" --pids <pid> --format json

# Execute the recommended actions (needs robot_mode.enabled = true in policy.json,
# and passes the robot gates: posterior, blast radius, kill cap, live pre-checks)
pt agent apply --session "$SESSION" --recommended --yes --format json

# Confirm what happened
pt agent verify --session "$SESSION"

# Compare with an earlier session
pt agent diff --base <earlier-session> --compare "$SESSION"
```

Tips:
- Persist the plan before applying, so the audit trail shows what was decided.
- `--dry-run` (global flag) shows what apply would do without doing it.
