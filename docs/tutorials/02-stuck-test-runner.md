# Tutorial 02: Stuck Test Runner

Goal: Find test runners (jest/pytest/bun) that are idle or stuck for hours.

## 1) Generate a plan (safe, no actions)

```bash
pt agent plan --format json --min-age 3600 > /tmp/pt-plan.json
SESSION=$(jq -r .session_id /tmp/pt-plan.json)
```

## 2) Filter likely test runners

```bash
jq '.candidates[]
    | select(.command_short | test("jest|pytest|bun|vitest|cargo"; "i"))
    | {pid, command_short, age_seconds, score, recommended_action, p_abandoned: .posterior.abandoned}' \
  /tmp/pt-plan.json
```

## 3) Explain a candidate

```bash
pt agent explain --session "$SESSION" --pids <pid> --format json
```

Look for:
- Runtime far beyond what a test run normally takes
- Low CPU with no recent I/O
- Orphaned processes (parent exited, process kept its old session)

## 4) Optional: act on it (manual decision)

Prefer the plan's recommendation (often a reversible `pause`), and review the
evidence first. Applying requires robot mode to be enabled in your policy.

```bash
# Example only. Review evidence before applying.
pt agent apply --session "$SESSION" --pids <pid> --yes --format json
pt agent verify --session "$SESSION"
```

If you are unsure, do not apply. Re-run the plan later to see if the process is still idle.
