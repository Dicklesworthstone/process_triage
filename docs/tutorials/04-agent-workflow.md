# Tutorial 04: Agent Workflow (Plan, Explain, Apply)

Goal: Run pt in a structured, automation-friendly way without taking unsafe actions.

## Current (implemented) workflow

Plan-only:

```bash
pt agent plan --format json > /tmp/pt-plan.json
```

Explain a candidate:

```bash
pt agent explain --pid <pid> --format json > /tmp/pt-explain.json
```

Apply (manual decision):

```bash
# Example only. Review evidence before applying.
pt agent apply --pids <pid> --yes --format json
```

## Session-based workflow

Session lifecycle is already available for resumable workflows:

```bash
# Session-aware interface
SESSION=$(pt agent plan --format json | jq -r .session_id)
pt agent explain --session "$SESSION" --pid <pid>
pt agent apply --session "$SESSION" --recommended --yes
pt agent verify --session "$SESSION"
pt agent diff --session "$SESSION" --vs <prior-session>
```
