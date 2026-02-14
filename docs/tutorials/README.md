# Tutorials

This directory contains hands-on, safe-by-default tutorials for Process Triage.
All commands are non-destructive by default (scan/plan/explain). Any destructive
steps are clearly labeled as optional and should only be run after review.

Tutorial index:
- 01-first-run.md
- 02-stuck-test-runner.md
- 03-port-conflict.md
- 04-agent-workflow.md
- 05-fleet-workflow.md

CLI onboarding helper:
- `pt learn` shows your progress and the next tutorial.
- `pt learn list` lists all tutorials with completion state.
- `pt learn show <id-or-slug>` displays a specific tutorial and hints.
- `pt learn verify --topic <id-or-slug>` runs budgeted command checks.
- `pt learn verify --all --mark-complete` verifies all tutorials and records progress.
- `pt learn reset` clears tutorial progress.

Verification is conservative by default:
- Per-check runtime budget: 750ms (configurable with `--verify-budget-ms`)
- Total runtime budget: 5000ms (configurable with `--total-budget-ms`)
- On budget exhaustion, `pt learn` falls back to static tutorial guidance.

If a command or subcommand is not yet implemented, the tutorial will call it out
explicitly and show a plan-only alternative.
