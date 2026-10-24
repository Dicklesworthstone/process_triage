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
- 06-shadow-calibration.md
- 07-deep-scan-evidence.md

CLI onboarding helper:
- `pt learn` shows your progress and the next tutorial.
- `pt learn list` lists all tutorials with completion state.
- `pt learn show <id-or-slug>` displays a specific tutorial and hints.
- `pt learn verify <id-or-slug>` runs budgeted command checks.
- `pt learn verify --all --mark-complete` verifies all tutorials and records progress.
- `pt learn reset` clears tutorial progress.

What verification checks:
- Read-only commands from the tutorial (`scan`, `agent plan`, `deep-scan`,
  `shadow status`, ...) are run for real and must succeed. They use a scratch data
  directory, so verification never adds sessions to your history.
- A completed `agent plan` may exit 1 when it finds candidates. That verifies the
  step; a policy refusal, partial failure, or interrupted command does not.
- Commands that need your values (a session id, a PID) are run with placeholders:
  they fail for lack of a real session, but pt-core must accept their arguments, so a
  tutorial cannot document a flag that does not exist.

Verification is conservative by default:
- Per-check runtime budget: 45 seconds (configurable with `--verify-budget-ms`)
- Total runtime budget: 420 seconds, shared across selected tutorials (configurable
  with `--total-budget-ms`)
- On budget exhaustion, `pt learn` falls back to static tutorial guidance.
