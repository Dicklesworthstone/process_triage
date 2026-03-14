# Tutorial 02: Stuck Test Runner

Goal: Find test runners (jest/pytest/bun) that are idle or stuck for hours.

## 1) Generate a plan (safe, no actions)

```bash
pt agent plan --format json --min-age 3600
```

## 2) Filter likely test runners

```bash
pt agent plan --format json --min-age 3600 \
  | jq '.candidates[] | select(.cmd_short | test("jest|pytest|bun test"; "i")) \
  | {pid, cmd_short, runtime_seconds, recommendation, posterior_abandoned}'
```

## 3) Explain a candidate

```bash
pt agent explain --pid <pid> --format json
```

Look for:
- Long runtime vs expected
- Low CPU + low IO
- Orphaned processes (PPID=1)

## 4) Optional: staged termination (manual decision)

If you decide to terminate, prefer graceful shutdown first.

```bash
# Example only. Review evidence before applying.
pt agent apply --pids <pid> --yes --format json
```

If you are unsure, do not apply. Re-run plan later to see if the process is still idle.
