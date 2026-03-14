# Tutorial 01: First Run (Safe and Conservative)

Goal: Understand what pt reports without taking any actions.

## 1) Verify installation

```bash
pt --version
```

If `pt` is missing, install per README.

## 2) Run a quick scan (no actions)

```bash
pt scan
```

What to look for:
- KILL: highest suspicion (review carefully)
- REVIEW: worth checking
- SPARE: likely safe

## 3) Inspect JSON output (optional)

```bash
pt scan --format json | jq '.summary, .candidates[] | {pid, cmd_short, recommendation, confidence}'
```

## 4) Try interactive mode (safe by default)

```bash
pt
```

Interactive mode will always ask before taking any action.

## 5) Generate a plan for automation review (plan-only)

```bash
pt agent plan --format json
```

This generates a machine-readable plan with evidence and recommendations. No actions are taken.

## Next steps

- If you see a candidate you recognize, run `pt agent explain --pid <pid>` to view evidence.
- If nothing looks suspicious, you are done. pt does not invent problems.
