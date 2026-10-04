# Tutorial 01: First Run (Safe and Conservative)

Goal: Understand what pt reports without taking any actions.

## 1) Verify installation

```bash
pt --version
```

Both lines should print: the `pt` wrapper version and the `pt-core` engine it runs.
If `pt` is missing, install per README.

## 2) Take a raw snapshot (no scoring, no actions)

```bash
pt scan
```

This prints the process snapshot pt works from (JSON by default). It does not rank
anything; the next step does.

## 3) Rank candidates (plan only, no actions)

```bash
pt agent plan --format json \
  | jq '.summary, (.candidates[] | {pid, command_short, age_seconds, score, recommended_action})'
```

- `score` is 100 × P(abandoned or zombie).
- `recommended_action` is the action with the lowest expected loss: usually `keep`,
  `review` or a reversible one (`pause`, `renice`); `kill` needs overwhelming evidence.
- Processes younger than one hour are not candidates by default (`--min-age`).

## 4) Try interactive mode (safe by default)

```bash
pt
```

Interactive mode always asks before taking any action.

## Next steps

To see why one process scored the way it did, explain it within the plan's session:

```bash
SESSION=$(pt agent plan --format json | jq -r .session_id)
pt agent explain --session "$SESSION" --pids <pid> --format json
```

If nothing looks suspicious, you are done. pt does not invent problems.
