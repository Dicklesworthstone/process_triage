# Tutorial 03: Port Conflict (Leaked Dev Server)

Goal: Identify a dev server holding a port (e.g., 3000) and stop it safely.

## 1) Check which process holds the port (optional)

```bash
lsof -i :3000
```

If you see a PID, you can use it in the steps below.

## 2) Generate a plan (safe)

```bash
pt agent plan --format json --min-age 3600 > /tmp/pt-plan.json
SESSION=$(jq -r .session_id /tmp/pt-plan.json)
```

## 3) Filter for dev servers

```bash
jq '.candidates[]
    | select(.command_short | test("next|vite|webpack|node"; "i"))
    | {pid, command_short, age_seconds, score, recommended_action}' \
  /tmp/pt-plan.json
```

## 4) Explain a candidate

```bash
pt agent explain --session "$SESSION" --pids <pid> --format json
```

Verify it is yours (same UID) and not protected. If it is supervised by a tool
(systemd, docker, pm2), the plan's `supervisor` field gives the command to stop it
through its supervisor instead; killing it would only make it restart.

## 5) Optional: stop the server (manual decision)

```bash
# Example only. Review evidence before applying.
pt agent apply --session "$SESSION" --pids <pid> --yes --format json
```
