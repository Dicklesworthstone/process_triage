# Tutorial 03: Port Conflict (Leaked Dev Server)

Goal: Identify a dev server holding a port (e.g., 3000) and stop it safely.

## 1) Check which process holds the port (optional)

```bash
lsof -i :3000
```

If you see a PID, you can use it in the steps below.

## 2) Generate a plan (safe)

```bash
pt agent plan --format json --min-age 3600
```

## 3) Filter for dev servers

```bash
pt agent plan --format json --min-age 3600 \
  | jq '.candidates[] | select(.cmd_short | test("next dev|vite|webpack|node .*dev"; "i")) \
  | {pid, cmd_short, runtime_seconds, recommendation, posterior_abandoned}'
```

## 4) Explain a candidate

```bash
pt agent explain --pid <pid> --format json
```

Verify it is yours (same UID) and not protected. If it is supervised by a tool
(systemd, docker, pm2), prefer the supervisor action.

## 5) Optional: stop the server (manual decision)

```bash
# Example only. Review evidence before applying.
pt agent apply --pids <pid> --yes --format json
```

If you see a supervisor recommendation in the plan, follow that instead of killing directly.
