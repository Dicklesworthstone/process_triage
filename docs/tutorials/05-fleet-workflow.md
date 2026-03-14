# Tutorial 05: Fleet Workflow (Multi-Host, Plan-Only)

Goal: Run pt across multiple hosts safely and aggregate results.

## Planned fleet commands (contract)

```bash
# Planned interface (may not be implemented yet)
pt agent fleet plan --hosts fleet-hosts.txt --format json
pt agent fleet status --session <fleet-session-id>
# Apply only after review
pt agent fleet apply --session <fleet-session-id> --recommended --yes
```

## Safe alternative today (plan-only via SSH)

Create a host list:

```
# fleet-hosts.txt
build-01
build-02
user@devbox-01
```

Run plan-only scans over SSH:

```bash
while read -r host; do
  echo "==> $host"
  ssh "$host" "pt agent plan --format json" > "/tmp/pt-plan-$host.json"
done < fleet-hosts.txt
```

Review and compare the results locally:

```bash
jq '.summary' /tmp/pt-plan-*.json
```

Notes:
- Do not run apply across the fleet until you have reviewed each host plan.
- If a host requires privilege escalation, opt in explicitly per host.
