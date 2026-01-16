# Fleet Operations Guide (Multi-Host)

Status: Planned/contracted behavior. Fleet mode commands are specified in the CLI contract but may not be fully implemented yet. Treat this guide as the operational target.

## 1) What fleet mode is and is not

Fleet mode is:
- A coordinated way to scan, plan, and (optionally) apply actions across many hosts.
- Conservative by default (plan-first). Apply requires explicit consent.
- Designed to minimize correlated errors by using shared safety budgets.

Fleet mode is not:
- An unattended kill daemon. It does not auto-kill without explicit apply.
- A root escalation tool. Default scope is same-UID; privilege escalation is opt-in.
- A replacement for per-host policy and protected patterns.

## 2) Host inventory and connectivity

### Host inventory file (recommended)

Use a simple newline-delimited host file:

```
# fleet-hosts.txt
build-01
build-02
user@devbox-01
bastion-host
```

Notes:
- Each line is a host spec. Use `user@host` when needed.
- Keep the file under source control only if you are comfortable with hostnames being visible.
- If the CLI supports a comma-separated list, you may pass `--hosts host1,host2` instead.

### SSH requirements

- SSH key-based auth is recommended.
- If using a bastion/jump host, configure it in `~/.ssh/config`:

```
Host build-*
  User ops
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump bastion
```

### Permissions model

- Default: same-UID only. Fleet mode should not auto-sudo.
- If a host requires elevated privileges, use host-specific configuration and explicit opt-in.
- Prefer running pt under a dedicated ops user with minimal privileges.

## 3) Coordination model

Fleet mode aggregates per-host sessions into a fleet session:

- Each host produces a normal session (`pt-YYYYMMDD-...`).
- Fleet plan returns a `fleet_session_id` and a per-host list of session IDs.
- Cross-host patterns are computed to detect recurring offenders.

Shared safety budgets (avoid correlated errors):
- Pooled FDR/e-value: total false discovery budget across the fleet.
- Alpha-investing: a shared risk budget that shrinks when false positives occur.
- Max kills: per-host cap and fleet-wide cap.

Action sequencing:
- Apply actions in staggered batches (rate limit).
- Prefer action types with lower blast radius first (pause/throttle/renice).
- Abort or require confirmation if any host hits a safety gate.

## 4) Evidence and telemetry in fleet mode

What stays local:
- Full process snapshots, raw evidence, and local logs remain on each host.

What is aggregated:
- Summaries, anonymized identifiers, and redacted fields needed for fleet reporting.

Redaction profiles:
- Use safe/minimal profiles when sharing bundles across teams.
- Avoid storing raw command lines or unredacted paths in shared outputs.

Reports:
- Per-host HTML reports are generated locally.
- Fleet reports aggregate summaries and cross-host patterns.

## 5) Failure modes and recovery

Common failures:
- Host unreachable (network/SSH). Result: host marked failed, fleet plan continues.
- Permission denied. Result: host marked blocked, no actions applied.
- Partial apply. Result: fleet apply returns partial status; do not retry blindly.

Recovery guidance:
- Fix the underlying issue (SSH, permissions) and re-run plan.
- Use resume when supported to avoid re-scanning healthy hosts.
- Keep identity checks enabled; never re-apply stale plans without validation.

## 6) Practical playbooks

### Playbook A: Free RAM across build agents

Goal: find idle build processes consuming memory.

```bash
pt agent fleet plan --hosts fleet-hosts.txt --format json
# Review candidates and apply only if approved
pt agent fleet apply --session <fleet-session-id> --recommended --yes --format json
```

Tips:
- Set strict max kills per host.
- Prefer throttling or pause for long-running but potentially useful tasks.

### Playbook B: Stop leaked dev servers

Goal: terminate stale dev servers across laptops.

```bash
pt agent fleet plan --hosts dev-hosts.txt --format json
# Filter for dev servers in the plan output
pt agent fleet apply --session <fleet-session-id> --only dev-server --yes
```

Tips:
- Require known signatures for dev servers if available.
- Use `--min-posterior` guardrails if supported.

### Playbook C: Investigate runaway test workers

Goal: find test runners stuck for hours.

```bash
pt agent fleet plan --hosts ci-hosts.txt --format json
pt agent fleet status --session <fleet-session-id>
# Apply only after reviewing evidence and resource impact
pt agent fleet apply --session <fleet-session-id> --recommended --yes
```

Tips:
- Set a low max-kills budget and review each host.
- Look for cross-host patterns indicating a systemic issue.

## 7) Example fleet plan response (contract)

```json
{
  "schema_version": "1.0.0",
  "command": "fleet plan",
  "status": "success",
  "data": {
    "fleet_session_id": "fleet-20260115-143022-a7b3",
    "hosts": [
      {"host_id": "devbox1", "session_id": "pt-20260115-143022-a7b3", "status": "planned"},
      {"host_id": "devbox2", "session_id": "pt-20260115-143025-b8c4", "status": "planned"}
    ],
    "fleet_summary": {"total_hosts": 2, "total_candidates": 13},
    "fleet_fdr": {"pooled": true, "alpha": 0.05, "total_selected": 5},
    "cross_host_patterns": [
      {"pattern": "node server.js", "hosts": ["devbox1", "devbox2"], "count": 4}
    ]
  }
}
```

## 8) Safety checklist (before apply)

- Confirm `fleet_session_id` maps to the correct host set.
- Review per-host candidates and blast radius.
- Ensure shared FDR/alpha budget remains within limits.
- Confirm protected patterns and session safety are enabled.
- Apply in batches; stop if any host blocks on safety gates.

