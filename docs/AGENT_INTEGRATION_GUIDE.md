# Agent Integration Guide

> **Bead**: `process_triage-835.2`
> **Status**: Active
> **Version**: 1.0.0

This guide helps AI agents integrate with the `pt agent` CLI interface. It covers the mental model, common workflows, output parsing, safety guarantees, and best practices.

---

## Table of Contents

1. [Mental Model](#mental-model)
2. [Quickstart Workflows](#quickstart-workflows)
3. [Output Formats and Parsing](#output-formats-and-parsing)
4. [Exit Codes and Error Taxonomy](#exit-codes-and-error-taxonomy)
5. [Safety and Governance](#safety-and-governance)
6. [Best Practices](#best-practices)
7. [Real Workflow Examples](#real-workflow-examples)

---

## Mental Model

### What Process Triage Does

Process Triage (`pt`) is a Bayesian-inspired tool that identifies and manages "zombie" or abandoned processes on a system. It classifies processes into four categories:

| Class | Description | Typical Action |
|-------|-------------|----------------|
| `useful` | Active, doing real work | Leave alone |
| `useful_bad` | Active but misbehaving | Throttle, review |
| `abandoned` | Idle, likely forgotten | Kill (recoverable) |
| `zombie` | Dead but not reaped | Clean up |

### The Session Lifecycle

All agent operations flow through a **session**—a stateful context that tracks a complete triage cycle:

```
snapshot → plan → explain → apply → verify → export
    ↓        ↓        ↑        ↓        ↑
    └──── all share session_id ────┘
```

**Key insight**: The session model enables **interruption and resumption**. An agent can:
1. Take a snapshot
2. Generate a plan
3. Get interrupted (timeout, reboot, etc.)
4. Resume later with the same session ID

### Plan vs Apply: The Two-Phase Model

**Phase 1: Plan (Read-Only)**
- Scans processes, collects evidence, runs inference
- Produces a plan with recommendations
- **Zero side effects**—safe to run repeatedly

**Phase 2: Apply (Mutating)**
- Executes actions from an approved plan
- Validates identity before each action
- Records outcomes for verification

This separation allows agents to:
- Generate plans for human review
- Apply plans autonomously when confidence is high
- Retry failed applications without re-planning

### Session ID Format

```
pt-YYYYMMDD-HHMMSS-<random4>
```

Example: `pt-20260115-143022-a7xq`

---

## Quickstart Workflows

### Minimal One-Shot Cleanup

```bash
# Generate plan and apply recommendations in one flow
SESSION=$(pt agent plan --format json | jq -r .session_id)
pt agent apply --session "$SESSION" --recommended --yes
pt agent verify --session "$SESSION"
```

### Conservative Scan (Information Only)

```bash
# Just scan and report, no actions
pt agent plan --format json --limit 10
```

### High-Confidence Autonomous Cleanup

```bash
# Only act on very confident classifications
SESSION=$(pt agent plan --format json | jq -r .session_id)
pt agent apply --session "$SESSION" \
  --recommended --yes \
  --min-posterior 0.99 \
  --max-kills 5 \
  --max-blast-radius 2GB
```

### Resuming an Interrupted Session

```bash
# Check status of existing session
pt agent status --session pt-20260115-143022-a7xq

# Resume from where it left off
pt agent apply --session pt-20260115-143022-a7xq --resume
```

---

## Output Formats and Parsing

### Default JSON Structure

Every response includes these envelope fields:

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "generated_at": "2026-01-15T14:30:22Z",
  "host_id": "devbox1.example.com"
}
```

### Plan Output

The `plan` command returns candidates with mandatory fields:

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "generated_at": "2026-01-15T14:30:22Z",
  "host_id": "devbox1.example.com",
  "summary": {
    "total_scanned": 142,
    "candidates_found": 3,
    "kill_recommended": 2,
    "review_recommended": 1,
    "spare_count": 0,
    "total_recoverable_mb": 2400,
    "total_recoverable_cpu_pct": 15.2
  },
  "candidates": [
    {
      "pid": 1234,
      "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:1234",
      "uid": 1000,
      "ppid": 1,
      "cmd_short": "node jest --worker",
      "cmd_full": "node /path/to/jest/bin/jest.js --worker=12345",
      "classification": "abandoned",
      "posterior": {
        "abandoned": 0.94,
        "useful": 0.03,
        "useful_bad": 0.02,
        "zombie": 0.01
      },
      "confidence": "high",
      "blast_radius": {
        "memory_mb": 1200,
        "cpu_pct": 98,
        "child_count": 3,
        "risk_level": "low",
        "summary": "Killing frees 1.2GB RAM, terminates 3 children; no external impact"
      },
      "reversibility": {
        "reversible": false,
        "recovery_options": ["Restart via: npm test"],
        "data_at_risk": false
      },
      "supervisor": {
        "detected": false,
        "type": null,
        "recommended_action": "kill"
      },
      "uncertainty": {
        "confidence_level": 0.94,
        "uncertainty_drivers": [
          {"factor": "io_activity", "impact": "medium", "note": "Last IO 45min ago"}
        ],
        "decision_robustness": "high"
      },
      "recommended_action": "kill",
      "action_rationale": "High-confidence abandoned process; blast radius contained"
    }
  ],
  "recommended": {
    "preselected_pids": [1234, 5678],
    "actions": [
      {
        "target": {"pid": 1234, "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:1234"},
        "action": "kill",
        "stage": 1,
        "gates": ["identity_valid", "not_protected"]
      }
    ],
    "total_actions": 2,
    "estimated_recovery_mb": 2400
  }
}
```

### Apply Output

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "results": [
    {
      "target": {"pid": 1234, "start_id": "9d2d4e20..."},
      "action": "kill",
      "outcome": "success",
      "duration_ms": 50,
      "verification": {
        "process_exited": true,
        "exit_code": null,
        "memory_freed_mb": 512
      }
    }
  ],
  "summary": {
    "total": 2,
    "successful": 2,
    "skipped": 0,
    "failed": 0,
    "memory_freed_mb": 1200
  }
}
```

### Verify Output

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "verification": {
    "requested_at": "2026-01-15T14:31:00Z",
    "completed_at": "2026-01-15T14:31:02Z",
    "overall_status": "success"
  },
  "action_outcomes": [
    {
      "target": {"pid": 1234},
      "action": "kill",
      "outcome": "confirmed_dead",
      "time_to_death_ms": 50,
      "resources_freed": {"memory_mb": 1200}
    }
  ],
  "resource_summary": {
    "memory_freed_mb": 2400,
    "expected_mb": 2400
  }
}
```

### Parsing Tips

1. **Always check `schema_version`** before parsing—future versions may add fields
2. **Required fields are guaranteed** within a major version
3. **Unknown fields should be ignored**, not cause errors
4. **Use jq for extraction**: `jq -r '.candidates[] | select(.recommended_action == "kill")'`

### Token Efficiency Flags

| Flag | Effect |
|------|--------|
| `--compact` | Minimal output (default) |
| `--verbose` | Include all optional fields |
| `--include-prose` | Add natural language summaries |
| `--galaxy-brain` | Add full Bayesian math derivations |
| `--fields pid,classification` | Project specific fields only |
| `--limit 5` | Top N candidates only |
| `--only kill` | Filter by action type |

---

## Exit Codes and Error Taxonomy

### Standard Exit Codes

| Code | Constant | Meaning | Agent Response |
|------|----------|---------|----------------|
| 0 | `OK_CLEAN` | Success: nothing to do | No action needed |
| 1 | `OK_CANDIDATES` | Candidates found, plan produced | Review/apply plan |
| 2 | `OK_APPLIED` | Actions executed successfully | Verify outcomes |
| 3 | `ERR_PARTIAL` | Some actions failed | Retry or escalate |
| 4 | `ERR_BLOCKED` | Safety gates blocked action | Review constraints |
| 5 | `ERR_GOAL_UNREACHABLE` | Goal not achievable | Report to user |
| 6 | `ERR_INTERRUPTED` | Session interrupted (resumable) | Resume session |
| 10 | `ERR_ARGS` | Invalid arguments | Fix command |
| 11 | `ERR_CAPABILITY` | Required capability missing | Check prerequisites |
| 12 | `ERR_PERMISSION` | Permission denied | Escalate (sudo) |
| 13 | `ERR_VERSION` | Version mismatch | Update pt |
| 14 | `ERR_LOCK` | Another pt instance running | Wait and retry |
| 15 | `ERR_SESSION` | Session not found/invalid | Create new session |
| 20 | `ERR_INTERNAL` | Internal error (bug) | Report bug |
| 21 | `ERR_IO` | I/O error | Retry or escalate |
| 22 | `ERR_TIMEOUT` | Operation timed out | Increase timeout |

### Error Response Format

When an error occurs, JSON output includes:

```json
{
  "schema_version": "1.0.0",
  "error": {
    "code": "IDENTITY_MISMATCH",
    "message": "PID 1234 identity changed since plan was created",
    "details": {
      "expected_start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:1234",
      "actual_start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456990:1234"
    },
    "recoverable": true,
    "recovery_action": "Generate fresh plan with: pt agent plan"
  }
}
```

### Error Code Reference

| Code | Meaning | Recoverable | Recovery Action |
|------|---------|-------------|-----------------|
| `IDENTITY_MISMATCH` | PID reused or process changed | Yes | Regenerate plan |
| `SESSION_NOT_FOUND` | Session ID doesn't exist | No | Create new session |
| `SESSION_EXPIRED` | Session past retention | No | Create new session |
| `PERMISSION_DENIED` | Insufficient privileges | Maybe | Try with sudo |
| `PROTECTED_PROCESS` | Target is protected | No | Skip this target |
| `BUDGET_EXHAUSTED` | FDR/alpha budget depleted | Yes | Wait for reset |
| `GATE_FAILED` | Safety gate blocked | Depends | Check gate details |
| `INTERNAL_ERROR` | Unexpected error | No | Report bug |

---

## Safety and Governance

### Safety Gates

Every action passes through safety gates before execution:

| Gate | Check | Failure Behavior |
|------|-------|------------------|
| `identity_valid` | PID + start_id + UID match | Abort, require fresh plan |
| `not_protected` | Not in protected list | Skip, log warning |
| `posterior_threshold` | P(target_class) > threshold | Skip with explanation |
| `blast_radius_limit` | Impact < configured max | Skip with explanation |
| `fdr_budget` | Within FDR/alpha-investing budget | Skip, log exhausted |
| `supervisor_check` | Supervisor action preferred | Warn if suboptimal |

### Gate Evaluation Order

Gates are evaluated in a specific order (fail-fast):

1. `identity_valid` — Ensures process hasn't been replaced
2. `not_protected` — Respects protected process list
3. `supervisor_check` — Prefers supervisor actions
4. `posterior_threshold` — Enforces confidence requirements
5. `blast_radius_limit` — Limits impact
6. `fdr_budget` — Statistical false discovery control

### Process Identity Validation

**The start_id is critical**. It's a composite key:

```
<boot_id>:<start_time_ticks>:<pid>
```

This ensures:
- PID reuse is detected (different start_time)
- Reboots invalidate stale plans (different boot_id)
- Wrong process is never killed

### Protected Processes

The following are always protected:
- PID 1 (init/systemd)
- Kernel threads
- Processes matching `protected_patterns` in config
- Processes owned by root (unless explicitly targeted)

### Blast Radius Assessment

Every candidate includes blast radius info:

```json
{
  "blast_radius": {
    "memory_mb": 1200,
    "cpu_pct": 98,
    "child_count": 3,
    "connection_count": 2,
    "open_files": 47,
    "dependent_processes": [
      {"pid": 2345, "relationship": "child", "cmd_short": "node worker.js"}
    ],
    "risk_level": "low",
    "summary": "Killing frees 1.2GB RAM, terminates 3 children; no external impact"
  }
}
```

Risk levels: `none`, `low`, `medium`, `high`, `critical`

### FDR Control

Process Triage uses **False Discovery Rate** control:
- Each kill consumes "alpha budget"
- Budget regenerates over time
- When exhausted, confident kills are still blocked
- Prevents runaway automation

---

## Best Practices

### 1. Always Use Sessions

```bash
# Good: Explicit session management
SESSION=$(pt agent plan --format json | jq -r .session_id)
pt agent apply --session "$SESSION" --recommended --yes

# Bad: Re-scanning each time (inconsistent state)
pt agent apply --recommended --yes
```

### 2. Validate Schema Version

```python
def parse_plan(output):
    data = json.loads(output)
    major = int(data["schema_version"].split(".")[0])
    if major > 1:
        raise ValueError(f"Unsupported schema version: {data['schema_version']}")
    return data
```

### 3. Handle All Exit Codes

```bash
pt agent apply --session "$SESSION" --recommended --yes
case $? in
    0) echo "Clean system, nothing to do" ;;
    1) echo "Plan ready, no actions taken" ;;
    2) echo "Actions applied successfully" ;;
    3) echo "Partial failure—check results" ;;
    4) echo "Safety blocked—review constraints" ;;
    6) echo "Interrupted—can resume" ;;
    *) echo "Error: check logs" ;;
esac
```

### 4. Set Confidence Thresholds

For autonomous operation, require high confidence:

```bash
pt agent apply --session "$SESSION" \
  --recommended --yes \
  --min-posterior 0.99 \
  --max-kills 3 \
  --max-blast-radius 1GB
```

### 5. Use Field Projection for Large Systems

```bash
# Get just the fields you need
pt agent plan --format json \
  --fields pid,classification,posterior,recommended_action \
  --limit 20
```

### 6. Verify After Apply

Always verify outcomes:

```bash
pt agent apply --session "$SESSION" --recommended --yes
pt agent verify --session "$SESSION"
```

### 7. Handle Supervised Processes Correctly

When `supervisor.detected` is true, prefer the supervisor command:

```python
for candidate in plan["candidates"]:
    if candidate["supervisor"]["detected"]:
        # Use supervisor action instead of direct kill
        cmd = candidate["supervisor"]["supervisor_command"]
        # e.g., "systemctl --user stop my-app.service"
```

### 8. Respect Resumability

If interrupted, don't start fresh:

```bash
# Check if resumable
STATUS=$(pt agent status --session "$SESSION")
if echo "$STATUS" | jq -e '.resumable' > /dev/null; then
    pt agent apply --session "$SESSION" --resume
else
    # Start fresh
    SESSION=$(pt agent plan --format json | jq -r .session_id)
fi
```

---

## Real Workflow Examples

### Example 1: Development Machine Cleanup Agent

**Scenario**: An AI agent runs hourly on a developer's workstation to clean up abandoned build processes.

```bash
#!/bin/bash
# dev-cleanup-agent.sh

set -euo pipefail

LOG=/var/log/pt-agent/cleanup.log

log() { echo "$(date -Iseconds) $*" >> "$LOG"; }

# Only proceed if memory pressure is high
AVAIL_GB=$(awk '/MemAvailable/ {printf "%.1f", $2/1024/1024}' /proc/meminfo)
if (( $(echo "$AVAIL_GB > 4" | bc -l) )); then
    log "INFO: Available memory ${AVAIL_GB}GB - skipping cleanup"
    exit 0
fi

log "INFO: Low memory (${AVAIL_GB}GB available) - starting cleanup"

# Generate plan targeting typical dev process patterns
SESSION=$(pt agent plan --format json \
    --patterns "node,python,cargo,rustc" \
    --min-idle-minutes 30 | jq -r .session_id)

# Check what we found
PLAN=$(pt agent plan --session "$SESSION" --format json)
KILLS=$(echo "$PLAN" | jq '.summary.kill_recommended')

if [[ "$KILLS" -eq 0 ]]; then
    log "INFO: No candidates found"
    exit 0
fi

log "INFO: Found $KILLS kill candidates"

# Apply with conservative settings
pt agent apply --session "$SESSION" \
    --recommended --yes \
    --min-posterior 0.95 \
    --max-kills 5 \
    --max-blast-radius 2GB

# Verify and log results
VERIFY=$(pt agent verify --session "$SESSION" --format json)
FREED=$(echo "$VERIFY" | jq '.resource_summary.memory_freed_mb')

log "INFO: Cleanup complete - freed ${FREED}MB"
```

### Example 2: CI/CD Pipeline Health Monitor

**Scenario**: A monitoring agent checks for stuck CI jobs and reports via webhook.

```bash
#!/bin/bash
# ci-monitor-agent.sh

WEBHOOK_URL="${CI_WEBHOOK:-https://hooks.example.com/ci-alerts}"

# Scan for CI-related processes only
PLAN=$(pt agent plan --format json \
    --patterns "jenkins,gitlab-runner,docker,buildkite" \
    --min-idle-minutes 120 \
    --include-prose)

SESSION=$(echo "$PLAN" | jq -r .session_id)
CANDIDATES=$(echo "$PLAN" | jq '.summary.candidates_found')

if [[ "$CANDIDATES" -eq 0 ]]; then
    exit 0
fi

# Extract prose summary for human-readable alert
SUMMARY=$(echo "$PLAN" | jq -r '.prose_summary.executive // "Stuck CI processes detected"')

# Build alert payload
PAYLOAD=$(cat <<EOF
{
  "alert": "stuck_ci_processes",
  "session_id": "$SESSION",
  "candidate_count": $CANDIDATES,
  "summary": "$SUMMARY",
  "candidates": $(echo "$PLAN" | jq '[.candidates[] | {pid, cmd_short, idle_minutes: .evidence.idle_minutes, memory_mb: .blast_radius.memory_mb}]')
}
EOF
)

# Send alert (don't auto-kill CI processes)
curl -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"

echo "Alert sent for session $SESSION"
```

### Example 3: Kubernetes Node Recovery Agent

**Scenario**: An agent runs on K8s nodes to handle container processes that escape the kubelet.

```python
#!/usr/bin/env python3
"""k8s-node-recovery-agent.py

Identifies and cleans up orphaned container processes on K8s nodes.
Integrates with node-problem-detector for reporting.
"""

import json
import subprocess
import sys
from datetime import datetime

def run_pt(*args):
    """Run pt agent command and return parsed JSON."""
    result = subprocess.run(
        ["pt", "agent", *args, "--format", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode >= 10:
        raise RuntimeError(f"pt error: {result.stderr}")
    return json.loads(result.stdout) if result.stdout else None

def main():
    # Generate plan targeting container-related processes
    plan = run_pt(
        "plan",
        "--patterns", "containerd-shim,runc,pause",
        "--min-idle-minutes", "60",
        "--exclude-patterns", "kubelet,dockerd,containerd"
    )

    session_id = plan["session_id"]
    candidates = plan["candidates"]

    if not candidates:
        print(f"[{datetime.now().isoformat()}] No orphaned containers found")
        return 0

    print(f"[{datetime.now().isoformat()}] Found {len(candidates)} orphaned containers")

    # Filter to high-confidence abandoned containers only
    high_confidence = [
        c for c in candidates
        if c["posterior"]["abandoned"] > 0.98
        and c["blast_radius"]["risk_level"] in ("none", "low")
    ]

    if not high_confidence:
        print("No high-confidence candidates - skipping cleanup")
        # Report for investigation
        report_to_npd(plan, "orphaned_containers_detected")
        return 1

    # Apply cleanup
    result = run_pt(
        "apply",
        "--session", session_id,
        "--recommended", "--yes",
        "--min-posterior", "0.98",
        "--max-kills", "10"
    )

    # Verify
    verify = run_pt("verify", "--session", session_id)

    freed_mb = verify.get("resource_summary", {}).get("memory_freed_mb", 0)
    print(f"Cleanup complete: freed {freed_mb}MB across {len(high_confidence)} containers")

    # Report success to node-problem-detector
    report_to_npd(verify, "orphaned_containers_cleaned")

    return 0

def report_to_npd(data, event_type):
    """Report to node-problem-detector via custom plugin."""
    event = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "data": data
    }
    # Write to NPD custom plugin socket
    try:
        with open("/var/run/npd-custom/pt-agent.sock", "w") as f:
            json.dump(event, f)
    except IOError:
        pass  # NPD not available

if __name__ == "__main__":
    sys.exit(main())
```

### Example 4: Interactive Agent Assistant

**Scenario**: An AI assistant helps a user understand and clean up their system.

```python
#!/usr/bin/env python3
"""interactive-pt-assistant.py

An AI assistant that uses pt to help users understand
process issues on their system.
"""

import json
import subprocess

def get_plan_summary():
    """Get a human-friendly summary of system state."""
    result = subprocess.run(
        ["pt", "agent", "plan", "--format", "json", "--include-prose"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return "Your system looks clean - no problematic processes detected."

    plan = json.loads(result.stdout)
    prose = plan.get("prose_summary", {})

    return {
        "session_id": plan["session_id"],
        "executive_summary": prose.get("executive", ""),
        "recommended_actions": prose.get("actions", ""),
        "rationale": prose.get("rationale", ""),
        "candidate_count": plan["summary"]["candidates_found"],
        "recoverable_memory_mb": plan["summary"]["total_recoverable_mb"]
    }

def explain_candidate(session_id: str, pid: int):
    """Get detailed explanation for a specific process."""
    result = subprocess.run(
        ["pt", "agent", "explain",
         "--session", session_id,
         "--pid", str(pid),
         "--format", "json",
         "--galaxy-brain"],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout)

    # Build human-friendly explanation
    candidate = data["candidate"]
    explanation = [
        f"Process {pid}: {candidate['cmd_short']}",
        f"",
        f"Classification: {candidate['classification']} "
        f"({candidate['posterior'][candidate['classification']]*100:.1f}% confidence)",
        f"",
        f"Why this classification:",
    ]

    for driver in candidate["uncertainty"]["uncertainty_drivers"]:
        explanation.append(f"  - {driver['factor']}: {driver['note']}")

    if candidate["supervisor"]["detected"]:
        explanation.append(f"")
        explanation.append(f"This process is managed by {candidate['supervisor']['type']}.")
        explanation.append(f"Recommended: {candidate['supervisor']['supervisor_command']}")

    return "\n".join(explanation)

def apply_with_confirmation(session_id: str, pids: list[int]):
    """Apply actions with user confirmation."""
    # First show what would happen
    preview = subprocess.run(
        ["pt", "agent", "apply",
         "--session", session_id,
         "--pids", ",".join(map(str, pids)),
         "--dry-run",
         "--format", "json"],
        capture_output=True,
        text=True
    )

    preview_data = json.loads(preview.stdout)

    print("The following actions will be taken:")
    for action in preview_data["actions"]:
        print(f"  - {action['action']} PID {action['target']['pid']}: "
              f"{action['target'].get('cmd_short', 'unknown')}")

    confirm = input("\nProceed? [y/N] ")
    if confirm.lower() != 'y':
        return "Cancelled"

    # Execute
    result = subprocess.run(
        ["pt", "agent", "apply",
         "--session", session_id,
         "--pids", ",".join(map(str, pids)),
         "--yes",
         "--format", "json"],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout)
    summary = data["summary"]

    return (f"Complete: {summary['successful']} successful, "
            f"{summary['failed']} failed, "
            f"{summary['memory_freed_mb']}MB freed")

# Example usage in an agent loop:
if __name__ == "__main__":
    print("Analyzing your system...")
    summary = get_plan_summary()

    if isinstance(summary, str):
        print(summary)
    else:
        print(summary["executive_summary"])
        print(f"\nFound {summary['candidate_count']} candidates "
              f"({summary['recoverable_memory_mb']}MB recoverable)")
        print(f"\nSession: {summary['session_id']}")
```

---

## Appendix: JSON Schema Reference

For complete JSON schemas, see [AGENT_CLI_CONTRACT.md](./AGENT_CLI_CONTRACT.md).

### Required Candidate Fields

Every candidate in plan output includes these fields (never omitted):

- **Identity**: `pid`, `start_id`, `uid`, `ppid`, `cmd_short`, `cmd_full`
- **Classification**: `classification`, `posterior`, `confidence`
- **Safety**: `blast_radius`, `reversibility`, `supervisor`
- **Decision**: `uncertainty`, `recommended_action`, `action_rationale`

### Verification Outcomes

| Outcome | Meaning |
|---------|---------|
| `confirmed_dead` | Process terminated as expected |
| `confirmed_stopped` | Process stopped (SIGSTOP) |
| `still_running` | Process still exists |
| `respawned` | Process was killed but respawned |
| `pid_reused` | PID reassigned to different process |
| `cascaded` | Supervisor restarted the service |
| `timeout` | Verification timed out |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-15 | Initial release |
