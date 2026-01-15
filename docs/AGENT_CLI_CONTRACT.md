# Agent CLI Contract Specification

> **Bead**: `process_triage-jqi`
> **Status**: Specification
> **Version**: 1.0.0

## Overview

This document defines the contract for AI agents consuming the `pt agent` CLI interface. It specifies output schemas, session semantics, safety gates, and behavioral guarantees that agents can rely on.

### Design Goals

1. **Deterministic behavior**: Same inputs produce same outputs (modulo timestamps)
2. **Token efficiency**: Minimal output by default, deeper details on demand
3. **Schema stability**: Additive changes only; breaking changes bump schema_version
4. **Safety first**: Identity validation, reversibility info, blast radius always present
5. **Resumability**: All operations can be interrupted and resumed

---

## Schema Versioning

Every JSON response includes:

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "generated_at": "2026-01-15T14:30:22Z",
  "host_id": "devbox1.example.com"
}
```

### Version Semantics

- **MAJOR**: Breaking changes (field removals, semantic changes)
- **MINOR**: Additive changes (new optional fields)
- **PATCH**: Bug fixes, documentation

### Compatibility Promise

- Agents targeting schema 1.x can safely ignore unknown fields
- Required fields will never be removed within a major version
- Field semantics will not change within a major version

---

## Session Model

Sessions provide stateful context across multiple CLI invocations.

### Session Lifecycle

```
snapshot → plan → explain → apply → verify → diff → export/report
    ↓        ↓        ↑        ↓        ↑
    └──── all share session_id ────┘
```

### Session Storage

```
~/.local/share/process_triage/sessions/<session_id>/
├── manifest.json          # Session metadata
├── snapshot.json          # Initial system state
├── plan.json              # Generated plan
├── telemetry/             # Collected evidence
├── outcomes.json          # Action outcomes
└── audit.jsonl            # Audit log
```

### Session States

| State | Description |
|-------|-------------|
| `created` | Session initialized (snapshot taken) |
| `planned` | Plan computed, awaiting approval |
| `approved` | Plan approved, awaiting execution |
| `executing` | Actions in progress |
| `interrupted` | Execution stopped mid-way (resumable) |
| `completed` | All actions finished |
| `verified` | Outcomes confirmed |

### Session ID Format

```
pt-YYYYMMDD-HHMMSS-<random4>
```

Example: `pt-20260115-143022-a7xq`

### Session Context Passing

Commands accept `--session <id>` to reuse context:
- `plan --session <id>`: Reuses snapshot (skip re-scanning)
- `explain --session <id>`: Retrieves cached inference
- `apply --session <id>`: Validates against saved plan
- `verify --session <id>`: Compares against pre-action state

---

## Resumability Contract

All operations support interruption and resumption.

### Resume Semantics

```bash
pt agent apply --session <id> --resume
```

- Resumes from last completed action
- Completed actions are idempotent (re-running is a no-op)
- Pending actions are re-validated before execution
- Progress is checkpointed after each action

### Status Query

```bash
pt agent status --session <id>
```

Returns:

```json
{
  "session_id": "pt-20260115-143022-a7xq",
  "state": "interrupted",
  "phase": "apply",
  "progress": {
    "total_actions": 4,
    "completed_actions": 2,
    "pending_actions": 2
  },
  "resumable": true,
  "resume_command": "pt agent apply --session pt-20260115-143022-a7xq --resume"
}
```

### Failure Modes

| Failure | Behavior |
|---------|----------|
| Process gone (PID reused) | Skip action, log warning |
| Permission denied | Retry with escalation hint |
| Timeout | Checkpoint progress, exit 6 |
| Unexpected error | Log details, exit >= 10 |

---

## Token Efficiency Controls

### Default Behavior

Defaults optimize for minimal token consumption:
- Summary statistics only
- Top candidates with essential fields
- No prose, no galaxy-brain math
- Compact JSON formatting

### Expansion Flags

| Flag | Effect |
|------|--------|
| `--compact` | Minimal output (default) |
| `--verbose` | Include all optional fields |
| `--include-prose` | Add `prose_summary` object |
| `--galaxy-brain` | Add full math derivations |
| `--include-raw` | Include raw sample data |
| `--include-ledger` | Include evidence ledger |

### Field Projection

```bash
--fields pid,classification,posterior,action_rationale
```

Returns only specified fields for each candidate.

### Array Limiting

```bash
--limit 5             # Top 5 candidates
--only kill           # Only kill recommendations
--only kill,review    # Kill and review recommendations
```

---

## Pre-Toggled Plan Semantics

Plans include pre-computed recommendations.

### Plan Structure

```json
{
  "recommended": {
    "preselected_pids": [1234, 5678, 9012],
    "actions": [
      {
        "target": {"pid": 1234, "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:1234"},
        "action": "kill",
        "stage": 1,
        "gates": ["identity_valid", "not_protected"]
      }
    ],
    "total_actions": 3,
    "estimated_recovery_mb": 2400
  }
}
```

### Pre-Toggle Rules

1. `kill` recommended only if posterior(abandoned | zombie) > threshold
2. `review` recommended if posterior > review_threshold but < kill_threshold
3. Protected processes never pre-selected regardless of score

### Applying Pre-Toggled Plan

```bash
pt agent apply --session <id> --recommended --yes
```

Executes all pre-selected actions in staged order.

---

## Safety Gates

Every action must pass safety gates before execution.

### Gate Types

| Gate | Check | Failure Behavior |
|------|-------|------------------|
| `identity_valid` | PID + start_id + UID match | Abort, require fresh plan |
| `not_protected` | Not in protected list | Skip, log warning |
| `posterior_threshold` | P(target_class) > threshold | Skip, explain in output |
| `blast_radius_limit` | Impact < configured max | Skip, explain in output |
| `fdr_budget` | Within FDR/alpha-investing budget | Skip, log budget exhausted |
| `supervisor_check` | Supervisor action preferred | Warn if direct kill on supervised |

### Gate Evaluation Order

1. `identity_valid` (fail-fast)
2. `not_protected` (skip if protected)
3. `supervisor_check` (warn if suboptimal)
4. `posterior_threshold` (skip if uncertain)
5. `blast_radius_limit` (skip if too impactful)
6. `fdr_budget` (skip if budget exhausted)

### Confidence-Bounded Automation

```bash
pt agent apply --session <id> --recommended --yes \
  --min-posterior 0.99 \
  --max-blast-radius 2GB \
  --max-kills 5 \
  --require-known-signature
```

Only acts when ALL conditions met:
- Posterior > 0.99
- Total impact < 2GB
- At most 5 kills
- Pattern library match exists

---

## Mandatory Candidate Fields

Every candidate in `pt agent plan` output includes these fields (never omitted):

### Identity Fields

```json
{
  "pid": 1234,
  "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:1234",
  "uid": 1000,
  "ppid": 1,
  "cmd_short": "node jest --worker",
  "cmd_full": "node /path/to/jest/bin/jest.js --worker=12345"
}
```

### Classification Fields

```json
{
  "classification": "abandoned",
  "posterior": {
    "abandoned": 0.94,
    "useful": 0.03,
    "useful_bad": 0.02,
    "zombie": 0.01
  },
  "confidence": "high",
  "matched_signature": "jest-worker-stuck",
  "novel_pattern": false
}
```

### Blast Radius (Always Present)

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

### Reversibility (Always Present)

```json
{
  "reversibility": {
    "reversible": false,
    "recovery_options": ["Restart via: npm test"],
    "data_at_risk": false,
    "open_write_fds": [],
    "note": "Not supervised; kill is final but restartable"
  }
}
```

### Supervisor Info (Always Present)

```json
{
  "supervisor": {
    "detected": false,
    "type": null,
    "unit": null,
    "recommended_action": "kill",
    "supervisor_command": null
  }
}
```

When supervised:

```json
{
  "supervisor": {
    "detected": true,
    "type": "systemd",
    "unit": "my-app.service",
    "recommended_action": "systemctl_stop",
    "supervisor_command": "systemctl --user stop my-app.service"
  }
}
```

### Uncertainty (Always Present)

```json
{
  "uncertainty": {
    "confidence_level": 0.94,
    "uncertainty_drivers": [
      {"factor": "io_activity", "impact": "medium", "note": "Last IO 45min ago"}
    ],
    "to_increase_confidence": [
      {"probe": "wait 15 minutes", "expected_gain": 0.03, "cost": "time"}
    ],
    "decision_robustness": "high"
  }
}
```

### Action Fields (Always Present)

```json
{
  "recommended_action": "kill",
  "action_rationale": "High-confidence abandoned process; blast radius contained"
}
```

---

## JSON Schemas

### Plan Output Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["schema_version", "session_id", "generated_at", "host_id", "summary", "candidates"],
  "properties": {
    "schema_version": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$"},
    "session_id": {"type": "string"},
    "generated_at": {"type": "string", "format": "date-time"},
    "host_id": {"type": "string"},
    "summary": {
      "type": "object",
      "required": ["total_scanned", "candidates_found", "kill_recommended", "review_recommended"],
      "properties": {
        "total_scanned": {"type": "integer"},
        "candidates_found": {"type": "integer"},
        "kill_recommended": {"type": "integer"},
        "review_recommended": {"type": "integer"},
        "spare_count": {"type": "integer"},
        "total_recoverable_mb": {"type": "number"},
        "total_recoverable_cpu_pct": {"type": "number"}
      }
    },
    "candidates": {
      "type": "array",
      "items": {"$ref": "#/$defs/candidate"}
    },
    "recommended": {
      "type": "object",
      "properties": {
        "preselected_pids": {"type": "array", "items": {"type": "integer"}},
        "actions": {"type": "array", "items": {"$ref": "#/$defs/action"}},
        "total_actions": {"type": "integer"},
        "estimated_recovery_mb": {"type": "number"}
      }
    }
  },
  "$defs": {
    "candidate": {
      "type": "object",
      "required": ["pid", "start_id", "uid", "classification", "posterior", "blast_radius", "reversibility", "supervisor", "uncertainty", "recommended_action", "action_rationale"],
      "properties": {
        "pid": {"type": "integer"},
        "start_id": {"type": "string"},
        "uid": {"type": "integer"},
        "ppid": {"type": "integer"},
        "cmd_short": {"type": "string"},
        "cmd_full": {"type": "string"},
        "classification": {"enum": ["useful", "useful_bad", "abandoned", "zombie"]},
        "posterior": {
          "type": "object",
          "properties": {
            "useful": {"type": "number"},
            "useful_bad": {"type": "number"},
            "abandoned": {"type": "number"},
            "zombie": {"type": "number"}
          }
        },
        "confidence": {"enum": ["low", "medium", "high", "very_high"]},
        "blast_radius": {"$ref": "#/$defs/blast_radius"},
        "reversibility": {"$ref": "#/$defs/reversibility"},
        "supervisor": {"$ref": "#/$defs/supervisor"},
        "uncertainty": {"$ref": "#/$defs/uncertainty"},
        "recommended_action": {"enum": ["kill", "pause", "throttle", "restart", "review", "spare"]},
        "action_rationale": {"type": "string"}
      }
    },
    "blast_radius": {
      "type": "object",
      "required": ["memory_mb", "risk_level", "summary"],
      "properties": {
        "memory_mb": {"type": "number"},
        "cpu_pct": {"type": "number"},
        "child_count": {"type": "integer"},
        "connection_count": {"type": "integer"},
        "open_files": {"type": "integer"},
        "dependent_processes": {"type": "array"},
        "risk_level": {"enum": ["none", "low", "medium", "high", "critical"]},
        "summary": {"type": "string"}
      }
    },
    "reversibility": {
      "type": "object",
      "required": ["reversible"],
      "properties": {
        "reversible": {"type": "boolean"},
        "recovery_options": {"type": "array", "items": {"type": "string"}},
        "data_at_risk": {"type": "boolean"},
        "open_write_fds": {"type": "array"},
        "note": {"type": "string"}
      }
    },
    "supervisor": {
      "type": "object",
      "required": ["detected", "recommended_action"],
      "properties": {
        "detected": {"type": "boolean"},
        "type": {"type": ["string", "null"]},
        "unit": {"type": ["string", "null"]},
        "recommended_action": {"type": "string"},
        "supervisor_command": {"type": ["string", "null"]}
      }
    },
    "uncertainty": {
      "type": "object",
      "required": ["confidence_level", "decision_robustness"],
      "properties": {
        "confidence_level": {"type": "number", "minimum": 0, "maximum": 1},
        "uncertainty_drivers": {"type": "array"},
        "to_increase_confidence": {"type": "array"},
        "decision_robustness": {"enum": ["low", "medium", "high"]}
      }
    },
    "action": {
      "type": "object",
      "required": ["target", "action", "stage"],
      "properties": {
        "target": {
          "type": "object",
          "required": ["pid", "start_id"],
          "properties": {
            "pid": {"type": "integer"},
            "start_id": {"type": "string"}
          }
        },
        "action": {"type": "string"},
        "stage": {"type": "integer"},
        "gates": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
```

### Apply Output Schema

```json
{
  "type": "object",
  "required": ["schema_version", "session_id", "results"],
  "properties": {
    "schema_version": {"type": "string"},
    "session_id": {"type": "string"},
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["target", "action", "outcome"],
        "properties": {
          "target": {"type": "object"},
          "action": {"type": "string"},
          "outcome": {
            "enum": ["success", "skipped", "failed", "blocked"]
          },
          "reason": {"type": "string"},
          "duration_ms": {"type": "integer"}
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total": {"type": "integer"},
        "successful": {"type": "integer"},
        "skipped": {"type": "integer"},
        "failed": {"type": "integer"},
        "memory_freed_mb": {"type": "number"}
      }
    }
  }
}
```

### Verify Output Schema

```json
{
  "type": "object",
  "required": ["schema_version", "session_id", "verification", "action_outcomes"],
  "properties": {
    "schema_version": {"type": "string"},
    "session_id": {"type": "string"},
    "verification": {
      "type": "object",
      "properties": {
        "requested_at": {"type": "string", "format": "date-time"},
        "completed_at": {"type": "string", "format": "date-time"},
        "overall_status": {
          "enum": ["success", "partial_success", "failure"]
        }
      }
    },
    "action_outcomes": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["target", "action", "outcome"],
        "properties": {
          "target": {"type": "object"},
          "action": {"type": "string"},
          "outcome": {
            "enum": ["confirmed_dead", "confirmed_stopped", "still_running", "respawned", "pid_reused", "cascaded", "timeout"]
          },
          "time_to_death_ms": {"type": "integer"},
          "resources_freed": {"type": "object"},
          "respawn_detected": {"type": "object"}
        }
      }
    },
    "resource_summary": {
      "type": "object",
      "properties": {
        "memory_freed_mb": {"type": "number"},
        "expected_mb": {"type": "number"},
        "shortfall_reason": {"type": "string"}
      }
    }
  }
}
```

---

## Error Handling

### Error Response Format

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

### Error Codes

| Code | Meaning | Recoverable |
|------|---------|-------------|
| `IDENTITY_MISMATCH` | PID reused or process changed | Yes (replan) |
| `SESSION_NOT_FOUND` | Session ID doesn't exist | No |
| `SESSION_EXPIRED` | Session past retention | No |
| `PERMISSION_DENIED` | Insufficient privileges | Maybe (sudo) |
| `PROTECTED_PROCESS` | Target is protected | No |
| `BUDGET_EXHAUSTED` | FDR/alpha budget depleted | Yes (wait) |
| `GATE_FAILED` | Safety gate blocked action | Depends |
| `INTERNAL_ERROR` | Unexpected error | No |

---

## Prose Output Contract

When `--include-prose` or `--format prose` is used:

```json
{
  "prose_summary": {
    "executive": "Your devbox is under memory pressure with only 4.2GB available...",
    "actions": "I recommend killing 3 abandoned processes consuming 2.4GB combined...",
    "rationale": "These processes have been idle for hours with no I/O activity...",
    "next_steps": "After cleanup, monitor for recurring patterns. Consider..."
  }
}
```

### Prose Style Options

| Style | Characteristics |
|-------|-----------------|
| `terse` | Bullet points, minimal |
| `conversational` | Natural, friendly (default) |
| `formal` | Professional report style |
| `technical` | Include technical details |

---

## Galaxy-Brain Contract

When `--galaxy-brain` is enabled:

```json
{
  "galaxy_brain": {
    "enabled": true,
    "cards": [
      {
        "id": "posterior_core",
        "title": "Posterior Core",
        "equations": [
          "log P(C|x) = log P(C) + Σ_j log P(x_j|C)",
          "log odds = log P(abandoned|x) - log P(useful|x)"
        ],
        "values": {
          "log_prior_useful": -2.11,
          "terms": {"cpu": 1.37, "tty": 0.84},
          "log_odds": 1.12
        },
        "intuition": "CPU+TTY evidence dominates; IO softens confidence."
      }
    ]
  }
}
```

### Standard Card IDs

| ID | Description |
|----|-------------|
| `posterior_core` | Main posterior computation |
| `hazard_time_varying` | Time-varying hazard analysis |
| `conformal_interval` | Conformal prediction intervals |
| `conformal_class` | Conformal class sets |
| `e_fdr` | Anytime-valid FDR control |
| `alpha_investing` | Alpha-investing budget tracking |
| `voi` | Value of Information analysis |

---

## Agent Workflow Patterns

### One-Shot Cleanup

```bash
SESSION=$(pt agent snapshot --format json | jq -r .session_id)
pt agent plan --session $SESSION --format json > plan.json
pt agent apply --session $SESSION --recommended --yes
pt agent verify --session $SESSION
```

### Monitored Loop

```bash
while true; do
  SESSION=$(pt agent plan --format json | jq -r .session_id)
  KILLS=$(pt agent plan --session $SESSION --only kill --format json | jq '.candidates | length')
  if [ "$KILLS" -gt 0 ]; then
    pt agent apply --session $SESSION --recommended --yes
    pt agent verify --session $SESSION
  fi
  sleep 300
done
```

### Differential Monitoring

```bash
LAST_SESSION=""
while true; do
  if [ -n "$LAST_SESSION" ]; then
    pt agent plan --since $LAST_SESSION --format json
  else
    pt agent plan --format json
  fi
  LAST_SESSION=$(jq -r .session_id < /dev/stdin)
  sleep 60
done
```

---

## Testing Requirements

Agents integrating with this contract should verify:

1. **Schema parsing**: All required fields present
2. **Idempotency**: Same plan applies identically twice
3. **Resumability**: Interrupted operations resume correctly
4. **Error handling**: Graceful handling of all error codes
5. **Identity safety**: PID reuse detected and blocked
