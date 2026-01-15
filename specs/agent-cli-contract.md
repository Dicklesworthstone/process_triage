# Agent CLI Contract Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-jqi

---

## 1. Overview

This document specifies the complete contract for the `pt agent` CLI interface, designed for consumption by AI agents. It extends the CLI surface specification with precise JSON schemas, session semantics, and behavioral guarantees.

### Design Principles

1. **Token efficiency**: Minimize output size while preserving essential information
2. **Deterministic parsing**: Every output conforms to a strict JSON schema
3. **Resumable workflows**: Sessions preserve state across CLI invocations
4. **Fail-safe defaults**: Conservative behavior when parameters are unspecified
5. **Self-documenting**: Schema version and capability information in every response

### Target Consumers

- AI agents (Claude, GPT-4, etc.) orchestrating system management
- Automation scripts with strict parsing requirements
- Other pt instances in fleet mode
- Human operators using `--format md` for review

---

## 2. Session Semantics

### 2.1 Session Identity

Sessions are the fundamental unit of pt workflow continuity.

```
Session ID Format: pt-YYYYMMDD-HHMMSS-XXXX
Example: pt-20260115-143022-a7b3
```

| Component | Description |
|-----------|-------------|
| `pt-` | Fixed prefix for identification |
| `YYYYMMDD` | Date in UTC |
| `HHMMSS` | Time in UTC |
| `XXXX` | 4-character random suffix (base32, lowercase a-z2-7) |

### 2.2 Session Lifecycle

```
┌─────────┐     ┌──────────┐     ┌───────────┐     ┌───────────┐     ┌──────────┐
│ created │ ──▶ │ scanning │ ──▶ │ inferring │ ──▶ │ deciding  │ ──▶ │ planned  │
└─────────┘     └──────────┘     └───────────┘     └───────────┘     └──────────┘
                                                                           │
                                                                           ▼
┌──────────┐     ┌───────────┐     ┌──────────────┐     ┌────────────────────────┐
│ complete │ ◀── │ verifying │ ◀── │ applying     │ ◀── │ awaiting_confirmation  │
└──────────┘     └───────────┘     └──────────────┘     └────────────────────────┘
                                          │
                                          ▼
                                   ┌─────────────┐
                                   │ interrupted │
                                   └─────────────┘
```

### 2.3 Session State Enum

| State | Description | Resumable |
|-------|-------------|-----------|
| `created` | Session initialized, no work done | No |
| `scanning` | Collecting process data | No |
| `inferring` | Computing posteriors | No |
| `deciding` | Generating action plan | No |
| `planned` | Plan ready, awaiting confirmation | Yes |
| `awaiting_confirmation` | User/agent confirmation needed | Yes |
| `applying` | Executing actions | Yes |
| `verifying` | Confirming outcomes | No |
| `complete` | All work finished | No |
| `interrupted` | Execution halted mid-stream | Yes |
| `failed` | Unrecoverable error | No |
| `expired` | Session timed out | No |

### 2.4 Session Continuity Guarantees

1. **Idempotent reads**: `plan`, `explain`, `status`, `sessions` can be called multiple times
2. **Single-writer**: Only one `apply` operation per session at a time
3. **Lock coordination**: Sessions acquire per-user locks before destructive operations
4. **Atomic transitions**: State transitions are atomic; partial states are not visible

### 2.5 Session Storage

Sessions are stored in the pt data directory:

```
~/.local/share/process_triage/sessions/
├── pt-20260115-143022-a7b3/
│   ├── manifest.json       # Session metadata
│   ├── scan.parquet        # Raw scan data
│   ├── inference.parquet   # Inference results
│   ├── plan.json           # Action plan
│   ├── outcomes.parquet    # Execution outcomes
│   └── ledger.parquet      # Math ledger (if --galaxy-brain)
└── pt-20260115-150801-c2d4/
    └── ...
```

---

## 3. JSON Output Schemas

### 3.1 Common Envelope

Every agent command returns this envelope:

```json
{
  "$schema": "https://process-triage.dev/schemas/agent-response/1.0.0",
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "generated_at": "2026-01-15T14:30:22.456Z",
  "host_id": "devbox1",
  "command": "plan",
  "duration_ms": 1234,
  "status": "success",
  "warnings": [],
  "data": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | Yes | Schema version (semver) |
| `session_id` | string | Yes | Session identifier |
| `generated_at` | string | Yes | ISO 8601 timestamp with milliseconds |
| `host_id` | string | Yes | Host identifier (hashed if privacy mode) |
| `command` | string | Yes | Command that produced this output |
| `duration_ms` | int | Yes | Command execution time |
| `status` | enum | Yes | `success`, `partial`, `error` |
| `warnings` | array | Yes | Non-fatal warnings (may be empty) |
| `data` | object | Yes | Command-specific payload |

### 3.2 Warning Object

```json
{
  "code": "WARN_TOOL_UNAVAILABLE",
  "message": "lsof not available; network connections not scanned",
  "severity": "info",
  "affects": ["network_connections", "open_files"]
}
```

### 3.3 Error Response

When `status` is `error`:

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "status": "error",
  "error": {
    "code": "ERR_PERMISSION",
    "message": "Cannot read /proc/1234/io: Permission denied",
    "details": {
      "pid": 1234,
      "path": "/proc/1234/io",
      "errno": 13
    },
    "recoverable": false,
    "suggestion": "Run with elevated privileges or exclude this PID",
    "documentation_url": "https://process-triage.dev/errors/ERR_PERMISSION"
  }
}
```

---

## 4. Candidate Schema

The candidate object is the core data structure returned by `plan` and `explain`.

### 4.1 Candidate Object (Full)

```json
{
  "pid": 45678,
  "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942820:45678",
  "uid": 1000,
  "user": "developer",
  "cmd_short": "node",
  "cmd_full": "node /home/developer/app/server.js",
  "cwd": "/home/developer/app",
  "tty": "?",
  "state": "S",
  "ppid": 1,
  "pgid": 45678,
  "sid": 45678,

  "classification": "abandoned",
  "posterior": {
    "useful": 0.02,
    "useful_bad": 0.08,
    "abandoned": 0.85,
    "zombie": 0.05
  },
  "confidence": "high",
  "confidence_score": 0.92,

  "metrics": {
    "cpu_percent": 0.1,
    "rss_mb": 512,
    "runtime_seconds": 86400,
    "threads": 4,
    "open_fds": 23,
    "io_read_mb": 1.2,
    "io_write_mb": 0.0
  },

  "signals": {
    "orphaned": true,
    "tty_lost": true,
    "io_flatline": true,
    "cpu_stalled": false,
    "memory_growing": false
  },

  "category": "dev_server",
  "signature_match": null,

  "blast_radius": {
    "total_mb": 512,
    "child_count": 0,
    "client_count": 0,
    "severity": "low"
  },

  "reversibility": {
    "can_restart": false,
    "supervisor": null,
    "restart_command": null,
    "data_loss_risk": "none"
  },

  "supervisor": {
    "detected": false,
    "type": null,
    "unit": null,
    "recommendation": null
  },

  "uncertainty": {
    "data_quality": "good",
    "model_confidence": "high",
    "known_limitations": []
  },

  "recommended_action": "kill",
  "action_rationale": "High posterior (85%) abandoned with orphaned+TTY-lost signals. No active I/O for 24h.",

  "fdr_state": {
    "lfdr": 0.08,
    "e_value": 12.5,
    "in_selected_set": true,
    "selection_rank": 3
  }
}
```

### 4.2 Candidate Object (Compact)

When `--compact` is specified, optional fields are omitted:

```json
{
  "pid": 45678,
  "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942820:45678",
  "uid": 1000,
  "cmd_short": "node",
  "classification": "abandoned",
  "posterior": {"useful": 0.02, "useful_bad": 0.08, "abandoned": 0.85, "zombie": 0.05},
  "confidence": "high",
  "blast_radius": {"total_mb": 512, "severity": "low"},
  "reversibility": {"data_loss_risk": "none"},
  "supervisor": {"detected": false},
  "uncertainty": {"model_confidence": "high"},
  "recommended_action": "kill",
  "action_rationale": "High posterior abandoned with orphaned+TTY-lost signals."
}
```

### 4.3 Critical Fields (Always Present)

These fields MUST be present in every candidate, regardless of `--compact`:

| Field | Type | Description |
|-------|------|-------------|
| `pid` | int | Process ID |
| `start_id` | string | Stable identity: `<boot_id>:<start_time>:<pid>` |
| `uid` | int | User ID |
| `cmd_short` | string | Short command name (first 32 chars) |
| `classification` | enum | `useful`, `useful_bad`, `abandoned`, `zombie` |
| `posterior` | object | Posterior probabilities per class |
| `confidence` | enum | `low`, `medium`, `high` |
| `blast_radius` | object | Impact assessment (always computed) |
| `reversibility` | object | Recovery options (always computed) |
| `supervisor` | object | Supervisor detection (always checked) |
| `uncertainty` | object | Model uncertainty (always reported) |
| `recommended_action` | enum | `keep`, `pause`, `throttle`, `kill`, `restart`, `review` |
| `action_rationale` | string | Human-readable justification |

---

## 5. Command-Specific Schemas

### 5.1 `agent snapshot` Response

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "command": "snapshot",
  "status": "success",
  "data": {
    "system": {
      "hostname": "devbox1",
      "os": "linux",
      "kernel": "6.5.0-generic",
      "uptime_seconds": 864000,
      "load_avg": [1.2, 0.8, 0.5],
      "memory": {
        "total_mb": 32768,
        "used_mb": 24576,
        "available_mb": 8192,
        "swap_used_mb": 0
      },
      "cpu": {
        "cores": 8,
        "usage_percent": 15.5
      },
      "psi": {
        "cpu_some": 2.5,
        "memory_some": 0.1,
        "io_some": 0.3
      }
    },
    "census": {
      "total_processes": 245,
      "by_state": {"R": 3, "S": 230, "D": 2, "Z": 1, "T": 9},
      "orphans": 12,
      "zombies": 1,
      "my_user_processes": 89
    },
    "resource_hogs": {
      "top_cpu": [
        {"pid": 1234, "cmd_short": "rust-analyzer", "cpu_percent": 45.2}
      ],
      "top_memory": [
        {"pid": 5678, "cmd_short": "chrome", "rss_mb": 4096}
      ],
      "top_io": [
        {"pid": 9012, "cmd_short": "rsync", "io_rate_mbps": 120.5}
      ]
    },
    "anomalies": {
      "long_running_orphans": 5,
      "high_memory_growth": 2,
      "suspicious_patterns": []
    },
    "capabilities": {
      "can_deep_scan": true,
      "can_kill_others": false,
      "available_probes": ["lsof", "ss", "perf"]
    },
    "next_steps": [
      {"command": "pt agent plan", "description": "Generate action plan for detected issues"},
      {"command": "pt agent plan --deep", "description": "Deep scan suspicious processes"}
    ]
  }
}
```

### 5.2 `agent plan` Response

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "command": "plan",
  "status": "success",
  "data": {
    "scan_summary": {
      "processes_scanned": 245,
      "candidates_found": 8,
      "scan_duration_ms": 1200,
      "deep_scan_performed": false
    },
    "plan": {
      "total_candidates": 8,
      "by_action": {
        "kill": 3,
        "pause": 1,
        "review": 4
      },
      "expected_recovery": {
        "memory_mb": 2048,
        "cpu_percent": 5.2
      },
      "safety_gates": {
        "fdr_alpha": 0.05,
        "fdr_passed": true,
        "max_kills_check": true,
        "protected_check": true,
        "all_gates_passed": true
      },
      "blast_radius_total": {
        "memory_mb": 2048,
        "process_count": 3,
        "severity": "medium"
      }
    },
    "candidates": [
      { /* Candidate object - see Section 4 */ }
    ],
    "pre_toggled": {
      "action": "kill",
      "pids": [45678, 45679, 45680],
      "rationale": "3 candidates pass FDR gate with high confidence (>95% posterior abandoned)"
    },
    "requires_confirmation": true,
    "apply_command": "pt agent apply --session pt-20260115-143022-a7b3 --recommended --yes"
  }
}
```

### 5.3 `agent explain` Response

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "command": "explain",
  "status": "success",
  "data": {
    "candidate": { /* Full candidate object */ },
    "evidence": {
      "log_likelihood_contributions": {
        "cpu_beta": -1.23,
        "runtime_gamma": -2.45,
        "orphan_beta": -0.12,
        "tty_beta": -0.89,
        "io_active_beta": -3.21,
        "category_dirichlet": -0.45
      },
      "bayes_factors": {
        "vs_useful": 42.5,
        "vs_useful_bad": 10.2,
        "vs_zombie": 17.0
      },
      "top_evidence_items": [
        {
          "feature": "io_active",
          "value": false,
          "contribution_nats": -3.21,
          "interpretation": "No I/O activity strongly indicates abandoned"
        },
        {
          "feature": "runtime",
          "value": 86400,
          "contribution_nats": -2.45,
          "interpretation": "24h runtime without TTY is unusual for dev processes"
        }
      ]
    },
    "process_tree": {
      "ancestors": [
        {"pid": 1, "cmd_short": "systemd"}
      ],
      "children": [],
      "siblings": []
    },
    "timeline": [
      {"ts": "2026-01-14T14:30:00Z", "event": "process_started"},
      {"ts": "2026-01-14T14:35:00Z", "event": "tty_detached"},
      {"ts": "2026-01-14T14:40:00Z", "event": "parent_exited", "details": "reparented to init"},
      {"ts": "2026-01-15T14:30:00Z", "event": "flagged_abandoned"}
    ],
    "what_would_change_mind": [
      {"condition": "Recent I/O activity", "posterior_shift": "+25% useful"},
      {"condition": "TTY reattached", "posterior_shift": "+40% useful"},
      {"condition": "Child processes spawned", "posterior_shift": "+15% useful"}
    ],
    "galaxy_brain": null
  }
}
```

### 5.4 `agent explain --galaxy-brain` Response Extension

When `--galaxy-brain` is specified, the `galaxy_brain` field contains:

```json
{
  "galaxy_brain": {
    "cards": [
      {
        "id": "posterior_core",
        "title": "Posterior Computation",
        "equations": [
          "log P(C|x) = log P(C) + Σ_j log P(x_j|C)",
          "P(abandoned|x) = exp(log_post_abandoned) / Σ_C exp(log_post_C)"
        ],
        "values": {
          "log_prior_abandoned": -1.61,
          "log_likelihood_abandoned": -8.35,
          "log_posterior_abandoned": -9.96,
          "posterior_abandoned": 0.85
        },
        "interpretation": "Prior 20% × strong evidence from IO+orphan+TTY → 85% posterior"
      },
      {
        "id": "sprt_threshold",
        "title": "SPRT Decision Boundary",
        "equations": [
          "kill if log_odds > log[(L(kill,useful)-L(keep,useful))/(L(keep,abandoned)-L(kill,abandoned))]",
          "threshold = log[(100-0)/(30-1)] = log(3.45) = 1.24"
        ],
        "values": {
          "log_odds_abandoned_vs_useful": 3.76,
          "threshold": 1.24,
          "decision": "kill"
        },
        "interpretation": "Log odds 3.76 >> threshold 1.24; strong kill signal"
      },
      {
        "id": "fdr_selection",
        "title": "FDR-Gated Selection",
        "equations": [
          "lfdr_i = P(useful|x_i)",
          "Select largest K with (1/|K|) Σ lfdr_i ≤ α"
        ],
        "values": {
          "lfdr": 0.02,
          "alpha": 0.05,
          "k": 3,
          "in_set": true
        },
        "interpretation": "lfdr=0.02 < α=0.05; included in FDR-controlled kill set"
      }
    ]
  }
}
```

### 5.5 `agent apply` Response

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "command": "apply",
  "status": "success",
  "data": {
    "applied": [
      {
        "pid": 45678,
        "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942820:45678",
        "action": "kill",
        "signal": "SIGTERM",
        "result": "success",
        "duration_ms": 50,
        "verification": {
          "process_exited": true,
          "exit_code": null,
          "memory_freed_mb": 512
        }
      },
      {
        "pid": 45679,
        "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942825:45679",
        "action": "kill",
        "signal": "SIGTERM",
        "result": "success",
        "duration_ms": 45,
        "verification": {
          "process_exited": true,
          "exit_code": 0,
          "memory_freed_mb": 256
        }
      }
    ],
    "skipped": [
      {
        "pid": 45680,
        "reason": "identity_mismatch",
        "details": "Process start_id changed; PID may have been reused"
      }
    ],
    "failed": [],
    "summary": {
      "attempted": 3,
      "succeeded": 2,
      "skipped": 1,
      "failed": 0,
      "memory_freed_mb": 768,
      "cpu_freed_percent": 2.1
    },
    "session_state": "complete",
    "verify_command": "pt agent verify --session pt-20260115-143022-a7b3"
  }
}
```

### 5.6 `agent verify` Response

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7b3",
  "command": "verify",
  "status": "success",
  "data": {
    "outcomes": [
      {
        "pid": 45678,
        "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942820:45678",
        "action": "kill",
        "outcome": "confirmed_gone",
        "side_effects": [],
        "user_feedback": null
      },
      {
        "pid": 45679,
        "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942825:45679",
        "action": "kill",
        "outcome": "confirmed_gone",
        "side_effects": [],
        "user_feedback": null
      }
    ],
    "system_delta": {
      "memory_change_mb": -768,
      "cpu_change_percent": -2.1,
      "load_avg_change": [-0.3, -0.2, -0.1]
    },
    "unexpected_effects": [],
    "recommendation": "No issues detected. Safe to close session."
  }
}
```

### 5.7 `agent sessions` Response

```json
{
  "schema_version": "1.0.0",
  "command": "sessions",
  "status": "success",
  "data": {
    "sessions": [
      {
        "session_id": "pt-20260115-143022-a7b3",
        "state": "complete",
        "created_at": "2026-01-15T14:30:22Z",
        "updated_at": "2026-01-15T14:35:45Z",
        "candidates_found": 8,
        "actions_applied": 2,
        "resumable": false
      },
      {
        "session_id": "pt-20260115-120000-b2c4",
        "state": "interrupted",
        "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:05:30Z",
        "candidates_found": 5,
        "actions_applied": 1,
        "resumable": true
      }
    ],
    "total": 2,
    "resumable_count": 1
  }
}
```

### 5.8 `agent capabilities` Response

```json
{
  "schema_version": "1.0.0",
  "command": "capabilities",
  "status": "success",
  "data": {
    "os": {
      "family": "linux",
      "name": "Ubuntu",
      "version": "24.04"
    },
    "privileges": {
      "effective_uid": 1000,
      "is_root": false,
      "can_sudo": true,
      "can_kill_others": false
    },
    "probes": {
      "proc_fs": true,
      "lsof": true,
      "ss": true,
      "perf": false,
      "bpftrace": false,
      "systemctl": true,
      "cgroups_v2": true
    },
    "actions": {
      "kill_own": true,
      "kill_others": false,
      "pause_own": true,
      "throttle_cgroups": true
    },
    "storage": {
      "data_dir": "/home/developer/.local/share/process_triage",
      "sessions_available": 42,
      "disk_usage_mb": 128
    },
    "limits": {
      "max_kills_per_run": 5,
      "max_blast_radius_mb": 4096,
      "fdr_alpha": 0.05
    }
  }
}
```

---

## 6. Pre-Toggled Plan Semantics

### 6.1 Definition

A "pre-toggled" plan represents the system's recommended actions based on:

1. Posterior probabilities exceeding thresholds
2. FDR-controlled selection (limiting false kills)
3. Policy guardrails (protected patterns, max kills)
4. Blast radius limits

### 6.2 Selection Algorithm

```python
def select_pretoggled(candidates, policy, fdr_alpha):
    # 1. Filter by posterior threshold
    strong = [c for c in candidates
              if c.posterior['abandoned'] + c.posterior['zombie'] > 0.8]

    # 2. Filter by guardrails
    allowed = [c for c in strong
               if not matches_protected(c, policy.guardrails)]

    # 3. Sort by lfdr (ascending = safest first)
    sorted_candidates = sorted(allowed, key=lambda c: c.lfdr)

    # 4. FDR selection: largest K where avg(lfdr) <= alpha
    selected = []
    for i, c in enumerate(sorted_candidates):
        test_set = sorted_candidates[:i+1]
        avg_lfdr = sum(c.lfdr for c in test_set) / len(test_set)
        if avg_lfdr <= fdr_alpha:
            selected = test_set

    # 5. Apply max_kills limit
    return selected[:policy.guardrails.max_kills_per_run]
```

### 6.3 Pre-Toggle Output

```json
{
  "pre_toggled": {
    "action": "kill",
    "pids": [45678, 45679, 45680],
    "start_ids": ["9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942820:45678", "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942825:45679", "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:1736942830:45680"],
    "rationale": "3 candidates pass FDR gate (α=0.05) with avg lfdr=0.02",
    "gates_applied": ["fdr_control", "max_kills", "protected_patterns"],
    "excluded_by_gates": [
      {"pid": 45681, "gate": "protected_patterns", "pattern": "sshd"}
    ]
  }
}
```

### 6.4 Agent Confirmation Flow

```
1. pt agent plan
   → Returns pre_toggled.pids = [45678, 45679]
   → requires_confirmation = true

2. Agent reviews candidates, may call:
   pt agent explain --session <id> --pid 45678

3. Agent applies pre-toggled set:
   pt agent apply --session <id> --recommended --yes

   OR applies subset:
   pt agent apply --session <id> --pids 45678 --yes
```

---

## 7. Resumability Contract

### 7.1 `--resume` Behavior

When `--resume` is specified with a session in `interrupted` or `planned` state:

1. **Load session state**: Restore inference results, plan, and partial outcomes
2. **Revalidate targets**: Check that PIDs still exist with matching `start_id`
3. **Skip completed**: Don't re-execute actions that already succeeded
4. **Continue from failure**: Retry or skip previously failed actions

### 7.2 Resumable States

| State | Resumable | Behavior on Resume |
|-------|-----------|-------------------|
| `planned` | Yes | Start fresh apply |
| `awaiting_confirmation` | Yes | Re-prompt for confirmation |
| `applying` | Yes | Continue from last successful action |
| `interrupted` | Yes | Retry from interruption point |
| `complete` | No | Error: session already complete |
| `failed` | No | Error: session failed; start new |

### 7.3 Resume Output

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-120000-b2c4",
  "command": "apply",
  "resumed": true,
  "resume_context": {
    "original_started_at": "2026-01-15T12:00:00Z",
    "interrupted_at": "2026-01-15T12:05:30Z",
    "resumed_at": "2026-01-15T14:30:22Z",
    "previous_state": "interrupted",
    "already_completed": [45678],
    "remaining": [45679, 45680]
  },
  "data": { /* normal apply response */ }
}
```

---

## 8. Token Efficiency Controls

### 8.1 `--compact` Mode

Removes optional fields to minimize token usage:

| Removed Fields | Conditions |
|----------------|------------|
| `cmd_full` | Always in compact |
| `cwd` | Always in compact |
| `metrics` | Always in compact |
| `signals` | Always in compact |
| `fdr_state` | Always in compact |
| `timeline` | Always in compact |
| `galaxy_brain` | Unless explicitly requested |

### 8.2 `--fields` Selection

Request specific fields only:

```bash
pt agent plan --fields "pid,cmd_short,classification,recommended_action"
```

Output:

```json
{
  "candidates": [
    {"pid": 45678, "cmd_short": "node", "classification": "abandoned", "recommended_action": "kill"},
    {"pid": 45679, "cmd_short": "python", "classification": "abandoned", "recommended_action": "kill"}
  ]
}
```

### 8.3 `--include-prose` Mode

Adds human-readable summaries for agent-to-user handoff:

```json
{
  "data": {
    "candidates": [...],
    "prose_summary": "Found 8 candidates. 3 abandoned processes (node x2, python) recommended for termination. Total recovery: 2GB RAM. All safety gates passed."
  }
}
```

### 8.4 `--prose-style` Options

| Style | Description | Example |
|-------|-------------|---------|
| `terse` | Minimal, bullet points | "3 kills: node(2), python(1). 2GB freed." |
| `conversational` | Friendly, complete sentences | "I found 3 abandoned processes that should be safe to kill..." |
| `formal` | Technical, precise | "Analysis identified 3 process candidates classified as abandoned..." |
| `technical` | Maximum detail | "Bayesian inference yields 3 candidates with P(abandoned)>0.95..." |

---

## 9. Safety Gate Behavior

### 9.1 Gate Types

| Gate | Description | Behavior on Fail |
|------|-------------|------------------|
| `fdr_control` | FDR threshold exceeded | Reduce selection set |
| `max_kills` | Too many kills in one run | Truncate to limit |
| `max_blast_radius` | Impact exceeds threshold | Block or warn |
| `protected_patterns` | Matches protected process | Exclude from selection |
| `data_loss` | Open write handles detected | Block kill |
| `min_posterior` | Confidence too low | Exclude from selection |
| `identity_mismatch` | PID reused since plan | Skip action |

### 9.2 Gate Response Format

```json
{
  "safety_gates": {
    "fdr_control": {"passed": true, "alpha": 0.05, "selected": 3},
    "max_kills": {"passed": true, "limit": 5, "requested": 3},
    "max_blast_radius": {"passed": true, "limit_mb": 4096, "actual_mb": 768},
    "protected_patterns": {"passed": true, "blocked": []},
    "data_loss": {"passed": true, "warnings": []},
    "all_gates_passed": true
  }
}
```

### 9.3 Gate Failure Response

When a gate blocks execution:

```json
{
  "status": "error",
  "error": {
    "code": "ERR_BLOCKED",
    "message": "Safety gate 'data_loss' blocked kill action",
    "details": {
      "gate": "data_loss",
      "pid": 45678,
      "reason": "Process has open write handles",
      "handles": ["/home/developer/data.db-wal"]
    },
    "recoverable": true,
    "suggestion": "Wait for writes to complete or use --force-data-loss (dangerous)"
  }
}
```

---

## 10. Fleet Mode Extensions

### 10.1 Fleet Plan Response

```json
{
  "schema_version": "1.0.0",
  "command": "fleet plan",
  "status": "success",
  "data": {
    "fleet_session_id": "fleet-20260115-143022-a7b3",
    "hosts": [
      {
        "host_id": "devbox1",
        "session_id": "pt-20260115-143022-a7b3",
        "candidates_found": 8,
        "status": "planned"
      },
      {
        "host_id": "devbox2",
        "session_id": "pt-20260115-143025-b8c4",
        "candidates_found": 5,
        "status": "planned"
      }
    ],
    "fleet_summary": {
      "total_hosts": 2,
      "total_candidates": 13,
      "by_action": {"kill": 5, "pause": 2, "review": 6}
    },
    "fleet_fdr": {
      "pooled": true,
      "alpha": 0.05,
      "total_selected": 5
    },
    "cross_host_patterns": [
      {"pattern": "node server.js", "hosts": ["devbox1", "devbox2"], "count": 4}
    ]
  }
}
```

---

## 11. Error Codes Reference

| Code | Exit | Description |
|------|------|-------------|
| `OK_CLEAN` | 0 | Success, nothing to do |
| `OK_CANDIDATES` | 1 | Candidates found, plan produced |
| `OK_APPLIED` | 2 | Actions executed successfully |
| `ERR_PARTIAL` | 3 | Some actions failed |
| `ERR_BLOCKED` | 4 | Safety gate blocked action |
| `ERR_GOAL_UNREACHABLE` | 5 | Goal not achievable |
| `ERR_INTERRUPTED` | 6 | Session interrupted, resumable |
| `ERR_ARGS` | 10 | Invalid arguments |
| `ERR_CAPABILITY` | 11 | Required capability missing |
| `ERR_PERMISSION` | 12 | Permission denied |
| `ERR_VERSION` | 13 | Version mismatch |
| `ERR_LOCK` | 14 | Lock contention |
| `ERR_SESSION` | 15 | Session not found/invalid |
| `ERR_IDENTITY` | 16 | Process identity mismatch |
| `ERR_INTERNAL` | 20 | Internal error (bug) |
| `ERR_IO` | 21 | I/O error |
| `ERR_TIMEOUT` | 22 | Operation timed out |

---

## 12. References

- PLAN §3.5: Agent/Robot CLI Contract
- Bead: process_triage-3mi (CLI Surface)
- Bead: process_triage-o8m (Target Identity)
- Bead: process_triage-bg5 (Policy Schema)
