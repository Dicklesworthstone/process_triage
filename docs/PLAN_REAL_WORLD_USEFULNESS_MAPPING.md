# Plan Real-World Usefulness Mapping (Section 8)

This file maps Plan Section 8 (real-world usefulness enhancements) to canonical beads so the enhancement list is preserved without reopening the plan.

## Plan 8 - Enhancement list (mapped)

### Rich observability (IO/syscalls/context switches/page faults/swap/run-queue delay/fd churn/lock contention/socket backlog)
- Evidence collection epic + tool runner (timeouts/caps/backpressure): process_triage-3ir, process_triage-71t
- Deep scan via /proc inspection: process_triage-cki
- Maximal instrumentation install strategy (Phase 3a): process_triage-167

### Context priors (TTY/tmux/git status/recent shell activity/open editor)
- User-intent/context features: process_triage-cfon.6

### Human-in-the-loop updates (decisions update priors; conjugate updates)
- Pattern learning from user decisions: process_triage-dikk
- Empirical Bayes + conjugate update workflows: process_triage-21f, process_triage-72j.3, process_triage-nao.10

### Shadow mode (advisory only; log decisions for calibration)
- Shadow mode + calibration epic: process_triage-21f

### Safety rails (rate-limit; never kill system services)
- Safety/policy/guardrails epic: process_triage-dvi
- Policy enforcement engine: process_triage-3nz
- Protected process pattern matching: process_triage-gic
- Rate limiting: process_triage-8z2

### Data-loss gate (open write FDs; inflate kill loss or hard-block in --robot)
- Data-loss safety gate (open write handles, locks): process_triage-dvi.1
- Safety gate tests: process_triage-c982

### Runbooks (suggest safe restart/pause for known services)
- Pattern/signature library + runbook metadata: process_triage-79x

### Incident integration (logging, rollback hooks)
- Telemetry lake + outcome records: process_triage-k4yc
- Action execution outcomes + verification: process_triage-kyl, process_triage-4gq

### Systemd/Kubernetes plugins for service-aware control
- Supervisor detection + supervisor-aware actions: process_triage-6l1, process_triage-sj6.8
- Fleet mode + cross-host coordination: process_triage-8t1

### Data governance (explicit retention policy; full audit trail; no silent deletions)
- Redaction/hashing policy spec: process_triage-8n3
- Redaction/hashing enforcement: process_triage-k4yc.1
- Retention policy + explicit retention events: process_triage-k4yc.6
- Telemetry tests (no sensitive strings persisted): process_triage-8t2k

### Counterfactual testing (recommended vs actual)
- Shadow mode + outcome logging/analysis: process_triage-21f
- Differential session comparison: process_triage-9k8

### Risk-budgeted optimal stopping based on load
- Sequential stopping rules: process_triage-of3n
- Load-aware thresholds (queueing): process_triage-p15.1

### Dependency graph + impact scoring in loss matrix
- Dependency impact features: process_triage-cfon.5
- Dependency-weighted loss: process_triage-un6

### User intent injection for priors (declared runs / active sessions)
- User-intent/context features: process_triage-cfon.6

### Time-to-decision bound with pause default
- Time-to-decision bound: process_triage-p15.6
- Pause/resume actions: process_triage-sj6.2

### PAC-Bayes validation in shadow mode
- PAC-Bayes bounds reporting: process_triage-72j.2

### Coupled process-tree inference for correlated stuckness
- PPID-tree belief propagation (coupled prior): process_triage-d7s

### Hawkes/marked point process burst detection
- Hawkes layer: process_triage-hxh
- Marked point process features: process_triage-cfon.8

### Robust stats to reduce false positives
- Robust stats summaries: process_triage-nao.8

### Empirical Bayes shrinkage to stabilize rare command categories
- Hierarchical priors + EB shrinkage: process_triage-nao.10

### BOCPD-based detection of regime shifts
- BOCPD: process_triage-lfrb

### Optional perf/eBPF instrumentation for high-fidelity signals
- Tool install strategy (Linux perf/eBPF/etc): process_triage-167

### Copula-based joint dependence modeling
- Copula dependence summaries: process_triage-nao.1

### Kalman smoothing for noisy CPU/load signals
- Kalman smoothing: process_triage-0io

### Wasserstein shift detection for drift
- Wasserstein drift detection: process_triage-9kk3

### Martingale bounds for persistent anomalies
- Time-uniform martingale/e-process gates: process_triage-p15.8
- Martingale deviation features: process_triage-cfon.9

### Risk-sensitive control (CVaR/entropic)
- Risk-sensitive control (CVaR): process_triage-ctb

### Bayesian model averaging across inference layers
- BMA: process_triage-nao.7

### Conformal prediction for robust intervals
- Conformal prediction: process_triage-tcf

### Agent/robot CLI parity with TUI (JSON/MD/JSONL)
- Agent/robot contract spec: process_triage-jqi
- Parity layer epic: process_triage-bwn

### Shareable .ptb bundles + premium single-file HTML reports
- Bundles/reports epic: process_triage-bra
- Bundle E2E tests: process_triage-aii.2
- Report E2E tests: process_triage-j47h

### Dormant mode daemon (24/7 guardian)
- Dormant daemon epic: process_triage-b4v

---

## Plan 8.1 - Pitfalls to avoid (premium guardrails)
- Canonical pitfalls/guardrails checklist: process_triage-h89.2

---

## Coverage checklist (Plan Section 8)
- [x] Every bullet in Section 8 is mapped above to a canonical bead.
- [x] Cross-cutting safety + governance (redaction/retention/lock) remain explicit and test-backed.

## Acceptance criteria
- [x] Canonical mapping remains accurate (no missing plan subsection).
- [x] All referenced canonical bead IDs exist and are the intended owners.
- [x] Coverage checklist items in this bead are satisfied.
