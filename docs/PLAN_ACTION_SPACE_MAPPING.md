# Plan Action Space Mapping (Section 6)

This file maps Plan Section 6 (Action Space) to canonical beads so execution work does not require re-opening the full plan document.

## Plan 6.0 - Actions beyond kill
Plan requirement: action set includes (at minimum):
- keep
- pause/resume (SIGSTOP/SIGCONT)
- renice
- cgroup freeze/quarantine (cgroup v2 freezer where available)
- cgroup CPU throttle
- cpuset quarantine
- supervisor/service stop/restart/reload when managed
- zombie resolution (reap via parent chain)
- kill (SIGTERM -> SIGKILL) as last resort

Canonical beads
- Action execution system epic: process_triage-sj6
- Action plan generation (ordering/staging): process_triage-1t1
- Staged execution protocol: process_triage-kyl
- Kill actions (TERM -> KILL, group-aware, TOCTOU safety): process_triage-sj6.3
- Pause/resume actions (group-aware): process_triage-sj6.2
- Renice: process_triage-sj6.4
- Cgroup freeze/quarantine: process_triage-sj6.5
- Cgroup CPU throttle: process_triage-sj6.6
- Cpuset quarantine: process_triage-sj6.7
- Zombie + D-state handling rules: process_triage-sj6.1

Critical safety constraints (invariants)
- PID reuse / TOCTOU: revalidate identity immediately before action; never kill by PID alone.
- Session safety: protect the active login/session chain by default.
- Privilege scope: default to same-UID only; cross-UID requires explicit policy and is not auto-executable by default.

Supporting spec beads
- Identity + privilege contract (pid/start_id/uid/...): process_triage-o8m, process_triage-cfon.2
- Session safety protections: process_triage-sj6.9

---

## Plan 6.1 - Supervisor detection and supervisor-aware actions
Plan requirement: detect supervisors (systemd/launchd/supervisord/pm2/docker/containerd/nodemon/tmux/screen/etc.) and prefer supervisor-level actions; track respawn loops.

Canonical beads
- Supervisor detection epic: process_triage-6l1
- Supervisor-aware action executors: process_triage-sj6.8
- Supervisor detection integration into action phase: process_triage-mty

---

## Plan 6.2 - Failure recovery trees (agent error handling)
Plan requirement: attach recovery trees (retry/fallback/escalate/report-only) rather than silently continuing.

Canonical beads
- Failure recovery trees for agent error handling: process_triage-asdq
- Failure recovery and retry logic: process_triage-rtb

---

## Test coverage anchors (Plan Section 11 tie-in)
- Action tray E2E tests (pause/throttle/renice/cgroups): process_triage-aii.1
- Safety gate tests (identity, data-loss, zombie/D-state rules): process_triage-c982

---

## Coverage checklist (Plan Section 6)
- [x] All required actions and safety constraints are mapped above.
- [x] Supervisor-aware actions exist and respawn loops are detectable.
- [x] Failure paths are explicit and auditable (no silent failures).

## Acceptance criteria
- [x] Canonical mapping remains accurate (no missing plan subsection).
- [x] All referenced canonical bead IDs exist and are the intended owners.
- [x] Coverage checklist items in this bead are satisfied.
