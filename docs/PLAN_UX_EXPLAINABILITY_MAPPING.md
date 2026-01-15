# Plan UX and Explainability Mapping (Section 7)

This file maps Plan Section 7 (UX + explainability) to canonical beads so implementation and review do not require the original plan document.

## Plan 7.0 - Golden path (one coherent run)
Plan requirement: default `pt` is a single guided workflow:
1) quick multi-sample scan
2) infer + generate plan (with gates + staged actions)
3) "Apply Plan" TUI approval
4) staged execution
5) after-view + session summary + export/report affordances

Canonical beads
- Golden path UX spec: process_triage-6rf
- Default behavior implementation anchor: process_triage-tiw6
- Durable session model (session_id + artifact dir): process_triage-qje, process_triage-t6lf
- TUI approval flow: process_triage-2ka

---

## Plan 7.1 - Evidence ledger
Plan requirement: per-process ledger includes posterior, Bayes factors, evidence contributions, confidence; surface top evidence items.

Canonical beads
- Evidence ledger generation: process_triage-myq
- Evidence ledger TUI display/drilldown: process_triage-03n

---

## Plan 7.2 - Confidence and explainability
Plan requirement: confidence from posterior concentration; glyphs/badges for key evidence categories.

Canonical beads
- Confidence visualization: process_triage-ic9d
- Feature provenance + evidence categories: process_triage-cfon

---

## Plan 7.3 - Human trust features
Plan requirement: clear "Why" summary and "what would change your mind" hint (VOI).

Canonical beads
- Natural language explanation generator (human readable why): process_triage-7h8
- VOI computation (drives "what would change your mind"): process_triage-brh7
- What-if explainer (agent-oriented version): process_triage-p7bq

---

## Plan 7.4 - Full-auto approval flow (TUI + robot mode)
Plan requirement:
- Default run ends in a single "Apply Plan" confirmation step
- `--robot` executes pre-toggled plan non-interactively (still gated; honors `--shadow` and `--dry-run`)

Canonical beads
- TUI golden-path approval surface: process_triage-2ka
- Automation/robot mode tests: process_triage-y3ao
- Confidence-bounded automation controls: process_triage-dvi.2

---

## Plan 7.5 - Premium TUI layout
Plan requirement: plan-first UI, persistent system bar, two-pane layout, progressive disclosure, stable visual language.

Canonical beads
- Two-pane layout: process_triage-6sfz
- Responsive layout system: process_triage-dj9
- Progressive disclosure UI: process_triage-t65l

---

## Plan 7.6 - Interaction design (fast, keyboard-first)
Plan requirement: keyboard-first navigation and bulk operations; after-action diff.

Canonical beads
- Keyboard shortcuts and navigation: process_triage-qhla
- Differential/resumable sessions (after-view + delta mechanics): process_triage-9k8

---

## Plan 7.7 - Sharing and reporting UX
Plan requirement: one-command export `.ptb` and single-file HTML report with dashboard-quality output.

Canonical beads
- Bundles/reports epic: process_triage-bra
- Bundle writer/reader + manifest/checksums: process_triage-k4yc.3
- HTML report generator: process_triage-k4yc.5
- Agent commands: export/report: process_triage-mcrv, process_triage-to7r
- E2E tests:
  - `.ptb` integrity + profiles/redaction: process_triage-aii.2
  - HTML report `file://` + pinned+SRI + `--embed-assets`: process_triage-j47h

---

## Plan 7.8 - Galaxy-brain mode (math transparency + fun)
Plan requirement: full math ledger with equations + substituted numbers; TUI toggle (`g`), CLI flag, report tab.

Canonical beads
- Galaxy-brain mode contract: process_triage-8f6
- Galaxy-brain TUI mode: process_triage-8gfb
- Galaxy-brain math display/ledger rendering: process_triage-wme
- Report integration (galaxy-brain tab): process_triage-k4yc.5

---

## Test coverage anchors (Plan Section 11 tie-in)
- What-if explanation tests: process_triage-p7bq
- Summary mode tests: process_triage-c7rx

---

## Coverage checklist (Plan Section 7)
- [x] The default workflow feels like one coherent run (not a pile of verbs).
- [x] Every recommendation has an inspectable ledger with concrete numbers.
- [x] Galaxy-brain view is available in TUI, agent output, and reports.
- [x] Sharing (bundle/report) is one-keystroke/one-command and works on `file://`.

## Acceptance criteria
- [x] Canonical mapping remains accurate (no missing plan subsection).
- [x] All referenced canonical bead IDs exist and are the intended owners.
- [x] Coverage checklist items in this bead are satisfied.
