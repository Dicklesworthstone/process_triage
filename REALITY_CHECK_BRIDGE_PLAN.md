# Reality Check & Bridge Plan — process_triage (`pt`)

## Current validation — 2026-10-05 18:16 UTC

The combined repaired source is archived at
`/data/tmp/pt-source-recovery-20261005-1724.se2lcrn6/frozen-source.tar.gz`,
SHA-256 `0627bc7fb9ca69dc38f807b34173099a69800613d55a7c024a9d864b11176c5d`.
Its 502-file receipt `current-1724-source.sha256` has SHA-256
`e153d4d8af3766f5a9a750c7b39a4cd759b6658ca65f0b2d259fdb2a35f7002a`.
Root and hz2/hz3/hz4/vmi1227854 checksum commands returned 0. All four mandatory
compiler/formatting gates returned 0 on that source. Nonroot hz3 then completed
the library, binary and all twelve previously failing integration targets:
**4,208 passed, zero failed, seven existing ignores, zero filtered**, 14 summaries,
actual RCH exit 0 at 17:37:42 UTC. Raw
`current-1724-affected-tests-hz3.log` SHA-256 is
`bc34078df9a012a28653fedcd302af4211bc3820937404491f66539e9101cbdc`.
Separate config library coverage passed all 247 tests. These are selected targets,
not a complete workspace pass. The existing cgroup permission-return branches
ran but do not prove positive cgroup actuation. All fifteen daemon cases passed
with their original windows; this does not establish the cause of the old failures.

The exact newly built action-tray executable also passed a direct nonroot native
renice test at launcher nice 0: owned PID 2652127, full birth/UID identity,
actual priority 0 -> 10, production execution/verification successful, unchanged
identity afterward. `current-1724-native-renice-mutation-hz3.log` retains both
streams, exact executable SHA-256 and command. This is one selected test with
17 filtered cases, explicitly separate from the unfiltered affected run.

The complete ROOT workspace invocation on this archived source lost SSH at
17:45:19 UTC (caller exit 1, transport exit 255); remote completion is unconfirmed.
The observed prefix contains 5,031 passes and four failures, not a complete result:
three permission fixtures require a nonroot caller, and the PID-1 throttle fixture
expected refusal but the runner actually succeeded. A read-only check found
`/sys/fs/cgroup/init.scope/cpu.max` at `25000 100000`. I should have inspected the
privileged mutation fixtures before launching this run. The test did not record
the previous value; restoration awaits the operator's intended quota. No guessed
system-service write has been performed. Normal owner-bound RCH cancellation
reported exit 130 without terminal acknowledgment; recovery returned RCH-E504
without replay. Source ownership has not been forcibly cleared.

The original CPU-throttle task `process_triage-sj6.6` is reopened; its original
positive relief, identity, protection, isolation and reversal criteria remain.
`bd-qr40.4` is now in progress for actual dedicated-leaf/sibling evidence. Source
changes add direct-runner protected-PID/full-birth/owner checks, strict exclusive
leaf checks, captured-identity reversal and explicit refusal of unknown settings.
They are unverified. Existing unsafe inherited-cgroup positives are being replaced
with explicitly provisioned delegated-parent fixtures; unavailable prerequisites
cannot count as live actuation. Unquarantine without recorded state is now refused,
not called reversible. Snapshot checks still do not provide atomic kernel isolation.

The three complete permission fixtures now share a child-only privilege-drop
helper, with actual UID/GID/groups/capabilities checks and retained file handles.
Independent source review corrected a root artifact-path race. Fresh runtime
validation remains required. No root or nonroot complete workspace pass is claimed. The first
17:15 repair attempt failed compilation on two ambiguous PID parses; both now
have explicit u32 types. The prior root job was owner-cancelled, then recovered
through RCH's normal API with source ownership released; its 137 recovery status
is not an unexplained OOM or a pass. The failed root-worker source-lock attempt
returned 103 and did not run cargo locally.

The retained seventeen-file UBS scan remains exit 1: 37 critical, 2,243 warnings,
2,049 informational findings. Independent review classified every critical row
(17 test panics, nine public comparisons, eight bounded executable sites, one
fixed test shell and two valid/guarded initialization sites); it confirmed no new
critical production defect. Warnings remain unreviewed and the gate stays failed.
The nineteen dependency updates remain paused at the skill's >10-failure circuit
breaker pending an actual operator response; the security audit still fails.

Current local edits now differ from the accepted 17:24 archive and are unverified:
root-compatible permission fixtures, truthful normalization refusal, baseline-field
validation and actual merged prior values in import previews. The original fleet
transfer task `process_triage-hc7.3` was reopened at 17:13, preserving all criteria.
The previous target baseline of 5,000 observations/72 hours/50% CPU was invented.
Existing snapshot/learning helpers provide no comparable measured trial counts
behind transferred Beta parameters. A live PID census is occupancy and would
increase confidence without relevant evidence; it was considered and rejected
before implementation. Ordinary validated transfers remain the positive path;
requested normalization must refuse until real learning exposure is wired. This
is removal of fabrication, not delivery of normalization or task completion.

### Earlier frozen action-kind result

The frozen action-kind workspace invocation finished with **7,144 passes, 23
failures and 27 existing ignores**, zero filtered tests and actual RCH/Cargo exit
101 at 16:41:44 UTC. All 139 target summaries are retained. Core's 4,038/main's 42
passes, the actual Pause/resume/kind-tampering test, the original lifecycle five
and TUI workflow 64 passed. Twelve targets failed: real signal fixtures; five
apply-gate fixture targets; action tray; fleet transfer; CLI scenarios; dormant
daemon; provenance origin; safety gates. Invented birth IDs, nonexistent targets
and an old poisoned global environment lock account for several failures; these
are not all the same defect. Fleet's sharing-profile packaging is unimportable,
shadow's vanished outcome oracle is obsolete, daemon has three unchanged timeout
failures, worker Git metadata is absent, and the lock fixture never holds flock.
Raw log `current-action-kind-full-workspace-hz3.log` SHA-256 is
`522cd6d117b1c841c3de9e4caa40e3148ca0d29527e1508bc1569b494e4cdbba`.
No workspace pass is claimed. The exact source is preserved separately at
`/tmp/actionlint-bd-ufqb11/current-action-kind-runtime-recovery-iz2s8zah/frozen500-source.tar.gz`,
SHA-256 `b5279c174b3452499a06ec419024469aea5f7b35288d785e5d97057d29140d77`.
The disjoint repairs later received the selected 17:24 acceptance recorded above.
They do not retroactively change this failed invocation or its archived source.

The action-kind correction is frozen in
`target/test-logs/privacy/current-action-kind-source.sha256`: SHA-256
`f19e474f99e76ee38272087a258133759af8b4f3d93c71b90b66764fcaf67d57`,
500 files, with successful root and three-worker checksum checks at freeze. Workspace
all-targets checking, warnings-denying workspace Clippy, the lean core check and
formatting all returned 0. Their raw `current-action-kind-*` logs are retained in
that directory. The complete workspace runtime invocation runs on
hz3 as UID 1000 and returned 101 as recorded above. The corrected five-file UBS
scan returned 1 (31 critical, 2,598 warnings, 1,942 informational findings).
Independent triage found all critical rule/path/text entries already present in
the previous scan; this does not waive UBS or certify the unreviewed warnings.

The frozen 14:20 source passed all four mandatory compiler gates and the selected
eight library targets, core binary tests and five critical integration targets:
**5,079 passed, zero failed, seven existing ignores**. The retained source receipt is
`target/test-logs/privacy/current-1420-source.sha256` (500 files). Raw commands and
results are in `current-1420-libraries-critical-bundles-hz3.log`,
`current-1420-workspace-check-hz4.log`, `current-1420-workspace-clippy-hz2.log`,
`current-1420-lean-check-hz2.log` and `current-1448-fmt-check.log` in that directory.
This is selected coverage; the complete workspace integration/doctest run remains
open. Its earlier 13:13 attempt failed two unchanged policy-hash assertions and
later ended with exit 137; its automatic retry was cancelled through the normal
owner-bound RCH operation. Neither attempt is credited as a pass.

The real bundle failures exposed randomized policy serialization when the
workspace enables serde_json's preserve_order feature. Policy rule/profile maps
now use ordered maps, with equivalent-order and meaningful-change tests. Both
original bundle assertions passed unchanged in the 14:20 invocation. This proves
stable equivalent instances in that build, not identical bytes across all feature
configurations. The five deferred-task TUI guards, real producer, respawner and
strict idempotent-resume neighbors also passed in that invocation.

The 14:50:52 and 14:52:00 Git resets removed the tested source; their actor remains
unproven. The preserved handwritten changes were restored manually, and a separate
500-file checksum command returned 0. The tracker retained newer records in its
database. Normal `br sync --merge --json --no-auto-import` recovered all 958 issues
with zero deletions, conflicts or forced resolutions; all 421 comments, 595 events
and 1,938 dependencies were retained. JSONL/base SHA-256 is
`ce66416ea3f57ffa7dc5ad5cf95a244b373448b5c3c42623adccbde86cc5243f`.
Sync coverage matches and active cycles remain zero. A newly attempted pre-merge
snapshot path was missing and that command failed; it is not cited as a successful
backup. A fresh reconciled source/graph snapshot is retained at
`/data/tmp/pt-source-recovery-20261005-1518.BK2F0I/`. The independent 500-source-file
and runtime archive remains at
`/tmp/actionlint-bd-ufqb11/current-1420-recovery-h9jxfnhm/frozen-source-and-owned-runtime.tar.gz`.

Eleven product tasks were independently closed during the session; two older
positive-capability closures were reopened on discovered gaps. The current graph
has 959 total issues, 823 closed, 124 open and twelve in progress (**136 remaining**).
The earlier 135 figure was arithmetic error. Active dependency cycles are zero;
one archived closed cycle is preserved. Original Plan/verify acceptance was independently satisfied on the
frozen source and restored-tree review; `bd-uacs.1/.2` are now closed. Nineteen
dependency families, including Clap 4.6.7, have bounded runtime/compiler validation.
The security audit and unchanged-rule UBS scan remain exit 1; neither is waived.

- [x] Restore the tested source exactly and harmonize the surviving graph without
  deleting records or forcing a winner.
- [x] Fix deterministic policy serialization and rerun both original bundle hash
  assertions unchanged in the workspace feature combination.
- [x] Run the five actual deferred Model task tests and original live producer,
  respawner and idempotent-resume neighbors on the corrected source.
- [x] Close `bd-uacs.1`, then `bd-uacs.2`, after restored-tree independent acceptance
  and durable normal JSONL export; retain their original criteria.
- [x] Implement `bd-uacs.17` in the existing writer, verifier and pause integration:
  bind action kind, refuse Pause-to-Kill evidence reuse, retain unchanged budget,
  outcomes and live birth/owner identity, and obtain independent acceptance.
  The existing shared writer, strict verifier/matcher, three constructors and real
  TUI persisted-outcome assertion are source-ready. The extended real Pause fixture
  retains SIGCONT/stale/protected phases and logs idempotent resume, kind tampering
  and exact restored-Plan resume. Independent source review found no material
  blocker. All four frozen-source compiler gates passed. The real Pause/kind test
  passed, and a direct O_RDONLY/O_NOFOLLOW budget read independently returned
  ENOENT in the retained existing UID1000 data directory. Independent original-criteria
  acceptance verified all 55 retained runtime files, seven commands/fourteen streams,
  original actions 14/lifecycle five/TUI 64 and four compiler gates. Normal closure
  at 16:45:14 UTC retains full workspace exit 101 and UBS exit 1 explicitly; later
  local fixture/renice/fleet edits are not certified by the accepted f19 source.
- [ ] Repair the observed older workspace fixture failures under `bd-ufqb.9/.11`,
  preserving original scope and no hosted-CI/root-workspace completion claim:
  - [x] Replace fake birth/owner fields in the four real signal tests with owned
    quick-scan identities; preserve real effects and add stale/mock Pause refusal.
  - [x] Replace nonexistent constraint PIDs/global environment mutation with owned
    targets and command-scoped isolated policy/data; exercise split A+Z=.98 versus
    max=.49 positive, high-Useful=.99/A+Z=.01 negative, and missing posterior.
  - [x] Make the dry-run positive reach a real eligible target, retain its original
    exit/count/precheck assertions, and assert explicit unexecuted resource values.
  - [x] Repair blocked-Plan, protected-precheck and confirmation fixtures with
    real owned full identities; preserve original exit/status/count assertions and
    require survivor identity and genuine NotFound for confirmation side effects.
  - [x] Repair the action tray's genuine positive identities and require actual
    SIGTERM versus SIGKILL exit status; retain deliberate identity negatives and
    all original observation/grace/death windows. Correct renice's monotone-priority
    oracle and retain separate actual mutation coverage below nice 10.
  - [x] Fail renice verification when priority cannot be observed. Predicate
    neighbors are not live unreadable-/proc evidence.
  - [ ] Restore an explicit importable fleet configuration-transfer contract with
    checksum, credential and matcher validation; preserve sharing-profile privacy
    and publish the support/refusal split instead of weakening bundle redaction.
    - [x] Validate actual encrypted Forensic export/import and activated environment
      matchers, plus the actual shipped default-priors export without removing prose.
    - [x] Keep original supplied canonical checksum and outer archive bytes intact;
      refuse sharing profiles, invalid active/inactive matchers and mutated checksums.
    - [x] Refuse detected credentials in free-form values and map keys before
      diagnostic disclosure; typed parse failures use a static error. The corrected
      new guard scans explicit patterns across full text and unchanged entropy per
      token. Whole-text entropy from separate low-entropy words is admitted; arbitrary
      passphrases are not comprehensively detected.
    - [x] Reject nonfinite prior, Beta and Gamma parameters in the existing validator;
      prove finite normalized replacement and finite-input overflow refusal on the CLI,
      preserving configuration bytes and all original 120-second command deadlines.
      That archived invocation exercised a mathematical 10x fixture based on the
      invented baseline; it is not measured-host normalization evidence. Subsequent
      source removes that premise and keeps finite unscaled CLI activation positive.
    - [ ] Wire comparable measured learning exposure for baseline normalization;
      until then explicitly refuse requests without inventing local statistics or
      silently skipping a requested transform. Original hc7.3 remains open.
    - [ ] Validate supplied baseline numbers and show actual merged values in
      import dry-run previews; validate all three strategies against saved priors.
    - [ ] Make multi-file priors/signature activation atomic or recoverable; current
      validation-before-write does not protect against a later signature save failure.
  - [x] Keep missing shadow exits unlabelled and add an actually waited known-exit
    report neighbor; this is report consumption, not calibration-quality evidence.
  - [ ] Diagnose the three actual daemon timeout failures without widening windows;
    capture owned diagnostics, and repair real Git/flock fixture setup.
    The source retains all 15 daemon fixtures, actual child signals/status, state,
    inbox and command streams. The separate old-3182 native hz4 escalation completed
    within 7.031 seconds of its unchanged 30-second limit and exited after SIGTERM.
    That successful reproduction does not explain the old hz3 failures. Original
    root/nonroot workspace and hosted-CI acceptance remain open under `bd-ufqb.9/.11`.
  - [x] Run all fifteen instrumented daemon fixtures and genuine Git/flock setups
    on the corrected nonroot source, preserving windows and original assertions.
    This supplies current runtime evidence, not a diagnosis of the earlier timeouts.
  - [ ] Run the entire root and nonroot workspace on the final source, including
    root-compatible owned privilege-drop fixtures; preserve each failed attempt.
  - [ ] Restore PID 1's quota only after its intended value is supplied; retain the
    incident and uncertain remote terminal state without guessing a recovery.
  - [ ] Validate direct cgroup runner protected-PID, exact birth/UID, caller-owner,
    invoking-process, infrastructure and leaf guards, including explicit undo.
  - [ ] Exercise throttle/freeze in a fresh delegated owned leaf and verify an
    unaffected sibling before, during and after exact reversal; prerequisite
    absence is unavailable evidence, not delivered positive capability.
  - [ ] Wire durable quarantine reversal into CLI actions. A bare Unquarantine
    refusal does not deliver that feature or close its original task.
  - [ ] Finish complete deterministic fleet diff coverage: remaining Gamma/IO/
    hazard/category fields and actual matcher/lifecycle changes are omitted.
    Current preview acceptance covers its nine numeric fields only. Invalid merge
    strategy now fails CLI parsing instead of silently selecting Weighted; source
    and runtime regression validation remain pending.
  - [ ] Independently review the legitimate fixture-fix win/lose split, then run
    affected targets and all mandatory compiler gates on the new combined source.
- [ ] Run the complete workspace test suite on the final source; do not replace
  full coverage with the selected 5,079-test result.
- [ ] Continue one researched dependency family at a time with real consumer
  validation after the requested circuit-breaker response: the full run exceeds
  ten failures, so new dependency changes are paused under library-updater. Keep
  the pending large-refactor approvals and failing security audit explicit.

### Bounded work and honesty audit — 2026-10-05 15:54 UTC

Window: 14:20–15:54 UTC. Mechanical inputs: current JSONL records, the two original
Plan/verify closures and criteria, four complete code diffs against the preserved
14:20 source, unchanged CI/toolchain paths, current gate logs, and the four newest
reflog entries. The README purpose is to find abandoned processes and help remove
them safely. This inventory is an assessment, not a release certificate.

Process-artifact worksheet: running code does not branch on this TODO. Consumer:
the operator explicitly requested a granular list; root uses its unchecked items
to select work. Gate and observed defect: that request supplies the creation
authorization; actual resets discarded tested source twice and invalidated old
results. Retirement: stop updating this session list at handoff; preserve its
history, with no deletion authorized. Recovery receipts satisfy the integrity
exception: they preserve source lost in those observed resets; this risk is real;
existing source hashes, patch and owned raw streams suffice; a weaker summary
cannot reconstruct source or independently check artifacts. They receive zero
capability credit. The highest-priority ready capability is action-kind binding;
an hour implementing/testing it is more valuable than another report. Verdict:
retain this requested list and minimal recovery data; create no extra machinery.

Real-work inventory, each item classified once: deterministic policy serialization
USER (tested); action-kind binding USER (runtime unverified); Clap consumer
validation ENABLER; original producer/respawn/TUI acceptance ENABLER; source
restoration ENABLER; full workspace validation ENABLER (pending); graph recovery
and closures PROCESS; documentation/receipt upkeep PROCESS. Tally: USER 2,
ENABLER 4, PROCESS 2, UNKNOWN 0. No root commit or publication occurred.

1. Most visible tested change: semantically equivalent redaction policies now
   produce stable hashes in this workspace feature build; both original bundle
   assertions pass unchanged. The new action-kind refusal is not demo-proven yet.
2. Graph/assessment work changes no product behavior. Recovery evidence did allow
   restoring tested source; repeated certificates would add nothing.
3. Actual consumers exercised the enablers: 5,079 selected tests, including the
   producer, respawner, TUI and both formerly failing bundle assertions.
4. The oldest user-relevant open item is `bd-l3s5`, fleet false-positive calibration
   from September 24. Execution/evidence integrity took priority; this remains a
   material gap, not something disposable-process tests can close.
5. Root closed two original tasks after WhiteBeaver's independent acceptance;
   children made no closures in this window. Reviewer/scanner/research activity
   receives no product capability credit.
6. No window commit edits requirements. `.17` records a separately discovered
   defect; it does not carry an unmet original `.1/.2` criterion into a follow-up.

Verdict: DRIFTING. Cold builds, source recovery and record updates consume too
much of the window. Correction to root: finish the currently running real safety
acceptance, then implement the next product gap; do not create new report layers
or repeat passing checks without a changed source or unresolved concern.

Honesty inventory, adopting the independent auditor's position:

1. No (checked: four complete 14:20-to-current code diffs and unchanged CI paths).
   Original assertions/windows remain; no new ignores or weakened protections.
2. No (checked: the extended actual SIGSTOP fixture and three explicit constructor
   updates). The lifecycle's deliberately synthetic success remains a fault
   injection test, never evidence of actual execution.
3. No (checked: changed paths and executed commands). No golden regeneration.
4. Yes: stricter verifier tests accompany the production fix. The invocation-only
   remote deadline is 10,800 seconds rather than 3,600 after compilation consumed
   53 minutes in the earlier failed attempt. Product/test windows and assertions
   remain unchanged; the earlier exit 137 is retained, with its cause unproven.
5. No (checked: complete new production hunks). No test-path branch or bypass.
6. No (checked: selected-runtime terminal summaries and all current gate logs).
   The 5,079 result is selected coverage; the new full suite has no pass claim.
7. Yes: the attempted pre-merge backup used a missing directory and failed, while
   the command sequence continued. It is explicitly withdrawn as backup evidence;
   the later successfully created snapshot is separately identified above.
8. No (checked: current source-review, raw runtime and report scope statements).
   Source agreement is not runtime proof; the new safety fixture remains unproven.
9. No (checked: top-level status and retained logs). UBS/audit are exit 1, earlier
   bundle failures/exit 137 remain visible, and broad workspace coverage is open.
10. No (checked: retained Cargo logs and the new three-resume stream writers).
    Cited command stderr is retained. No omitted stderr is credited as evidence.
11. No (checked: original `.1/.2` descriptions, independent final review and
    closure reasons). Existing-file placement is disclosed, original positive
    chain and negative neighbors were exercised, and `.17` remains in progress.
12. No (checked: those original descriptions and current source changes).
    No requirement was rewritten to match the implementation.
13. No (checked: current-window closure records). Root alone closed `.1/.2`,
    citing independent exact-source/raw-artifact review, not an author's vote.
14. No (checked: current review/scanner/research assignments). Real effects,
    planted negatives and explicit no-claim boundaries are required.
15. No (checked: complete four-file delta, raw integrated runtime summaries and
    current gate terminals). Research suggestions are not credited as upgrades;
    agreeing source reviews are not additional independent runtime samples.
16. No (checked: closed original producer/respawn criteria and live positives).
    The new action-kind task cannot close on unit refusals alone.
17. No (checked: acceptance wording). Agent agreement remains source review;
    retained hashes establish artifact identity, not statistical independence.
18. No (checked: fixed invocation targets and counts). No speedup/calibration
    metric is claimed; overlapping earlier runs are not summed.
19. The owner should see the failed backup sequence, expensive repeated cold
    builds, reset recovery, both non-green scanners and the large remaining graph.
    Passing compiler checks do not complete the new safety task.
20. Strongest completed proof: original SHA-bound actual producer/apply/verify
    and respawner runs, with 57 retained steps/114 streams independently rehashed.
    A skeptic can rerun the existing tests. New `.17` proof is still pending.

Older-session coverage remains limited to the previously completed six project
Cass queries with no indexed project hits; this is not a clean-history claim.
Disposition: the failed-backup claim was corrected in place and disclosed in the
operator record; dependent mutations must stop after an earlier failed prerequisite
(RH-16, exact observed results). Invocation deadline changes are recorded separately
from functional gates (RH-1/RH-2). Earlier failures, lower proof classes and open
original requirements remain visible (RH-7/RH-9/RH-12). No waiver follows from this
inventory; no additional certificate or retrospective search machinery is needed.

### Previous validation — 2026-10-05 13:59 UTC

`bd-h2y0` is closed on its original acceptance after WhiteBeaver's independent
56-step current-native observer and complete retained-artifact recheck: 304 hashes,
112 streams, 29 HTML reports, 15 ZIPs/75 members and 14 unchanged fixtures. Results
are retained under `target/test-logs/privacy/pt-independent-forensic-html-ppgtm6p0/`.
This session has now closed seven tasks on cited independent evidence. Including
the newly identified action-kind defect, the graph has 127 open and ten in progress,
137 remaining, with zero active cycles. Exact-ledger persistence, broader report
flag parity and encrypted/platform acceptance retain their own open criteria.

The corrected 13:13 source passed all four mandatory compiler gates: workspace
all-targets check, warnings-denying workspace Clippy, lean core check and formatting.
The native build also returned 0. Its immutable hz4 copy is
`/data/tmp/pt-current-native-20261005-1348.92ituu/pt-core`, SHA-256
`3182e7152002d746efe970bb2aa1f84841a2aab4c48cbf0d29e2d81ac4ae4d00`;
all 500 source files matched the corrected receipt before copying. The unchanged
62-case BATS suite, original scoped demo, exact published Plan schema and independent
56-step report observer are now running against this copy. The full workspace test
run remains compiling on hz3; these source additions still have no runtime credit.

Independent triage accounts for all 57 critical static findings without changing
scanner rules or exit status. None identifies a new confirmed production defect;
the 5,039 warnings have not all been reviewed. UBS remains exit 1. The fresh security
audit also remains exit 1. Eighteen dependency families are completed; the proposed
Clap family still awaits full runtime validation. The next bounded safety fix,
`bd-uacs.17`, is
binding saved successful execution evidence to the canonical action kind, with an
actual Pause-to-Kill tamper/refusal test. Rust source remains frozen during these
checks. The ready independent wrapper task `bd-uacs.12` is now in progress in `pt`
and its existing Bash tests: published-release discovery and removal of ignored
UI switches, preserving signing pins and explicit verification behavior.

### Previous validation — 2026-10-05 13:15 UTC

The parent-supervision correction, TUI operation/ticket guards and strict resume
evidence wiring are source-ready. Apply now uses the existing canonical Plan
parser and session binding; resume uses the verifier's target/execution evidence
and shared future-timestamp refusal. The real primary includes valid idempotent
resume and altered PID/birth/UID/time, malformed outcome, duplicate/empty action-ID
and wrong-session neighbors, preserving saved artifacts, budget bytes and owned
survivor identity. Five TUI tests run actual deferred Model tasks. These additions
have no runtime credit yet.

The first full-workspace test and all-targets check both returned Cargo 101 before
runtime on an unnecessary `as_str()` call on an existing `&str`. That call is now
removed; formatting and whitespace checks returned 0. The 500-file corrected
receipt is `target/test-logs/privacy/current-1313-source.sha256`. Two hz2 retries
were refused before Cargo for slots/pressure; normal scheduling admitted the full
workspace rerun on hz3 without local fallback or lock interventions. The corrected
all-targets check is running on hz4. Clippy, lean and final native acceptance remain
pending.

The fresh unfiltered main-lock audit returned 1: rkyv vulnerability
`RUSTSEC-2026-0235`, LRU unsoundness `RUSTSEC-2026-0253`, and Paste maintenance
warning `RUSTSEC-2024-0436`. The unchanged-rule static scan of all 27 changed Rust
files returned 1 with 57 critical findings; complete current critical triage is
underway. Neither gate is waived. Eighteen dependency families remain completed;
Clap is proposed. The existing progress JSON is reconciled, without upgrade credit.
Recorded outcomes still omit action kind, so tampering only the Plan's action kind
while retaining an ID/target is a separate unproven completion-binding limitation.

## Execution update — 2026-10-05 12:51 UTC

The corrected 12:24 source actually finished with **4,661 passes, one failure and
seven existing ignores**, Cargo 101: 4,395 selected library/main tests passed;
266 executable tests passed. Core's 4,034 include all nine new typed-supervision
cases, real owned clean/TCP/non-dumpable/supervisord observations, fresh ancestry,
required parsers and socket-cache positives. Workspace all-targets checking
returned 0. Clippy on hz4 was refused before Cargo; its hz2 retry returned 101 on
two `question_mark` lints. Both now use `?` with unchanged typed error semantics;
new-source Clippy/lean and final checks remain pending.

The sole runtime failure is a production target mismatch, not a fixture defect:
the real two-zombie producer returns zero routed actions because it requires the
dead child's unreadable environment, although dispatch signals the known live
parent with SIGCHLD. Two independent reviewers confirmed the raw plan and actual
dispatch target. The local correction probes the eligible parent, validates its
birth/UID before and after probing, records its full supervision subject identity,
and retains the original child's Unknown diagnostic separately. No unreadability
exception or general parent restart/kill capability is added. Fresh same-parent
readable/protected/unreadable producer assertions and live birth/owner neighbors
are prepared but unexecuted.

Immutable native `a4ea50a8…`, bound to all 500 files of the 12:24 receipt before
and after, passed **62/62 unchanged BATS, zero skips**, the scoped simulation demo,
exact published Plan schema and the unchanged independent **56-step report
observer**. The current report suites passed 46 and 16 tests. These bounded passes
do not upgrade the failed primary or validate subsequent source changes. Complete
triage accounts for all 48 static critical findings without suppressing a rule;
UBS remains exit 1. Separate existing signal-registration, AppleScript escaping
and resume-evidence binding defects remain on the work list.

The bounded TUI refresh/execute repair is now being implemented in existing files:
operation serialization, captured confirmed selection and one-use tickets, stale
completion rejection and failure recovery. It does not complete shared decisions,
watch/snapshot parity, final filters or the original `bd-uacs.8` workstream.

### Previous execution update — 2026-10-05 12:23 UTC

The 11:24 complete primary rerun retained its original positive chain, identity
refusals, hourly cap and full I/O windows, then failed at the new zombie fixture's
exact descriptor assertion: Python's libffi descriptor remained open. The owned
helper now closes its own extra descriptors before forking. Independent inspection
of three launches and 90 samples per variant confirmed the original retained FD3
and the corrected helper has exactly descriptors 0–2 pointing to `/dev/null`.
The original five-second readiness deadline and exact assertion are unchanged.

The 12:11 receipt freezes 500 source/manifest/test files. Its first strict remote
test invocation returned Cargo 101 before any runtime test: a new descriptor test
references a public IPC helper that the supervision module does not re-export.
The test now calls the existing public `IpcAnalyzer::analyze` API with the same
permission assertion; its fresh full rerun is pending. The concurrent workspace
check is still running. Formatting and whitespace checks passed for the receipt.
The unchanged-rule, all-24-changed-file UBS static scan returned 1 (48 critical,
4,562 warnings, 3,063 informational findings); complete critical triage is in
progress. Cargo checks run separately through strict remote offload.

Independent source review found no weakened original producer assertion in the
new owned non-dumpable CLI phase. Its live refusal exercises the earlier enabled
data-loss gate; its dry-run refusal exercises mandatory supervision directly.
Neither has current runtime credit yet. Independent review of the retained 11:07
respawn run found the original `bd-uacs.2` behavior criteria satisfied; its closure
still depends on `bd-uacs.1` and current validation.

The next concrete TUI safety defect is PID-only selection surviving refresh while
the execution cache already contains a replacement incarnation. Clearing at
refresh completion is insufficient: refresh/execute must be serialized, pending
selection/confirmation cleared at request, and queued execution refused while a
refresh is outstanding. This is unimplemented and does not close `bd-uacs.8`.

### Previous execution update — 2026-10-05 11:38 UTC

Six independently reviewed tasks remain closed; the graph now has 127 open and ten
in progress, **137 remaining**. `bd-toa2.6` is claimed for mandatory-observation gaps.
There are no active cycles; one historical closed-only cycle remains archived.

The frozen 10:24 proposal actually finished with **4,303 passes, ten failures and seven
existing ignores**, Cargo 101. Common passed 243; core library passed 4,006 with eight
failures; main passed 39 with one failure; report passed 15 with one failure. This
invocation remains failed. The eight workspace fixtures used an inherited TMPDIR inside
the checkout; their retained fixture helper now selects a verified non-repository root
without changing resolver behavior or assertions. The main timestamp oracle used a
noncanonical UTC spelling; it now expects Chrono's exact recorded `Z` representation.
The real bundle report exposed hashed history keys: finite `state_history`/`ts` support
now preserves only validated public timestamps and states, retaining secret exclusion.

New source also binds routed action IDs to both complete process identities, omits
init/protected parents and checks the parent's actual protection, age and memory policy.
Persisted inference recommendations follow the final canonical Plan. A real producer
test with two zombies sharing one parent and a protected-parent negative is being added
to the existing test file. No direct supervisor-restart, collision-proof ID or live
missing-parent claim follows from this work.

The enabled recent-I/O gate now preserves read/parse failures, birth changes, decreasing
counters and stale activity as Unknown/refusal. It retains the full configured shared
window and revalidates cached idle counters. Nine meaningful inline tests include a real
owned non-dumpable child, readable idle and active-writer positives. These tests ran in
the passing 11:07 library invocation. Cross-UID, macOS and
the remaining supervision/locks/TTY/CWD/session/intent observations still need proof.

The corrected 11:07 source passed **4,386 selected library/main tests**, zero failures,
seven existing ignores: common 243, core 4,025, main 41, redact 61 and report 16. This
includes the real non-dumpable/idle/writer I/O checks, workspace-fixture corrections,
terminal history and parent-routing units. Workspace all-targets checking returned 0.
The executable invocation passed **266 tests and failed one fixture setup assertion**:
145 CLI, 46 report, 57 MCP, five lifecycle and 13 action tests passed. Its new zombie
phase inherited a later-modified policy instead of the originally configured policy;
the exact equality assertion remains, and the 11:24 correction is running the complete
original primary chain again. All previous failed invocations remain failed.

Clippy caught one redundant borrow; the 11:24 source corrects it without changing
behavior or allowing a lint. Its first retry was refused before Cargo because hz4
reported a missing runtime; no local fallback ran. Current Clippy/lean remain pending.
Clap 4.6.7 remains proposed, not a nineteenth completed family.

Immutable native `7c9f16a1…`, bound to all 500 files of the 11:07 receipt, passed
**62/62 BATS, zero skips**, the unchanged scoped demo and exact generated Plan schema.
The independent real-report observer passed **56 CLI steps**, including 13 paired
terminal/missing/malformed/resumed histories, actual Forensic and explicit Safe labels,
all original privacy/escaping/signature/refusal checks and ZIP checksums. Its two
earlier failures were observer setup defects (a valid second-pass hash marker and an
invalid fixture SessionId); both raw failures remain retained. No marker idempotence,
archive identity, latency, macOS or fleet claim follows.

Read-only review found a concrete next mandatory-evidence defect: the supervisor
precheck reads the state field as PPID, while combined supervision detection discards
leaf read failures. The bounded next slice preserves typed required-probe errors and
blocks Unknown independently of robot confirmation policy. It remains unvalidated;
the broader `bd-toa2.6` criteria are not closed by the passing I/O subset.
The new unsupported-probe refusal also restricts macOS: unavailable ancestry/IPC
evidence makes planning Review and prevents both apply modes even with confirmation.
Restoring positive macOS capability requires real supported probes, not an override
that converts Unknown to absence. No macOS runtime acceptance is credited.

### Previous execution update — 2026-10-05 10:24 UTC

Six tasks are independently closed on their original criteria: `bd-gn74`, `bd-r1mu`,
`bd-uacs.16`, `bd-pdyb`, `bd-p2ks` and `bd-uacs.3`. The graph contains 128 open and
nine in-progress issues, **137 remaining**, with no active dependency cycles. The
last narrow closure changed only `bd-uacs.3`; its original description and all 1,936
dependencies stayed unchanged. Detailed remaining work is listed below.

The frozen 09:06 source passed all four required compiler gates. Workspace all-targets
checking has independently retained nonce-bound Cargo exit 0 despite RCH wrapper exit 1
on an SSH completion-probe failure. Clippy with warnings denied and the lean check returned
0 normally; lean retains its existing unused queue-fields warning. Formatting passed.
Current verifier and app consumers passed 38 and 51 tests respectively. The complete
corrected action/lifecycle run passed **19/19**, reaching the original respawn diagnostic,
malformed/empty/restored/review checks and PID-reuse oracle. Cargo returned 0; its wrapper
returned 1 after a release acknowledgement timeout. Independent inspection found the
remote grant already released; the unreconciled local journal is not relabeled green.

Native `a19a631d…`, built at 09:35:54 UTC and copied at 09:54:13, passed **62/62 BATS,
zero skips**, exit 0, including the unchanged 30-second closed-stdin check. All 500 worker
files matched `current-0906-source.sha256` before and after execution. The real producer's
saved Plan equals stdout; 14 original stream digests, two identity-refusal survivals,
actual pidfd delivery and confirmed death are retained under
`target/test-logs/e2e/agent_loop/bats-1791194432637062129-330973/`. The older `653e…`
61-pass/one-timeout loss remains separate. No latency, calibration or resource-relief
claim follows from the latest pass.

Independent review found two additional production gaps before closing plan/report work:
blocked zombie Keep placeholders could appear in executable actions, and actual Planned
HTML reports carried an invented end time and mislabeled the Forensic profile as Safe.
The next source batch omits blocked/unroutable actions and unsupported generic Restart;
valid zombie parent routing retains identity, checks and timeouts. Agent reports reconcile
by full incarnation, expose real stages/IDs/targets and persist the same Plan once. Reports
use actual terminal transitions, treat resumed/malformed history as unknown and normalize
both visible and embedded profile labels from validated active configuration.

`current-1024-source.sha256` freezes these changes with the proposed Clap 4.6.7 update.
Exactly three manifest lines and six coupled lockfile package records changed; features,
MSRV, pins and clap_complete are preserved. This is **not** a nineteenth validated family.
Fresh main/common/core/report consumers are running remotely. Required current compiler,
Clippy/lean, CLI and real saved-report metadata proofs remain pending. Review also identified
that bundle redaction's finite timestamp allowlist may omit state-history `ts`; that path
needs actual test evidence and a validated finite-data correction, not a privacy-gate waiver.

No local heavy fallback, destructive recovery, golden regeneration, macOS/fleet acceptance,
security-clean result or performance win is claimed. The remaining mandatory-evidence,
shared decision, root/full-host performance and calibration gaps remain open.

### Previous execution update — 2026-10-05 09:33 UTC

The current frozen source is `target/test-logs/privacy/current-0906-source.sha256`:
all 500 files match after manual recovery. Reflog records external resets to `origin/main`
at 09:05:39 and 09:06:48; this team performed neither reset. Reset bytes, a read-only
database dump and the recovered source patch are retained outside Git in
`/data/tmp/pt-source-recovery-20261005-0908.C1ebrt/`. Recovery earns no capability credit.
The audited normal tracker export restored exactly three known status changes, one
new issue and comments 383–407. There are **128 open and 12 in-progress issues**,
with no active dependency cycles; exactly three independently evidenced closures
from this work remain (`bd-gn74`, `bd-r1mu`, `bd-uacs.16`).

Current-lock workspace libraries actually passed **4,891 tests, zero failures,
seven existing ignores** at 08:28:17 on the 08:15 source. All seven targeted collector
tests and the case-insensitive credential cases ran. This excludes subsequent app/MCP
and birth-order test changes. The 08:34 executable batch finished normally at 09:00:
**358 passed, two failed**, Cargo 101. Main 39, report 46, exit codes 45, MCP 57,
rate-limit 37 and signatures 117 passed; actions passed 13/14 and lifecycle 4/5.
No passing subset turns that invocation green.

The real minute-limit test passed the original strict gate: first pre-execution evidence
to exact third-target refusal was **32.501 seconds**, with two actual pidfd kills,
exact third-target survival and byte-identical persistent counters. Apply-loop elapsed
time was 48.809 seconds. Global host memory deltas do not establish per-target relief.
The failed respawn test reached the correct scan-refusal exit 20, then failed its
unchanged full-snapshot diagnostic assertion. Production now restores that diagnostic;
later malformed/empty/restored/review assertions require a new complete run. The
lifecycle PID-reuse fixture now uses a distinct birth strictly before execution;
its unchanged PidReused oracle and explicit before/equal/after birth-order unit test
preserve reuse, ambiguity and real respawn coverage. At 09:23:42 the current verifier
filter actually passed **38 tests**, including all 23 verifier tests and 15 matching
audit/session tests. Both corrected integration targets and app consumers remain pending.

Independent current-native privacy evidence passed **16 real CLI steps**. It preserves
typed original SignatureSchema matching, literal harmless markup with escaped visible
HTML, exact recorded values, mandatory secret exclusion, five ZIP-member checksums,
and refusal of Safe/redacted matcher activation without changing user stores. Two
earlier observer losses remain retained: only two null comment keys were pseudonymized
without changing typed schema, and a valid second-pass hash marker was not idempotent.
Neither schema-key identity nor marker idempotence is claimed. The original three
component secret-exclusion failures subsequently passed unchanged in the 287-test run.

Native `653eab94…` passed the original producer/adopted-orphan chain with actual delivery
and confirmed death. The full BATS invocation passed **61/62, zero skips**, exit 1:
the unchanged closed-stdin plan exceeded its 30-second deadline. Its observed kernel
I/O wait does not establish a latency cause. The scoped dry-run demo and exact generated
Plan schema passed; bare learn, bare verify and all-tutorial verify returned 0/0/0,
all seven checks were OK without fallback, and progress remained 0/7. Scratch directories
remain retained. These native proofs bind to the 08:34 production source, before the
later diagnostic wording and integration-fixture changes.

Formatting passed on current source. Workspace checking printed successful compilation
at 09:25:49, but RCH's completion probe failed SSH and retained ownership; its wrapper
exit 1 is not a completed green gate until independently reconciled. Current Clippy,
lean checking, corrected runtime and the BATS timeout remain outstanding. No local
heavy fallback, lock deletion, assertion weakening, golden regeneration, measured
performance win, calibration guarantee, macOS acceptance or security-clean result is claimed.

### Previous execution update — 2026-10-05 08:18 UTC

The corrected bundle/redaction/report component run completed normally on hz2 at 07:59:10:
**287 passed, zero failed, exit 0**. All three original failing privacy integration assertions
executed unchanged and passed. This run binds to the component sources in
`target/test-logs/privacy/current-0757-source.sha256`; concurrent core work is outside its scope.
The final frozen 500-file receipt is `current-0815-source.sha256`. Current workspace libraries,
the seven executable runtime targets and all-target checking were normally admitted remotely at
08:16:46; their results, final Clippy/lean checks and a new native verification remain pending.
Formatting passed on this source. No current whole-project green result is claimed yet.

Source review confirms the existing IPC table already has a two-second TTL cache, but planning
does not share its collected network snapshot with supervision. Each candidate also constructs
an unused default signature database and recompiles its regexes. These are concrete remaining
operations, not a quantified explanation of the observed delay. The original root/full-host,
2,000-process/50,000-socket budget and phase-timing acceptance remain unchanged. `bd-uacs.15`
is now claimed while this remaining work is investigated; the targeted collector fix alone does
not close it or establish a competitive performance win.

### Previous execution update — 2026-10-05 08:05 UTC

Immutable native `163b5e62…` passed **62/62 BATS contracts, zero skips**, the scoped documented demo
and exact generated/published Plan-schema comparison. Its original real signature-prior/adopted-orphan
chain delivered a pidfd Kill and verified `confirmed_dead`; the demo remained a dry-run and preserved
the original live identity. These results cover the 06:54 production build, not subsequent privacy,
collector or tutorial-retention edits. Raw current primary evidence is retained under
`target/test-logs/e2e/agent_loop/bats-1791186457960368067-641491`.

The corrected minute test's first rerun still failed its conservative completion bound. Raw events
show actual policy refusal only **5.417 seconds** after first pre-execution evidence, followed by
**68.25 seconds** of reporting tail work. Apply-loop cumulative latency was **77.275 seconds**;
the **115.25-second** test duration includes fixture setup and must not be called CLI-only latency.
Independent review supports the existing exact session/action/PID/phase/status refusal event as the
endpoint of the original strict within-minute criterion. The final fixture retains `<60s`, genuine
signals, exact third-target survival and byte-identical counters; its fresh runtime remains pending.
Neither removed pre-action setup nor report-tail completion time receives performance credit.

The privacy correction narrows raw Forensic handling to finite SignatureSchema names and six string-only
matcher arrays, routes them through the configured command rule, hashes unrelated free text/arguments,
and detects whole-command secret/password/token/API-key flags case-insensitively. Environment guards
remain unconditional. The three original failing assertions and actual CLI round-trip canary are unchanged.
The first correction retry refused SSH admission before Cargo; the next normally admitted hz2 component
run started at 07:55:38 with checksum freshness and is compiling. Core collector work was concurrent and
is outside that component run's compiled scope; it cannot certify the final whole-source tree.

Bare native `learn` passed, but `learn verify` returned exit 3/degraded with a genuine plan timeout.
The old verifier also reached its existing automatic scratch-directory removal; its inner sessions
cannot be claimed retained. The further old-native all-tutorial run was stopped using identity-bound
signals to only its owned verifier/child, with raw return −9 and termination audit retained. Root source
now retains uniquely named scratch directories and removes automatic cleanup. No successful tutorial
verification or bounded timeout cleanup latency is claimed; the remaining real default-budget behavior
requires a new native build. The observed owned plan child was in disk sleep, which is evidence of its
state rather than proof of the latency's cause.

The target-only collector correction is now source-complete and under review: Linux uses `ps -q`, macOS
uses `-p`, while empty selections keep the original full-host scans used for ancestry and tree safety.
It deduplicates requests and refuses invalid IDs, diagnostics and malformed targeted results instead of
treating failures as vanished targets. Native `ps` semantics were checked with owned targets; the Rust
collector and current action regressions remain unexecuted. No performance win or broad collector-Bead
closure is claimed. Exactly three independently evidenced closures remain; the original larger work
graph, audit and broader UBS failures remain open.

### Previous execution update — 2026-10-05 07:36 UTC

The fresh target-directory workspace library run completed normally at 07:09:22: **4,883 passed,
zero failed, seven existing ignored** across all eight crates. The three new default-Forensic tests,
paired recorded-deep-scan HTML/ZIP test, final doctor allocation/classification test and narrowed tutorial
exit-code test all actually executed and passed. The 500-file `current-0654-source.sha256` receipt matches
the uploaded worker. A later policy-test struct-initializer style fix is the only 07:03 source delta;
it fixed an actual Clippy lint without changing production behavior or assertions. Workspace all-targets
check, warning-denying Clippy, lean check and formatting then passed; lean retains its existing unused
queue-fields warning. Inventory refusal on hz4 was resolved by ordinary admission to healthy hz2,
without deleting locks, bypassing admission or running a local heavy fallback.

The current executable batch completed at 07:22:08 with **302 passes and one failure**, Cargo exit 101:
main 39, report 46, exit codes 45, rate-limit integrations 37, lifecycle 5 and signatures 117 all passed;
actual action tests passed 13 of 14. The genuine producer/apply/verify and saved hourly-policy drift
passed, as did both corrected age/nice fixtures. The minute test delivered two real pidfd kills and
refused the third with exit 4 and the exact minute-limit message, but its incidental startup-inclusive
60-second timer failed at 104.205 seconds. Its later survival/counter assertions were not reached.

Independent nonauthor review supports retaining the original third-within-minute criterion with the
same strict 60-second bound measured from the earliest pre-execution evidence timestamp, through the
second command's completion. Delayed persisted charge time alone is insufficient. The corrected
fixture also retains raw budget bytes each step, exact identity/delivery/signal-path checks, two sorted
nonfuture charges, pending=false, third-target original-identity survival and byte-identical refusal
budget. Win/lose split: valid within-minute execution can pass despite pre-action startup; the removed
incidental total-CLI-under-60 requirement earns **no latency credit**. The observed 100/104-second
latency remains an open performance gap. Corrected source is in `current-0734-source.sha256`; its
fresh one-test runtime is pending. Original Bead criteria and production limits remain unchanged.

The separate fresh component run found **three failures**, Cargo exit 101: one original all-profile
redaction canary and both bundle/report pipeline tests. Forensic Allow exposed detector gaps for bare
values, short API-like text and `--secret=` arguments previously hidden by hashing. These are required
credential-exclusion gates; they will not be weakened. Component/privacy acceptance remains open
while the smallest production correction is reviewed. The offload subsequently reported unconfirmed
source-authority release; no automatic replay, lock deletion or local fallback is authorized by that.

An independent real Forensic CLI/report/ZIP probe did preserve a literal markup-containing command
while escaping visible HTML, preserving its JSON value, retaining exactly two script elements and
verifying all archive checksums. This positive is bound to immutable native SHA256 `163b5e62…` and
the 06:54 production source; it does not cancel the three component failures. Current native BATS,
demo, exact schema and bare tutorial verification are being repeated with both subsequent test-only
source deltas explicitly recorded.

Exactly **three** Beads have independent closure evidence: `bd-gn74`, `bd-r1mu`, and now `bd-uacs.16`.
The last used actual native usage/help/version/agent-help exits 10/0/0/0 and preserved the original
criterion. Sharing/report/guardrails/doctor/platform tasks remain open until their complete original
acceptance passes. The broader UBS scan still exits 1 despite bounded critical-finding review; the
doctor-only scan exits 0. Audit findings, the minifier's three-failure stop and unanswered larger
dependency-migration approval remain unresolved.

### Previous execution update — 2026-10-05 06:52 UTC

The 06:15 source passed workspace all-targets checking at 06:29:17. The subsequent library invocation
exited 0 at 06:44:20 with 4,879 passing tests and seven existing ignores. Its 500-file uploaded source
receipt matches, but its cached redaction and report test binaries omit the three new `default_forensic_*`
cases and `recorded_deep_scan_indicator_agrees_across_session_and_bundle_reports`. Those cases receive
**no execution credit** from this run. A fresh remote target-directory library build started at 06:50:39;
its named tests and final result must be inspected before privacy/report acceptance. No cached artifact
was deleted, no gate was weakened, and no local heavy fallback ran.

The preceding library run exited 101 because a shared deleted-file inode chose PID 501 while its test
expected PID 500. The doctor reader now sorts numeric PIDs and counts allocated blocks separately from
logical size. The original 2 GiB sparse fixture remains: it now correctly reports its observed allocation
and logical length, deduplicated once, at Info below the unchanged allocated-GiB warning threshold.
A written-file positive checks actual allocation and deduplication; explicit classification-only inputs
check GiB−1/Info and GiB/Warn. These classification inputs are not live allocation or reclaimed-space
evidence. Initial reader changes passed in the 06:44 core suite; the final classification assertions still
require the fresh build. Original `bd-p1o0.19` acceptance is broader and remains open.

Clippy admission on hz4 refused runtime inventory twice and ran no Cargo. Direct installed-component
inspection found Clippy present; the normal capability refresh reports an inventory-cache lock failure.
This is an offload blocker, not a compiler failure or permission to bypass admission. Final Clippy,
lean build, executable integration, default Forensic CLI and current-native contracts remain pending.
The complete fresh eight-file UBS critical-finding triage is retained; UBS still exits 1, and its warnings
are not fully triaged. A separate scan of the later doctor changes is running.

### Previous execution update — 2026-10-05 06:15 UTC

The 05:28 source passed workspace all-targets checking and the full runtime targets for main (39), report (46),
exit codes (45) and lifecycle (5). The action target passed 12 of 14, including the genuine adopted-orphan
producer/apply/verify, saved hourly-policy drift, minute-limit, real-RSS and respawn tests. The whole invocation
exited 101: the age-floor test supplied a malformed partial recorded Policy, and `ps` returned `-` for the
live renice target's initial nice value. Both fixture corrections retain the original action/refusal assertions:
complete saved Policy with age 0, and Linux kernel `getpriority` with explicit errno handling. Their runtime
reruns are pending. Raw primary/hourly/minute/respawn logs were independently read and their stream digests
recomputed, then copied into the existing `target/test-logs/e2e` directories without overwriting or deleting.

The immutable native binary SHA256 `53cca897f3f229cdc30e8a2b031585d975fc1d8e567eb44c4d8c58d068947142`,
bound to all 500 files in `saved-policy-0528-source.sha256`, passed all 62 BATS contracts, the scoped documented
dry-run demo and exact generated/published Plan schema comparison. The primary BATS chain preserves default
loss/FDR settings and demonstrates stale/UID refusals followed by actual Kill and `confirmed_dead` verification.
These results certify that source and controlled Linux behavior, not calibration or subsequent source changes.

Review found two further original report/sharing gaps: recorded deep-scan status was lost in the bundle adapter,
and the default Forensic producer hashed fields needed for intact signature activation while an earlier test used
a custom allow policy. The source now preserves the finite Forensic local-detail allowlist while retaining secret,
environment and URL-credential guards. The canary invokes the actual CLI Forensic producer and import/matcher
consumer. Session and real Safe-ZIP HTML adapters derive deep-scan status from unsigned recorded milliseconds,
preserving zero as enabled, explicit null as disabled, and absent/invalid history as unknown. These source changes
and the paired HTML/ZIP tests still require execution.

The tutorial Run gate was narrowed from the external all-0–9 acceptance to completed `agent plan` 0/1 and other
commands 0; policy refusal, partial execution, interruption and unknown codes remain failures. Its real-command
budgets now replace obsolete help-only defaults, with the before/after evidence retained in `bd-uacs.13`. Bare
current-native verification and macOS acceptance remain pending. Current workspace checking started remotely
at 06:12:57 against `current-0615-source.sha256`; the earlier hz3 library build uses its separately recorded
source and cannot certify later edits. The original hz4 target path has disappeared; the immutable native copy
and raw evidence remain intact. No local heavy fallback or cache deletion was performed by this team.

Only `bd-gn74` and `bd-r1mu` are independently closed so far. Original P0, sharing/report and platform acceptance
remain open until their named current-source evidence and nonauthor reviews complete. Audit and UBS remain
non-green, and the larger dependency migrations retain the existing unanswered skill-required approval.

### Previous execution update — 2026-10-05 05:27 UTC

Independent review declined `bd-uacs.3` closure: the recorded full Policy previously enforced only its age
floor, and the TUI plan builder could exceed the run cap. The original acceptance remains unchanged. Root
now applies the original saved and current predicates separately, sharing one durable kill counter; both
live precheck providers and robot constraint checkers retain their own settings. Evidence collection follows
either policy. Only numeric budget caps intersect. TUI selection refuses an over-cap executable plan with
an actionable error. Malformed present snapshots, including their legacy age field, return a structured
`invalid_policy_snapshot` policy refusal. These are **unvalidated source changes** at this timestamp:
the strict current workspace all-targets check started at 05:25 and has not returned a compiler result.

The existing primary Rust/BATS fixtures now use typed four-class signature priors and an owned subreaper
with genuine double-fork/setsid adoption, exact UID/start/parent identity, null descriptors and no inherited
agent environment. Default loss, FDR configuration, posterior and I/O settings remain intact. The corrected
BATS primary passed 1/1 against the preceding native binary `4e6ada…`; that result does not certify the new
production changes or the entire BATS suite. The new Rust phase saves two genuine plans under hourly cap 1,
delivers one kill, raises the current caps, then requires the second saved plan to refuse without signaling
or adding another durable charge. Its compiled runtime and the current-source gates remain pending.

The independently closed `bd-gn74` and `bd-r1mu` remain the only feature closures from this batch. Earlier
positive evidence below is retained with its exact source scope; it does not certify these later edits.

### Previous execution update — 2026-10-05 04:59 UTC

The following is the latest evidence. Older dated entries below retain the failures and their corrections;
their then-pending statements are historical, not replacements for the current results.

- The strict `--workspace --lib --features pt-core/test-utils` run passed 4,854 tests at 04:24:35,
  with zero failures and seven existing ignores. Core passed 3,980; all eight workspace crates executed.
  `final-0413-source.sha256` matched the worker; `final-0413-workspace-lib.log` retains the complete run.
  All eleven genuine-Git/Unicode workspace tests subsequently passed at 04:28:17, including the added
  39-byte malformed HEAD case. Their final source receipt is `final-0429-source.sha256`.
- The 03:58 hz4 upload passed all 14 actual action tests, all 45 exit-code tests and all five lifecycle tests.
  This includes the real saved-plan producer/apply/verify chain, mandatory-check tampering, actual resident-memory
  budget, two-run minute limit, protected group, default robot spare, and real respawn attribution with collision
  negatives. The whole invocation still exited 101: main had two invalid fixtures and report had one.
- Corrected main now passes all 38 tests, including all five real TUI execution/budget/tree regressions.
  The earlier report run passed 45 of 46, failing when its canary negative tried to write over a pre-created
  telemetry directory. The directory is now retained under a checked-absent sibling name. The entire corrected
  canary passed at 04:35:55: one test passed, 45 filtered, normal exit 0 (`final-report-canary-0429.log`).
  This partition covers all 46 report tests; it is not one full 46-test invocation on the final source.
- All seven new extraction tests passed twice: genuine verified-byte positives plus malicious destination,
  symlink, existing-file and corrupted-checksum negatives. This is Linux execution evidence, not macOS acceptance.
- The current production native binary SHA256 `4e6adafda1426da1d14f38c1d164ef41e091e86b8e8f39bc18510c562934eb05`
  passed all 62 BATS contracts. Its isolated demo used the correct `PROCESS_TRIAGE_DATA`/`PROCESS_TRIAGE_CONFIG`,
  returned 0, retained the original live PID/start identity, and saved zero executed verification outcomes.
  Its generated Plan schema exactly matches the published bytes. An independent reviewer recalculated every
  primary BATS step digest and validated both its actual producer JSON and the demo's saved Plan against that
  exact schema, including a missing-plan-id negative. Logs: `final-native-bats-0419.log` and
  `final-native-demo-schema-corrected-0423.log`. The first probe's wrong verification-file lookup is retained
  as a probe failure; the corrected probe reran the complete demo rather than assuming its missing assertion.
- Workspace all-targets check and warning-denying Clippy passed the 03:58/04:03 source. Lean check passed
  at 04:09:17 with one existing unused queue-diagnostic-fields warning. Formatting, shellcheck and actionlint pass.
  Final-source all-targets checking passed at 04:30:26 and warning-denying Clippy passed at 04:46:46 on hz4.
  `final-0429-source.sha256` matched the uploaded worker. The preceding hz3 Clippy admission refused a runtime
  inventory-cache lock and ran no Cargo; standard healthy hz4 admission succeeded without a probe bypass.
  Final lean checking passed at 04:50:30 with the disclosed existing warning. Original bundle tests passed
  89/89 under the final lock at 04:54:26 (`final-bundle-integration-0453.log`), zero failed/ignored/filtered.
  The primary fixture correction below will require a fresh targeted runtime and compiler/Clippy/formatting pass.
- Eighteen compatible dependency families have affected-consumer evidence; the current lock is
  `dd6f11e6fc7da70dcf994ee08303db3feb3a8ff8389880c0d94ab856a4cef8f0`.
  The fresh cached audit exits 1 for rkyv, with LRU unsound and paste unmaintained findings. The isolated minifier
  experiment stopped after three failures and was not landed. Larger Criterion/TUI migrations await the earlier
  skill-required approval; neither elapsed time nor the full library pass supplies that approval.
- UBS completed its eleven-file static scan but exited 1: 38 critical, 2,988 warnings and 2,122 informational
  findings. `status: ok` describes scanner execution, not gate success. Independent reconstruction accounted
  for all 38 critical findings: test panics, guarded valid C initialization, public-value comparisons and
  explicit process execution. No confirmed critical defect was found in that bounded review; UBS still exits 1.
  No suppression, waiver, clean-security or publishable-tree claim is made. Full retained triage is in
  `/tmp/process-triage-ubs-triage.nk8zOU/triage.md`.
- Original `bd-uacs.1` acceptance remains open: the existing primary Rust/BATS fixtures forced the loss matrix
  and disabled FDR, rather than using the required test signature prior. Two actual native probes used an owned
  subreaper and double-fork/setsid to prove real kernel adoption and null descriptors. The factory 80% prior
  correctly produced Pause. Explicit synthetic four-class priors (abandoned Beta(999,1), others Beta(1,999))
  produced an executable Kill with the default loss matrix, FDR configuration and posterior gates intact.
  The full native chain then passed: stale-start refusal 10 and wrong-UID refusal 3 both preserved the live
  target; unchanged producer Plan restored, actual apply 2 killed it and verify 0 reported `confirmed_dead`.
  The retained full log is `/tmp/actionlint-bd-ufqb11/native-signature-orphan-full-chain-20261005.log`.
  The smallest existing Rust/BATS fixture correction and repeatable runtime proof remain in progress.
  This is controlled plumbing evidence, not calibration, a proven FDR gate or an empirical FDR guarantee.
- Independent nonauthor verifier GoldenKnoll closed `bd-gn74` at 04:58:14 and `bd-r1mu` at 04:58:34,
  citing their original production callers, positive/negative tests, exact source/lock receipts and required
  gates. Original acceptance descriptions and dependencies remain unchanged. `bd-uacs.3` is being audited
  by a different nonauthor because GoldenKnoll contributed its planned-kill cap; self-certification is refused.

The product is substantially closer to its safety-first cleanup promise, but it is not finished. Calibration on
the real false-positive corpus, fleet/macOS acceptance, measured relief/settle windows and the remaining original
workstreams are still required. Only the independently proven narrow Beads above are closed; P0 and the
remaining original workstreams stay open until their own acceptance evidence exists.

The assessment below describes the inspected baseline. The working tree now connects the canonical executable
Plan to agent planning, saves the exact scorer ledger, enforces the current/saved policy age floor at apply,
sanitizes bundle payloads before checksums/output, and renders recorded session/bundle candidates and outcomes
with static offline rows. These are implementation changes awaiting final acceptance, not closed tasks.

Actual strict remote validation so far:

- The first privacy/report run passed bundle, encryption, redaction and most report suites, then failed nine
  obsolete report-profile fixtures that used opaque Safe archives. The fixtures now exercise raw structured Safe
  data, explicit Forensic archives and refusal negatives; a subsequent 13 report unit + 14 profile tests passed.
- The latest actual-action run passed all seven existing live apply tests, including an open writer refusal and
  renice, pause/resume, kill, zombie-parent routing and blast-radius limits. Two new tests failed: the planner's
  documented `PlanReady` exit 1 was incorrectly treated as failure, and empty apply JSON lacked an outcomes array.
  Both are corrected in the working tree; the actual planner-to-apply positive path still needs a successful rerun.
- Source review found `--targets pid:start_id` discarded the start ID. It now requires a matching saved action
  identity, rejects malformed selections and conflicting selectors, with planted stale-identity tests pending.
- The prior 65 focused precheck tests passed. A later audit strengthened the unlinked regular-file case: a writable
  unnamed regular file now blocks, while a FIFO and read-only file remain permitted. Rerun evidence is required.
- Workspace all-targets check passed for the earlier 21:46 source upload. It does not certify the current tree.
  Current source passes workspace formatting and diff checks; final compiler, clippy, lean and full regression
  gates remain pending. The earlier pass does not certify later policy/activation changes.
- Dependency updates are tested individually and recorded in `UPGRADE_LOG.md`. Current remaining large migrations
  and known audit findings must not be described as a completed latest-version or vulnerability-free upgrade.
- The full bundle/redaction/report suites passed at 22:53, before the later typed Plan/signature and artifact-path
  collision corrections. Actual producer round trips and those corrections require another execution pass.
- Eleven compatible dependency upgrades passed affected consumers one at a time. The frozen lockfile is
  SHA256 `55957d71fd29bac6cd6fc18a79809d6db81036a54b0fec36ab5153ea4d7f4455`; the cached audit still exits 1 for
  rkyv, with LRU unsound and paste unmaintained warnings. Standalone fuzz lock/campaign remain unvalidated.
- Two isolated cold remote builds reached their 30-minute deadline without running the current tests. A subsequent
  workspace-check admission refused critical worker memory pressure (103). No local fallback ran. Current frozen
  source was uploaded at 00:44/00:45 to hz3/hz4; workspace check and the three CLI regression suites are executing.
  The check has a larger resource deadline; functional assertions and acceptance thresholds remain unchanged.
  No green result is inferred from admission, compilation progress, commits or independent source agreement.
- Source now connects the existing typed kernel-pressure reader/assessment to snapshot, plan and TUI load inputs,
  preserves unavailable readings as null, records signature age weights, and maps usage errors to ArgsError 10.
  These additional producer connections remain unverified until the current binary tests and compiler gates run.
- A fresh review found redacted signature patterns remained valid regexes and could be activated through import.
  Source now distinguishes structural inspection from activation, guards every executable matching field in the
  signature database, and refuses sharing-profile or extracted-redacted imports before saving user signatures.
  Actual archive/plain import refusals plus an intact original matcher positive are added, awaiting execution.
- Apply and TUI now hold one execution lock across current-policy checks, real actions, verification and persistent
  kill accounting. Budget checks reload locked state; corrupt/unreadable budgets refuse kills; concurrent writers
  retain each other's events. Actual two-run minute-budget and headless TUI success/failure regressions are added.
  Missing/nonfinite posterior evidence cannot satisfy a positive floor, and CLI category allowlists intersect policy.
  These changes remain unaccepted until their current-source tests run.
- The prior disposable-process fixture used numeric-PID cleanup; Linux cleanup now pins the original target with
  a pidfd. A local wrapper termination was initially mistaken for stopping a durable remote job; durable cancellation
  and terminal recovery acknowledgment corrected that mistake. The canceled run provides no action-test evidence.
- Further original acceptance gaps are tracked as `bd-gn74` (bundle extraction destination/symlink boundary) and
  `bd-zisi` (macOS notification quoting). Neither has an implemented or executed fix in this batch.
- A writer outside this agent team merged isolated dependencies and placement changes during the earlier freeze.
  Source receipts exposed the mismatch. The older check/CLI uploads cannot certify that newer main; the fixture PID
  needed an explicit u32, and that compile defect is fixed. The next transfer failed before Cargo started, its
  ownership was recovered, and an unadmitted retry was stopped before any source sync or execution.
- Six more sequential dependency consumer runs passed in isolation: YAML replacement (12 tests), once_cell (104),
  serde_json, regex, thiserror and Serde (602 each). These overlap in consumers and are not summed as distinct tests.
  Serde was merged before its run completed; its actual pass arrived at 01:01:42. The frozen tested lock is now
  SHA256 `95e0ff8b5ff2b3d969338c517e189ae597b6bd84284b598b4d6d6bbf7369d951`. Audit findings remain non-green.
- Fresh review reopened `bd-qr40.7`: the prior sleeping-target fixture assigned invented 100 MB estimates and proved
  estimate arithmetic, not the original real-byte acceptance. Apply now checks and debits current scan RSS, and its
  replacement allocates actual resident memory while recording zero estimates. Two permitted kills and a third
  live refusal still require an executed pass; no original acceptance criterion was weakened.
- Required snapshots now derive from a typed recorded Policy; the producer stores that full snapshot and apply
  refuses missing/incomplete snapshots when current policy requires one. Invalid numeric CLI limits are rejected
  before loading a session. Final planned kills obey per-run limits with children selected before parents, and
  excluded children trigger tree safety again. The generated tightening property includes exclusions, repeated
  total caps, nonzero prior usage and boundary positives. Verify exposes the saved start identity for the BATS chain.
- The new workspace check and actual CLI suites uploaded at 01:15 on hz3/hz4. A test-only archive-path correction
  raced the upload: the hz3 source receipt differs only at e2e_report.rs. Repeat the corrected report test and final
  current-source gates after this run; do not promote a source-mismatched result to a current-tree pass.
- UBS still exits 1. Independent review accounted for its 39 critical findings as test panics, valid guarded FFI
  initialization, ordinary domain comparisons and executable selection. This bounded explanation is not a waiver
  or green scanner result; the actual remaining budget/snapshot/UI gaps were fixed separately and await execution.
- The 01:15 workspace check exited 101 at 01:22:38: the age-floor fixture imported the older common Policy schema,
  which has no builtin_protection field. Its two imports now use the actual production configuration schema; no
  assertion or production protection was removed. Both worker receipts differ only at the corrected report test.
  A fresh current-source check and report rerun remain necessary.
- Canonical verification now reads the same Plan as apply and binds successful saved outcomes to exact target,
  command, original parent, UTC execution time and Linux boot ticks. Review-only/unexecuted recommendations do not
  become completed actions. Respawn matching requires exact normalized arguments, UID, parent identity and birth
  after execution; a matching process born in the same tick is explicitly ambiguous, not confirmed dead.
  Expected saved memory is labeled expected, and no observed relief or time-to-death is invented. CLI/TUI recording,
  session-state preservation, actual respawner/orphan fixtures and the feature-gated lifecycle test are updated.
  These changes compile but still require runtime acceptance, including retained parent/substring negatives.
- The canonical verification migration replaced 82 old report-shape unit functions with 18 tests, including
  table-driven coverage of identity/UID/full commands, paused/alive/dead/PID-reused outcomes, status, recommendations,
  expected-memory arithmetic, schemas and timestamps. The old minimal report JSON, unknown-ID permissiveness,
  short/empty-command fallback, missing execution timestamps and scan-only proof of unrelated action effects
  are intentionally rejected. Previously unproduced Cascaded/Timeout variants were removed. Counts are not
  progress; the new suite has not run and this inventory does not waive any original acceptance requirement.
- Current all-targets checking exposed two fixture API mistakes: require_confirmation needed Some(true) under the
  actual Policy schema, and the duplicate-artifact tests called BundleWriter with a nonexistent run-id/builder API.
  Both are corrected without removing assertions. The 02:04 upload finished Cargo checking successfully at 02:05;
  durable completion, exact source receipt, clippy, lean check and execution remain required.
- The next isolated dependency experiment removes the rkyv-bearing generic HTML minifier by minifying only owned
  CSS/JavaScript assets. A real release consumer run is pending, and main has not received that patch. LRU/paste
  audit findings remain; no vulnerability-free or equal-size/performance claim is made.
- The 01:15 hz4 upload finished its real action suite at 02:10: all 11 tests passed, including the actual
  planner/apply/verify identity chain, genuine allocating-target RSS cap and persistent two-run kill limit.
  The report suite then passed 38 tests and failed its intact archive import because the known fixture-path fix
  missed that upload; exit-code tests did not run. Durable recovery acknowledged terminal exit 101. This is useful
  original-path execution evidence for the earlier source, not certification of the new verification batch.
- Warning-denying clippy failed on the existing socket-cache type and two cloned test slices. The cache now uses
  a named type, and the slices are being corrected; no warning suppression was added. Independent integration
  review also found ignored mandatory outcome-write errors, failed attempts reported as clean verification,
  pre-check command/parent evidence reused at execution and a separate broad goal-progress respawn matcher.
  Those gaps are being repaired. Actual delivered destructive signals now count against budgets even if later
  verification fails, with a real-signaling/zero-observation-window regression awaiting execution.
- The 02:25 frozen upload completed its live suite at 02:44: 11 of 12 passed, including the new actual respawner,
  exact parent/command negatives, unexecuted/review-only state, actual RSS and persistent budget tests. Renice
  failed its initial `ps` priority read before apply; the test's raw initial observation was missing and is being
  investigated. Cargo stopped there, so report/exit-code suites in that invocation did not execute. There is no
  full-suite pass. The source receipt and raw log `target/test-logs/privacy/current-main-0225-cli.log` are retained.
- Workspace all-targets check and warning-denying clippy both passed on the 02:40/02:41 source uploads. Subsequent
  verification/TUI corrections are outside those passes and need fresh gates. Runtime inventory refresh resolved
  worker admission without disabling probes; the underlying inventory-lock contention was observed read-only.
- The current canonical Plan schema emitted by the 02:25 binary exactly matches `docs/schemas/plan.schema.json`.
  Worker and copied binary SHA256 is `e09db70d4f5e6949bbf458075147892f16126757c96843da72501ea10322b938`.
  This confirms the unchanged schema artifact, not the later execution source or actual saved-plan validation.
- Original BATS policy/plan/stale-identity/apply/death/verify assertions passed against that binary. Its final
  logging assertion correctly failed: a wall-clock adjustment produced `elapsed_ms=-598`. The Bash logger now
  uses Linux boot uptime and retains the nonnegative assertion. Earlier failures were actual built-in service
  protection on the local host and Bats' inherited writable capture FD4 on the worker; no safety gate was waived.
  The owned launcher closes inherited descriptors before spawning, and retained actual FD/identity observations
  confirm exactly null stdio. Full BATS acceptance still requires a clean rerun, including its logging assertion.
- Fresh independent review found failed/partially parsed process snapshots could falsely confirm death, a copied
  wrong-session Plan was accepted, and `identity_check_failed` was ignored. Source now rejects nonzero/empty
  full snapshots, refuses incomplete verification observations, binds the opened session, and preserves both
  identity-check and unsupported-platform failures. Unknown statuses refuse instead of disappearing. CLI tests
  inject explicit failing/malformed/empty `ps` subprocesses and require preserved earlier reports/manifests, then
  restore the actual positive observation. These negatives are fault-injection evidence, not live kill proof.
- Independent TUI review found repeated applies replace the saved Plan while appending older outcomes and reset
  the per-run counter through a fresh enforcer. Cumulative canonical actions, retained run accounting and outer
  error propagation are being corrected in the same original Bead. CLI later-tree-scan errors now reach the common
  original-outcome logging/JSON/failure tail, and fallback escalation refuses unreadable identity. Runtime and
  macOS acceptance remain pending; successful delivery accounting alone does not close these gaps.
- The isolated minifier experiment failed after three actual release attempts and is not landed. Its last run
  passed 16 library, 42 HTML and 14 existing profile tests, then failed one new fixture's incorrect raw Forensic
  ledger assumption. No fourth attempt, rkyv-removal, latest-version or audit-green credit is claimed. A separately
  researched small dependency update may proceed; the existing greater-than-ten-file permission stays pending.
- Current bundle/redaction/report consumers passed normally at 02:58:31: 282 tests in one invocation, zero failed,
  ignored or filtered, including three compiled doctests. The exact component upload hashes matched the worker.
  This validates those consumers, not unsafe CLI extraction or the newer core/TUI source.
  The unchanged main lock and SHA-bound component files are retained with the actual log
  `target/test-logs/privacy/current-components-0254.log`.
  The latest six-file UBS scan remains non-green (15 critical, 1047 warnings, 1656 info); differing scopes are not
  compared as improvement. Findings are under review, with no suppression or publication waiver.
- The BATS real chain passed all original production/effect/log assertions after its monotonic logger correction.
  Its staged binary hash remains the earlier 02:25 artifact; all 62 contracts are now running. These results do not
  certify the later core changes. Five actual producer Plan documents passed Draft 2020-12 schema validation,
  with missing-plan-id and invalid-UID negatives refused; the emitted schema still exactly matches the committed one.
- Fresh TUI review found the new test oracles incorrectly assumed targeted scans contained no host-wide rows.
  The owned-target subsets now retain the original exact identity, session, kill/death, spared-target, canonical
  binding and budget oracles; the full observation remains available to verification. Win: valid target oracles;
  loss: this does not repair or certify the existing `ps -eo ... -p` collection-scope defect or prove performance.
  Renice now retains exact initial `ps` status/stdout/stderr and leader/liveness errors without retries or weakened
  priority assertions. Its earlier remote setup failure remains undiagnosed.
- Durable intent is being integrated into the existing kill budget before signaling. Completion records actual
  delivery; a failed completion save leaves the readable pending intent and refuses future kills, including force.
  CLI execution identity/time is refreshed after intent I/O. TUI additionally uses the same final live-child guard
  as CLI. Actual disk-failure, non-delivery and live TUI wrapper negatives and final gates remain pending.
- The complete 62-test BATS contract suite passed on the retained 02:25 binary; this is earlier-source
  evidence, not certification of the new durable-intent or extraction changes. The scoped dry-run demo also
  passed on that binary, but its first invocation used unsupported data/configuration environment names.
  The demo must be repeated with PROCESS_TRIAGE_DATA/PROCESS_TRIAGE_CONFIG and the current binary.
- The 02:55 core library run executed zero tests: compilation exposed a Linux fallback identity helper hidden
  behind a macOS-only cfg. That cfg is corrected without weakening identity checks. A 03:28 retry timed out
  before remote admission (103); the 03:38 strict remote retry is now compiling the corrected libraries.
  Durable completion recovery of the failed older job remains pending after an SSH release timeout.
- Reflog records external resets at 03:25 and 03:26, followed by commits made outside this agent team.
  Reverted test helpers were restored manually, and patches/copies are retained outside the repository.
  No reset, deletion, commit or push was performed by this team; exact source receipts remain necessary.
- Bundle extraction (`bd-gn74`) is now in progress: verified-byte positives and unsafe destination negatives
  are written, while the production destination boundary is being repaired. No runtime or closure credit yet.
  A new default-spare fixture is being checked against actual default inference; youth alone may recommend
  Pause rather than Keep, so that assertion must not be weakened or represented as a default-policy pass.

### Active completion checklist

- [x] Connect final post-policy candidates to the existing executable Plan builder; preserve canonical identities,
  required checks, rationale, parent routing and final review/keep decisions.
- [x] Persist exact four-class evidence ledgers without recomputing historical sessions with current priors.
- [x] Connect structured profile redaction to plain, encrypted and in-memory archive preparation.
- [x] Add static escaped report rows and recorded outcomes/ledger rendering; preserve unknown timing/counts.
- [x] Inspect and repair CI source configuration, including invalid job secret conditions and masked test failures.
- [x] Add activation validation while retaining inspectable typed Safe signature exports.
- [x] Connect apply/TUI current-policy checks and persistent kill accounting with shared execution locking.
- [x] Reject missing/invalid positive-floor probabilities; intersect category overrides and add tightening property.
- [x] Rerun actual planner → apply → verify with a real detached target and stale-identity refusal.
- [x] Execute canonical verification unit/lifecycle tests with strict saved execution identity and timestamp binding.
- [x] Execute actual respawner attribution plus foreign-parent, substring and same-tick ambiguity negatives.
- [x] Independently review CLI/TUI execution evidence and remove the remaining broad goal-progress respawn matcher.
- [x] Count partial kill execution against budgets even when subsequent effect verification fails; prove both entry paths.
- [x] Reject failed, empty or incomplete verification snapshots and wrong-session canonical Plans; retain prior reports
  and manifests on explicit subprocess fault injection, then re-execute a real positive observation.
- [x] Preserve identity-check/unsupported-platform failed retries and reject unrecognized saved outcome statuses.
- [x] Preserve every prior canonical TUI action across repeated applies, carry the run budget across callbacks, and
  propagate callback/persistence/accounting errors through the outer command exit.
- [x] Persist kill intent before signaling, reconcile actual delivery without charging refusals, and prove a failed
  final save cannot reset the retained run count or permit a fresh invocation; apply the same live-child guard in TUI.
- [x] Retain earlier real CLI outcomes if a later process-tree refresh fails; refuse unreadable fallback signal identity.
- [x] Investigate the missing initial renice priority observation without weakening its action/effect assertions.
- [x] Execute the corrected complete-age-policy and Linux getpriority fixtures on the 06:54 source.
- [x] Rerun BATS with actual FD-bound launcher evidence and monotonic timings; keep every original positive/negative.
- [ ] Rerun current-age-floor, regular/unlinked writer, read-only/FIFO and unreadable-evidence cases.
- [x] Rerun actual CLI saved-session → plain/encrypted bundle and session/plain-bundle HTML canary regression.
- [x] Rerun sharing/report library and integration suites on the 02:53 source and lockfile (282 tests, 02:58:31).
- [x] Repeat affected sharing/report consumers after the subsequently integrated Schemars family update:
  current corrected component run 287 passed, including the three unchanged original failed assertions.
- [x] Add and execute the BATS twin against the validated binary; prohibit implicit local heavy builds.
- [x] Repair and execute the scoped plan/review/apply demo; publish the generated Plan schema.
- [x] Verify a tampered plan cannot remove mandatory runtime checks.
- [ ] Complete sequential compatible dependency consumer tests, freeze the lockfile and rerun security audit.
- [ ] Obtain the existing pending permission for migrations exceeding ten source files before starting them.
- [ ] Run current-tree workspace all-targets check, warning-denying clippy, formatting and lean check.
- [ ] Verify actual Safe Plan and SignatureSchema typed round trips, preserving checks, routing and numeric evidence.
- [ ] Verify distinct secret artifact filenames preserve both payloads/checksums and duplicate paths refuse publication.
- [ ] Verify malformed signatures/provenance audit and unreadable requested telemetry refuse before output creation.
- [ ] Verify snapshot/plan kernel-pressure readings and their persisted schema; review remaining unknown-value consumers.
- [x] Verify CLI usage error 10 and explicit help/version 0, including existing label/degraded-environment expectations.
- [x] Complete bd-uacs.3 apply/TUI policy-enforcer and persistent kill-count wiring with real cross-run rate-limit proof;
  independent closure at 10:02:14 UTC cites exact original within-minute delivery/survival/counter evidence.
- [ ] Validate independent saved/current policy enforcement after current protections, posterior floors and budget
  limits are loosened; retain stricter-current and exact permitted-boundary positives.
- [x] Execute the producer-driven hourly saved-policy drift phase: first delivery charged once, second saved
  target refused with `rate_limit`, exact identity still alive and no additional persistent charge.
- [x] Execute TUI planned-cap boundary/refusal and repeat all real headless TUI delivery/accounting regressions.
- [x] Execute malformed full-snapshot and legacy-age JSON refusals before any signal or outcome publication.
- [x] Execute headless TUI real-kill/accounting regression and preserve earlier outcomes on later evidence failure.
- [x] Execute corrupt/unreadable budget and concurrent-writer tests; report permission evidence separately on root.
- [x] Execute actual Safe/encrypted bundle import and extracted-JSON refusal without changing existing signatures.
- [x] Execute intact original/Forensic signature import and intended/unrelated matcher behavior.
- [x] Verify protected-group evidence on a live target and current policy/CLI missing-posterior refusals.
- [x] Verify default robot planning retains a nonempty spare set and generated overrides never loosen policy.
- [ ] Execute current-RSS budget proof with saved zero estimates; independently verify reopened `bd-qr40.7`.
- [x] Execute missing/incomplete required-snapshot refusals and intact producer-snapshot positive apply.
- [x] Execute nonfinite/negative CLI limit refusals before session loading; retain finite boundary positives.
- [x] Execute final planned-kill cap and child-before-parent/tree exclusion tests.
- [x] Fix and execute bundle extraction destination/symlink boundary (`bd-gn74`) before treating extraction as safe.
- [ ] Fix macOS notification argument interpolation (`bd-zisi`); require actual macOS evidence for platform acceptance.
- [x] Finish `bd-r1mu`: prove both below/above cutoff malformed UTF-8 HEAD files return typed Unreadable;
  preserve genuine main/detached Git and live-process cwd positives, then independently review final gates.
- [x] Execute all eight workspace library suites on the 04:13 source/lock (4,854 passed, seven existing ignores).
- [x] Execute corrected main-binary tests on the 04:23 upload (38 passed; all five TUI regressions included).
- [x] Finish the existing report canary's unreadable-telemetry negative without deleting its pre-created directory;
  rerun its complete plain/encrypted/session/bundle/activation/privacy/publication assertions.
- [x] Independently recompute the latest native BATS step digests and validate its real producer Plan instance.
- [x] Replace the primary Rust/BATS forced-loss fixture with the original test-signature/adopted-orphan fixture;
  execute full native and Rust/BATS apply/verify while preserving default loss/FDR and every safety oracle.
- [ ] Run appropriate workspace regressions; distinguish pre-existing failures from new ones using evidence.
- [x] Rebuild and stage the saved-policy SHA-bound native binary; repeat the corrected 62-test BATS suite, scoped
  dry-run demo and exact generated/published Plan schema check after the saved-policy production fix.
- [x] Execute current default-policy Forensic CLI export/import with intact matcher positives and mandatory secret
  negatives; rerun original all-profile no-secret component consumers without weakening their assertions.
- [x] Execute paired session/Safe-ZIP HTML deep-scan status, evidence, privacy and unknown-history regression
  on the 06:54 source; later privacy-policy changes require their affected rerun.
- [x] Inspect fresh-target test names before granting the new Forensic/deep-scan cases execution credit;
  source hashes and a successful cached invocation alone did not prove those cases ran.
- [x] Execute final doctor allocated/logical-size reader, deterministic inode representative and unchanged
  allocated-GiB classification boundaries; retain original sparse and real allocated-file positives.
- [x] Run the 06:54-native Forensic HTML probe with visible harmless script-like text and exact recovered JSON;
  a Safe profile's hashed text alone does not prove the escaping of a displayed local-detail field.
- [x] Correct the three actual Forensic component failures in production; retain original integration assertions
  and exact CLI signature export/import positive, including harmless visible markup under the narrowed policy.
- [x] Execute the strict within-minute gate from actual first pre-execution evidence to the exact refusal event;
  retain startup/report-tail latency losses, exact identities, actual signals and unchanged saved counters.
- [ ] Correct targeted `ps` selection while retaining full-host ancestry/tree/provenance scans; execute actual
  exact-subset, missing/duplicate/invalid PID and diagnostic refusal cases plus the original action/TUI regressions.
- [x] Execute all seven new collector unit cases on the 08:15 source; preserve current action diagnostic failure
  and repeat its complete original negative/positive sequence after the production diagnostic correction.
- [x] Execute all 57 MCP protocol cases, including explicit planner-child configuration and both invalid controls;
  retain the broader same-snapshot decision/parity and protected-context work on `bd-uacs.8`.
- [x] Execute narrowed tutorial command/exit matrix and bare current-native `learn verify --all`; retain macOS gap.
- [x] Execute explicit same-PID before/equal/after birth-order classification on current source; retain exact
  PidReused/ambiguous/Respawned outcomes and zero invented resource relief.
- [x] Repeat corrected actual respawn/action and lifecycle integrations on the final 09:06 source: 19/19,
  Cargo 0; retain separate RCH release-acknowledgement wrapper 1 and released-claim inspection.
- [x] Execute all existing app-supervision consumers after removing unused signature construction: 51/51;
  no speedup claim.
- [x] Repeat the unchanged closed-stdin BATS contract and full native suite: a19a native 62/62, zero skips;
  retain the older actual 30-second loss and source-bound raw producer-chain evidence.
- [ ] Finish canonical executable-only action/report reconciliation, including staged remedies, valid parent routing,
  no-parent zombies, blocked candidates, unsupported Restart and full-incarnation near negatives; execute fresh
  real producer/apply/verify and independent original bd-uacs.1 acceptance before closure.
- [x] Correct actual report profile/end metadata across session and verified bundle paths; prove terminal,
  archived, resumed, missing, malformed and contradictory history with unchanged secret-exclusion/checksum gates.
- [x] Execute typed recent-I/O read/parse, full-window/birth/cache tests and actual owned unreadable/idle/writer
  consumers; retain the original shared-window periodic-writer and 110-second acceptance bound.
- [ ] Finish the other mandatory-observation Unknown paths in `bd-toa2.6`, with real permission/provenance
  refusals, explicit disabled gates, interactive warning behavior and cross-UID/macOS evidence where required.
- [x] Execute the supervision slice's typed stat/ancestry/environment/IPC failures, fresh successful negatives,
  observed-root termination, namespace-correct socket evidence and bind-after-cache positive.
- [x] Execute actual owned non-dumpable and `supervisord`-parent checks; prove explicit CLI planning/dry-run/live
  refusal under both human-confirmation policies while preserving enabled data-loss guards and birth identity.
- [x] Run the corrected two-zombie producer after closing the interpreter's owned persistent `libffi` descriptor;
  preserve the exact three `/dev/null` descriptors, five-second bootstrap bound and original primary chain.
- [ ] Validate watch's corrected combined abandoned-plus-zombie probability; finish shared decision/TUI routing,
  policy thresholds and final `--only` filtering under the original `bd-uacs.8` criteria.
- [x] Bind routed-zombie mandatory supervision to the actual parent, preserving dead-child diagnostics;
  execute unchanged two-action/default-policy positive plus real same-parent unreadability/protection and
  changed-birth/owner negatives before granting the target correction runtime credit.
- [x] Serialize TUI refresh/execute and invalidate pending confirmation at refresh request; execute actual
  Model task closures for pre-display cache replacement, stale/duplicate tickets and error recovery.
- [ ] Check every daemon signal-registration return and surface installation failure; preserve harmless
  POD initialization and async-signal-safe handlers rather than changing scanner rules.
- [ ] Fix the existing macOS notification's generated AppleScript string escaping, including backslash
  before quote; retain the actual macOS parser/runtime acceptance requirement on `bd-zisi`.
- [x] Bind resumed successful outcomes to canonical action target PID/start/owner and execution evidence;
  preserve valid idempotent resumption and refuse wrong-target success records with the same action ID.
- [ ] `bd-uacs.17`: bind saved execution outcomes to the action kind as well as ID/target; require an altered-Plan
  Pause-to-Kill neighboring refusal and preserve genuine typed CLI/TUI producer records.
- [x] Validate Clap 4.6.7 on main with actual common library and CLI consumers, then all four compiler gates;
  only then credit the nineteenth family and continue the next compatible family sequentially.
- [ ] Repeat current-source compiler/Clippy/lean/library/component gates and source-bound native contracts after
  the subsequent Forensic, deep-scan, tutorial and fixture changes; do not reuse the 0528 result as their proof.
- [ ] Re-execute workflow static checks and review scanner findings before committing.
- [ ] Complete fresh original-acceptance review and the real-work/honesty inventories; close only proven tasks.
- [ ] Flush Beads, commit reviewed changes and push verified main plus the required legacy branch synchronization.

No calibrated precision/recall, fleet acceptance, macOS live probe, hosted-CI success or encrypted-bundle CLI
reporting is claimed by these tests. The full original workstream checklist below remains open where its named
acceptance evidence has not been obtained. Further gaps discovered during execution belong on that checklist
and their existing Beads rather than being hidden in a completion summary.

### Fresh real-work audit and honesty inventory — 2026-10-05 04:52 UTC

Subsequent correction at 05:27: nonauthor review found the saved-policy/TUI-plan omissions above; preliminary
eligibility for `bd-uacs.3` was retracted before closure. It remains in progress, with the original requirement
and a genuine producer-driven drift regression. GoldenKnoll independently closed only `bd-gn74` and `bd-r1mu`
on their complete positive/negative evidence; root made no feature closure. Later source changes are not
covered by earlier compiler/native passes. These corrections change answers 5/11/13 in the subsequent window;
the dated twenty-answer audit below remains the bounded 04:52 record, not an assertion about later work.

Consumer: the operator requested this assessment and granular TODO. Gate: the completion claims below;
retirement: this session's handoff, retaining the historical record rather than creating another certificate.
Recovery receipts serve the observed source-overwrite/upload-race defect and receive zero capability credit.

Mechanical audit window: the three newest commits (`39b4a0e`, `e2f6329`, `defa7c0`), their complete fixture
diffs, current compiler/runtime receipts, the five newest closures and six oldest open Beads. Reflog confirms
an external maintenance writer made those commits; this team made no commit, reset or push. Classification:
ENABLER 2 (actual descriptor/host oracles and timestamp/telemetry/Unicode fixtures), PROCESS 1 (assessment and
tracker evidence), USER 0, UNKNOWN 0. This bounded count is not a quota or a claim about the whole session.
README purpose: “pt finds abandoned processes and helps you get rid of them safely.”

The six worksheet answers:

1. The largest user-visible improvement exercised in this block is the real producer Plan reaching apply,
   persistent safety accounting and canonical effect verification. The retained native demo proves a safe
   scoped dry-run in two minutes; real actions are shown in the 14-test CLI run and headless TUI tests.
   The original signature/adopted-orphan fixture still needs its full apply/verify proof before P0 closure.
2. Omitting the PROCESS commit would change no runtime behavior. It records observed failures and prevents
   unsupported completion claims; more certificates would add no capability. Keep this existing document only.
3. The corrected fixtures enabled actual consumers: all 38 main tests, the full privacy canary, and eleven
   genuine Git/Unicode tests now pass. These are named shipping gates, not speculative infrastructure.
4. The oldest open foundation is `bd-l3s5` (September 24), the real fleet false-positive corpus. The immediate
   work corrected a broken executable contract and unsafe execution/sharing boundaries. Fleet calibration
   remains a material gap; success on disposable Linux targets cannot close that foundation.
5. No feature closure was made by this team in this window. CI repaired real fixtures, the independent
   reviewer audited original acceptance, and the dependency agent triaged scanner findings. None gets
   capability credit for a close count, agreeing with another agent or finishing a review.
6. The PROCESS commit changes no original acceptance. The original P0 remains open after discovering that
   forced-loss fixtures missed its signature requirement; no follow-up was minted to launder that remainder.

**Verdict: DRIFTING.** This narrow window delivers fixture/gate completion rather than new production code,
and repeated cold builds plus evidence updates are costly. The earlier production changes now have substantial
runtime proof, but a large remaining work graph and the literal primary fixture are unresolved. Correction:
freeze new assessment machinery and unrelated migrations; CI completes the existing default-policy native
chain and the smallest original fixture correction while root finishes bundle integrations and compiler gates.

The twenty honesty answers (bounded fresh checks above, with known earlier mistakes retained):

1. No (checked: complete three-commit fixture diffs, current CI configuration, final run summaries and reflog).
   No new ignores, threshold relaxation or protection removal occurred. Nulling a disposable child's inherited
   log FD changes the fixture, with actual FD/type/access observations before the original live-child oracle.
   The timestamp fix compares the exact nanosecond instant and rendered recorded value, not a loose substring.
2. Yes: the earlier fictional 100 MB sleeper fixture was inadequate real-byte evidence. Its Bead was reopened;
   the real allocating-target/zero-estimate test now passes. Synthetic signature priors and saved-session canaries
   remain explicitly controlled test data, never measured decision quality or a real-host calibration corpus.
3. No (checked: changed paths, test diffs and recorded commands). No BLESS or golden regeneration ran.
4. Yes: tests and CI were changed during implementation. The win/lose split is explicit: genuine Git repositories
   replace an absent worker `.git` assumption; real zombie exit is observed before the unchanged effect deadline;
   equivalent UTC serialization preserves the exact saved instant; retained telemetry directory obstruction
   reaches the intended I/O refusal. These fixes admit legitimate fixtures, not weaker production safety.
   Larger remote resource deadlines and two test threads affect infrastructure, not functional thresholds.
5. No (checked: production main/parser patches and actual positive/negative artifacts). No benchmark/test-path
   success branch was added. Forced-loss fixtures are plumbing evidence and their original P0 shortfall is open.
6. No (checked: every cited summary includes executed tests). Canary is one pass/45 filtered; resolver is eleven
   passes/3,976 filtered. The full library run has 4,854 passes, seven existing ignores and zero filtered.
7. Yes: the earlier remote-wrapper completion mistake and the initially described Clippy attempt that actually
   refused admission required correction. Durable terminal receipts establish completion; the refused attempt
   ran no Cargo. Its later standard-admitted hz4 retry genuinely passed at 04:46:46.
8. Yes: the prior estimate-only fixture inflated its proof class. Actual RSS execution corrects it. Schema checks,
   synthetic report data, source review, old-lock component tests and native action tests retain distinct scopes.
9. Yes: external source changes and missed test-only uploads invalidated earlier broad pass claims. Exact hashes
   exposed them; failed runs are retained and the affected fixtures reran. UBS and audit remain non-green;
   complementary report partitions are not presented as a single all-green final invocation.
10. No (checked: retained Cargo tee logs and raw CLI/BATS stdout/stderr with recomputed digests). Cited command
    stderr is retained. Disposable process null descriptors are the safety fixture, not suppressed CLI evidence.
11. Yes: the historical real-byte Bead had been closed on invented estimates and remains reopened pending its
    complete original scope. Root has closed no feature at this timestamp; original P0 acceptance stays intact.
12. No (checked: original `bd-uacs.1/.2/.3`, `bd-gn74`, `bd-r1mu` descriptions and this TODO). No requirement was
    reduced to match implementation. Single-host/FDR calibration, fleet and macOS requirements remain open.
13. Yes: the earlier graph-hygiene closure was self-verified, explicitly PROCESS. Current independent review
    cites exact source/runtime receipts before any root feature close. External commits are not root publication.
14. No (checked: current CI and reviewer dispatches). They specify real effects, planted refusals, unchanged gates
    and no calibration/platform claims, rather than asking only for green tests.
15. Yes: individual dependency upgrades initially relied on the isolated agent's consumer receipts. Root read
    their changes and now observed 4,854 integrated library passes under the exact final lock; individual
    integrations/all-features/MSRV/fuzz still require their own evidence, not inferred completion.
16. No (checked: recent Bead closures and current handoffs). No current feature was closed on refusals alone;
    valid byte extraction, actual Kill effects and preserved original matcher positives are mandatory.
17. No (checked: review dispositions). Independent source agreement is review, not a second runtime sample.
18. No (checked: frozen commands and reported counts). Overlapping 602-test dependency runs are not summed;
    no speedup, measured relief, calibrated precision or FDR guarantee is reported.
19. The owner should see the expensive retry/fixture chain, the original forced-loss mismatch, the earlier
    estimate claim, external source resets and both non-green scanners. None is hidden by a passing subset.
20. Strongest evidence: SHA-bound actual CLI action runs with retained before/after identities, real signal
    delivery, persistent budgets, native BATS raw commands and independently recomputed digests. A skeptic can
    rerun the existing Rust/BATS tests; the original default-policy chain correction remains pending.

Cass's earlier six bounded project queries found no indexed project sessions; broader inspected hits were
unrelated. That missing coverage cannot certify older history. Disposition: observed false claims/fixtures were
corrected in place and retained; known failures are disclosed above and in operator updates. Countermeasures:
original acceptance and independent closure (RH-1/RH-2/RH-7/RH-9), no regenerated goldens (RH-3), no fixture
quality inflation (RH-5/RH-12), exact source/terminal receipts and retained stderr (RH-16). Runtime and scanner
remainders remain unchecked. This inventory supplies no waiver or release certification.

### Historical real-work audit and honesty inventory — 2026-10-05 01:30 UTC

This is the filled anti-ceremony worksheet, not a completion certificate. The mechanical window is the seven
commits from 01:00 through 01:28 UTC, their test/main/constraint diffs, current dirty fixture imports, the newest
five closed Beads and oldest six open Beads. Known earlier session mistakes are included explicitly. The README's
purpose is: “pt finds abandoned processes and helps you get rid of them safely.”

The third committer made all seven commits using the repository owner's identity; this team authored their
source changes but did not make those commits. Classification: USER 3 (b6d4970 current RSS/snapshots, 2983642
verification identity, 5c5888f planned kill cap); ENABLER 3 (86c09e2 genuine-memory/properties, e9fde08 numeric
CLI assertions, 50d9568 original archive positive); PROCESS 1 (dc28667 reopen unsupported budget closure);
UNKNOWN 0. These counts are a diagnosis, not a delivery metric or quota.

The six worksheet answers:

1. The most useful implemented behavior is refusing a third kill when the first two consume the actual RSS
   budget even though saved estimates are zero. The two-minute demonstration is the real allocating-target CLI
   test. It has not passed yet; source and a fixture are not a shipped demonstration.
2. Without the PROCESS item, behavior would be unchanged, but an unsupported closed budget claim would remain.
   Reopening that claim is necessary correction; further tracker certificates would add no capability.
3. Earlier consumer runs exercised the upgraded libraries and the sharing/report adapters. The new boundary
   properties and archive positive have not yet exercised the current binary. Do not label them delivered.
4. The oldest open user-facing foundation is bd-l3s5, the real fleet false-positive corpus (September 24).
   The immediate effort went to a broken executable agent contract and unsafe sharing/accounting boundaries.
   That prioritization does not establish calibrated fleet quality; the original quality gate stays open.
5. GreenLotus closed one graph-hygiene task, self-verified, and supplied separate production source changes.
   The other agents closed no features. No pane's close count is treated as capability evidence.
6. This window contains one tracker correction and this requested in-place assessment, not specification changes
   substituting for implementation. Original acceptance text was retained; no follow-up carries a missing
   acceptance condition out of a closed original.

**Verdict: DRIFTING.** Production changes are substantial, but final positive execution has remained unresolved
through repeated cold builds, source races and discovered fixture errors. The correction is to stop expanding
the machinery: execute the current CLI positive/negative chain, repair observed defects, and finish the named
gates. The verification contract is the next product gap; it cannot be claimed closed while bd-uacs.1 is blocked.
The tracker correctly refused claiming bd-uacs.2; preparation is recorded without bypassing that dependency.

The twenty honesty answers, bounded as above:

1. No (checked: all test-touching diffs in the seven-commit window, embedded main/constraint tests and fixture
   import diff). No assertions, ignores or thresholds were removed. Earlier isolated fixtures deliberately
   disable unrelated protection and shorten I/O sampling; they prove those isolated predicates, not default
   decision quality. Their limits are disclosed in the execution notes.
2. Yes: the prior sleeping-target fixture assigned fictional 100 MB footprints. It proved saved-estimate
   arithmetic, not real-byte acceptance. bd-qr40.7 was reopened; the replacement allocates resident memory,
   saves zero estimates and checks the surviving refused target. Actual execution is still required (RH-2/RH-5).
3. No (checked: this session's changed golden/snapshot paths and command record). No golden regeneration or
   BLESS execution occurred.
4. Yes: validators and regressions changed with the implementation; CI configuration was also repaired earlier.
   Infrastructure build/sync deadlines were increased after observed cold-build/transfer timeouts. Functional
   timing thresholds and assertions were retained. Static workflow positives/planted invalid-condition negative
   passed; hosted CI and fresh functional gates remain pending (RH-1/RH-14/RH-15).
5. No (checked: allocating-target fixture, planner cap, property boundaries and numeric parser diffs). The
   production code does not branch on benchmark/test paths. Fixture-specific loss matrices are only plumbing
   evidence; their kill recommendations are not a calibrated-quality result (RH-12).
6. No (checked: cited prior suite summaries contain nonzero executed test counts). Newly added tests are marked
   unexecuted; admission, compilation and filters without results are not counted as green.
7. Yes: an earlier local wrapper termination was initially treated as remote-job completion. Durable cancellation
   and terminal recovery later established the actual state; the run supplies no test evidence. Subsequent
   remote jobs require durable terminal acknowledgment and source receipts (RH-2).
8. Yes: the estimate-only budget fixture could inflate its proof class. The reopening and genuine-memory probe
   correct that claim. Source agreement, isolated consumers and old uploads remain labeled as such (RH-2).
9. Yes: source retrieval and a separate committer's merges made earlier green results inapplicable to newer main.
   Exact receipts exposed the mismatch. The report-path fix also missed both uploads; corrected tests and final
   gates must rerun. These failures are recorded above instead of being hidden behind commit progress (RH-2).
10. No (checked: cited remote tee logs, current CLI step artifact code and recorded failed runs). Cited stderr
    is retained; any read-only command output reduction is not treated as a functional pass (RH-16).
11. Yes: bd-qr40.7 was already closed without the real-byte proof. It is now reopened. This root agent has closed
    no feature Beads in the session; implementation and passing original acceptance remain separate (RH-7/RH-9).
12. No (checked: retained bridge acceptance and original descriptions of bd-uacs.1/.2/.3 and bd-qr40.7).
    No original requirement was edited down to match the implementation (RH-10).
13. Yes: GreenLotus self-closed graph hygiene, explicitly labeled self-verified. That is a PROCESS result,
    not an independently verified feature. Its source/runtime handoffs do not close root feature tasks.
14. No (checked: current fixture-repair and verify dispatches and prior detailed source handoffs). They name
    concrete positives, planted negatives and source-only/no-runtime boundaries; “make it green” is not their
    acceptance condition. This check does not certify every older external session's dispatch.
15. Yes: dependency consumer evidence comes from the isolated dependency agent and is labeled self-verified.
    Root read the patches/receipts but has not independently rerun every individual upgrade. Current main gates
    and independent original-acceptance review are still mandatory before feature closure (RH-2).
16. No (checked: agent deliverables and current tracker closes). No feature was closed on refusal-only tests;
    original archive import, genuine-memory admission and actual planner/apply positives are required.
17. No (checked: current execution notes and receipt interpretation). Shared-source agreement establishes
    implementation reachability, not independent runtime confirmation.
18. No (checked: reported consumer counts and frozen lock digest). Overlapping 602-test runs are not added as
    distinct tests, and no speedup, precision/recall or fleet-quality denominator was reported.
19. The moments requiring explanation are the wrapper/remote-state mistake, estimate-only budget claim,
    concurrent source changes, and the archive-path upload race. Each is disclosed and has a concrete next check;
    prior effort does not justify calling any of them successful.
20. The strongest observed evidence is the earlier seven real action tests and full sharing/report execution,
    plus the dependency agent's reproducible consumer logs. None proves the current final agent chain. The
    skeptic-reexecutable main acceptance commands and raw artifacts are the pending checklist above.

Cass health was ready, but six bounded project-workspace queries returned no indexed project sessions. Broader
hits were mostly skill catalogs; the inspected Grok fingerprint incident was unrelated. Missing coverage cannot
establish a clean past history. Countermeasures are source-only labels and original-acceptance closure (RH-2/RH-7),
retained stderr and failures (RH-16), frozen exact receipts rather than Git-head guesses, durable remote ownership,
and no gate suppression/bypass (RH-1/RH-13/RH-14). Corrections are recorded in place and disclosed; the still-pending
runtime checks cannot honestly be checked off in this disposition.

## Current assessment and execution checklist — 2026-10-04

**Evidence boundary:** source inspected at HEAD/tag `d06fa71` / v2.2.1, plus the shared working tree. The
assessment author read the full README, repository and suite AGENTS, the original 3,526-line alien-artifact plan,
all 11 `docs/PLAN*.md` mappings and all eight `specs/*.md`. Code inspection establishes reachable implementation,
not passing tests, successful actions, published-binary behavior, measured decision quality or fleet acceptance.
No Cargo, RCH, action execution or fleet command was run for this assessment. Nothing below closes a Bead.

The existing revision-2 assessment below is retained unchanged as another session's dated work, including its
reported hetzner1 and test results. Those execution claims were not independently reproduced by this assessor.
The September assessment remains in Git history at `HEAD:REALITY_CHECK_BRIDGE_PLAN.md`; the original WS0–WS9
requirements and their acceptance conditions remain binding. Historical failures are not current measurements.

**Current verdict:** core scoring, protection, identity checks, deep collection, learning and action dispatch have
real production callers. Nevertheless, the agent plan/apply file contracts disagree; unreadable safety evidence can
be treated as absent; sharing profiles do not sanitize bundle bytes; reports discard saved candidates and outcomes;
and calibrated quality remains unproven. Wiring advanced models before fixing these paths would not deliver the
project's safety-first process cleanup goal.

### Source, release and validation claims

- Source/tag v2.2.1 already enables `ui`, `report`, `daemon`; runs Linux deep evidence in agent planning; invokes
  `CompositeActionRunner` from apply; batches recent-I/O sampling; and makes MCP `pt_plan` invoke the real CLI
  engine. Older Bead descriptions saying these callers are missing require fresh verification, not reimplementation.
- Published release assets, installer behavior, Linux/macOS actions and fleet rollout need exact-artifact smoke
  evidence. A tag's source configuration is not that evidence. No artifact smoke result is asserted here.
- `agent plan` saves rich candidate JSON (`main.rs`, `run_agent_plan`); `agent apply` deserializes the same path as
  `plan::Plan`, which requires `plan_id`, `actions`, `gates_summary`. This mismatch was independently inspected in
  source. Another session reports a live reproduction; its execution is not credited to this assessment.
- `verify::PlanCandidate` expects `cmd_short`/`cmd_full`, while rich candidates save `command_short`/`command`.
  Canonical inventory identities and rich candidate `pid:start_time_unix` identities also differ. Resolve the shared
  contract; do not imply identity equivalence or successful respawn verification from parse success alone.
- Required code gates remain workspace check, clippy with `-D warnings`, formatting, lean check, appropriate Rust
  and BATS tests, and the named real probes in each Bead. No gate is waived by this plan or by interrupted validation.
- **Validation interruption, reported by root:** competing checkout/plan/Beads activity was traced to another Claude
  session sharing this workspace during the RCH source-reset interruption. The reset mechanism and causal chain are
  not proven. Do not attribute the reset to RCH or a person as established causation; preserve logs and establish the
  exact source tree before rerunning or citing affected results. This is a coordination/provenance blocker, not a
  compiler failure and not a successful gate run.

### Concrete vision checklist

`SOURCE` means a reachable implementation was inspected; `PARTIAL`, `BROKEN`, `STUB` and `UNPROVEN` describe the
remaining gap. None of these labels means independent end-to-end acceptance. README/plan commitments are the
measuring stick; draft specs with contradictory class counts or encryption formats need reconciliation, not blind
implementation of obsolete alternatives.

| Vision commitment | Current evidence and gap | Existing task coverage |
|---|---|---|
| V1 Ranked abandonment candidates | SOURCE: shared four-class `Scorer`; score is A+Z. Lifetime CPU and weak evidence still require labeled quality proof. | WS1 `bd-zi8p.*`; WS0 `bd-l3s5.*`; WS4 `.6` |
| V2 Confident, conservative kill recommendations | SOURCE: kill can win the loss matrix; no held-out calibrated precision, recall or false-kill guarantee established here. | WS1 `.1/.12`; WS0 `.5/.7`; WS6 `.6` |
| V3 Advanced models contribute when useful | DISCLOSED: many library modules have no production caller. Activation requires a measured win with the incumbent live. | WS7 `bd-t9qm.*`; ambition `bd-bjrh.*` |
| V4 Deep evidence and exact historical explanation | PARTIAL: agent plan calls deep collection; I/O uses lifetime counters and saved evidence is rounded. Exact historical ledger is not persisted. | WS4 `bd-u7gc.6`; `bd-h2y0`; `bd-uacs.10` |
| V5 Agent plan → apply → verify | WORKING in bounded Linux acceptance: one executable Plan, real adopted-orphan and respawner producer chains, generated-precheck and full-identity refusals, schema/BATS/demo and strict idempotent resume passed. Saved action-kind binding is a separate remaining defect. | `bd-uacs.1/.2/.17`; WS3 `.9` |
| V6 Advertised actions execute safely | SOURCE: composite dispatch; Restart still errors and planning considers it feasible. Shared cgroups are refused; dedicated-leaf positive capability needs proof. | WS3 `bd-qr40.4/.5/.6/.9` |
| V7 Identity-safe staged signals | SOURCE: identity and pidfd paths exist; platform/action/PID-reuse acceptance still requires real disposable probes. | WS3 `.9`; ambition `bd-bjrh.6` |
| V8 Protected infrastructure and caller chain | SOURCE: protection rules exist. Complete agent liveness, root workload visibility, PID-1-child handling and all-surface parity remain acceptance work. | WS2 `bd-toa2.*`; `bd-uacs.7/.8` |
| V9 Data-loss protection | PARTIAL: descriptor classification, typed unreadable supervision and required snapshot refusals have real positive/negative Linux coverage. Complete recent-I/O/lock failure semantics, all callers and platforms remain open. | `bd-28v9`; WS2 `.6`; `bd-aq9x`; WS3 `.9` |
| V10 Honest robot risk controls | PARTIAL: posterior constraints exist. Calibration, single-host conformal/eBH and full per-action enforcement are not established. | WS1 `.4`; WS7 `.1`; ambition `.5`; `bd-uacs.3/.9` |
| V11 Human decisions improve future priors | SOURCE: store and scorer consume human verdicts; outcome provenance, decay, pooling, label coverage and held-out improvement need acceptance. | WS6 `bd-codb.*`; `bd-uacs.5/.6` |
| V12 Interactive TUI in installed product | SOURCE/tag defaults include UI. Real artifact smoke, final safety parity and TUI labeling still need proof. | WS5 `bd-ufqb.1`; WS6 `.5`; `bd-uacs.8` |
| V13 Daemon monitors safely | SOURCE: daemon path exists; graded memory-pressure logic and service installation remain incomplete. | WS8 `bd-1y2g.5/.6`; proposed WS10 |
| V14 Fleet planning/apply | PARTIAL: SSH planning exists; apply explicitly reports unsupported and executes nothing remotely; dependency/guarantee claims need proof. | WS8 `bd-1y2g.*`; `bd-uacs.9` |
| V15 MCP uses the real planner | WORKING in bounded protocol acceptance: actual child planner and explicit configuration/PID refusal neighbors passed. Full same-snapshot parity with every surface remains open. | WS7 `bd-t9qm.7`; WS9; `bd-uacs.8` |
| V16 Sharing profiles remove sensitive data | WORKING in bounded Linux sharing acceptance: payload sanitization occurs before publication, Forensic signature import retains intentional secrets, Safe override removes them, and unchanged mandatory-secret consumers pass. Broader flag/platform acceptance remains open. | closed `bd-p2ks`; overlapping `bd-uacs.10` |
| V17 Reports expose recorded candidates/actions | WORKING for saved sessions/plain ZIPs: actual four-class candidates, canonical actions/outcomes, evidence/deep status and honest terminal/unknown history passed an independent 56-step observer. Exact historical ledger and broader flags remain open. | closed `bd-h2y0`; `bd-uacs.10`; WS4 `.6` |
| V18 Offline readable reports | WORKING in that bounded report acceptance: static escaped rows and evidence render without JavaScript; pre-render sharing-profile redaction and session/ZIP consistency passed. Remaining embed/asset flags and encrypted/platform acceptance are separate. | closed `bd-h2y0`; `bd-uacs.10`; WS9 |
| V19 Telemetry feeds calibration | DISCLOSED: Parquet recorder library is not a demonstrated live calibration input. Storage earns value only with a real consumer. | WS7 `bd-t9qm.9`; WS6 `.6` |
| V20 Bounded, safe collection | SOURCE: collection code exists; io_uring fault/sanitizer evidence and loaded-host budgets remain required. | WS4 `bd-u7gc.2/.3/.4/.5` |
| V21 Intent/workspace/GPU/container evidence | DISCLOSED/PARTIAL: multiple collectors remain library-only; robot safety and namespace semantics must survive integration. | WS7 `.10`; WS2 `.6` |
| V22 Bounded session storage | SOURCE: retention code exists; lifecycle coverage, in-use protection and backlog migration need cited acceptance. Deletion requires authorization. | WS5 `bd-ufqb.6/.7` |
| V23 Respawn-aware cleanup | PARTIAL: one execution-bound verifier/matcher passed a real respawner, plain orphan and owner/command/parent/birth neighbors; the genuine spawner is reported. Full tracking, supervisor-stop execution and broader remedies remain open. | WS7 `.2`; `bd-uacs.2/.17`; WS3 `.6` |
| V24 Resource-goal plans | PARTIAL: memory/CPU contributions exist; port/fd contributions are zero and goal/final-action agreement needs proof. | WS7 `.8`; WS1 `.11/.12` |
| V25 Incremental planning and current CPU rates | PARTIAL: `--since`/`--since-time` explicitly ignored; reopening a session rescans; tick-delta utility has no scoring caller. | WS4 `.6` and WS2 `.7` for shared sampling; proposed WS10; caching has no explicit original positive-capability task |
| V26 Cross-platform release, CI and truthful docs | UNPROVEN in this audit: platform/release gates and README command verification remain. Source or structure tests are insufficient. | WS5 `bd-ufqb.*`; WS9 `bd-75la.*`; acceptance `bd-1bi0`; dependencies `bd-souq` |

### Task inventory and work order

The audit began with **86 open/in-progress original tasks, including their epics**. They are all enumerated below.
Four additions from this operator session are `bd-souq`, `bd-28v9`, `bd-p2ks`, `bd-h2y0`. At the read-only graph
snapshot **2026-10-04 20:56 UTC**, another session had also added WS11 `bd-uacs` plus `.1`–`.14`, and WS10
`bd-p1o0`: **106 remaining entries, 86 open and 20 in progress**. Those totals are a dated snapshot, not a claim
about a graph another writer continues to change. Beads remain the source of task status and dependencies.

**Order:** safety and the broken agent handoff → labeled fixtures/invariants → privacy and useful reports → action
feasibility/current sampling/performance → calibration and measured models → deployment and release acceptance.
CI/dependency research and truthful docs can proceed in parallel when their file surfaces are isolated. Respect
existing dependency edges; a ready flag alone does not justify doing an easy peripheral task first.

Other-session `bd-uacs.10` overlaps `bd-h2y0` and the bundle integration in `bd-p2ks`. Coordinate ownership and
dependencies through the graph's writer; do not create a third report/export implementation. Its inventory/results
filename fix and our profile sanitizer belong on one production path. Keep unavailable exact ledgers honest while
adding persistence; old sessions must not be recalculated using a new configuration. The broader WS10 proposal is
retained below, but no new pressure-remediation feature is approved as complete by merely adding it to this plan.

### Granular TODO: original workstreams and current additions

Unchecked items retain their original acceptance conditions. Source already present means verify those conditions;
it does not mean recreate the implementation or close a task from this checklist. Each claimed completion must cite
the reachable caller, exact revision/tree, appropriate tests, negative cases and the task's named real probe.

**WS2/WS3 immediate safety; executable agent handoff**

- [ ] `bd-28v9`: distinguish regular writable/read-only/deleted files from FIFO/socket/device descriptors; inspect
  descriptor metadata and flags completely; preserve unreadable as unknown/block. Exercise a real writer, permitted
  FIFO/no-write process and failed inspection. Preserve the full configured recent-I/O window.
- [ ] `bd-toa2.6`: inventory required supervision/intent/data-loss evidence across plan/apply/TUI/MCP/daemon;
  make unreadable recent-I/O before/after samples, `/proc/locks` and other required reads refuse robot action with a
  reason. Do not convert an inaccessible process into a safe zero. Verify with an unprivileged real probe.
- [ ] `bd-toa2.9`: prove self/invoker/ancestor protection while a hung sibling remains eligible; repeat via MCP and
  nested terminal sessions without extending protection indiscriminately to descendants.
- [ ] `bd-toa2.1`: prove structural multiplexer/SSH/session/dashboard protection and deliberate overrides; retain
  stale-client eligibility. Test live ControlMasters and the built-in infrastructure rules.
- [ ] `bd-toa2.3`: complete argv/env agent-kind and session-file mapping, including hosted variants; prove negative
  arbitrary node/bun cases; compare detected kinds with recorded/live ground truth.
- [ ] `bd-toa2.7`: reuse a shared sampling window for TTY/child progress and session mtime; distinguish a waiting
  live agent, a dead detached agent and its genuinely hung child; preserve hung-child recall.
- [ ] `bd-toa2.4`: prove UID/unit-based root system protection and root workload visibility; profile precedence,
  selected reason and worker detection must be observable; run read-only worker probes.
- [ ] `bd-toa2.5`: prove PID 1 remains protected while user PID-1 children are evaluated and real services remain
  protected; validate policy migration and zombie-parent eligibility.
- [ ] `bd-toa2` epic: close only when the preceding original protection tasks and their acceptance probes are met.
- [x] Other-session `bd-uacs.1/.2`: reconcile saved planning, executable targets and verification; chain production
  plan → apply → verify on disposable processes, without hand-built executable plans. Resolve command/identity
  field drift and verify only outcomes actually attempted; retain protected-parent routing.

**WS0/WS1 measured foundations and consistent decisions**

- [ ] `bd-l3s5.1`: finish redacted replay format, capture tool and injection seam into the real planner; include
  protected processes and negative targets so filtering/truncation cannot remove the denominator.
- [ ] `bd-l3s5.2`: capture/label dev-host live infrastructure, stuck tests and fresh compilers with provenance.
- [ ] `bd-l3s5.3`: capture/label root worker workloads and macOS launchd/app cases; record unavailable hosts honestly.
- [ ] `bd-l3s5.5`: replay through the production decision path; compute KILL/REVIEW precision@k, must-not-flag
  violations, kill recall, zombie routing and latency; retain held-out host splits and the initial loss baseline.
- [ ] `bd-l3s5.7`: tighten the ratchet into the required hard assertions after prerequisites land; demonstrate a
  planted regression fails; never exclude failing fixtures or lower recall to obtain a green result.
- [ ] `bd-l3s5` epic: confirm capture → replay → metrics → CI is one consumed path, not disconnected utilities.
- [ ] `bd-zi8p.1`: verify reachable kill and tie-breaking while retaining high useful-kill loss; cite default-policy
  behavior and real idle-orphan evidence rather than lowering safety cost.
- [ ] `bd-zi8p.2`: verify score is `100 × P(abandoned or zombie)` and distinguish model belief from calibration.
- [ ] `bd-zi8p.3`: prove sorting/bands/MCP/TUI/explain/watch/narrative agree on score semantics for one snapshot.
- [ ] `bd-zi8p.4`: prove robot posterior constraints use the action's intended event and reject useful-majority kills.
- [ ] `bd-zi8p.5`: verify default policy age across every promised surface and explain explicit overrides.
- [ ] `bd-zi8p.7`: verify one orphan term, correct init/subreaper semantics and no contradictory supervised credit;
  coordinate other-session `bd-uacs.4` instead of duplicating its lineage change.
- [ ] `bd-zi8p.9`: verify zombies never receive direct kill/renice/pause; parent/supervisor action must preserve
  identity, service protection and explicit human review when the parent is protected.
- [ ] `bd-zi8p.10`: audit remaining output claims: RSS-threshold blast radius, queue “rates,” intervals, entropy,
  trajectories and fleet risk; compute from observations or report unknown, never synthesize measured guarantees.
- [ ] `bd-zi8p.11`: check goal selection against the final post-policy/post-tree-safety candidate actions and ensure
  compact saved artifacts do not retain an earlier contradictory recommendation.
- [ ] `bd-zi8p.12`: run meaningful production-function properties/metamorphic cases, deterministic seeds and the
  required mutation failure; cover useful-majority scores, neutral terms, orphan duplication, candidate ordering,
  goal agreement and zombie feasibility.
- [ ] `bd-zi8p` epic: complete the original decision acceptance evidence; source implementations alone are partial.

**Privacy and reporting: positive user-facing integration**

- [x] `bd-p2ks`: apply one existing redaction engine/profile policy before archive bytes, checksums or output;
  preserve numeric/structural evidence, consistent pseudonyms and explicit forensic behavior. Minimal omits detailed
  process artifacts. Malformed/unknown/opaque sharing content must not bypass sanitization.
- [x] `bd-p2ks` tests: plant hostname/home-path/credential/command canaries in a real saved session; invoke actual
  bundle create and verify/extract the ZIP, including encrypted and in-memory paths. The current BATS safe/minimal
  tests synthesize already-clean ZIPs and therefore do not establish production export privacy.
- [x] `bd-h2y0` recorded-report scope: implement one session/bundle adapter for saved candidates and
  outcomes. Prefer final rich-plan recommendations; load checksum envelopes deliberately; join outcomes by action ID.
- [x] Report rows: retain all four classes, known age/CPU/RSS and actual action verbs; represent unrecorded I/O,
  timestamps and recovery as unknown. Do not map useful-bad into “uncertain” or expected RSS into measured recovery.
- [ ] Report ledger: persist exact scorer ledger/likelihood/prior data in the existing inference artifact; display
  it only when recorded. Label A-versus-U Bayes factors correctly and exclude the prior term from evidence Log BF.
  Rounded integer contributions cannot prove an exact historical ledger.
- [x] Report safety/usability: redact visible and embedded JSON fields; escape HTML/script context; render a static
  candidate table without CDN JavaScript. Remove canned success/prose and unrelated default mathematics.
- [x] Report tests in the accepted Linux saved-session/plain-ZIP scope: invoke actual session and bundle report paths with a known candidate/action, planted secrets,
  markup, missing old-session ledger and corrupted data. Assert displayed final action/score and truthful omissions.
- [ ] Bundle contents/flags: coordinate `bd-uacs.10` actual `scan/inventory.json` and `inference/results.json`
  filenames, shared CLI report flags and README layout; verify round-trip checksums without weakening reader tests.

**WS3/WS4 action capability, current rates and performance**

- [ ] `bd-qr40.4`: prove dedicated leaf cgroups or conservative shared-group refusal; capture/restore previous
  state and verify a sibling remains unaffected for freeze/throttle/quarantine and reversal.
- [ ] `bd-qr40.5`: verify the already-reachable composite runner and truthful platform feasibility before planning;
  execute each supported action and observe its real effect.
- [ ] `bd-qr40.6`: wire supervisor restart or remove it from feasible recommendations before planning; exercise
  a disposable transient user service and prove an unsupervised process never receives Restart.
- [ ] `bd-qr40.9`: exercise the production chain for staged kill, pause/resume, renice, cgroups, supervisor actions,
  identity/PID-reuse refusal, writable-file gates and accumulating budgets on disposable targets and both platforms.
- [ ] `bd-qr40` epic: retain every original action acceptance condition; unsupported output alone is not completion.
- [ ] `bd-aq9x`: verify shared recent-I/O sampling preserves the entire policy window and safety for multiple
  targets; inspect the TUI executor path too. Do not shorten the window to claim a speed improvement.
- [ ] `bd-u7gc.2`: exercise timeout/cancel/drain under sanitizer/equivalent fault injection; prove no in-flight
  buffer lifetime error or dropped timeout/probe coverage and add the named CI job.
- [ ] `bd-u7gc.3`: verify one shared network snapshot and one reused fd walk per PID on actual callers; profile
  repeated supervision/provenance parsing as well; compare against the live incumbent in the same invocation.
- [ ] `bd-u7gc.4`: finish identity/user/ancestor caches and remove remaining multiplicative loops with preserved
  safety/error semantics; validate loaded-host behavior.
- [ ] `bd-u7gc.6`: replace lifetime I/O activity with identity-bound two-sample rates; reuse tick sampling for
  current CPU/TTY/child evidence; report missing samples and actual per-signal coverage. Keep uncalibrated queue
  heuristics labeled as such until measured rates and validation exist.
- [ ] `bd-u7gc.5`: run the 2,000-process/50,000-socket/load-500 budget with completeness and safety countermetrics;
  report a loss directly rather than weakening the budget or comparing only against the new implementation itself.
- [ ] `bd-u7gc` epic: finish collection correctness and loaded-host proof, not just quiet-host elapsed time.
- [ ] Incremental/cache promise: after the shared sampling/fixture foundation, reconcile `--since`/`--since-time`
  and session reuse with a real identity-aware consumer. Use the graph writer to assign existing/proposed ownership;
  no new duplicate task is created by this checklist.

**WS6/WS7 and ambition: labels before mathematical guarantees**

- [ ] `bd-codb.1`: prove human verdict/outcome recording, three-level keys and concurrent-writer persistence on
  the intended surfaces; retain label provenance and prevent robot predictions training on themselves.
- [ ] `bd-codb.3`: verify specificity, partial pooling, decay and influence caps; explain the learned term and
  compare held-out quality. Coordinate other-session `bd-uacs.5` decay/broad-key/TUI-label defects.
- [ ] `bd-codb.4`: collect trajectories and later outcomes on the required hosts/duration; distinguish weak,
  strong and unknown labels. Coordinate `bd-uacs.6`; a vanished PID alone does not prove abandonment or normal exit.
- [ ] `bd-codb.5`: exercise deliberate TUI labeling and persistence; distinguish confirmation of a preselection
  from an independent human label.
- [ ] `bd-codb.6`: feed real WS0/store/shadow labels into existing calibration code; produce reliability/ECE and
  versioned refit priors, with held-out log-loss versus the incumbent in one invocation or an explicit reported loss.
- [ ] `bd-codb` epic: close the consumed label → prior → inference → calibration loop with provenance.
- [ ] `bd-t9qm.4`: establish incumbent/candidate held-out ablation and safety countermetrics before model wiring.
- [ ] `bd-t9qm.1` and `bd-bjrh.5`: preserve the refusal-until-calibrated requirement; prove category calibration,
  valid selection inputs and coverage/FDR under the stated assumptions. Coordinate `bd-uacs.9` fleet guarantees.
- [ ] `bd-t9qm.2`: use the respawn tracker through apply/verify and identify the real supervisor; recommend its
  stop when justified instead of repeatedly targeting replacements.
- [ ] `bd-t9qm.3`: output the real transitive blast-radius estimate; test dependents and graph completeness.
- [ ] `bd-t9qm.5`: ablate BOCPD on real CPU/I/O trajectories; wire only if it wins without raising false positives.
- [ ] `bd-t9qm.6`: apply the same measured rule to Hawkes/idle hazard; an honest loss leaves it experimental.
- [ ] `bd-t9qm.7`: prove MCP/CLI same-snapshot parity and tool-list truth for the existing subprocess route.
- [ ] `bd-t9qm.8`: implement real port/fd contributions and free-port grammar; exercise a real listener and enforce
  final-action/goal agreement.
- [ ] `bd-t9qm.9`: wire telemetry only with a real calibration reader, or retain the qualified library-only claim.
- [ ] `bd-t9qm.10`: ablate intent/workspace/GPU signals; keep unreadable robot safety and container identity/namespace
  semantics conservative; unavailable GPU hardware is an explicit limitation.
- [ ] `bd-bjrh.1`: validate consumer liveness with real producer/consumer death and progress, then held-out ablation.
- [ ] `bd-bjrh.2`: fit right-censored survival from trajectories; avoid counting lifetime and hazard twice.
- [ ] `bd-bjrh.3`: validate signature/host-role shrinkage against held-out hosts, preserving bounded influence.
- [ ] `bd-bjrh.4`: validate anytime idleness assumptions, null simulations and daemon behavior before claims.
- [ ] `bd-bjrh.6`: hold plan-time pidfds where live modes permit it and prove PID reuse cannot redirect action.
- [ ] `bd-bjrh.7`: enable stacking/BMA only on a measured held-out win; expose actual learned weights.
- [ ] `bd-t9qm` and `bd-bjrh` epics: retain experimental results and losses; module tests alone never close runtime
  integration or measured-benefit requirements.

**WS5/WS8/WS9 dependencies, deployment and final acceptance**

- [ ] `bd-souq`: inventory every eligible direct registry dependency; research current stable upstream changes;
  update one dependency, migrate its real consumers and run affected checks before the next. Preserve path/git/
  prerelease dependencies and record justified exceptions in the requested upgrade log. Respect the invoked
  library-updater approval requirement for migrations touching more than ten source files; finish full gates/audit.
- [ ] `bd-ufqb.9`: make root and non-root precheck tests assert correct positive/negative outcomes; no ignore.
- [ ] `bd-ufqb.10`: fix BATS quoting/link/BSD helpers; review semantic fixture equality before any manifest update;
  run both platforms and justify remaining skips.
- [ ] `bd-ufqb.11`: finish stable dependency/toolchain/workflow repairs; prove a real green main CI run, with
  detected-capability reasons for legitimate unavailable infrastructure rather than silent skips.
- [ ] `bd-ufqb.4`: enumerate unavailable command paths and verify nonzero truthful outcomes; refusal does not
  close separate positive-capability tasks.
- [ ] `bd-ufqb.6`: verify retention across old Planned/Scanning sessions, bounded runtime and in-use locks.
- [ ] `bd-ufqb.7`: prepare backlog dry-run counts/bytes; obtain the required explicit deletion authorization
  before migration and retain before/after evidence. This plan does not authorize deleting sessions.
- [ ] `bd-ufqb.1`: smoke exact installed Linux/macOS/musl artifacts for TUI/report/daemon and justify measured
  size budgets; defaults in source are already present and do not substitute for artifact acceptance.
- [ ] `bd-ufqb.12`: check and roll out the same tested version across the required 20 hosts with observable
  version/identity facts; distinguish rollout from read-only audit.
- [ ] `bd-ufqb` epic: prove installer/release/gates/retention complete as a delivered product.
- [ ] `bd-1y2g.1`: finish SSH-group inventory/profile mapping and per-host versions; optional installs follow
  the task's explicit confirmation requirements.
- [ ] `bd-1y2g.2`: align fleet CLI/docs/FDR flags and run the documented planning examples on the required hosts.
- [ ] `bd-1y2g.3`: implement confirmed remote apply with remote identity/prechecks/caps; test only targets the
  suite spawned on test hosts. Existing planned-action output is not remote execution.
- [ ] `bd-1y2g.4`: exercise ControlMaster/worker dependencies in both directions or retain qualified claims.
- [ ] `bd-1y2g.5`: prove safe-default user-service install/uninstall on Linux and macOS.
- [ ] `bd-1y2g.6`: wire measured memory-pressure escalation/notifications through daemon ticks; exercise a
  controlled cgroup hog and preserve recommend/dry-run defaults; coordinate proposed WS10.
- [ ] `bd-1y2g` epic: finish the real fleet/service story and its multi-host evidence.
- [ ] `bd-75la.1`: map each README claim to observed source/acceptance or an explicit limitation; do not claim
  measured guarantees from posterior confidence or library tests.
- [ ] `bd-75la.2`: align fleet/MCP/daemon/TUI/platform availability and config paths with tested artifacts.
- [ ] `bd-75la.3`: make tutorial list/content/verification commands real; coordinate `bd-uacs.13` and wrapper
  fixes `bd-uacs.12`, rather than adding overlapping tutorial tasks.
- [ ] `bd-75la.4`: check CLI specification against actual help and reconcile stale draft contracts.
- [ ] `bd-75la.5`: correct AGENTS defaults from code, including actual default features, age, retention/profile
  values and the absent suite sections referenced by the project file; do not invent missing law.
- [ ] `bd-75la.6`: execute sandboxed documented commands through CI; retain small, justified host/action exclusions
  and fail on stub-success or false examples.
- [ ] `bd-75la` epic: keep docs truthful as work lands, without using spec edits as capability credit.
- [ ] `bd-1bi0`: rerun the original release/fleet acceptance on exact versions after prerequisites; cite the real
  20-host probe, no false positives, correct routes, useful kill recall and unchanged performance requirements.

### Evidence-based ambition and refinement disposition

Ambition pass 1: inspect finished libraries for cheap existing callers. This found the report adapter, redaction
engine, composite runner and shared sampling paths; only actual missing integration is prioritized. Pass 2:
inspect observable harm and missing evidence. This found raw sharing bytes, disconnected privacy tests, unreadable
safety evidence and planning contract drift; safety/fixtures/privacy now precede optional sophistication. Pass 3:
retain consumer-liveness, survival and pressure proposals behind the existing ablation and safety requirements.
No claim that a proposed model improves quality follows from its mathematical name.

Refinement checks: (1) every original remaining task is accounted for; (2) known duplicate report ownership is
flagged instead of multiplied; (3) positive and planted-negative production probes replace skeleton/synthesized
proof; (4) dependencies put labels before calibration/guarantees and privacy before richer sharing; (5) source,
historical results, interrupted gates and independently executed evidence stay distinct. These are bounded
inspection passes, not five completed implementation/test rounds. Remaining outcomes are open until observed.

### Filled anti-ceremony audit for this plan update

- **Consumer/gate/retirement:** the operator explicitly requested the detailed TODO and in-place assessment; the
  next implementer/reviewer uses it to select and review real changes. The evidence gate forbids claiming closure
  without the named production path and acceptance probe. Retire individual checklist entries when their Beads close
  on cited evidence; stop maintaining this snapshot when the graph fully carries its useful detail. Historical
  material remains provenance; deletion still requires permission.
- **Capability credit:** this markdown is planning/audit work and earns zero runtime capability credit. No test,
  gate, golden, policy or product file was edited by this update; no task was closed or dependency changed.
- **Honesty:** no unrun test/fleet action is called successful. Existing other-session claims are preserved and
  labeled rather than promoted to independent evidence. Source inspection found real gaps, including a contract
  mismatch absent from the earlier concise report; it is now included here.
- **Proof quality:** generated clean ZIPs and HTML skeleton assertions cannot prove sharing privacy/content.
  Agreement between agents sharing the same source counts once. A refusal-only fix remains less than positive
  capability, and unresolved acceptance work stays open.
- **Disposition:** proceed with bounded product implementation and required verification; no new certificates,
  scoreboards, duplicate Beads or unrelated process artifacts. Save the requested diff outside the repository.

---

## Retained prior-session revision 2 — execution claims not independently reproduced above

**Revision 2 — 2026-10-04** · HEAD `d06fa71` · shipped v2.2.1 · supersedes revision 1 (2026-09-24, HEAD `e24ee78`, v2.1.0).
Revised in place per the `reality-check-for-project` workflow (Phase 1 reality check → Phase 2 bridge plan →
Phase 4 ambition). Every bead created from this revision carries its own copy of the relevant context, so this file
never needs to be consulted to implement a bead. Revision 2 adds **WS10 (pressure-aware remediation: bringing the
`system-performance-remediation` playbook into pt as deterministic code, no LLM calls)** and **WS11 (revision-2 P0
defects)**, and re-grades every revision-1 item against the code as it stands today.

How revision 2 was produced: README.md, AGENTS.md (repo + suite), the alien-artifact plan, docs/DORMANT_DAEMON_SPEC.md
and the full `system-performance-remediation` skill (SKILL.md + 9 references + `diagnose-system.sh`) were read; four
independent code audits produced file:line evidence for every claim; the installed v2.2.1 was exercised read-only on
hetzner1 (8 cores, 30 GB, ~12 live agent CLIs, load 4–5); the plan→apply handoff was reproduced safely; fmt, clippy
and the workspace tests were run through rch. A fleet-wide sweep was **not** repeated (fleet hosts do not resolve from
hetzner1); revision 1's 20-host table remains the newest multi-host data.

---

## 1. Verdict (brutally honest)

**A lot of the "stop being wrong" layer was fixed in ten days, and the README now discloses honestly what is
library-only. But the documented agent workflow is broken in the shipped release, and pt still has no model of the
machine, only of individual processes, so it cannot do the job its own origin story describes.**

1. **The headline agent workflow does not work (P0, new).** `pt agent plan` writes a report-shaped
   `decision/plan.json` (`main.rs:13025-13091`); `pt agent apply` parses that file strictly as `plan::Plan`
   (`main.rs:14106-14112`, `plan/mod.rs:61-72`), which requires `plan_id`, `actions`, `gates_summary`, … Reproduced on
   the installed v2.2.1: `pt-core agent apply --session pt-20261004-203004-w75q` → `agent apply: invalid plan.json:
   missing field 'plan_id'`. Only TUI-written plans (`main.rs:2276`) can be applied. All seven `agent_apply_*` tests
   construct `Plan` by hand and `tests/e2e_workflow.rs` says "(skip apply)", so ~7 000 tests never chained the two
   commands. `agent verify` in turn expects `cmd_short/cmd_full` (`verify.rs:21-31`) while plan writes
   `command/command_short` (`main.rs:12560-12561`), so respawn checks always see an empty command.
2. **pt has no model of system state, so it cannot restore a sluggish machine.** README *Origins*: "23 stuck
   `bun test` workers and a 31 GB Hyprland instance brought a 64-core workstation to its knees." That is a *pressure*
   incident. Faced with it today pt would (correctly) protect the compositor, would rank the bun workers only if older
   than 1 h and idle by **lifetime-average** CPU (`ps %cpu`, `quick_scan.rs:351-358`), and would have no idea the
   machine is in trouble, who is causing the stall *now*, or whether its actions helped. Specifically:
   * the only system signals read are load, core count, MemTotal/MemAvailable, Swap totals and PSI `some avg10`
     (`main.rs:11029-11150`); PSI appears only in `agent snapshot`; no `full` line, avg60/avg300, vmstat, slab, vm
     sysctls, file-nr, cgroup `*.pressure`, `memory.current`, oomd configuration;
   * `useful_bad` (alive but hogging) **always gets `keep`**: `L(keep|useful_bad) = 0` (`pt-config/src/policy.rs:133-140`),
     and the only pressure hook (`load_aware`, off by default, `policy.rs:483-486`) *multiplies* that 0 (`load_aware.rs:141`);
     README L358/L1087 promise "throttle, review";
   * the gentle levers the playbook relies on are missing or ineffective: no ionice/ioprio, no `cpu.weight`/`cpu.idle`/
     `memory.high`, renice touches one thread and stops at nice 10 (`action/renice.rs:16`), and cgroup actions refuse any
     shared cgroup (`action/dispatch.rs:60-104`);
   * the daemon triggers on **absolute** load 4.0 (`daemon/triggers.rs:39`) and on "processes with ppid==1"
     (`main.rs:9920-9958`: 43 on idle hetzner1 vs a default threshold of 20), ignores which trigger fired
     (`_triggers`, `main.rs:9778`) and never reads PSI;
   * apply's before/after snapshot has no settle window and no load/PSI (`main.rs:13994-14007`); verify reports
     *expected* MB freed, not measured (`verify.rs:268`).
3. **The learning loop is still open.** Human verdicts are wired (`decision_store.rs`, plan/explain/TUI/MCP read them),
   but: shadow mode labels **every** resolved observation "not abandoned" (a vanished process maps to `NormalExit`,
   `calibrate/validation.rs:750-790`), calibration scores a different quantity than the displayed score
   (`validation.rs:383` vs `shadow.rs:103`), decay resets whenever any label is added (`decision_store.rs:154-161, 303`),
   one TUI kill of `node x.js` raises every unlabeled `node` to P≈0.5 through the broad key, and the TUI records its own
   pre-selected kills as human verdicts. The WS0 fixture-replay false-positive corpus still does not exist.
4. **Process debt.** CI: all 8 workflows `disabled_manually` since 2026-08-12; v2.2.0/v2.2.1 were built and uploaded
   locally (signed). 70 open beads; 16 `in_progress` beads untouched since 2026-09-24/26 although several are done in
   code. ~18 README statements drifted (HTML report is overview-only and exits 0; bundles never contain the snapshot or
   inference; tutorial commands use a non-existent `--pid` flag; `pt learn verify` only runs `--help`).

### 1.1 Fixed since revision 1 (verified at `d06fa71`)

| Rev-1 finding | Now | Evidence / remaining caveat |
|---|---|---|
| Kill unreachable (loss tie) | **Fixed** | `abandoned.kill=0.1` vs pause 3.5 (`policy.rs:122-159`); kill wins iff ≈ P(useful) < 0.68 % (b=z=0). `paranoid` preset still makes kill unreachable. |
| Score = max-class | **Fixed** on plan/TUI/explain/MCP/snapshot | `agent watch` still `max(ab,zb)` (`main.rs:17591`); narrative output calls the score "Confidence". |
| Robot gate on max-class | **Fixed** | `gate_posterior` (`robot_constraints.rs:744-753`); CLI `--min-posterior` can *loosen* policy (`:150-158`). |
| No default min-age | **Fixed** (3600 s) | MCP `pt_scan` and `agent apply` do not enforce it. |
| ps `etimes` trusted (47 721-day ages) | **Fixed** on Linux | `/proc/<pid>/stat` starttime + btime (`quick_scan.rs:419-463`). |
| Live infra rated abandoned (agents, mux, ControlMasters, db/web workers, login shells, monitors) | **Fixed** | Built-in rules + cgroup roles; hetzner1: 193/213 filtered by 9 rules (ssh_control_master 44, session_infra 49, cgroup:UserService 42, …). `pi`, `am` agent CLIs unrecognized. |
| Root blinds workers | **Mostly fixed** | Root in session/transient scopes is a candidate; root with *Unknown* cgroup role still protected; macOS root always protected. |
| Orphan double count | **Fixed**, but a new contradiction | Real Linux orphans now get `provenance_ownership_supervised` (+0.60 useful/−0.70 abandoned) because `classify_ownership` maps `ppid==1` with an ancestor chain to `InitChild` (`lineage_evidence.rs:278-289`, `scoring.rs:661-671`). |
| Zombies renice/kill | **Fixed** in plan; route advisory | TUI/watch/snapshot use `allow_all()` feasibility; `parent_identity` is never `Some`, so the ZombieToParent route is unreachable from the TUI. |
| Fake fields | **Mostly fixed** | Plan JSON `blast_radius.risk_level` is still "medium if RSS>1 GiB" (`main.rs:12600-12605`) although the real provenance estimate exists. |
| apply = signals only | **Fixed** | renice/pause/freeze/throttle/quarantine dispatch; restart only zombie→parent (README L155/L958 now *understate* this). |
| Identity / PID reuse | **Fixed** | pidfd for every signal on Linux; exact start ticks. |
| macOS: nothing executes | **Fixed** | kill/pause/resume/renice + session safety; but `never_kill_ppid:[1]` turns every macOS orphan into review (`enforcer.rs:539-551`). |
| io_uring UAF / SQ overflow / lost timeout | **Fixed** | Chunking, generation tags, cancel-and-leak; one inferred hang (late completion satisfies the new timeout count, `prober.rs:206-249`). |
| Release built without features | **Fixed** | `default = ["ui","report","daemon"]`; v2.2.1 asset sha256 = installed binary. |
| Session backlog (ts1: 3 017) | **Fixed** | Hourly auto-GC honoring `PROCESS_TRIAGE_RETENTION` (`session/mod.rs:418-751`). |
| Learning unwired | **Wired** (defects §1 item 3) | `pt agent label`, TUI kills → `decisions.json` → learned prior in every surface. |
| fmt / clippy red | **Green** (Linux, rch) | `cargo fmt --check` ✓, `cargo clippy --workspace --all-targets -- -D warnings` ✓. |
| Workspace tests | see §1.3 | |

### 1.2 Live evidence (hetzner1, installed v2.2.1, 2026-10-04)

* `pt-core agent plan` (default): 213 scanned · 193 protected · 20 younger than 1 h · **0 candidates** · 75 ms wall.
  Correct for a healthy agent box (PSI cpu some avg10 = 2.7 %).
* `--min-age 0`: 54 evaluated, 7 above threshold, all children of live agents. Top: `rch exec -- cargo build`
  (265 s old, the build runs *remotely*, local CPU ≈ 1 %) at **P(abandoned)=0.85, score 91**; evidence: signature
  prior +2.0 bits ("cargo-build: likely abandoned"), no TTY +1.1, low CPU +1.0; VoI rationale "Act now: Pause";
  saved only by the `agent_descendant` tree cap. Root causes: (a) `ProcessExpectations`
  (`typical_lifetime_seconds: 300`, `max_normal_lifetime_seconds: 3600`, `cpu_during_run`, `idle_cpu_normal`, …,
  `supervision/signature.rs:152-215`) are defined for every built-in signature **and read by nothing**, so a
  4-minute-old build gets the "abandoned if old" prior; (b) proxy processes (`rch exec`, `ssh`, `timeout`, `env`
  wrappers) are judged by their own CPU instead of the liveness of their child/remote work.
* `pt-core agent snapshot`: `system_state = {load, cores, memory{total,used,available}, process_count, psi{cpu,memory,io}}`
  (some-avg10 only; missing PSI files read as 0.0, `main.rs:11146-11148`).
* `pt-core agent apply --session <agent-plan session>` → `invalid plan.json: missing field 'plan_id'` (WS11.1).
* Host facts that shape WS10 (all read without privileges):
  * Every agent CLI runs in **its own transient scope with all its descendants**
    (`…/user@1000.service/app.slice/run-p<PID>-i<N>.scope`); the memory controller is enabled there and the files are
    owned by the user, so per-agent `memory.current`, `memory.peak`, `memory.pressure`, `memory.high`, `cpu.stat`,
    `cgroup.freeze` and `cgroup.kill` are available **today, without root**. The cgroup tree *is* the
    "responsible root" decomposition the playbook reconstructs with `ps | grep`.
  * The CPU controller is delegated to `user@1000.service` but **not** below `app.slice` (`subtree_control: memory pids`),
    and `sched_autogroup_enabled=1` (autogroup is ignored for tasks outside the root task group). Which scheduling knob
    actually moves CPU share (nice vs `cpu.weight` vs `cpu.idle`) therefore depends on topology and must be computed and
    then *measured*, not assumed.
  * Block scheduler `[none]` on `sda` → **ionice is a no-op here** (ioprio is honored by BFQ only). The playbook's
    `ionice -c3` advice is ineffective on such hosts; pt must detect lever efficacy.
  * VM tuning already follows the playbook (vfs_cache_pressure 200, min_free 512 MB, swappiness 10, zram 16 GB at
    prio 100 + 16 GB swapfile); systemd-oomd **inactive**; Slab 6.7 GB (5.9 GB reclaimable) of 30 GB.

### 1.3 Quality gates at HEAD

* `cargo fmt --check` ✓ · `cargo clippy --workspace --all-targets -- -D warnings` ✓ (Linux, rch).
* `cargo test --workspace` (rch): see the "Test run" note at the end of this section.
* CI: all 8 workflows `disabled_manually`; last runs 2026-08-11/12 red (nightly `cargo-fmt` component missing,
  ShellCheck on generated completions, `cpuset_quarantine` reversal test, BATS docs/learn tests, `update-packages.yml`
  invalid). Releases v2.2.0/v2.2.1 built and uploaded locally (signed, pinned key).
* Test blind spots: no plan→apply→verify chain; HTML report tests assert only the skeleton; no fixture-replay corpus
  (bd-l3s5.1/.2/.3/.5/.7 open); the live fleet gate (`scripts/fleet_reality_e2e.py`) is manual; fuzz targets never run.

Test run (`cargo test --workspace --no-fail-fast` via rch, worker vmi1227854, tests running as root, 2026-10-04):
**6 835 passed / 11 failed / 25 ignored across 138 test binaries** (exit 101). The failures fall into four classes,
each now tracked:
* `agent_apply_dry_run_returns_actions_ok`, `agent_apply_executes_renice_then_kill_on_live_process` —
  `blocked_by_prechecks` for the spawned target (environment-sensitive live prechecks) → WS11.10a (`bd-uacs.11`).
* `e2e_plan.rs`: `plan_blast_radius_counts_real_children`, `plan_blocks_kill_of_open_writer`,
  `plan_deep_adds_network_evidence`, `plan_identifies_agent_cli_kind`, `plan_keeps_agent_with_active_terminal`,
  `plan_goal_never_puts_non_kill_candidates_in_kill_set` — `agent plan` produced no stdout / was interrupted by the
  test timeout; the event stream stops after `inference_progress`. The same command takes 0.34 s non-root on
  hetzner1. Suspect: per-candidate `/proc/net/unix` re-parse in supervision detection, explosive as root on a busy
  build worker → WS11.12 (`bd-uacs.15`).
* `protected_patterns::policy_protected_users_enforced` — expectation predates the root-in-session exemption → WS11.10a.
* `performance_tests::test_database_load_under_3000ms`, `test_pattern_library_load_performance` — wall-clock
  budgets on a shared, loaded worker (flaky by construction; budgets belong in criterion/bench jobs, WS10.16d).

---

## 2. Vision checklist (revision 2)

Status vocabulary: WORKING · PARTIAL · STUB · UNPROVEN · NOT_STARTED · REGRESSED/BROKEN · NO_BEAD · WRONG_APPROACH ·
DISCLOSED (library-only and the README says so).

| # | Goal (source) | Status | Evidence / gap | Beads |
|---|---|---|---|---|
| V1 | Finds abandoned processes, ranked (README L17) | PARTIAL | Correct score + protection; evidence is lifetime averages; signature expectations unused; orphan↔supervised contradiction; proxy processes misjudged | WS10.3, WS10.8, WS11.4 |
| V2 | Kill recommendations with confidence | UNPROVEN | Reachable; calibration absent; no corpus | WS0, WS6 |
| V3 | Experimental models | DISCLOSED | ~35 modules library-only; README honest | WS7 |
| V4 | Evidence ledger + deep evidence | PARTIAL | `--deep` feeds net/io/queue, but `io_active` = lifetime bytes>0, `net_active` = any socket | bd-u7gc.6, WS10.3 |
| V5 | 8 actions executable | REGRESSED for agents | Executable via TUI only; **agent plan→apply broken**; shared-cgroup refusal makes freeze/throttle/quarantine unavailable for most dev processes | WS11.1, bd-qr40.4, WS10.5 |
| V6 | Identity-safe staged kill | WORKING | pidfd; global 5 s grace; no per-signature grace / SIGTERM-ignorer knowledge | WS10.7 |
| V7 | Protection before scoring | WORKING | `pi`/`am` missing; env inheritance marks whole agent trees "human-supervised"; macOS orphans always review | bd-toa2.3, WS11.6 |
| V8 | Provenance blast radius | PARTIAL | Plan JSON risk level is an RSS heuristic | bd-t9qm.3 |
| V9 | Robot guardrails | PARTIAL/BROKEN | Persistent kill rate limiter never records kills (`enforcer.rs:1157`); apply bypasses enforcer; robot gates block even Keep in `--robot` plans | WS11.3 |
| V10 | Learns from decisions | PARTIAL | Wired; decay/generalization/self-reinforcement defects | WS11.5 |
| V11 | Interactive TUI | PARTIAL | Shipped; lacks plan-only safety steps (agent force-review, tree safety); 60 s data-loss probe per kill | WS11.7, bd-aq9x |
| V12 | Daemon | PARTIAL | Shipped; absolute load / ppid==1 triggers; no PSI; no service install; escalation ignores trigger | WS10.14, bd-1y2g.5/.6 |
| V13 | Fleet | PARTIAL | Planning works; apply stub; pooled "e-values" are odds³ (not valid e-values → eBY guarantee void); host health discarded | WS11.8, WS10.15, bd-1y2g.* |
| V14 | MCP server | WORKING | `pt_scan` ignores min-age; no label tool | bd-t9qm.7 |
| V15 | HTML report / bundles | STUB/BROKEN | Report overview-only, exits 0; bundles miss snapshot+inference (`scan/snapshot.json` never written) | WS11.9 |
| V16 | Telemetry | DISCLOSED | | bd-t9qm.9 |
| V17 | Wait-free probing | WORKING | Inferred late-completion hang | bd-u7gc.2 |
| V18 | Data-loss gate | PARTIAL | apply: one 60 s window; TUI: 60 s per kill; `wchar` counts tty/pipe writes → any logging process blocked | bd-aq9x, bd-28v9 |
| V19 | Intent/workspace/GPU | DISCLOSED | | bd-t9qm.10 |
| V20 | Session retention | WORKING | | — |
| V21 | Respawn awareness | BROKEN | verify field mismatch → always 0; tracker unwired; no parent attribution | WS11.2, WS10.7 |
| V22 | Goal-based kill sets | PARTIAL | memory works; CPU baseline = sum of candidates' lifetime %cpu; port/fd contribute 0 | bd-t9qm.8, WS10.6 |
| V23 | macOS | PARTIAL | Orphans always review; no memory-pressure signal | WS11.6, WS10.1 |
| V24 | Scan performance | WORKING (hetzner1 75 ms) | Per-candidate `/proc/net/unix` re-parse remains in supervision detection | bd-u7gc.4/.5 |
| V25 | Quality gates / CI | PARTIAL | Local gates green; CI disabled | bd-ufqb.11 |
| V26 | Docs match reality | PARTIAL | ~18 drift items (§1, item 4) | WS9 |
| **V27** | `agent snapshot` system state: load, memory+swap, PSI stalls, process census, top-N hogs by CPU/RSS/IO, anomaly indicators (alien plan §3.5 "Snapshot") | PARTIAL | load/mem/PSI-some only | WS10.1–10.3 |
| **V28** | `verify` resource_delta before/after: memory, CPU idle, loadavg, respawn gap reason (alien plan §3.5 verify) | NOT_STARTED / NO_BEAD | expected-not-measured | WS10.7 |
| **V29** | Dormant mode: PSI/sustained-load triggers relative to cores, EWMA + change detection, nice/ionice self-limit, systemd/launchd service (alien plan §3.7, DORMANT_DAEMON_SPEC) | PARTIAL | self nice/ionice ✓; PSI ✗; relative load ✗ (legacy config only) | WS10.14, bd-1y2g.5 |
| **V30** | `--goal "CPU < N%"` derived from system counters (alien plan §5.14) | WRONG_APPROACH | sums candidates' lifetime `%cpu` | WS10.6 |
| **V31** | Useful-but-bad → throttle/review (README L358, L1087) | BROKEN | `keep` always wins | WS10.4 |
| **V32** | Trajectory / time-to-threshold prediction (alien plan §4.44) | DISCLOSED/UNWIRED | | WS10.13 |
| **V33** | Supervisor-aware actions: prefer supervisor stop on respawn (alien plan §6.1) | PARTIAL | suggested text only | bd-qr40.6, WS10.7 |
| **V34** | Restore a sluggish machine in the origin scenario (README *Origins*) | NOT_STARTED / NO_BEAD | no pressure regime, attribution, relief planning, or closed-loop check | WS10 |
| **V35** | Agent loop plan → apply → verify (README Quick Start §3, AGENT_INTEGRATION_GUIDE) | BROKEN | WS11.1 | WS11.1, WS11.2 |
| **V36** | Shadow mode as calibration (README §Shadow) | WRONG_APPROACH | all labels negative | WS11.5, bd-codb.4 |

**Bead coverage.** Revision-1 epics WS0–WS9 + ambition cover V1–V26 except the items marked WS11. V27–V36 and every
WS10 item had **no bead** before this revision (`br` search: 0 open beads mention PSI, ionice, oomd, swap, load
average, competing builds, subtree accounting, poll loops, MCP servers or "doctor").

---

## 3. Bridge plan

Ordering principle (unchanged, one rung added on top): **(0) fix what is broken in the shipped agent path → (A) stop
being wrong → (B) ship what exists → (C) make the core decision good on real hosts with measured ground truth →
(D) give pt a model of the machine and close the remediation loop (WS10) → (E) wire advanced math only where it
measurably helps → (F) docs tell the truth at every step.** Every workstream ends with an e2e proof on real processes
(and, where relevant, real hosts) with detailed structured logs.

### 3.1 WS11 — Revision-2 P0/P1 defects (new epic)

| # | Defect | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| 11.1 | **plan→apply handoff broken** | §1 item 1 | One plan contract: `agent plan` emits a real `Plan` (stable `plan_id`, `actions[]` with targets, pre-checks, rationale, timeouts, `gates_summary`) inside or beside the report JSON; apply consumes it; schema-validated | e2e on real disposable processes: `agent plan` → `agent apply --yes` (robot policy in temp config) → `agent verify`, no hand-built `Plan`; BATS twin; demo script `docs/demos/plan-review-apply.sh` runs green |
| 11.2 | verify field mismatch; review candidates counted as failures | `verify.rs:21-31, 182-185, 236-240` vs `main.rs:12560` | Read the plan contract from 11.1; verify only executed actions | Respawn of a killed `sleep` respawner detected in e2e |
| 11.3 | Rate limiter never records kills; apply bypasses enforcer; robot gates block Keep; CLI `--min-posterior` can loosen policy | `enforcer.rs:651-655, 726-733, 1157-1164`; `robot_constraints.rs:150-158` | `record_kill` on every executed kill (plan/TUI/apply); apply runs `check_action`; robot gates apply only to non-keep actions; CLI overrides may only tighten | Unit + e2e: 6th kill in a minute refused with `rate_limit` reason; `--robot` plan keeps `spare_set` |
| 11.4 | Linux orphans scored "supervised" | `lineage_evidence.rs:278-289`, `scoring.rs:661-671` | `InitChild` only for real service children (cgroup role / never in a login or transient scope); true orphans get one orphan term | Fixture: orphan dev server in `session-N.scope` gets no supervised term; property test: no candidate has both terms |
| 11.5 | Learning defects | `decision_store.rs:154-161, 270-306`; TUI self-labeling `main.rs:2295-2403`; shadow `validation.rs:750-790`, `:383` | Per-verdict timestamps (decay each count); broad key only after ≥2 distinct exact patterns agree; TUI records only rows the human toggled/confirmed (not pre-selected defaults) plus spares; shadow outcomes: `still_running_idle_after_T`, `user_killed`, `exited_normally_while_active` with honest "unknown"; calibration uses the score (P(ab∪z)) | Unit tests for each; shadow e2e produces both positive and negative labels |
| 11.6 | macOS orphans always review; root/Unknown cgroup | `enforcer.rs:539-551` | Same "user workload" exemption via macOS placement rules (owner+executable) as the scan filter uses | macOS e2e: orphaned user `python3 -m http.server` can be recommended pause/kill |
| 11.7 | TUI skips plan-only safety steps; hard-coded 0.7 threshold | `main.rs:2887-3076` | One shared `decide_candidates()` used by plan, TUI, watch, MCP | Metamorphic test: TUI rows ≡ plan recommendations for the same snapshot |
| 11.8 | Fleet pooled e-values are odds³ | `session/fleet.rs:386-395, 439` | Use valid e-values (e.g. likelihood-ratio e-values against the useful null, or calibrated p→e conversion) or drop the FDR claim | Simulation test: eBY FDR ≤ α under the null with the new e-values |
| 11.9 | HTML report hollow (exit 0); bundles miss snapshot+inference | `main.rs:17925-18036`, `pt-report/src/generator.rs:68-101`; `main.rs:4169-4215` vs session files `scan/inventory.json`, `inference/results.json` | Bundle the real file names; one report implementation and flag set (`--embed-assets`). Report rendering is owned by `bd-h2y0` and bundle redaction by `bd-p2ks` (filed the same day by a concurrent reality check, label `reality-check-2026-10`) | Bundle round-trip contains inference; report assertions in `bd-h2y0` |
| 11.10 | Environment-sensitive apply tests; wrapper bugs; tutorials | test run §1.3; `pt:30-31, 168, 225, 348, 406`; `learn/mod.rs:20-33, 68, 96` | Tests build processes that pass live prechecks deterministically (setsid, no tty, no inherited agent env) or assert the precise block reason; wrapper: resolve symlinks, wrapper-only commands before `find_pt_core`, `history` read-only, `clear` counts per level; tutorials use `--session … --pids`; `learn verify` runs the real tutorial commands with a time budget | Tests pass on rch workers and locally; BATS for each wrapper fix |
| 11.11 | Work-graph hygiene | 16 stale `in_progress` beads | Re-verify each against code with cited evidence; close or reset to open with a note | `br list --status=in_progress` contains only actively worked beads |
| 11.12 | `agent plan` stalls past test timeouts as root on a loaded build worker | §1.3 test run; `supervision/ipc.rs:260-341` via `main.rs:12612` | One unix-socket inode→peer map per scan shared with the NetworkSnapshot; phase timings in the event stream; budget test with 2 000 procs / 50 000 sockets | e2e_plan tests pass on an rch worker as root; budget green |

### 3.2 Revision-1 workstreams: status delta

* **WS0 (corpus + metrics)** — open and now the critical path for anything statistical: `.1` format+capture, `.2/.3`
  captures, `.5` harness, `.7` CI assertions. **Add pressure fixtures (WS10.16) to the same format.**
* **WS1 (decision core)** — loss/score/gate/age/orphan/zombie largely done; open: `.12` property suite, `.3` remaining
  surfaces (watch, narrative "confidence"), `.9` zombie (TUI routing), `.11` goal/candidate agreement reporting.
* **WS2 (protection)** — largely done; finish `.3` (`pi`, `am`), `.7` (agent liveness from child activity + session
  files), `.5` (PID-1 children by unit), `.6` (fail-closed), and the env-inheritance design (WS11/WS10.11).
* **WS3 (actions)** — `.4` leaf cgroups is now a WS10 prerequisite; `.6` supervisor restart; `.9` integrated e2e.
* **WS4 (collection)** — `.6` rates instead of lifetime totals becomes part of WS10.3; `.4/.5` perf.
* **WS5 (ship)** — `.11` CI is the biggest remaining gap; `.12` fleet rollout of 2.2.x.
* **WS6 (learning)** — partly done (WS11.5 supersedes parts of `.2/.3a`); `.4` calibration still open.
* **WS7 / Ambition** — unchanged; WS10 gives several library models their first real job (Kalman/trend for
  time-to-threshold, BOCPD/e-process for sustained stall, respawn tracker, goal_contribution USS discount,
  tick_delta, cpu_capacity).
* **WS8 (fleet/daemon)** — `.5a` service install and `.6` mem-pressure wiring fold into WS10.14.
* **WS9 (docs)** — extend with the revision-2 drift list.

### 3.3 WS10 — Pressure-aware remediation: bringing `system-performance-remediation` into pt (no LLM calls)

#### 3.3.1 Why, and the one-sentence design

pt answers *"which processes are abandoned?"*; the playbook answers *"the machine is (about to be) sluggish — what is
causing it, what is the least harmful sequence of interventions that restores responsiveness, and did it work?"*. The
second question is a **closed-loop control problem over system state**; the first is per-process classification.
They share collection, protection, identity-safe actions and explanation, which pt already has. WS10 adds the missing
half: **sense pressure → classify the regime → attribute it to responsible units → choose the cheapest-risk relief
under a pressure-conditioned loss → act reversibly first → measure the realized relief → learn.**

Hard constraints: **no LLM or network calls**; every rule is data (signatures, policy) or closed-form statistics;
read-only by default; pt never edits host configuration (sysctl, systemd units, swap) — `doctor` prints exact
commands with rationale; agents and live infrastructure stay review-only exactly as today; all new outputs are
deterministic for a given input snapshot (fixture-replayable).

#### 3.3.2 Playbook → pt mapping

| Playbook idea (skill section) | Today in pt | WS10 construct |
|---|---|---|
| PSI is *the* sluggishness metric; thresholds cpu 10/30, io 5/15, mem 5/20 (Diagnosis) | some-avg10 in snapshot only | 10.1 sensor (some+full, avg10/60/300, totals for exact Δ rates) + 10.2 regime classifier with these thresholds as policy defaults |
| Load vs nproc (1.5 warn, 2 crit) | absolute 4.0 in daemon | 10.1 effective capacity (affinity, cgroup quota: `cpu_capacity.rs`, unwired today) + 10.2 |
| 2×2 tables: load vs CPU-PSI (IO-bound vs contention), free RAM vs mem-PSI (cache bloat vs exhaustion) | absent | 10.2 regimes `io_bound`, `cpu_contention`, `cache_bloat`, `memory_exhaustion`, with the table cell in the explanation |
| VM tuning, slab bloat, swap paradox, zram, oomd/slice limits, journald retention, file-nr, inotify (VM Tuning, oomd, Swap) | absent | 10.12 `pt doctor` (read-only host hygiene audit) + 10.13 oomd pre-emption |
| Kill hierarchy (zombies → exited sessions → stuck tests → poll loops → stuck CLIs → duplicate builds → old dev servers → stale agents → old tmux → old agents → active agents → system) | per-process loss only | 10.6 relief planner with risk tiers (lexicographic) + 10.8 signatures carrying the tier |
| "Kill the confused agent, not its children" (whack-a-mole) | live-child rule points the other way; no spawner attribution | 10.7 respawn attribution to the spawner + 10.11 agent subtree accounting (agents stay review-only) |
| Competing builds (multiple `CARGO_TARGET_DIR` for one project), duplicate `cargo check` (keep newest) | absent | 10.10 redundant/competing work detection (lock-holder aware) |
| Renice 19 + ionice idle for legit compilation | renice→10 on one thread; no ionice | 10.5 `deprioritize` action: topology-aware lever choice (nice on all threads / `cpu.weight` / `cpu.idle` / ioprio only when BFQ) + measured efficacy |
| Stuck tests 12 h, stuck `git add` 2 min, `vercel` 10 min, dev servers idle 24 h, gemini 24 h, agents 16 h | signature priors are age-blind; expectations dead data | 10.8 make `ProcessExpectations` live (survival evidence) + new built-in signatures |
| Orphaned poll loops (`while …; sleep; done`), orphaned MCP servers | absent | 10.9 wait-state + pipe-end liveness evidence; 10.8 signatures |
| `bun test` ignores SIGTERM (always escalate) | global 5 s grace | 10.7 per-pattern SIGTERM-sufficiency posterior → adaptive grace (policy-bounded) |
| Before/after verification (load, PSI, MemAvailable) | none | 10.7 settle window + measured `resource_delta` + predicted-vs-realized relief |
| Escalation ladder L1–L5 by load ratio | time-based notification ladder only | 10.6 severity → max eligible tier; L3+ never robot |
| Exited zellij sessions, stale `ntm-*` tmux sessions | multiplexers protected wholesale (correct) | 10.12 multiplexer hygiene *report* (sessions with no client for N days and only idle shells) — recommendation only |
| Fleet-wide audits, sequential SSH to avoid cascades | fleet plan in fixed chunks; host health discarded | 10.15 `fleet health` (sliding pool + circuit breaker; keeps host pressure) |
| systemd-oomd killed `user@1000.service` → 382 sessions lost | absent | 10.13 forecast time-to-oomd/time-to-MemoryMax from slice telemetry; daemon escalates with the subtrees whose stop prevents the massacre |
| Post-mortem: document what triggered, what was killed, was work lost | sessions only | 10.14 incident record (pressure series ± window, attribution, plan, actions, outcome) |
| Prevention (RCH, swarm size, test timeouts) | n/a | 10.12 reports swarm size vs capacity and stuck-test frequency from history (advice only) |

#### 3.3.3 Components (each is a bead; acceptance criteria are in the beads)

* **10.1 System pressure sensor.** New `collect::pressure` module (the logic currently scattered in `main.rs:11013-11150`
  and `9864-9958` moves there): PSI cpu/memory/io/irq some+full avg10/avg60/avg300 **and** `total` (µs) so a two-sample
  window gives exact stall rates; `/proc/loadavg` incl. runnable/total; effective CPU capacity (affinity + cgroup
  quota, `cpu_capacity.rs`); full meminfo (MemAvailable, Cached, Slab, SReclaimable, SUnreclaim, Dirty, Writeback,
  Shmem, AnonPages, SwapTotal/Free/Cached, Committed_AS, CommitLimit); vmstat deltas (pswpin/pswpout, pgmajfault,
  pgscan_direct, allocstall, compact_stall, oom_kill); `fs/file-nr`, `fs/inode-nr`; process census (R/S/D/Z/T counts,
  true orphans, threads). macOS: `vm.memory_pressure`/`kern.memorystatus_level`, vm_stat swapins/outs, load.
  Missing sources are `null` with a reason, never `0.0`. Output: `system` block in plan, snapshot, watch, daemon
  ticks and fleet; one-line `--format summary` mirroring the playbook's status line.
* **10.2 Pressure regime classifier.** Deterministic decision table (data in policy `pressure.*`, defaults = playbook
  thresholds) over 10.1 features with hysteresis (enter after N consecutive samples, leave after M): `healthy`,
  `cpu_contention`, `io_bound`, `memory_exhaustion`, `cache_bloat`, `swap_thrash`, `swap_paradox`, `fd_exhaustion`,
  `zombie_leak`, `dstate_storm`, `oomd_risk`, `runaway_process`; co-occurrence allowed; each regime carries severity
  (ok/warn/crit), the 2×2 cell that justified it, and the evidence values. Golden tests from real incident numbers
  (trj 2026-02-23: mem some avg10 18.78 %, vfs_cache_pressure 50, 388 GB cache + 40 GB slab; rev-1 ts2 load 466 on
  N cores; hz3).
* **10.3 Rate-based attribution ("who is causing it *now*").** Wire `tick_delta.rs` (two `/proc/<pid>/stat` samples,
  capacity-aware) for CPU *rates*; per-process Δ run-queue wait (`schedstat` field 2 — the *victims*), Δ
  read/write_bytes and `delayacct_blkio_ticks`, Δ majflt, VmSwap, RSS growth; aggregate per **responsible unit**: the
  leaf cgroup when it is a per-agent/per-tool scope, else agent session (process tree rooted at a recognized agent
  CLI), multiplexer pane, systemd unit, login session; per-cgroup `cpu.stat` usage Δ, `memory.current/peak`,
  `memory.pressure`, `io.pressure` where the controller is enabled. Output: an attribution table (unit → cores,
  GB RSS+swap, IO MB/s, stall share, top processes). This also delivers bd-u7gc.6 (rates instead of lifetime totals)
  for the posterior's `cpu`/`io_active` terms.
* **10.4 Pressure-conditioned decision.** Replace multiplicative `load_aware` scaling with an additive, explicit term:
  `E[L(a)] = Σ_c P(c)·L0(a,c) + κ·Σ_r s_r·share_r·(1 − ρ_{a,r})`, where `s_r` ∈ [0,1] is the regime severity for
  resource r (0 when healthy), `share_r` the unit's attributed share of the contended resource (10.3) and `ρ_{a,r}` the
  calibrated relief fraction of action a on resource r (keep 0; deprioritize partial CPU/IO; pause ~1 for CPU/IO, 0
  for memory; memory.high partial memory; kill ~1). **Invariants (property-tested):** (i) `s = 0` ⇒ decisions identical
  to the current engine; (ii) raising pressure never makes `keep` more attractive; (iii) **pressure never justifies a
  kill**: kill must win on the abandonment evidence alone (κ term enters kill's comparison only against reversible
  actions, never against keep for P(useful) above the kill threshold); (iv) units with zero share are unaffected;
  (v) agents and protected processes stay review-only. This fixes V31: a useful_bad compiler storm under CPU pressure
  gets `deprioritize`, not `keep`.
* **10.5 Remediation levers.** (a) `deprioritize`: lower CPU/IO priority with the lever that actually works for the
  target's scheduling topology — nice on **all threads** (`/proc/<pid>/task/*`) when the competition is inside the
  same CPU group; `cpu.weight`/`cpu.idle` on the target's own leaf cgroup when it owns one (per-agent scopes);
  ioprio idle only when the device scheduler honors it (BFQ) — capturing previous values for exact reversal
  (`undo`). (b) `pause_subtree`/`resume_subtree` via `cgroup.freeze` when the unit owns its cgroup, else SIGSTOP
  leaf-first / SIGCONT root-first with per-member identity. (c) `memory.high` soft cap on an owned leaf cgroup (the
  gentle memory lever). (d) Leaf-cgroup creation for a single process inside a delegated user subtree (finishes
  bd-qr40.4; refuses non-delegated `session-N.scope`). (e) `cgroup.kill` for atomic tree termination when the whole
  unit is selected. Every lever reports measured efficacy (10.7) so pt learns that, e.g., ionice is a no-op on `none`.
* **10.6 Relief planner (`--goal relieve`, `"cpu-pressure < X%"`, `"mem-pressure < X%"`, `"io-pressure < X%"`,
  `"load-ratio < X"`, `"swap < X"`).** Candidate actions over *all* evaluated units (not just abandoned ones); predicted
  relief per action from a calibrated relief model (CPU: fluid/processor-sharing approximation stall ≈ max(0, 1 −
  C/D) with demand D from runnable threads and capacity C; memory: USS (not RSS) + swap freed, using the unwired
  `goal_contribution.rs` shared-page discount; IO: attributed rate share); risk tiers from the kill hierarchy as a
  lexicographic order; solve with the existing branch-and-bound `goal_optimizer` (min risk-weighted expected loss s.t.
  predicted pressure ≤ target), report the Pareto frontier (risk vs relief) and the ordered ladder with predicted
  pressure after each step. Escalation level (L1 standard / L2 aggressive / L3 emergency) caps the eligible tiers;
  L3 requires an explicit flag and a human; robot mode never exceeds the policy level. Also fixes V30 (CPU goal from
  system counters).
* **10.7 Closed loop: settle, measure, attribute respawns, learn.** apply/verify gain a settle window (policy,
  default 15 s) and a measured `resource_delta` (PSI some/full, load, MemAvailable, swap, per-unit usage) with
  predicted-vs-realized relief per action; respawn detection keyed on (uid, normalized cmd, **parent**) over a window
  with the respawn tracker (`respawn_loop.rs`, persisted in the data dir) → "respawned by PID n (cmd)" → recommendation
  moves to the spawner (agent → review; supervisor → `systemctl [--user] stop`); per-pattern Beta posterior of
  "SIGTERM was sufficient" sets an adaptive grace (bounded, policy-capped); relief-model calibration by shrinkage of
  realized/predicted ratios per action class (empirical Bayes) surfaced in `pt shadow report`.
* **10.8 Remediation-aware signatures.** Make `ProcessExpectations` live: a runtime **survival** evidence term
  (log-normal lifetime with median `typical_lifetime_seconds`, p99 `max_normal_lifetime_seconds`, vs a heavy-tailed
  "abandoned" alternative; right-censored by construction because the process is still alive) replaces the
  age-blind signature prior; `cpu_during_run`/`idle_cpu_normal` compared against 10.3 *rates*. New built-ins (data,
  user-overridable): `bun test` (SIGTERM-ignorer), proxy/wrapper category (`rch exec`, `ssh` non-master, `timeout`,
  `env`, `nice`, `nohup`, `xargs`) whose liveness is inherited from children/sockets, compilers (`rustc`, `cc1plus`,
  `clippy-driver`, `ld`, `mold`, `lld`) as useful-heavy (deprioritize, never kill; the build tool is the unit),
  MCP servers (`playwright-mcp`, `@morphllm/morphmcp`, `npx … mcp`) abandoned iff their agent is gone, stuck CLIs
  (`git add/commit/status` > 2 min, `vercel` > 10 min, `npm|bun|pnpm install` > 30 min), poll-loop shells, `gemini`/`agy`
  via bun, `am`, `pi`, `ntm`, `cass index`. Each carries its kill-hierarchy tier and term grace.
* **10.9 Wait-state and pipe-end liveness evidence (causal, cheap).** `wchan` classes: `do_wait` (waiting on a child →
  liveness inherited from the child subtree), pipe/unix read with **no live writer** (orphaned consumer), nanosleep
  shell with short-lived `sleep` children churning (poll loop), `ep_poll` with active sockets (idle-normal server).
  Pipe-end liveness from `/proc/*/fd` inode matching + `fdinfo` flags ("no writer", "no reader"). A small fixpoint
  propagates liveness over the process/wait graph and replaces the ad-hoc `agent_descendant`/`live_child` caps with
  evidence. A concrete, shippable subset of ambition bead bd-bjrh.1.
* **10.10 Redundant and competing work.** Duplicate groups by (uid, exe, normalized argv, cwd/workspace root,
  whitelisted env keys such as `CARGO_TARGET_DIR` — redaction-aware); keep the newest; for cargo, never pick the holder
  of the build-directory lock (`/proc/locks`, already parsed) when newer duplicates are waiting on it — kill waiters
  instead. Competing builds (same workspace root, different target dirs, concurrently) are a *system* finding
  (contention) with a deprioritize/serialize recommendation, not abandonment evidence.
* **10.11 Agent-swarm awareness without auto-killing agents.** Per-agent unit accounting (10.3), child composition
  (only MCP servers, no tool children for N h), TTY idle (exists), session-file mtime (bd-toa2.7) → "agent idle X h,
  holds Y GB" review items sorted by reclaimable resources; supervision env inheritance (CLAUDECODE/TMUX in every
  descendant) is checked against the liveness of the supervising process instead of blanket-blocking.
* **10.12 `pt doctor` (read-only host hygiene).** VM tuning vs RAM/filesystem (vfs_cache_pressure, min_free_kbytes,
  swappiness, dirty ratios), swap present, zram present and persisted, swap paradox, systemd-oomd state and
  `ManagedOOM*` of `user@.service`, `user-UID.slice` MemoryMax/MemoryHigh including drop-in ordering (a later
  `MemoryMax=infinity` negates earlier limits), per-session scope limits, journald retention, `file-max`/`file-nr`,
  inotify limits, block scheduler vs ioprio usefulness, CPU controller delegation (which levers work), kcompactd CPU,
  multiplexer hygiene (detached tmux sessions without clients for N days whose panes are idle shells; zellij EXITED
  count), zombie parents. Each finding: severity, rationale (with the incident that motivated it), exact suggested
  command; nothing is executed. JSON/MD/summary; exit code by worst severity; `--fleet` via 10.15.
* **10.13 oomd and limit pre-emption.** Read oomd config (`oomd.conf`, unit properties) and slice telemetry
  (`memory.current/max/high/pressure`, `memory.swap.current`); forecast time-to-limit with a robust trend (the unwired
  Kalman/trend modules, with prediction intervals) over daemon ticks; when the forecast crosses within horizon H or slice
  memory pressure exceeds the oomd limit × margin for N s → `oomd_risk` regime → escalation naming the smallest-risk set
  of units whose stop/memory.high prevents the user-service kill (10.6 with a memory goal). Recommend-only by default.
* **10.14 Daemon modernization + incident records.** Triggers = 10.2 regimes (PSI some/full with hysteresis, load
  ratio to effective capacity, memory regimes, swap thrash rate, fd exhaustion), replacing absolute load and the
  ppid==1 "orphan" count; escalation runs `agent plan --goal relieve` for the fired regime; the over-budget path
  actually backs off (interval doubling) instead of skipping a tick; incident record on crit regimes; `agent watch`
  streams regime transitions with an adaptive baseline (not the first sample). Folds in bd-1y2g.6.
* **10.15 Fleet health.** `pt agent fleet health|doctor`: per-host regime + attribution summary + doctor findings;
  sliding-window concurrency (not fixed chunks) with a per-host circuit breaker and a default that avoids SSH cascades;
  keep the remote `host`/`system` blocks that fleet plan discards today.
* **10.16 Proof infrastructure for WS10.** Pressure fixtures in the WS0 fixture format (system series + per-process
  samples), incident replays → regime goldens; real-process e2e on a disposable host/VM or inside a delegated user
  scope: CPU burners pinned to one core (deprioritize must raise the victim's share to ≥ 80 % or report "lever
  ineffective"), memory hog under `memory.high`, IO writer, poll-loop shell, orphaned pipe consumer, duplicate builds,
  a respawner; decision property/metamorphic tests for 10.4 invariants; overhead budget (sensor ≤ 2 ms, attribution
  window configurable, daemon tick ≤ 1 % of one core) as criterion benches with a CI budget check.

* **10.18 TUI pressure views.** Always-visible pressure header (load ratio, PSI with severity colors, available
  memory, swap, zombies, active regimes in words), attribution panel, a "Relieve" view running the 10.6 ladder through
  the shared execution path with a settle countdown and the measured delta, and an undo panel for reversible actions.
* **10.19 Opt-in auto-mitigation (reversible levers only).** Implements the alien plan's dormant-mode step 5 and the
  dead `allow_auto_mitigation` flag: under a *sustained* crit regime, with explicit policy, the daemon may
  deprioritize, freeze (with TTL) or `memory.high`-cap non-agent, non-protected units within budgets; every action has
  an exact undo, is recorded in the incident, and is undone automatically when the regime clears. Never kills, never
  agents, never units with recent TTY activity or units holding locks others wait on.
* **10.20 Deleted-but-open files.** The process-centric slice of the playbook's "disk full" incidents: fds whose
  target ends in " (deleted)" keep blocks allocated until their holder exits. Per-process and per-mount reclaimable
  bytes (exclusive holders only), a `disk_exhaustion` regime, doctor attribution, and a `free-disk N GB` goal.

Refinement notes recorded on the beads: pressure credit is scoped to exactly what an action touches (renicing one
rustc must not earn credit for its whole agent scope); the plan's default sampling window is 500 ms (10 ms tick
resolution ⇒ ≤ 2 % of a core), reusing fresh daemon samples when available; doctor states when a fix only treats the
symptom (drop caches without VM tuning) and only suggests the swap flush when available RAM is more than twice the
swap in use.

#### 3.3.4 Sequencing

10.1 → 10.2 → 10.3 are the foundation (no behavior change; plan/snapshot/watch/daemon only gain fields). 10.4
depends on 10.2+10.3 and on WS1.10 (property suite). 10.5 depends on bd-qr40.4. 10.6 depends on 10.4+10.5 and the
existing goal optimizer. 10.7 depends on WS11.1+WS11.2. 10.8/10.9/10.10 depend on 10.3 and feed the posterior; they are
measured against WS0 + 10.16 fixtures before being enabled by default. 10.12 depends only on 10.1 (quick win). 10.13
depends on 10.1+10.3 (+ daemon). 10.14 depends on 10.2 (+ bd-1y2g.5 service install). 10.15 depends on 10.1/10.12.
10.16 runs alongside from the start.

---

## 4. Ambition pass (Phase 4) — where better math genuinely pays here

Revision 1's list stands (consumer liveness, survival runtime evidence, hierarchical priors, e-process idleness,
Mondrian conformal + eBH, pidfd protocol, ablation-gated wiring). Revision 2 adds the math that makes the *remediation*
half principled rather than a pile of thresholds:

1. **Pressure-conditioned expected loss with a safety invariant** (10.4). The cost of inaction scales with the unit's
   share of a contended resource and the regime severity, and enters only reversible-action comparisons, so the
   classical guarantee "a kill needs overwhelming abandonment evidence" survives intact.
2. **Queueing-theoretic relief prediction + online calibration** (10.6/10.7). A processor-sharing fluid model predicts
   stall reduction from removing demand; realized/predicted ratios are shrunk per action class (empirical Bayes). The
   planner's promises become *testable*, and an action class that does not work on a host (ionice under `none`, nice
   across cgroups) is discovered from data, not folklore.
3. **Anytime-valid "sustained stall" detection** (10.14). An e-process on PSI increments (test-martingale; the existing
   `martingale.rs` finally earns its keep) gives a daemon that never flaps and has an explicit false-alarm guarantee
   at any stopping time; BOCPD marks regime changes for the incident record.
4. **Time-to-threshold forecasting with prediction intervals** (10.13). A local-linear-trend Kalman filter on slice
   memory and swap gives "oomd will act in ~T ± δ minutes" — the alien plan's §4.44 with a concrete, high-stakes use.
5. **Survival-hazard runtime evidence** (10.8) from signature expectations first, refit from shadow data later
   (right-censored Kaplan–Meier/Weibull per signature; ties into bd-bjrh.2).
6. **Liveness as a fixpoint over the wait/pipe graph** (10.9). A process is live if it does work or waits on something
   live; abandonment evidence is strongest when nothing live consumes its output. This replaces hand-written tree caps
   with a causal model.
7. **Direct stall attribution from cgroup PSI** (10.3). On systemd hosts each unit's `*.pressure` file *is* its
   stall contribution; within a unit, CPU share × run-queue victimization separates culprits from victims without
   Shapley-style approximations.
8. **Action-efficacy posteriors** (10.7). Beta posteriors for "SIGTERM sufficient" and "lever moved the share",
   per pattern and host, adapt grace periods and lever choice within policy bounds.

---

## 5. What "done" means (revision 2)

* **Agent loop:** `pt agent plan` → `pt agent apply --session` → `pt agent verify` works end-to-end on real disposable
  processes in CI and on the installed release; respawns are attributed to their spawner.
* **Fleet (rev-1 criteria still apply):** zero `must_not_flag` hits; zombies routed to parents; idle stuck test
  runners flagged kill with P ≥ 0.95; wall time ≤ 5 s on every host; identical versions.
* **Remediation:** on a deliberately overloaded test machine (CPU burners in an agent-like scope, a memory hog, an IO
  writer, a stuck poll loop, an orphaned pipe consumer, duplicate builds, a respawner, a live agent and a mux server),
  `pt agent plan --goal relieve` identifies the right regimes, attributes ≥ 90 % of excess demand to the injected
  culprits, proposes reversible levers first, never touches the agent or the mux server, and after apply + settle the
  measured PSI is below target with relief-prediction error within ±30 %; `pt doctor` flags every injected host
  misconfiguration in a fixture (vfs_cache_pressure 50, no swap, `MemoryMax=infinity` drop-in) and nothing on a
  clean host.
* **Quality:** CI re-enabled and green (fmt, clippy, tests, BATS, musl, release); every README command example runs in
  a doc-truth test; every claim in README is backed by a test.

---

## Appendix A — Revision-2 bead map

Every bead below is self-contained (background, file:line evidence, design, acceptance criteria, tests with JSONL
logging, dependencies). Epics: `bd-uacs` (WS11, P0) and `bd-p1o0` (WS10, P1). Starting points with no blockers:
`bd-uacs.1` (plan contract), `bd-uacs.3` (guardrails that count), `bd-uacs.8` (one decide path), `bd-p1o0.1`
(pressure sensor), `bd-l3s5.1` (shared fixture format).

| WS11 item | Bead | P | | WS10 item | Bead | P |
|---|---|---|---|---|---|---|
| 11.1 plan contract | `bd-uacs.1` | 0 | | 10.1 sensor | `bd-p1o0.1` | 1 |
| 11.2 verify contract + respawn matcher | `bd-uacs.2` | 0 | | 10.2 regimes | `bd-p1o0.2` | 1 |
| 11.3 guardrails that count | `bd-uacs.3` | 0 | | 10.3a windowed rates | `bd-p1o0.3` | 1 |
| 11.4 orphan provenance | `bd-uacs.4` | 1 | | 10.3b unit attribution | `bd-p1o0.4` | 1 |
| 11.5a learned-prior defects | `bd-uacs.5` | 1 | | 10.4 pressure-conditioned loss | `bd-p1o0.5` | 1 |
| 11.5b shadow labels | `bd-uacs.6` | 1 | | 10.5a deprioritize | `bd-p1o0.6` | 1 |
| 11.6 macOS orphans | `bd-uacs.7` | 1 | | 10.5b freeze/terminate unit | `bd-p1o0.7` | 2 |
| 11.7 one decide path | `bd-uacs.8` | 1 | | 10.5c cap_memory + leaf cgroup | `bd-p1o0.8` | 2 |
| 11.8 fleet e-values | `bd-uacs.9` | 1 | | 10.6 relief planner | `bd-p1o0.9` | 1 |
| 11.9 bundles + report flags | `bd-uacs.10` | 1 | | 10.7a settle + resource_delta | `bd-p1o0.10` | 1 |
| 11.10a deterministic apply tests | `bd-uacs.11` | 1 | | 10.7b spawner attribution | `bd-p1o0.11` | 1 |
| 11.10b wrapper bugs | `bd-uacs.12` | 2 | | 10.7c SIGTERM handling | `bd-p1o0.12` | 2 |
| 11.10c tutorials / learn verify | `bd-uacs.13` | 2 | | 10.7d relief calibration | `bd-p1o0.13` | 2 |
| 11.11 work-graph hygiene | `bd-uacs.14` | 1 | | 10.8a survival evidence | `bd-p1o0.14` | 1 |
| 11.12 root/loaded-host plan stall | `bd-uacs.15` | 1 | | 10.8b signature catalog | `bd-p1o0.15` | 1 |
| | | | | 10.9 wait-state + pipe liveness | `bd-p1o0.16` | 2 |
| | | | | 10.10 redundant/competing work | `bd-p1o0.17` | 2 |
| | | | | 10.11 agent-swarm awareness | `bd-p1o0.18` | 2 |
| | | | | 10.12 `pt doctor` | `bd-p1o0.19` | 1 |
| | | | | 10.13 oomd pre-emption | `bd-p1o0.20` | 2 |
| | | | | 10.14 daemon on regimes + incidents | `bd-p1o0.21` | 1 |
| | | | | 10.15 fleet health | `bd-p1o0.22` | 2 |
| | | | | 10.16a pressure fixtures | `bd-p1o0.23` | 1 |
| | | | | 10.16b pressure lab e2e | `bd-p1o0.24` | 1 |
| | | | | 10.16c decision invariants | `bd-p1o0.25` | 1 |
| | | | | 10.16d overhead budgets | `bd-p1o0.26` | 2 |
| | | | | 10.17 docs | `bd-p1o0.27` | 2 |
| | | | | 10.18 TUI pressure views | `bd-p1o0.28` | 2 |
| | | | | 10.19 opt-in auto-mitigation | `bd-p1o0.29` | 2 |
| | | | | 10.20 deleted-but-open files | `bd-p1o0.30` | 2 |

Existing beads re-linked by this revision (comments added; superseded ones now depend on their successor):
`bd-u7gc.6` → `bd-p1o0.3`, `bd-t9qm.2` → `bd-p1o0.11`, `bd-1y2g.6` → `bd-p1o0.21`, `bd-codb.4` → `bd-uacs.6`,
`bd-qr40.9` → `bd-uacs.1`, `bd-uacs.10` → `bd-p2ks`; context comments on `bd-qr40.4`, `bd-zi8p.12`, `bd-bjrh.1`,
`bd-bjrh.2`, `bd-ufqb.9`, `bd-toa2.3`, `bd-toa2.7`, `bd-aq9x`, `bd-u7gc.3`, `bd-h2y0`, `bd-28v9`.
