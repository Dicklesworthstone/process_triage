# Reality Check & Bridge Plan — process_triage (`pt`)

## Execution update — 2026-10-04 23:35 UTC

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
  Changed safety/sharing paths pass formatting and diff checks. Workspace formatting currently fails in other
  concurrently edited files; final compiler, clippy, lean and full regression gates remain pending.
- Dependency updates are tested individually and recorded in `UPGRADE_LOG.md`. Current remaining large migrations
  and known audit findings must not be described as a completed latest-version or vulnerability-free upgrade.
- The full bundle/redaction/report suites passed at 22:53, before the later typed Plan/signature and artifact-path
  collision corrections. Actual producer round trips and those corrections require another execution pass.
- Eleven compatible dependency upgrades passed affected consumers one at a time. The frozen lockfile is
  SHA256 `55957d71fd29bac6cd6fc18a79809d6db81036a54b0fec36ab5153ea4d7f4455`; the cached audit still exits 1 for
  rkyv, with LRU unsound and paste unmaintained warnings. Standalone fuzz lock/campaign remain unvalidated.
- Strict remote current-source CLI acceptance timed out in admission without running; no local fallback ran.
  The retry is pending capacity. No green result is inferred from waiting, commits or independent source agreement.
- Source now connects the existing typed kernel-pressure reader/assessment to snapshot, plan and TUI load inputs,
  preserves unavailable readings as null, records signature age weights, and maps usage errors to ArgsError 10.
  These additional producer connections remain unverified until the current binary tests and compiler gates run.

### Active completion checklist

- [x] Connect final post-policy candidates to the existing executable Plan builder; preserve canonical identities,
  required checks, rationale, parent routing and final review/keep decisions.
- [x] Persist exact four-class evidence ledgers without recomputing historical sessions with current priors.
- [x] Connect structured profile redaction to plain, encrypted and in-memory archive preparation.
- [x] Add static escaped report rows and recorded outcomes/ledger rendering; preserve unknown timing/counts.
- [x] Inspect and repair CI source configuration, including invalid job secret conditions and masked test failures.
- [ ] Rerun actual planner → apply → verify with a real detached target and stale-identity refusal.
- [ ] Rerun current-age-floor, regular/unlinked writer, read-only/FIFO and unreadable-evidence cases.
- [ ] Rerun actual CLI saved-session → plain/encrypted bundle and session/bundle HTML canary regression.
- [ ] Rerun all sharing/report library and integration suites on current source and lockfile.
- [ ] Add and execute the BATS twin against the validated binary; prohibit implicit local heavy builds.
- [ ] Repair and execute the scoped plan/review/apply demo; publish the generated Plan schema.
- [ ] Verify a tampered plan cannot remove mandatory runtime checks.
- [ ] Complete sequential compatible dependency consumer tests, freeze the lockfile and rerun security audit.
- [ ] Obtain the existing pending permission for migrations exceeding ten source files before starting them.
- [ ] Run current-tree workspace all-targets check, warning-denying clippy, formatting and lean check.
- [ ] Verify actual Safe Plan and SignatureSchema typed round trips, preserving checks, routing and numeric evidence.
- [ ] Verify distinct secret artifact filenames preserve both payloads/checksums and duplicate paths refuse publication.
- [ ] Verify malformed signatures/provenance audit and unreadable requested telemetry refuse before output creation.
- [ ] Verify snapshot/plan kernel-pressure readings and their persisted schema; review remaining unknown-value consumers.
- [ ] Verify CLI usage error 10 and explicit help/version 0, including existing label/degraded-environment expectations.
- [ ] Complete bd-uacs.3 apply/TUI policy-enforcer and persistent kill-count wiring with real cross-run rate-limit proof.
- [ ] Run appropriate workspace regressions; distinguish pre-existing failures from new ones using evidence.
- [ ] Re-execute workflow static checks and review scanner findings before committing.
- [ ] Complete fresh original-acceptance review and the real-work/honesty inventories; close only proven tasks.
- [ ] Flush Beads, commit reviewed changes and push verified main plus the required legacy branch synchronization.

No calibrated precision/recall, fleet acceptance, macOS live probe, hosted-CI success or encrypted-bundle CLI
reporting is claimed by these tests. The full original workstream checklist below remains open where its named
acceptance evidence has not been obtained. Further gaps discovered during execution belong on that checklist
and their existing Beads rather than being hidden in a completion summary.

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
| V5 Agent plan → apply → verify | BROKEN in inspected source: rich planning JSON differs from executable `Plan`; verification command names also differ. | `bd-uacs.1/.2`; WS3 `.9` |
| V6 Advertised actions execute safely | SOURCE: composite dispatch; Restart still errors and planning considers it feasible. Shared cgroups are refused; dedicated-leaf positive capability needs proof. | WS3 `bd-qr40.4/.5/.6/.9` |
| V7 Identity-safe staged signals | SOURCE: identity and pidfd paths exist; platform/action/PID-reuse acceptance still requires real disposable probes. | WS3 `.9`; ambition `bd-bjrh.6` |
| V8 Protected infrastructure and caller chain | SOURCE: protection rules exist. Complete agent liveness, root workload visibility, PID-1-child handling and all-surface parity remain acceptance work. | WS2 `bd-toa2.*`; `bd-uacs.7/.8` |
| V9 Data-loss protection | PARTIAL: regular-descriptor classification and unreadable-evidence handling need repair; recent-I/O and lock read failures can also fail open. | `bd-28v9`; WS2 `.6`; `bd-aq9x`; WS3 `.9` |
| V10 Honest robot risk controls | PARTIAL: posterior constraints exist. Calibration, single-host conformal/eBH and full per-action enforcement are not established. | WS1 `.4`; WS7 `.1`; ambition `.5`; `bd-uacs.3/.9` |
| V11 Human decisions improve future priors | SOURCE: store and scorer consume human verdicts; outcome provenance, decay, pooling, label coverage and held-out improvement need acceptance. | WS6 `bd-codb.*`; `bd-uacs.5/.6` |
| V12 Interactive TUI in installed product | SOURCE/tag defaults include UI. Real artifact smoke, final safety parity and TUI labeling still need proof. | WS5 `bd-ufqb.1`; WS6 `.5`; `bd-uacs.8` |
| V13 Daemon monitors safely | SOURCE: daemon path exists; graded memory-pressure logic and service installation remain incomplete. | WS8 `bd-1y2g.5/.6`; proposed WS10 |
| V14 Fleet planning/apply | PARTIAL: SSH planning exists; apply explicitly reports unsupported and executes nothing remotely; dependency/guarantee claims need proof. | WS8 `bd-1y2g.*`; `bd-uacs.9` |
| V15 MCP uses the real planner | SOURCE: `mcp/tools.rs::tool_plan` invokes this executable's `agent plan`; same-snapshot parity and MCP transcript remain unproven. | WS7 `bd-t9qm.7`; WS9 |
| V16 Sharing profiles remove sensitive data | BROKEN: `run_bundle_create` copies raw artifacts; `BundleWriter::add_file` checksums/stores bytes. Safe/minimal is metadata without payload sanitization. | `bd-p2ks`; overlapping `bd-uacs.10` |
| V17 Reports expose recorded candidates/actions | BROKEN: session and bundle generators set candidates/evidence/actions to `None`; generic three-state math and canned prose are not observed session results. | `bd-h2y0`; overlapping `bd-uacs.10` |
| V18 Offline readable reports | PARTIAL: candidate table is an empty div until CDN JavaScript renders it; `embed_assets`/fallback configuration has no implementing consumer. | `bd-h2y0`; `bd-uacs.10`; WS9 |
| V19 Telemetry feeds calibration | DISCLOSED: Parquet recorder library is not a demonstrated live calibration input. Storage earns value only with a real consumer. | WS7 `bd-t9qm.9`; WS6 `.6` |
| V20 Bounded, safe collection | SOURCE: collection code exists; io_uring fault/sanitizer evidence and loaded-host budgets remain required. | WS4 `bd-u7gc.2/.3/.4/.5` |
| V21 Intent/workspace/GPU/container evidence | DISCLOSED/PARTIAL: multiple collectors remain library-only; robot safety and namespace semantics must survive integration. | WS7 `.10`; WS2 `.6` |
| V22 Bounded session storage | SOURCE: retention code exists; lifecycle coverage, in-use protection and backlog migration need cited acceptance. Deletion requires authorization. | WS5 `bd-ufqb.6/.7` |
| V23 Respawn-aware cleanup | PARTIAL: apply has an ad hoc respawn detector; full tracker and supervisor-stop recommendation remain unwired. | WS7 `.2`; `bd-uacs.2`; WS3 `.6` |
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

Every checkbox is intentionally open. Source already present means verify the remaining acceptance conditions;
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
- [ ] Other-session `bd-uacs.1/.2`: reconcile saved planning, executable targets and verification; chain production
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

- [ ] `bd-p2ks`: apply one existing redaction engine/profile policy before archive bytes, checksums or output;
  preserve numeric/structural evidence, consistent pseudonyms and explicit forensic behavior. Minimal omits detailed
  process artifacts. Malformed/unknown/opaque sharing content must not bypass sanitization.
- [ ] `bd-p2ks` tests: plant hostname/home-path/credential/command canaries in a real saved session; invoke actual
  bundle create and verify/extract the ZIP, including encrypted and in-memory paths. The current BATS safe/minimal
  tests synthesize already-clean ZIPs and therefore do not establish production export privacy.
- [ ] `bd-h2y0` with overlapping `bd-uacs.10`: implement one session/bundle adapter for saved candidates and
  outcomes. Prefer final rich-plan recommendations; load checksum envelopes deliberately; join outcomes by action ID.
- [ ] Report rows: retain all four classes, known age/CPU/RSS and actual action verbs; represent unrecorded I/O,
  timestamps and recovery as unknown. Do not map useful-bad into “uncertain” or expected RSS into measured recovery.
- [ ] Report ledger: persist exact scorer ledger/likelihood/prior data in the existing inference artifact; display
  it only when recorded. Label A-versus-U Bayes factors correctly and exclude the prior term from evidence Log BF.
  Rounded integer contributions cannot prove an exact historical ledger.
- [ ] Report safety/usability: redact visible and embedded JSON fields; escape HTML/script context; render a static
  candidate table without CDN JavaScript. Remove canned success/prose and unrelated default mathematics.
- [ ] Report tests: invoke actual session and bundle report paths with a known candidate/action, planted secrets,
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
