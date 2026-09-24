# Reality Check & Bridge Plan — process_triage (`pt`)

Date: 2026-09-24 · HEAD `e24ee78` · repo VERSION 2.1.0 · installed fleet versions: 2.1.0 (dev boxes), 2.0.5 (all 8 vmi workers + mac-mini-max)

This document is the Phase-1 reality check + Phase-2 bridge plan (+ one Phase-4 ambition pass) from the
`reality-check-for-project` workflow. It is the measuring stick for the bead graph created from it; every
bead carries its own copy of the relevant context so this file never needs to be consulted again.

---

## 1. Verdict (brutally honest)

**The beads say 792/792 closed. The product does not deliver the README's core promise.**

What pt actually does today when you run it:

* `pt agent plan` runs a single naive-Bayes step over 5–6 hand-set features (`cpu, runtime, orphan, tty,
  state_flag` + Linux-only hand-tuned `provenance_*` constants), then an expected-loss argmin over actions.
* **With the default policy, Kill can never win** (`pt-config/src/policy.rs:132-145`: `abandoned.kill = 0.1`
  equals `abandoned.renice = 0.1`; ties go to the reversible action). Result on the real fleet: **0 kill
  recommendations across all 20 hosts**; almost everything becomes `renice`.
* The **score is `max over all classes × 100`** (`main.rs:2822`, `11270`, `12118`), i.e. "how sure the model is
  about *some* class", not "how suspicious the process is". A 99%-useful process scores 99.
* The robot `min_posterior` gate compares the same max-over-classes number (`main.rs:13875`), so a
  P(useful)=0.96 process passes a 0.95 kill gate.
* ~35 of the README's advertised inference/decision modules (BOCPD, HSMM, IMM, Kalman, CTW, Hawkes, EVT,
  conformal, martingale gates, Wasserstein, compound Poisson, belief propagation, robust Bayes, BMA,
  sketches, LinUCB, Gittins/Wonham, CVaR/DRO, OPE, respawn-loop discount, pattern learning, user-intent,
  incremental engine, recovery trees, TypedSession, Chandy-Lamport, telemetry disruptor…) are **real,
  unit-tested code with zero production callers**. They are reachable only from their own tests.
* **Released binaries are built with no Cargo features** (`release.yml:153`, `install.sh:1102`,
  `pt-core/Cargo.toml default = []`): bare `pt` (the headline "interactive mode") prints a stub and exits 3;
  no TUI, no daemon, no HTML report (`report` stub exits **0**).
* `agent apply` uses `SignalActionRunner` only: Kill/Pause/Resume execute; Renice/Freeze/Throttle/Quarantine
  always fail; Restart fails everywhere. Nothing executes on macOS.

### 1.1 Fleet evidence (read-only `pt-core agent plan --format json`, `nice -n 19`, 20 hosts, 2026-09-24)

| Host | procs (ps) | pt scanned | evaluated | above thr | kill recs | wall time | load (1m) |
|---|---|---|---|---|---|---|---|
| trj | 2142 | 405 | 305 | 289 | 0 | 10 s | 14 |
| ts2 | 1766 | 479 | 426 | 417 | 0 | **86 s** | **466** |
| hz3 | 1002 | 296 | 200 | 194 | 0 | **366 s** | 94 |
| css | 1528 | 821 | 633 | 624 | 0 | 32 s | 79 |
| fmd | 513 | 243 | 188 | 155 | 0 | 6 s | 97 |
| ts1/csd/hz1/hz2/hz4 | 336–1042 | 147–376 | 93–275 | ~95% | 0 | 2–9 s | 0.4–25 |
| 8× vmi (root) | 230–436 | 108–261 | **14–42** (85–95% filtered as root) | ~all | 0 | 0–3 s | 0.4–16 |
| mac-mini-max/old | ~1000 | ~1000 | 305/403 | ~all | 0 | <1 s | 16–18 |

What it rated **P(abandoned) ≈ 1.000** (recommended renice):
* live Claude Code / Codex / agy agent CLIs (dozens, every dev box), `frankenterm-mux-server` (the
  terminal multiplexer hosting all sessions), tmux servers, `htop`, dashboard `foot/cage/tmux`, login zsh.
* **rch SSH ControlMaster connections** (`ssh -E … -S …/master -M`) on trj/ts2/hz2 at 0.995–0.999 —
  killing these breaks remote compilation.
* postgres background workers, nginx workers, mattermost + plugins on vmi workers (the `database`
  protected category does not match `postgres: 18/main: io worker`).
* **0-minute-old rustc / clippy-driver at 8–12% CPU** on hz3/hz4 (no default min-age; README promises 1 h).
* Processes with **age = 47 721 days** (`etimes` = 4 123 168 608 from procps, trusted blindly).
* macOS: Chrome/Brave/Spotify/Zed/ChatGPT helpers, interactive shells (orphan := `ppid == 1` on launchd).

What it **missed or mishandled** (independent ground truth from each host's `ps` snapshot):
* trj: 4 zombies (`faked`, `find`) 300 h old whose parent `sleep infinity` (a PID-1 child) is filtered out
  by the mandatory `never_kill_ppid:[1]` guard → pt classifies them `zombie` but recommends **renice**.
* ts2: `rch exec -- cargo test -p hfdt-cli date_filter` idle 2.7 h (0 CPU s) — rated abandoned but only
  `renice`; vmi1153651: `cargo test --locked --all-targets` 2.5 h as **root** → **invisible** (root protected).
* Every worker runs its real workload as root (rch builds under `/root`) → pt is blind on the worker fleet.

Operational usage reality: `decisions.json` is `{}`/absent on every host; no host has `policy.json` or
`priors.json`; ts1 holds **3 017** never-cleaned session dirs (289 MB) from a March test burst; outside pt's
own development sessions there is essentially no agent usage of pt in cass/session history. Fleet
hygiene is currently done by other means (earlyoom on ts1, manual remediation).

Side finding (other project): cass is unusable on trj/ts1/css/csd/ts2/mac-mini-old for this kind of query
("Quill query fuel exhausted", 7 477 index segments on trj; 60–100 s/query even with a 50× fuel budget);
workers have no agent sessions and no cass index (expected).

### 1.2 Quality gates at HEAD (via rch)

* `cargo fmt --check` FAIL (18 spots / 8 files) · `clippy -D warnings` FAIL (6 errors) ·
  `cargo test -p pt-core --all-features` **does not compile** (`tui/widgets/process_table.rs:940,954` E0063)
* `cargo test --workspace`: 6365 pass / 2 fail (`prechecks::live_provider_defaults`,
  `live_provider_run_all_checks_self` — fail when run as root) / 24 ignored
* BATS (macOS): 232 pass / 186 skip / 67 fail — real: fixture-manifest hash drift after `a99f026`, README
  link test, a quoting bug in test 11; rest GNU-vs-BSD tooling.
* CI: no runs since 2026-08-12; last runs red (nightly `cargo-fmt` missing, musl target missing, `toon` git
  dep SSL clone failure, broken `update-packages.yml`, cpuset test on runner).
* Beads DB was corrupt (`sqlite_master row 17`); rebuilt from JSONL on 2026-09-24 (bad files renamed
  `.bad_20260924T1630Z`, snapshot in `.beads/recovery_20260924T162810Z/`).

---

## 2. Vision checklist

| # | Goal (README) | Status | Evidence |
|---|---|---|---|
| V1 | Finds abandoned processes automatically, ranked | WRONG_APPROACH | score = max-class; ~95% of processes "above threshold"; live agents at 1.000 |
| V2 | Kill recommendations with confidence | REGRESSED/BROKEN | default loss matrix makes Kill unreachable; 0 kills on 20 hosts |
| V3 | 40+ models contribute evidence | LIBRARY-ONLY | 0 of 16 README-table models on scoring path |
| V4 | Evidence ledger (9 terms) via `pt deep` / `agent plan --deep` | PARTIAL | `--deep` ignored by plan; `pt deep` does no inference; net/io/queue always None in plan |
| V5 | 8 actions | PARTIAL | apply: Kill/Pause/Resume only; TUI-only others (TUI not shipped); Restart never |
| V6 | Identity-safe staged kill | PARTIAL | boot_id ignored, ±1.5 s tolerance, start from ps etimes, no pidfd, wide TOCTOU |
| V7 | Protected processes / root never flagged | OVERCLAIMED | only systemd/sshd/root-by-name; root protection blinds root-run workers |
| V8 | Blast radius (transitive, BFS, decay) | PARTIAL | direct co-holders only, Linux only; plan JSON hard-coded by RSS |
| V9 | Conformal/FDR/causal-snapshot robot gates | MISSING | gates `conformal_alpha`, `fdr_budget`, `causal_snapshot` don't exist; single-host FDR not applied |
| V10 | Learns from decisions | MISSING | nothing reads/writes `decisions.json`; `PatternLearner` unused |
| V11 | Interactive TUI | NOT-IN-RELEASE | `ui` feature not built; wrapper crashes on macOS bash 3.2 first |
| V12 | Daemon + memory-pressure escalation | NOT-IN-RELEASE / UNWIRED | `daemon` feature not built; `mem_pressure.rs` no callers |
| V13 | Fleet scan/plan/apply w/ consistent cut | PARTIAL/STUB | scan+pooled eBY real under `agent fleet plan`; apply stub; Chandy-Lamport unused; docs name wrong commands |
| V14 | MCP server | PARTIAL | tools list differs from README; `pt_plan` is a separate heuristic (recommended kill for 19 zombies) |
| V15 | HTML report / bundles | PARTIAL | bundles WORKING; report NOT-IN-RELEASE (stub exits 0) |
| V16 | Telemetry (disruptor + Parquet) | UNWIRED | recorder never imported; no parquet files anywhere |
| V17 | Wait-free io_uring /proc probing | BUGGY (memory safety) | SQ overflow drops ~27% of pids, timeout lost, UAF on timeout path |
| V18 | Critical-file / data-loss gate | PARTIAL | plan passes empty critical_files; apply gate blocks on any write fd incl. stdio |
| V19 | Supervision / user-intent / workspace / GPU / container awareness | LIBRARY-ONLY/PARTIAL | intent, workspace, GPU uncalled; Claude env names wrong; fail-open |
| V20 | Session retention 7 d | MISSING | env var only in README; Planned sessions kept forever (ts1: 3 017) |
| V21 | Respawn-loop detection | LIBRARY-ONLY | tracker uncalled |
| V22 | Goal-based kill sets | PARTIAL | memory goal works; port/fd goals contribute 0; "free port 8080" unparseable |
| V23 | macOS support ("basic collection") | WRONG_APPROACH | orphan := ppid==1 marks every app abandoned; no execution; verify flaky |
| V24 | Scan performance ("~1 s quick") | PERFORMANCE GAP | 86 s on ts2, 366 s on hz3 (O(N·S) `/proc/net` re-parse per candidate) |
| V25 | Quality gates green / CI green | REGRESSED | see §1.2 |
| V26 | Docs match reality | DRIFTED | fleet cmds, MCP tools, CLI_SPECIFICATION (`infer/decide/ui/duck`), tutorials 06/07, "~200 line wrapper", gum |

**Bead coverage:** all 792 beads are closed; **none** of V1–V26's remaining gaps is covered by an open bead
(every gap is `NO_BEAD`). Closing beads on unit-tested-but-unwired modules is the root process failure
("close-pump" / "proof-class inflation" in the suite rules): a module with tests ≠ a delivered feature.

---

## 3. Bridge plan

Ordering principle: **(A) stop being dangerous/wrong → (B) ship what exists → (C) make the core decision
genuinely good on the real fleet with measured ground truth → (D) wire advanced machinery only where it
demonstrably improves measured quality → (E) docs tell the truth at every step.**
Every workstream ends with an e2e proof on real hosts (trj/ts2/hz3/vmi/mac) with detailed logs.

### WS0 — Fleet false-positive regression corpus (foundation; everything else is measured against it)
* 0.1 Capture redacted, replayable scan fixtures from the 20 hosts (the exact false positives above:
  agent CLIs, mux servers, ControlMasters, postgres/nginx workers, 0-min rustc, 47 721-day ages, trj
  zombies, ts2 idle `cargo test`, root-run worker builds, macOS apps). Fixture format = what quick_scan +
  deep_scan consume, redacted with pt-redact.
* 0.2 Labels: `must_not_flag` (protected/live), `should_flag_kill`, `should_route_parent`, `review_ok`.
* 0.3 Metrics harness: precision@k of KILL/REVIEW, FP rate on `must_not_flag` (**must be 0**), recall on
  `should_flag_kill`, decision-latency. Runs in `cargo test` (fixture replay) + an opt-in live fleet e2e
  script (`scripts/fleet_reality_e2e.sh`) that runs read-only plans across hosts and diffs vs labels.

### WS1 — Decision-core correctness (P0)
* 1.1 Loss matrix: make Kill reachable for abandoned/zombie-routed targets; renice must not dominate kill for
  abandoned (renice doesn't free memory/ports); explicit, documented tie-break. Regression: default policy,
  P(abandoned)=0.99, orphaned test runner → `kill`.
* 1.2 Score = calibrated suspicion (e.g. `100·(P(abandoned)+P(zombie))`, or expected-loss-of-keep
  normalized), never max-class. Sorting, KILL/REVIEW/SPARE bands, MCP, TUI, explain all use it.
* 1.3 Robot `min_posterior` gate uses P(abandoned ∪ zombie) (a ts1 Codex session already noticed the
  `1.0 - useful` mis-wiring).
* 1.4 Default `min_age` = policy `min_process_age_seconds` (3600) for plan/TUI/MCP/daemon; explicit override.
* 1.5 Linux age/identity from `/proc/<pid>/stat` starttime + `btime`, not ps `etimes`; sanity-bound ages;
  exact start ticks in start_id.
* 1.6 Orphan evidence: no double counting (Beta `orphan` + `provenance_ownership_orphaned`); on Linux
  orphan = reparented to init *or* to a subreaper (systemd --user) after its original parent died; on macOS
  orphan must not be `ppid==1` (launchd parents everything) — use responsibility/XPC/launchd job info.
* 1.7 Zombie handling: Z-state never gets renice/kill; route to parent (SIGCHLD nudge → parent restart/kill
  if parent itself abandoned). Parent candidacy must work even when the parent is a PID-1 child.
* 1.8 Remove fake fields: `uncertainty.entropy = n_terms*0.1`, ±0.1 CI, `build_stub_predictions`,
  `fleet_fdr: 0.03 // Placeholder`, hard-coded `blast_radius` in plan JSON — compute truthfully or omit.
* 1.9 Goal-selected PIDs must agree with per-candidate action.

### WS2 — Protection model that fits an agent-heavy fleet (P0)
* 2.1 Built-in "live infrastructure" signatures (protected by default, overridable): terminal multiplexer
  servers (frankenterm/wezterm-mux-server, tmux/zellij/screen servers), SSH ControlMasters (`ssh … -M`,
  control sockets) incl. rch's, `sshd-session`, `(sd-pam)`, `systemd --user`, login shells that are
  session leaders with live children, dashboards (cage/foot/htop in kiosk), database worker children
  (postgres/mysql/redis by *parent* identity), web server workers (nginx/apache/caddy workers by parent).
* 2.2 Agent CLIs (claude, codex, agy/gemini, pi, cursor-agent, am): live if TTY/pty activity, child
  activity, or session JSONL mtime recent; correct env var names (`CLAUDECODE`, `CLAUDE_CODE_SESSION_ID`,
  `CLAUDE_CODE_ENTRYPOINT`, `CODEX_*`), prefix/regex matching.
* 2.3 Root: replace "protect any root-named user" with "protect system services" (uid 0 **and** (systemd
  system unit, kernel thread, or listed daemon)) + policy profile `worker` for root-run user workloads
  (rch builds under /root, tmux sessions). Match by UID, not username string.
* 2.4 `never_kill_ppid:[1]`: stop filtering all PID-1 children before inference; instead protect system
  services by unit membership; keep PID 1 itself untouchable. Validation updated.
* 2.5 Supervision/intent checks fail **closed** in robot mode when evidence can't be read.

### WS3 — Action layer safety & completeness (P0/P1)
* 3.1 Identity: include boot_id; exact starttime; `pidfd_open` + `pidfd_send_signal` (Linux ≥ 5.3) so the
  signal targets the verified process; re-verify immediately before each escalation.
* 3.2 Data-loss gate: count only regular files opened O_WRONLY/O_RDWR (exclude std streams to ttys/pipes,
  sockets, /dev/null, anon inodes); `/proc/locks` parser handles `->` waiter lines.
* 3.3 Freeze/throttle/quarantine: create a dedicated leaf cgroup (or refuse when the target shares its
  cgroup with other live processes incl. pt itself); capture & restore previous state.
* 3.4 `agent apply` uses the composite runner (renice/freeze/throttle/quarantine/restart via supervisor);
  Restart implemented through systemd/launchd/pm2/supervisor detection or reported unsupported *before*
  planning it.
* 3.5 Total blast-radius budget accumulates real bytes (`record_action(0, …)` bug).
* 3.6 macOS execution for kill/pause/renice with equivalent identity checks (`proc_pidinfo` start time).

### WS4 — Collection correctness & performance (P0/P1)
* 4.1 io_uring prober: fix SQ overflow (chunk ≤ ring/paths), never drop the timeout SQE, no buffer free
  while reads are in flight (cancel + drain CQEs), per-chunk user_data namespaces; Miri/ASan-style test +
  fault injection for D-state stalls.
* 4.2 One `NetworkSnapshot` per scan shared by all candidates; one fd walk per pid; passwd/group cache;
  ancestor cache; kill O(N·C)/O(K²) loops. Budget: ≤ 5 s on 2 000 procs / 50 k sockets at load 500
  (hz3 366 s → target, ts2 86 s → target). Criterion bench + budget test with synthetic /proc fixture.
* 4.3 `io_active` = rate over a sampling window (two samples Δt), not lifetime totals; net/queue evidence
  in `agent plan` (not only TUI).
* 4.4 `--deep` in `agent plan` actually runs deep collection and feeds all evidence terms.

### WS5 — Ship what exists (P0)
* 5.1 Release & install build with `--features ui,report,daemon` (metrics optional); binary-size budget
  script updated; musl builds included.
* 5.2 Wrapper: bash 3.2 empty-array `set -u` crash; `pt --version` shows wrapper + core; `pt update`
  passthrough for `update rollback/list-backups`; pin release signing-key fingerprint.
* 5.3 Stubs must exit non-zero (`report`, macOS `deep-scan`, `telemetry export/redact`, `query …`).
* 5.4 `config validate` detects file type by content/schema, not filename substring.
* 5.5 Session retention: automatic GC each run honoring `PROCESS_TRIAGE_RETENTION` (default 7 d) incl.
  `Planned`/`Scanning` sessions; one-shot migration cleans ts1-style backlogs (after confirmation).
* 5.6 Quality gates green: fmt, 6 clippy errors, all-features test compile (process_table.rs), root-safe
  prechecks tests, BATS fixture manifests regenerated *with review*, README link test, test-11 quoting,
  BSD-portable BATS helpers; CI infra (nightly components, musl target, toon dep vendoring/crates.io,
  update-packages.yml).
* 5.7 Fleet rollout: all 20 hosts on the same version (workers are on 2.0.5).

### WS6 — Learning & calibration loop (P1) — the part that makes "Bayesian" true
* 6.1 Decision store: record every apply outcome and every human kill/spare (TUI, CLI `pt spare/kill`,
  MCP) into `decisions.json` (or sqlite) with pattern keys at 3 specificity levels; `pt history/clear`
  operate on it.
* 6.2 Wire `PatternLearner` → `user_overrides` priors (hierarchical: exact → standard → broad with
  partial pooling), with decay and caps; explain shows the learned contribution.
* 6.3 Shadow mode as the label factory: run on dev boxes, record trajectories + later outcomes (process
  exited by itself? user killed it? still running idle after N h?) → weak labels; TUI quick-label flow.
* 6.4 Calibration report: reliability diagram / ECE per signature category from shadow + labels; priors
  refit (empirical Bayes) from fleet data, versioned `priors.json`.

### WS7 — Wire the advanced machinery *only where measured* (P2, gated on WS0/WS6)
* 7.1 Conformal robot gate (Mondrian by category) + single-host eBH FDR in `agent apply --robot`, active
  once ≥ N calibration labels; otherwise robot mode refuses kills (not "posterior-only").
* 7.2 Respawn-loop tracker in apply/verify with supervisor-stop recommendation.
* 7.3 Transitive blast radius (BFS with decay) + real estimator output in plan JSON.
* 7.4 Temporal evidence from daemon/shadow tick streams: BOCPD on CPU/IO deltas and a Hawkes/idle-hazard
  term — added via an ablation protocol: a model is wired only if it improves WS0 metrics on held-out
  labels; otherwise it stays documented as experimental.
* 7.5 MCP `pt_plan` uses the real engine; README tool list corrected.
* 7.6 Goal optimizer: port/fd goals + `free port N` grammar.
* 7.7 Telemetry recorder wired (or claim removed); Parquet only if consumed by calibration.

### WS8 — Fleet mode for this fleet (P1)
* 8.1 Inventory from `~/.ssh/config` host groups (dev/workers); version check + optional remote install.
* 8.2 `fleet scan/plan` CLI matches docs (or docs match CLI) incl. `--fdr-method`.
* 8.3 Fleet apply with `--confirm`, per-host identity/prechecks executed remotely, per-host kill caps.
* 8.4 Cross-host dependency awareness only if real (rch ControlMaster ↔ worker sshd pairs are exactly this
  case); otherwise remove Chandy-Lamport claim.
* 8.5 Daemon as systemd `--user` / launchd agent with install/uninstall, memory-pressure escalation,
  notifications; dry-run by default.

### WS9 — Documentation truth (continuous, P1)
* README: remove/qualify every overclaim in §2 as it stands at release time; "experimental library
  modules" section; correct fleet/MCP/daemon/TUI availability; macOS limitations; config paths
  (`~/Library/Application Support/process_triage` on macOS); tutorials 06/07; CLI_SPECIFICATION drift;
  AGENTS.md config table. Doc-truth test: every README command example executes in CI (no stub output).

---

## 4. Ambition pass (Phase 4) — where genuinely better math pays off here

The biggest error signal is not model sophistication; it is **wrong evidence**. So ambition goes into
evidence that is close to causal truth, then principled statistics on top:

1. **Consumer-liveness evidence (causal):** a process is abandoned when nothing consumes its effects.
   Build the output-consumer graph: pipe/pty readers alive and reading (fdinfo pos deltas), socket peers
   with recent traffic (tcp_info / `/proc/net` byte deltas), listeners with accepted connections, files
   written that anyone reads. "No live consumer for T" is a far stronger Bayes factor than idle CPU.
2. **Survival analysis for runtime evidence:** replace fixed Gamma runtime likelihoods with per-signature
   Kaplan–Meier / Weibull lifetime models learned from shadow data *with right-censoring* (processes
   still alive). Evidence = hazard-based "probability it should have finished by now".
3. **Hierarchical (partial-pooling) priors** per signature × host-role (dev box / worker / mac) estimated
   by empirical Bayes from fleet labels; shrinkage toward global priors for rare signatures.
4. **Anytime-valid idleness test** (e-process / test martingale on CPU+IO+consumer-activity increments)
   for the daemon: sequentially accumulates evidence of abandonment, with a guarantee that the false-kill
   rate is controlled at any stopping time — this is where the existing `martingale.rs` finally earns its keep.
5. **Mondrian conformal per category** once labels exist (existing `conformal.rs`), combined with eBH
   across candidates — robot mode's guarantee becomes real and testable against WS0.
6. **pidfd-based atomic action protocol** (open pidfd at plan time → verify → act through the fd) removes
   PID-reuse TOCTOU entirely on modern Linux.
7. **Ablation-driven wiring**: each advanced model enters the posterior through BMA/stacking only when
   it improves held-out log-loss / precision@k on WS0 + shadow labels; the ledger reports its weight.

---

## 5. What "done" means

* On the 20-host fleet, a read-only plan: 0 `must_not_flag` hits; zombies routed to parents; idle stuck
  test runners flagged kill with P ≥ 0.95; wall time ≤ 5 s everywhere; identical behavior across versions.
* Released binary: `pt` opens the TUI; `pt agent apply` executes all advertised actions or refuses
  before planning them; robot mode refuses kills without calibration.
* All quality gates + CI green; README claims each backed by a test.
