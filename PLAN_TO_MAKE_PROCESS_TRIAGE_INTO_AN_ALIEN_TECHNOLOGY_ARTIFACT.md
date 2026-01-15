# PLAN_TO_MAKE_PROCESS_TRIAGE_INTO_AN_ALIEN_TECHNOLOGY_ARTIFACT.md

## 0) Non-Negotiable Requirement From User
This plan MUST incorporate every idea and math formula from the conversation. The sections below explicitly enumerate and embed all of them. This is a closed-form Bayesian and decision-theoretic system with no ML.
Operational requirement: `pt` must be able to run end-to-end in a full-auto mode (collect -> infer -> recommend -> (optionally) act) with no user interaction except (by default) a final TUI approval step for destructive actions. A `--robot` flag must exist to skip the approval UI and execute automatically.

---

## 1) Mission and Success Criteria

Mission: transform Process Triage (pt) into an "alien technology artifact" that combines rigorous closed-form Bayesian inference, optimal stopping, and system-level decision theory with a stunningly explainable UX.

Implementation stance (critical): keep `pt` as a thin bash wrapper/installer for cross-platform ergonomics, but move all inference, decisioning, logging, and UI into a monolithic Rust binary (`pt-core`) for numeric correctness, performance, and maintainability.

Operational stance (critical): make every run operationally improvable by recording both raw observations and derived quantities to append-only Parquet partitions, with DuckDB as the query engine over those partitions for debugging, calibration, and visualization.

Success criteria:
- Decision quality: <1% false-kill rate in shadow mode, high capture of abandoned/zombie processes.
- Explainability: every decision has a full evidence ledger, posterior, and top Bayes factors.
- Safety: no auto-kill by default; multi-stage mitigations; guardrails enforced by policy; `--robot` explicitly opts into automated execution.
- Performance: quick scan <1s, deep scan <8s for typical process counts.
- Closed-form Bayesian core: posterior/odds/expected-loss updates use conjugate priors; no ML.
- Formal guarantees: PAC-Bayes bound on false-kill rate with explicit confidence.
- Real-world impact weighting: kill-cost incorporates dependency and user-intent signals.
- Operational learning loop: every decision is explainable and auditable from stored telemetry (raw + derived + outcomes).
- Telemetry performance: logging is low-overhead (batched Parquet writes; no per-row inserts).
- Telemetry safety: secrets/PII are redacted or hashed by policy before persistence.
- Concurrency safety: Parquet-first storage supports concurrent runs without DB write-lock contention.
- Full-auto UX: default mode runs to a pre-toggled approval UI; `--robot` runs to completion without prompts.

---

## 2) Source Idea Inventory (All Ideas and Formulas Captured)

This plan includes ALL of the following ideas and formulas from the conversation, verbatim or fully represented:

A) Basic closed-form Bayesian model (non-ML)
- Class set: C in {useful, useful-but-bad, abandoned, zombie}
- Bayes rule: P(C|x) proportional to P(C) * P(x|C)
- Features: CPU usage u, runtime t, PPID, command, CWD, state flags, child count, TTY, I/O wait, CPU trend
- Likelihoods:
  - u|C ~ Beta(alpha_C, beta_C)
  - t|C ~ Gamma(k_C, theta_C)
  - orphan o|C ~ Bernoulli(p_C), p_C ~ Beta(a_C, b_C)
  - state flags s|C ~ Categorical(pi_C), pi_C ~ Dirichlet(alpha_C)
  - command/CWD categories g|C ~ Categorical(pi_C), pi_C ~ Dirichlet(alpha_C)
- Posterior (Naive Bayes):
  P(C|x) proportional to P(C) * product_j P(x_j|C)
- Log-posterior formula:
  log P(C|x) = log P(C) + log BetaPDF(u; alpha_C, beta_C) + log GammaPDF(t; k_C, theta_C)
                + o log p_C + (1-o) log(1-p_C) + log pi_{C,g} + ...

B) Decision rule via expected loss (Bayesian risk)
- a* = argmin_a sum_C L(a,C) P(C|x)
- Example loss matrix:
  - useful: keep=0, kill=100
  - useful-but-bad: keep=10, kill=20
  - abandoned: keep=30, kill=1
  - zombie: keep=50, kill=1

C) Survival analysis and hazards
- hazard lambda_C
- P(still running | t, C) = exp(-lambda_C * t)
- Gamma prior on lambda_C yields closed-form posterior; integrated survival has Beta-like form

D) Change-point detection (closed-form)
- U_t ~ Beta(alpha_1, beta_1) before tau
- U_t ~ Beta(alpha_2, beta_2) after tau
- Geometric prior on tau; posterior computed via Beta-binomial

E) Hierarchical priors by command category
- alpha_{C,g}, beta_{C,g} ~ Gamma(...)

F) Continuous-time hidden semi-Markov chain
- S_t in {useful, useful-bad, abandoned, zombie}
- durations D_S ~ Gamma(k_S, theta_S)

G) CPU model as Markov-modulated Poisson / Levy subordinator
- N(t) ~ Poisson(kappa_S * t)
- burst size X_i ~ Exp(beta_S)
- cumulative CPU: C(t) = sum_{i=1..N(t)} X_i
- yields Gamma process with closed-form likelihood

H) Bayes factors for model selection
- BF_{H1,H0} = [integral P(x|theta,H1)P(theta|H1) dtheta] / [integral P(x|theta,H0)P(theta|H0) dtheta]
- log posterior odds = log BF + log prior odds

I) Optimal stopping + SPRT
- Kill if log odds cross a boundary:
  log [P(abandoned|x) / P(useful|x)] > log [(L(keep,useful)-L(kill,useful)) / (L(kill,abandoned)-L(keep,abandoned))]

J) Queueing theory for system-level cost
- M/M/c or M/G/c model
- Erlang-C delay: W_q = C(c,rho) / (c*mu - lambda)

K) Value of Information
- VOI = E[Delta loss | new observation] - cost of waiting
- If VOI < 0, act now

L) Robust Bayes (imprecise priors)
- P(C) in [lower P(C), upper P(C)]
- only kill if even optimistic posterior favors abandoned

M) Information-theoretic abnormality
- KL divergence: D_KL(p_hat || p_useful)
- Chernoff bound: P(useful) <= exp(-t * I(p_hat))
- Large deviations / rate functions

N) Wonham filtering (continuous-time partial observability)
- filter hidden states in continuous-time

O) Gittins indices
- optimal scheduling / stopping index for CPU trade-offs

P) Process genealogy / Bayesian network
- PPID tree as Bayesian network or Galton-Watson branching process
- orphan prior: BF = P(PPID=1|abandoned) / P(PPID=1|useful)
- "cobweb" model for process tree causality

Q) Practical enhancements
- Observability: IO, wait, syscalls, context switches, page faults, swap, run-queue delay, fd churn, lock contention, socket backlog
- Context signals: TTY, tmux session, git status, active shell commands
- Expanded action space: SIGSTOP, renice, cgroup throttle, cpuset quarantine, restart
- Shadow mode / A-B evaluation
- Human feedback updates priors
- Policy engine with cost matrix tied to SLOs
- Incident integration and rollback
- Rate limiting and quarantine
- Systemd / Kubernetes plugins
- Explainability ledger and audit logs
- Kill simulations (SIGSTOP) before kill
- No deletion of data; transparent logs

S) Causal intervention layer (do-calculus)
- Compare interventions: P(recovery | do(kill)) vs P(recovery | do(pause)) vs P(recovery | do(throttle))
- Closed-form Bernoulli/Beta outcome models per action

T) Coupled process-tree model
- Graphical coupling on PPID tree (Ising-style prior or pairwise Potts)
- Correlated state model: P(S_parent, S_child) with conjugate updates via pseudolikelihood

U) POMDP / belief-state decision
- Belief update: b_{t+1}(S) proportional to P(x_{t+1}|S) * sum_{S'} P(S|S') b_t(S')
- Myopic Bayes-optimal action under belief state (closed-form expected loss)

V) PAC-Bayes generalization guarantees
- Bound false-kill rate in shadow mode using Beta posterior on error rate
- Report: P(err <= eps) >= 1 - delta

W) Empirical Bayes calibration
- Fit hyperparameters by maximizing marginal likelihood of shadow-mode logs
- Still closed-form for conjugate families

X) Minimax / least-favorable priors
- Robust Bayes extended to minimax Bayes to guard against adversarial noise

Y) Time-to-decision bound
- If posterior odds do not cross threshold by T_max, default to pause+observe
- T_max derived from VOI decay and acceptable CPU-cost budget

Z) Dependency impact weighting
- Loss matrix scaled by live dependency graph (open sockets, clients, child process health)
- Kill cost increases with critical dependencies

AA) Hawkes processes (self-exciting point processes)
- Model bursty CPU/IO/syscall events with exponential kernels
- Closed-form likelihood for exponential kernels; conjugate updates for intensities

AB) Marked point processes
- Event times + magnitudes (syscall event + cost)
- Closed-form likelihood in exponential family

AC) Bayesian nonparametric survival (Beta-Stacy)
- Flexible hazard modeling with closed-form updates on discrete time bins

AD) Empirical Bayes shrinkage (Efron-Morris)
- Hyperparameters tuned by marginal likelihood; still closed-form for conjugate families

AE) Bayesian online change-point detection (BOCPD)
- Exact run-length recursion with conjugate updates

AF) Robust statistics (Huberization)
- Robust likelihoods to reduce noise/adversarial effects on log-CPU or event rates

AG) Large deviations / rate functions (Chernoff, Cramer)
- Quantify rarity of observed CPU/IO traces under useful hypothesis

AH) POMDP with belief-state approximation
- Belief update in closed form with discrete states
- Myopic Bayes-optimal action selection

AI) Multivariate Hawkes processes (cross-excitation)
- Model cross-metric bursts (syscalls -> IO -> network)
- Closed-form likelihood for exponential kernels with Gamma priors

AJ) Copula models for dependence (Archimedean/vine)
- Joint CPU/IO/net dependence without independence assumptions
- Closed-form densities for common copulas

AK) Risk-sensitive control / coherent risk measures
- CVaR and entropic risk to penalize tail-risk kills
- Closed-form for discrete outcome models

AL) Bayesian model averaging (BMA)
- Weight multiple models by marginal likelihood
- Avoids single-model brittleness; closed-form weights

AM) Composite-hypothesis testing (mixture SPRT / GLR)
- Generalized likelihood ratio for composite alternatives
- Closed-form with conjugate mixtures

AN) Linear Gaussian state-space (Kalman)
- Smooth CPU/load signals; closed-form filtering/smoothing

AO) Optimal transport / Wasserstein distances
- Distribution-shift detection with analytic 1D OT distances

AP) Martingale concentration / sequential bounds
- Azuma/Freedman bounds for sustained anomaly detection

AQ) Graph signal processing / Laplacian regularization
- Smooth posteriors on PPID tree; MAP via MRF with closed-form quadratic form

AR) Renewal reward / semi-regenerative processes
- Model event rewards (CPU/IO) between renewals with conjugate updates

AS) Conformal prediction (distribution-free coverage)
- Prediction intervals for runtime/CPU with finite-sample guarantees

AT) False Discovery Rate (FDR) control across many processes
- Multiple-testing correction (Benjamini-Hochberg, local fdr) for kill recommendations
- Prevents “1 false-kill in a thousand processes” during large scans

AU) Restless bandits / Whittle index policies
- Schedule deep scans/instrumentation under overhead budgets
- Choose which PIDs get eBPF/perf/stack sampling when you cannot instrument all

AV) Bayesian optimal experimental design (active sensing)
- Choose next measurement (perf vs eBPF vs stack sample) that maximizes expected information gain per cost
- Uses Fisher information / mutual information in exponential families

AW) Extreme value theory (POT/GPD)
- Model CPU/IO spike tails via peaks-over-threshold and generalized Pareto
- Distinguish legitimate spiky workloads from pathological runaway spikes

AX) Streaming sketches / heavy-hitter theory
- Count-Min sketch / Space-Saving to summarize high-rate events (syscalls, bytes) at scale
- Allows “collect everything” while staying low-overhead

AY) Belief propagation / message passing on process tree
- Exact sum-product on PPID trees for coupled state models (when tree-structured)
- Produces exact marginal posteriors under pairwise couplings (no pseudolikelihood needed on trees)

AZ) Wavelet / spectral periodicity analysis
- Detect periodic CPU/IO patterns (cron-like vs pathological loops) via wavelets or periodograms
- Multi-scale decomposition features feed survival/change-point models

BA) Switching linear dynamical systems (IMM filter)
- Combine discrete regime switching with Kalman dynamics for CPU/IO time series
- Closed-form updates via interacting multiple-model filtering

BB) Online FDR / alpha-investing for sequential operations
- Control false-kill risk over time as decisions accumulate
- Complements batch BH FDR in 4.32

BC) Posterior predictive checks / Bayesian model criticism
- Detect model misspecification by comparing observed traces to posterior predictive distributions
- Can be computed in closed form for conjugate families (e.g., Beta-Binomial, Gamma-Poisson)

BD) Distributionally robust decision theory (DRO)
- Guard against distribution shift using ambiguity sets (e.g., Wasserstein / f-divergence balls)
- Produces conservative expected-loss estimates; complements robust Bayes

BE) Submodular probe selection (near-optimal sensor scheduling)
- When probes have overhead and mutual redundancy, choose a set maximizing coverage/information
- Greedy selection with approximation guarantees; integrates with active sensing/Whittle policies

BF) Telemetry & analytics (Parquet-first + DuckDB query engine)
- Record raw tool outputs + normalized samples + derived quantities (features, likelihood terms, posteriors, VOI, actions, outcomes)
- Write append-only Parquet partitions (batched) for low overhead and concurrency safety
- Use DuckDB to query Parquet for calibration, debugging, visualization, and iterative manual improvement

BG) Implementation architecture (bash wrapper + monolithic Rust core)
- Keep `pt` as a cross-platform installer/orchestrator only
- Implement `pt-core` as the single high-performance artifact that does collection orchestration, inference, decisioning, logging, and UI
- Rationale: numeric stability (log-domain math, special functions), structured concurrency, high-throughput parsing, and multi-core feature/inference pipelines

BH) Privacy/secrets governance for telemetry
- Redact or hash sensitive fields (cmdline paths, env, endpoints) before persistence
- Preserve analytic utility via categorization + stable hashes for grouping without leakage

BI) Agent/robot CLI contract (no TUI)
- Full access to plan/explain/apply/session/report without interactive UI
- Token-efficient JSON/Markdown/JSONL outputs with stable schema + automation-friendly exit codes
- Pre-toggled plan semantics identical to the TUI defaults

BJ) Shareable session bundles + rich HTML reports
- One-file `.ptb` export with manifest, plan, telemetry (Parquet), optional raw (redacted), and a single-file HTML report
- Report loads UI libraries from CDNs (pinned + SRI) and delivers a premium “postmortem dashboard” UX

BK) Dormant mode (always-on guardian)
- Low-overhead daemon monitors for “triage needed” signals and escalates to active mode automatically
- Produces a ready-to-approve plan (or auto-applies mitigations only when explicitly configured)

R) Use-case interpretation of observed processes
- bun test at 91% CPU for 18m in /data/projects/flywheel_gateway
- gemini --yolo workers at 25m to 4h46m
- gunicorn workers at 45-50% CPU for ~1h
- several claude processes active

All of these are integrated in the system design below.

---

## 3) System Architecture (Full Stack)

### 3.0 Execution & Packaging Architecture
- `pt` (bash) remains for: OS detection, maximal tool installation, capability detection, and launching `pt-core`.
- `pt-core` (Rust monolith) is the artifact: structured concurrency for collection, robust parsing, all inference/decision math, telemetry writing, and the explainable UI.
- Subcommands (conceptual):
  - Analysis pipeline: `pt-core scan`, `pt-core deep-scan`, `pt-core infer`, `pt-core decide`
  - Human UI: `pt-core ui` (Apply Plan TUI)
  - Agent/robot UI: `pt-core agent` (JSON/Markdown/JSONL outputs; no TUI)
  - Telemetry analytics: `pt-core duck` (run standard DuckDB reports/queries)
  - Sharing & reporting: `pt-core bundle`, `pt-core report` (single-file HTML)
  - Always-on mode: `pt-core daemon` (dormant monitor + escalation)
- Modes:
  - Default: full-auto scan -> infer -> decide -> TUI approval with recommended actions pre-toggled.
  - `--robot`: skip TUI and execute the policy-approved action plan automatically (still subject to safety gates).
  - `--shadow`: run full-auto but never execute actions; log everything for calibration.
  - `--dry-run`: compute and print the action plan without executing (even if `--robot` is set).
- Outputs:
  - Human: TUI + explainability ledger.
  - Machine: `--output json` for integrations and unattended runs.
- Design rule: all cross-process boundaries are for external system tools only (perf/eBPF/etc.); internal boundaries stay in-process for performance and coherence.

### 3.1 Data Collection Layer
- Collection is orchestrated in `pt-core` as a staged pipeline: quick scan -> candidate ranking -> deep scan/instrumentation (when warranted).
- Quick scans are multi-sample (short window) to compute deltas/trends (CPU ticks, IO deltas, scheduler latency proxies) rather than relying on a single snapshot.
- Every collector emits structured events with provenance (tool name/version, args, exit code, timing). Raw outputs are captured (subject to redaction) alongside parsed fields for auditability.
- Installation is maximal, execution is budgeted: even if all tools are installed, expensive probes are scheduled via VOI/Whittle/submodular policies to control overhead.
- Self-protection: `pt-core` runs with an overhead budget (caps concurrency, sampling rates, and optional nice/ionice) so the triage system does not become a new source of load.
- Quick scan inputs (fast): ps pid, ppid, etimes, rss, %cpu, tty, args, state
- Deep scan inputs (slow):
  - /proc/PID/io (read/write deltas)
  - /proc/PID/stat (CPU tick deltas)
  - /proc/PID/status (RSS, threads)
  - /proc/PID/wchan (wait channel)
  - ss -tnp (sockets) for network activity
  - pgrep -P (children)
  - who (TTY sessions)
  - cwd via /proc/PID/cwd
  - optional: git -C cwd status -sb
  - optional: lsof /proc/PID/fd for live dependency graph signals (open sockets, files)
  - optional: ss -ntp correlation for live client count
  - optional: perf (cycles, cache misses, branch mispredicts)
  - optional: bpftrace / bcc (eBPF probes for syscalls, IO, scheduler latency)
  - optional: pidstat / iostat / mpstat / vmstat (sysstat suite)
  - optional: iotop (per-process IO)
  - optional: nethogs / iftop (per-process network throughput)
  - optional: sar (historical system metrics)
  - optional: atop (historical per-process accounting)
  - optional: sysdig (syscall stream capture)
  - optional: bpftool (eBPF program and map stats)
  - optional: turbostat / powertop (CPU frequency/residency)
  - optional: numastat (NUMA locality)
  - optional: smem (accurate RSS/USS/PSS)
  - optional: systemd-cgtop / cgget (cgroup v2 stats)
  - optional: conntrack-tools (connection tracking)
  - optional: nvidia-smi / rocm-smi (GPU process metrics)
  - optional: /proc/pressure/* (PSI) and /proc/schedstat
  - optional: acct/psacct (process accounting: lastcomm, sa)
  - optional: auditd (system call auditing, security context)
  - optional: pcp (Performance Co-Pilot) for richer historical + per-process time series
  - optional: flamegraph toolchain (stack profiling visualization)
  - optional: gdb + pstack/eu-stack (stack traces)
  - optional: language profilers: py-spy (Python), rbspy (Ruby), async-profiler (JVM), xctrace (macOS, if Xcode)
  - optional: osquery (structured system query surface)
  - optional: intel-pcm (memory bandwidth / uncore counters, where available)
- OS-level metrics for queueing cost and VOI:
  - loadavg, run-queue delay, iowait, memory pressure, swap activity

### 3.2 Feature Layer
- Feature computation is deterministic and provenance-aware: each derived quantity records its input sources and time window so it can be recomputed and debugged from telemetry.
- u: CPU usage normalized [0,1]
- t: elapsed time (seconds)
- o: orphan indicator (PPID=1)
- s: state flags (R,S,Z,D)
- g: command category (test, dev, agent, shell, build, daemon, unknown)
- cwd category: repo root, temp, unknown
- tty: active/detached
- io delta: active/idle
- cpu delta: progressing/stalled
- net activity: connected/no_connections
- wait channel: waiting_io/sleeping/waiting_child/running
- child activity: active_children/idle_children/no_children
- change-point statistics for CPU and IO
- survival term for runtime vs expected lifetime
- dependency impact score: live sockets, client count, open files, service bindings
- user intent signal: active TTY + recent shell + editor focus + project activity window
- belief transition probabilities for POMDP update
- Hawkes intensity parameters for event bursts (syscall/IO)
- Marked point process summaries (event magnitudes and rates)
- BOCPD run-length posterior for CPU/IO regimes
- Robust stats summaries (Huberized residuals for CPU/IO)
- perf-derived indicators (cache miss ratio, branch mispredict rate)
- eBPF-derived indicators (scheduler latency, syscall rate)
- PSI metrics (CPU/IO/memory stall)
- cgroup CPU/IO/memory pressure stats
- stack sampling fingerprints (tight loop vs blocked)
- NUMA locality indicators
- GPU utilization per PID (if present)
- copula dependence parameters across CPU/IO/net
- Kalman-smoothed CPU/load trend estimates
- martingale deviation bounds for sustained anomalies

### 3.3 Telemetry & Analytics Layer (Parquet-first, DuckDB query engine)
Telemetry is a first-class system component, not an afterthought. It is the substrate for shadow-mode calibration, PAC-Bayes guarantees, FDR tuning, empirical Bayes hyperparameters, and manual “why did it do that?” debugging.
DuckDB is the query engine because it is analytics-native: fast columnar scans, great for time series slices, joins across runs, and ad-hoc postmortems on decisions.

Storage approach:
- Write append-only Parquet partitions as the primary sink (low overhead, compressible, concurrency-safe).
- Query the Parquet lake with DuckDB (views over partitions). Optionally maintain a small `.duckdb` file for convenience views and macros, but do not rely on it for multi-writer ingestion.
- If a `.duckdb` file is used, treat it as read-mostly (or per-run) so concurrent runs never contend on a single writable DB file.
- Avoid per-row inserts; batch writes per scan cycle and emit new Parquet files atomically.
- Default telemetry root: a single per-user directory (e.g., `~/.local/share/pt/telemetry/`), overridable via config/env, so full-auto runs always have somewhere to write.
- Raw tool outputs are recorded with strict size caps and redaction; structured parsed fields are the primary analytic surface.
- Retention: enforce a disk budget and TTL for raw outputs and high-volume tables; keep aggregated summaries longer than raw streams.

What gets logged (raw + derived + outcomes):
- `runs`: run_id, host fingerprint, git commit, priors/policy snapshot hash, tool availability/capabilities, pt-core version.
- `system_samples`: timestamped loadavg, PSI, memory pressure, swap, CPU frequency/residency, queueing proxies.
- `proc_samples`: pid/ppid/state, cpu/rss/threads, tty/cwd/cmd categories, socket/client counts, cgroup identifiers.
- `proc_features`: Hawkes/BOCPD/Kalman/IMM state, copula params, EVT tail stats, periodicity features, sketches/heavy-hitter summaries.
- `proc_inference`: per-class log-likelihood terms, Bayes factors, posterior, lfdr, VOI, PPC flags, DRO drift scores.
- `decisions`: recommended action, expected loss, thresholds, FDR/alpha-investing state, safety gates triggered.
- `actions` + `outcomes`: what was actually done (if anything), and what happened next (recovery, regressions, user override).

Partitioning rule (example):
- Partition by `date` and `run_id` (and optionally `host_id`) so each run writes its own files and concurrent runs do not contend.

### 3.4 Redaction, Hashing, and Data Governance
- Before persistence, apply a redaction policy to sensitive fields (full cmdlines, paths, endpoints, env values).
- Preserve analytical utility by logging: command/category tokens, stable hashes for grouping, and carefully scoped allowlists.
- Keep an explicit “telemetry schema + redaction version” in `runs` so old data remains interpretable.

### 3.5 Agent/Robot CLI Contract (No TUI)
Goal: give coding agents a hyper-ergonomic console interface that exposes everything a human can see/do in the TUI, but via token-efficient JSON/Markdown outputs and deterministic automation primitives.

Core commands (conceptual surface; wrapper `pt` forwards to `pt-core agent ...`):
- `pt agent plan`:
  - Runs full-auto exploration (quick scan -> targeted deep scan -> infer -> decide).
  - Returns: `session_id`, `schema_version`, system snapshot, candidates, and a pre-toggled recommended plan (the same items the TUI would preselect).
- `pt agent explain --session <id> --pid <pid>`:
  - Returns: “why” summary + full evidence ledger (likelihood terms/Bayes factors) + relevant raw/proc samples (capped/redacted).
- `pt agent apply --session <id> --recommended --yes`:
  - Executes the recommended pre-toggled plan without UI.
  - Requires explicit `--yes`; respects `--shadow` and `--dry-run`.
- `pt agent sessions` / `pt agent show --session <id>` / `pt agent tail --session <id>`:
  - Discover, inspect, and stream progress for automation and debugging.
- `pt agent export --session <id> --out bundle.ptb` and `pt agent report --session <id> --out report.html`:
  - Programmatic sharing and reporting.

Output formats:
- Default: `--format json` (token-efficient and machine-stable).
- Optional: `--format md` (human-readable, still concise).
- Streaming: `--format jsonl` for progress/events (`plan_started`, `scan_done`, `infer_done`, `gates_evaluated`, `action_applied`, ...).
- Projection: `--fields`/`--compact`/`--limit`/`--only kill|review|all` to control token usage.

Schema invariants (for agents):
- Every output includes: `schema_version`, `session_id`, `generated_at`, and a stable `summary`.
- “Pre-toggled” semantics are explicit:
  - `recommended.preselected_pids` and/or `recommended.actions[]` (with staged action chains and per-PID safety gates).
- Exit codes are automation-friendly:
  - `0` clean / nothing to do
  - `1` candidates exist (plan produced) but no actions executed
  - `2` actions executed successfully
  - `3` partial failure executing actions
  - `4` blocked by safety gates / policy
  - `>=10` tooling/internal error

### 3.6 Session Bundles & Rich HTML Reports (Shareable Artifacts)
Goal: one-command export/share of a complete session, and one-command generation of a premium, richly interactive HTML report.

Bundle format (`.ptb`):
- A single portable file that contains:
  - `manifest.json` (schema versions, tool versions/capabilities, host fingerprint, redaction policy version, checksums)
  - `plan.json` (candidates + recommended actions + gates)
  - `telemetry/` (Parquet partitions or reduced aggregates, depending on profile)
  - `raw/` (optional; capped & redacted)
  - `report.html` (single static file; CDN-loaded libs)

Export profiles:
- `--profile minimal`: plan + summary only (max safe, tiny).
- `--profile safe`: includes derived features/inference but aggressively redacts raw strings/paths/endpoints.
- `--profile forensic`: includes more raw data; optionally support `--encrypt` for transport.

HTML report (single file, CDN-loaded):
- Requirements:
  - Single `report.html` that embeds session data (or references bundled Parquet) and loads UI/chart libraries from CDNs with pinned versions and SRI.
  - Visual polish: overview dashboard, sortable/searchable candidate table, per-process drilldown (timelines, evidence ledger, process tree, dependency impact), and actions/outcomes with before/after diffs.
  - Optional “power mode”: DuckDB-WASM in-browser for interactive queries over embedded/attached Parquet (when bundle profile permits).

### 3.7 Dormant Mode (Always-On Guardian)
Goal: keep pt running 24/7 with minimal overhead, automatically detecting when active triage is needed and escalating to full analysis.

Two operating modes:
- Active mode: full collection + inference + plan generation (resource-intensive; on-demand).
- Dormant mode (`ptd`): lightweight monitoring loop with strict overhead budget.

Dormant mode mechanics:
- Collect minimal signals at low frequency (loadavg, PSI, memory pressure, process count, top-N CPU by PID).
- Maintain baselines and detect triggers (sustained load, PSI stall, runaway top-N CPU, orphan spikes).
- On trigger:
  1) run quick scan
  2) run targeted deep scans on top suspects (budgeted)
  3) generate a session + plan
  4) notify (CLI inbox + optional hooks)
  5) optionally auto-apply non-destructive mitigations (pause/throttle) if explicitly configured; default is “plan ready for review”.

Service integration:
- Linux: systemd user service by default (`ptd.service` + timer), optional system-level install.
- macOS: launchd agent.
- Must include: cooldowns, backoff, and “never become the hog” protections (nice/ionice, probe budgeting, and hard caps).

---

## 4) Inference Engine (Closed-Form Bayesian Core)
Design constraint: all posterior/odds/expected-loss updates used for decisions must remain closed-form (conjugate, log-domain, numerically stable). Richer layers (Hawkes/EVT/copulas/wavelets/profilers) are allowed to produce deterministic summary statistics or analytic filter states, but they must feed the decision core as fixed features or via conjugate likelihood surrogates so the end-to-end decision remains auditable and non-ML.

### 4.1 State Space
C in {useful, useful-but-bad, abandoned, zombie}

### 4.2 Priors and Likelihoods (Conjugate)
- CPU usage u|C ~ Beta(alpha_C, beta_C)
- Runtime t|C ~ Gamma(k_C, theta_C)
- Orphan o|C ~ Bernoulli(p_C), p_C ~ Beta(a_C, b_C)
- State flags s|C ~ Categorical(pi_C), pi_C ~ Dirichlet(alpha_C)
- Command/CWD g|C ~ Categorical(rho_C), rho_C ~ Dirichlet(alpha_C)
- TTY activity y|C ~ Bernoulli(q_C)
- Net activity n|C ~ Bernoulli(r_C)

### 4.3 Posterior Computation (Closed-form)
- P(C|x) proportional to P(C) * product_j P(x_j|C)
- log posterior formula:
  log P(C|x) = log P(C)
               + log BetaPDF(u; alpha_C, beta_C)
               + log GammaPDF(t; k_C, theta_C)
               + o log p_C + (1-o) log(1-p_C)
               + log pi_{C,g} + ...
- Marginalize nuisance parameters with conjugate priors:
  - Beta-Bernoulli for orphan and TTY
  - Dirichlet-Multinomial for categorical features

### 4.4 Bayes Factors for Model Selection
- BF_{H1,H0} = [integral P(x|theta,H1)P(theta|H1) dtheta] / [integral P(x|theta,H0)P(theta|H0) dtheta]
- log odds = log BF + log prior odds

### 4.5 Semi-Markov and Competing Hazards
- hidden semi-Markov states S_t
- duration D_S ~ Gamma(k_S, theta_S)
- competing hazards: lambda_finish, lambda_abandon, lambda_bad
- survival term: P(still running | t, C) = exp(-lambda_C * t)
- Gamma priors on hazard rates yield closed-form posterior

### 4.6 Markov-Modulated Poisson / Levy Subordinator CPU
- N(t) ~ Poisson(kappa_S * t)
- burst sizes X_i ~ Exp(beta_S)
- C(t) = sum_{i=1..N(t)} X_i
- yields Gamma process likelihood

### 4.7 Change-Point Detection
- U_t ~ Beta(alpha_1, beta_1) before tau
- U_t ~ Beta(alpha_2, beta_2) after tau
- geometric prior on tau; posterior via Beta-binomial

### 4.7b Bayesian Online Change-Point Detection (BOCPD)
- Run-length recursion with conjugate updates for CPU/IO event rates
- Maintains posterior over change points for regime shifts

### 4.8 Information-Theoretic Abnormality
- compute D_KL(p_hat || p_useful)
- Chernoff bound: P(useful) <= exp(-t * I(p_hat))
- large deviation rate functions for rare event detection

### 4.8b Large Deviations / Rate Functions
- Cramer/Chernoff bounds on event-rate deviations
- Quantifies probability of observing bursts under useful model

### 4.8c Copula Dependence Modeling
- Use Archimedean/vine copulas to model joint CPU/IO/net dependence
- Closed-form likelihoods for common copula families

### 4.9 Robust Bayes (Imprecise Priors)
- P(C) in [lower, upper]
- compute lower and upper posteriors; kill only if even optimistic posterior favors abandoned

### 4.10 Causal Intervention Models (do-calculus)
- For each action a in {pause, throttle, kill}, define outcome O in {recover, no_recover}
- O|a,C ~ Bernoulli(theta_{a,C}), theta_{a,C} ~ Beta(alpha_{a,C}, beta_{a,C})
- Compare P(O=recover | do(a)) using conjugate Beta-Bernoulli marginals

### 4.11 Wonham Filtering and Gittins Indices
- Wonham filtering for continuous-time partial observability of S_t
- Gittins index for optimal stopping / CPU scheduling of process decisions

### 4.12 Process Genealogy
- PPID tree as Bayesian network
- Galton-Watson branching model for expected child activity
- Orphan Bayes factor:
  BF_orphan = P(PPID=1|abandoned) / P(PPID=1|useful)
- "cobweb" model to represent process tree causality

### 4.13 Coupled Tree Priors (Correlated States)
- Pairwise coupling on PPID edges: P(S_u, S_v) proportional to exp(J * 1{S_u=S_v})
- Use pseudolikelihood updates to keep closed-form tractability

### 4.14 Belief-State Update (POMDP Approximation)
- b_{t+1}(S) proportional to P(x_{t+1}|S) * sum_{S'} P(S|S') b_t(S')
- Myopic decision: minimize expected loss under b_t with action set A

### 4.15 PAC-Bayes Guarantees (Shadow Mode)
- Let e be false-kill rate, e ~ Beta(a,b) after observing k errors in n trials
- Bound: P(e <= eps) >= 1 - delta, where eps = BetaInvCDF(1-delta; a+k, b+n-k)

### 4.16 Empirical Bayes Hyperparameter Calibration
- Maximize marginal likelihood over shadow logs to tune alpha/beta/k/theta
- Still closed-form for conjugate families; update priors periodically

### 4.17 Minimax / Least-Favorable Priors
- Choose priors in credal set that maximize expected loss; act only if decision robust

### 4.18 Time-to-Decision Bound
- Define T_max based on VOI decay and CPU-cost budget
- If no threshold crossing by T_max, default to pause + observe

### 4.19 Hawkes Process Layer (Self-Exciting Events)
- Model syscalls/IO/network events as Hawkes process with exponential kernels
- Closed-form likelihood for exponential kernels; conjugate Gamma priors on intensity

### 4.20 Marked Point Process Layer
- Event times with magnitudes (bytes read/write, syscall cost)
- Likelihood in exponential family; summarizes burst severity

### 4.21 Bayesian Nonparametric Survival (Beta-Stacy)
- Discrete-time hazard h_t with Beta priors; closed-form updates per bin
- Captures long-tail stuckness beyond Gamma assumptions

### 4.22 Robust Statistics (Huberized Likelihoods)
- Huber loss on log-CPU/IO residuals to reduce noise sensitivity
- Keeps inference stable under outliers and kernel noise

### 4.23 Linear Gaussian State-Space (Kalman)
- Smooth CPU/load signals; closed-form filtering and smoothing

### 4.24 Optimal Transport Shift Detection
- Use 1D Wasserstein distance between observed and baseline distributions
- Closed-form for univariate distributions

### 4.25 Martingale Sequential Bounds
- Azuma/Freedman bounds for sustained anomaly evidence over time

### 4.26 Graph Signal Regularization
- Laplacian smoothing on PPID tree to reduce noisy per-process posteriors

### 4.27 Renewal Reward Modeling
- CPU/IO rewards per renewal interval; conjugate updates for reward rates

### 4.28 Risk-Sensitive Control
- CVaR and entropic risk to penalize tail outcomes in action selection

### 4.29 Bayesian Model Averaging (BMA)
- Combine models by marginal likelihood weights; robust to misspecification

### 4.30 Composite-Hypothesis Testing
- Mixture SPRT / GLR for composite alternatives with conjugate mixtures

### 4.31 Conformal Prediction
- Distribution-free prediction intervals for runtime/CPU

### 4.32 FDR Control (Many-Process Safety)
- Treat “kill-recommended” as multiple hypothesis tests across many PIDs
- Use local false discovery rate: lfdr_i = P(useful_i | x_i)
- Select a kill set K that controls expected false-kill proportion (BH-style on lfdr or p-values from Bayes factors)

### 4.33 Restless Bandits / Whittle Index Scheduling
- Each PID is an arm; actions are {quick-scan, deep-scan, instrument, pause, throttle}
- Compute an index per PID approximating marginal value of deep inspection (VOI per cost)
- Prioritize limited-overhead probes (perf/eBPF/stack sampling) on highest-index PIDs

### 4.34 Bayesian Optimal Experimental Design (Active Sensing)
- Choose next measurement m to maximize expected posterior entropy reduction per cost:
  argmax_m [E_x (H(P(S|x)) - H(P(S|x, new=m))))] / cost(m)
- For exponential-family likelihoods, use Fisher information approximations as a closed-form proxy

### 4.35 Extreme Value Theory (POT/GPD) Tail Modeling
- Model exceedances of CPU/IO/network bursts above a high threshold u0
- Fit generalized Pareto tail parameters; treat heavy-tail behavior as evidence of pathological bursts (or known spiky workloads)

### 4.36 Streaming Sketches / Heavy-Hitter Summaries
- When event streams are huge (syscalls, bytes), maintain sketches:
  - Count-Min sketch for rates per PID
  - Space-Saving / Misra-Gries for heavy hitters
  - Reservoir sampling for representative stack traces / syscalls
- Feed sketch summaries into Hawkes/marked-point-process layers without storing raw events

### 4.37 Belief Propagation on PPID Trees
- For tree-structured coupling graphs, compute exact marginals via sum-product message passing
- Use as the primary coupled-tree inference when PPID graph is a forest

### 4.38 Wavelet / Spectral Periodicity Features
- Multi-resolution wavelet energy + dominant period estimates
- Separates periodic “expected” load from steady runaway loops

### 4.39 Switching Linear Dynamical Systems (IMM)
- Interacting multiple-model filter for regime-switching CPU/IO dynamics
- Improves regime inference beyond single Kalman + BOCPD

### 4.40 Online FDR / Alpha-Investing
- Maintain an error budget over time; allocate “kill attempts” only when posterior is extremely strong
- Provides long-run safety even under repeated scans

### 4.41 Posterior Predictive Checks
- Compare observed traces to posterior predictive distributions to detect misspecification
- If PPC fails, widen priors / switch to more robust layers (Huberization, DRO, robust Bayes)

### 4.42 Distributionally Robust Optimization (DRO)
- Replace expected loss with worst-case expected loss over an ambiguity set (e.g., Wasserstein ball)
- Produces conservative “don’t kill unless safe” decisions under distribution shift

### 4.43 Submodular Probe Selection
- When probes overlap (redundant info) and have overhead, pick a near-optimal set maximizing information gain
- Greedy selection yields approximation guarantees; integrates with 4.34 active sensing

---

## 5) Decision Theory and Optimal Stopping

### 5.1 Expected Loss Decision
- a* = argmin_a sum_C L(a,C) P(C|x)
- loss matrix:
  - useful: keep=0, kill=100
  - useful-but-bad: keep=10, kill=20
  - abandoned: keep=30, kill=1
  - zombie: keep=50, kill=1

### 5.2 Sequential Probability Ratio Test (SPRT)
- kill if:
  log [P(abandoned|x)/P(useful|x)] > log [(L(keep,useful)-L(kill,useful)) / (L(kill,abandoned)-L(keep,abandoned))]

### 5.3 Value of Information (VOI)
- VOI = E[Delta loss | new observation] - cost of waiting
- if VOI < 0 then act (kill/pause/throttle)

### 5.4 Queueing-theoretic Threshold Adjustment
- model CPU contention as M/M/c or M/G/c
- Erlang-C delay: W_q = C(c,rho) / (c*mu - lambda)
- increase aggressiveness as W_q grows

### 5.5 Dependency-Weighted Loss
- Scale kill cost by dependency impact score (live sockets, clients, child health)
- L_kill = L_kill * (1 + impact_score)

### 5.6 Causal Action Selection
- Choose action a by maximizing P(recover | do(a)) under cost constraints
- Prefer pause/throttle if recovery likelihood is comparable to kill

### 5.7 Belief-State Policy (Myopic POMDP)
- a* = argmin_a sum_S L(a,S) b_t(S)
- Use belief update from 4.14; enforce safety constraints

### 5.8 FDR-Gated Kill Set Selection
- Rank candidate kills by lfdr_i = P(useful_i | x_i) (lower is “safer to kill”)
- Choose the largest set K such that estimated FDR(K) <= alpha (shadow-mode calibrated)
- This prevents “scan many processes and inevitably kill one useful one”

### 5.9 Budgeted Instrumentation Policy (Whittle / VOI)
- Under overhead constraints, allocate expensive probes to the highest expected VOI per unit cost
- Prefer: pause -> observe -> deep-scan -> throttle -> kill (as confidence increases)

### 5.10 Active Sensing Action Selection
- Choose measurement/action jointly to maximize expected improvement in decision quality per cost
- Guarantees: if VOI is low, stop measuring and act (or pause)

### 5.11 Online FDR Risk Budget (Alpha-Investing)
- Maintain a global false-kill risk budget across time and across repeated scans
- Spend budget only on extremely strong posterior odds; replenish with confirmed-correct actions

### 5.12 DRO / Worst-Case Expected Loss
- When model misspecification is detected (via PPC) or drift is high (Wasserstein), switch to worst-case loss estimates
- This tightens kill thresholds under uncertainty

### 5.13 Submodular Probe Set Selection
- If “install everything” is possible but “run everything at once” is too heavy, select a probe subset maximizing incremental value
- Provides a principled way to be maximal over time while staying safe on overhead

---

## 6) Action Space (Beyond Kill)

- keep
- pause (SIGSTOP) and observe
- resume (SIGCONT)
- renice
- cgroup CPU throttle
- cpuset quarantine
- restart (for known services)
- kill (SIGTERM -> SIGKILL)

Decision engine selects action with minimum expected loss. Destructive actions (especially kill) require explicit confirmation by default via the TUI, but can be executed automatically under an explicit `--robot` flag and only when all safety gates pass (robust Bayes/DRO/FDR/alpha-investing/policy allowlists).

---

## 7) UX and Explainability (Alien Artifact)

### 7.1 Evidence Ledger
- For each process: posterior, Bayes factors, evidence contributions, confidence
- Show top 3 Bayes factors and residual evidence

### 7.2 Confidence and Explainability
- Confidence from posterior concentration
- Evidence glyphs for I/O, CPU, TTY, orphan, wait channel, net

### 7.3 Human Trust Features
- Show "Why" summary: top evidence items and their weights
- Show "What would change your mind" (VOI hint)

### 7.4 Full-Auto Approval Flow (TUI + Robot Mode)
- Default UX: `pt` runs the entire exploration/analysis pipeline automatically, then presents a single “Apply Plan” TUI screen.
- The process list is pre-toggled according to the system’s recommended action plan (including FDR/alpha-investing gates), so the user usually just reviews and confirms.
- The TUI allows: drill-down evidence, bulk toggles, and an “apply selected” step that executes actions in a safe order (pause/throttle before kill when appropriate).
- `--robot` bypasses the approval UI and executes the pre-toggled plan non-interactively (still honoring `--shadow` and `--dry-run`).

### 7.5 Premium TUI Layout (Stripe-level in a Terminal)
- Plan-first UI (not list-first): show a top “Plan Summary” bar (expected relief, risk gates, blast radius) and render the actions as a coherent plan.
- Two-pane layout: left = candidates/actions table; right = drilldown (why summary, evidence ledger, process tree, dependency impact, “what would change my mind”).
- Progressive disclosure: default to a one-line “why”; expand to full ledger only on demand.

### 7.6 Interaction Design (Fast, Keyboard-First)
- One-keystroke actions: filter/search, sort, toggle recommended, apply plan, export bundle, generate report.
- Bulk operations: “select recommended”, “select none”, and guarded “select all kills” behind an explicit confirmation step.
- After-action diff: always show a “before/after” snapshot and outcomes (killed/failed/still-running) to make the tool feel complete.

### 7.7 Sharing & Reporting UX
- One command / one keybinding: export a `.ptb` bundle for sharing and render a single-file HTML report for premium postmortems.
- Reports should look like an incident dashboard: overview metrics, timelines, candidate table, drilldowns, and action outcomes.

---

## 8) Real-World Usefulness Enhancements (All Included)

- Rich observability: IO, syscalls, context switches, page faults, swap, run-queue delay, fd churn, lock contention, socket backlog
- Context priors: TTY, tmux, git status, recent shell activity, open editor
- Human-in-the-loop updates: decisions update priors (conjugate updates)
- Shadow mode: advisory only, log decisions for calibration
- Safety rails: rate-limit kill actions, never kill system services
- Runbooks: suggest safe restart or pause for known services
- Incident integration: logging, rollback hooks
- Systemd/Kubernetes plugins for service-aware control
- Data governance: no deletions, full audit trail
- Counterfactual testing: compare recommended vs actual
- Risk-budgeted optimal stopping based on load
- Dependency graph and impact scoring in loss matrix
- User intent injection for priors (declared runs or active sessions)
- Time-to-decision bound with pause default
- PAC-Bayes validation in shadow mode with confidence reporting
- Coupled process-tree inference for correlated stuckness
- Hawkes/marked point process burst detection for syscalls/IO
- Robust stats to reduce false positives from noisy kernel events
- Empirical Bayes shrinkage to stabilize rare command categories
- BOCPD-based detection of regime shifts
- Optional perf/eBPF instrumentation for high-fidelity signals
- Copula-based joint dependence modeling
- Kalman smoothing for noisy CPU/load signals
- Wasserstein shift detection for distribution drift
- Martingale bounds for persistent anomalies
- Risk-sensitive control (CVaR/entropic risk)
- Bayesian model averaging across inference layers
- Conformal prediction for robust intervals
- Agent/robot CLI parity with the TUI (JSON/MD/JSONL)
- Shareable session bundles (`.ptb`) + premium single-file HTML reports (CDN-loaded)
- Dormant mode daemon (24/7 guardian) with escalation to active triage when needed

---

## 9) Applied Interpretation of Observed Processes (from conversation)

Use the model to interpret the observed snapshot:
- bun test --filter=gateway at ~91% CPU for ~18m
  - Command category test; high CPU, short runtime; likely useful-but-bad, not abandoned
  - If no TTY, no IO progress, and change-point indicates stalled: posterior shifts toward abandoned
- gemini --yolo workers at 25m to 4h46m
  - Agent category; moderate CPU; likely useful unless orphaned or no TTY and no progress
- gunicorn with 2 workers at 45-50% CPU for ~1h
  - Server category; likely useful; kill cost high
- claude processes at 35-112% CPU
  - Agent category; likely useful unless orphan + no TTY + stalled

---

## 10) Implementation Plan (Phased)

### Phase 1: Spec and Config
- Define the packaging boundary: `pt` (bash wrapper/installer) vs `pt-core` (Rust monolith).
- Define `pt-core` CLI surface (scan/deep-scan/infer/decide/ui/agent/duck/bundle/report/daemon) and stable output formats (JSON/MD/JSONL + Parquet partitions).
- Create priors.json schema for alpha/beta, gamma, dirichlet, hazard priors
- Create policy.json for loss matrix and guardrails
- Define command categories and CWD categories
- Define telemetry schema + partitioning rules (section 3.3) and redaction/hashing policy (section 3.4); version these in `runs`.
- Define a capabilities cache schema: tool availability, versions, permissions, and “safe fallbacks” per signal.
- Define the agent/robot contract: schema versioning, exit codes, pre-toggled plan semantics, and gating behavior.
- Define the bundle/report contract: `.ptb` contents, export profiles, and the single-file CDN-loaded HTML report spec.
- Define dormant-mode daemon spec: triggers, escalation policy, cooldowns, and service integration (systemd/launchd).

### Phase 2: Math Utilities
- Implement BetaPDF, GammaPDF, Dirichlet-multinomial, Beta-Bernoulli
- Implement Bayes factors, log-odds, posterior computation
- Implement numerically-stable primitives (log-sum-exp, log-domain densities, stable special functions) to prevent underflow in Bayes factors/posteriors.
- Implement Arrow/Parquet schemas for telemetry tables and a batched Parquet writer (append-only).

### Phase 3: Evidence Collection
- Quick scan: ps + basic features
- Deep scan: /proc IO, CPU deltas, wchan, net, children, TTY
- Implement a tool runner in `pt-core` with timeouts, output-size caps, and backpressure so “collect everything” does not destabilize the machine.
- Persist raw tool events + parsed samples to Parquet as the scan runs (batched), so failures still leave an analyzable trail.
- Maximal system tools (auto-install; attempt all, degrade gracefully):
  - Linux: sysstat, perf, bpftrace/bcc/bpftool, iotop, nethogs/iftop, lsof, atop, sysdig, smem, numactl/numastat, turbostat/powertop, strace/ltrace, acct/psacct, auditd, pcp
  - macOS: fs_usage, sample, spindump, nettop, powermetrics, lsof, dtruss (if permitted)

### Phase 3a: Tooling Install Strategy (Maximal Instrumentation by Default)
Policy: always try to install everything and collect as much data as possible.
Implementation note: `pt` (bash) performs installation and capability discovery; it then launches `pt-core` with a cached capabilities manifest so inference/decisioning can gracefully degrade when tools are missing.
Non-invasiveness rule: install tools aggressively, but avoid enabling persistent daemons or making irreversible system configuration changes by default; prefer on-demand sampling/tracing and record what could not be accessed due to permissions.

Linux package managers:
- Debian/Ubuntu (apt):
  - sysstat (pidstat/iostat/mpstat/vmstat/sar)
  - linux-tools-common + linux-tools-$(uname -r) (perf)
  - bpftrace + bcc + bpftool (eBPF)
  - iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - turbostat, powertop
  - strace, ltrace
  - ethtool, iproute2 (ss)
  - conntrack-tools, cgroup-tools
  - acct, auditd, pcp
  - gdb, elfutils (eu-stack), binutils
  - python3-pip + pipx (py-spy), openjdk (async-profiler)
  - osquery (if available), intel-pcm (pcm) (if available)
- Fedora/RHEL (dnf):
  - sysstat, perf, bpftrace, bcc, bpftool, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - turbostat, powertop
  - strace, ltrace, ethtool, iproute, conntrack-tools, cgroup-tools
  - psacct, audit, pcp
  - gdb, elfutils, binutils
  - python3-pip + pipx (py-spy), java-latest-openjdk (async-profiler)
  - osquery (if available), intel-pcm (if available)
- Arch (pacman):
  - sysstat, perf, bpftrace, bcc, bpftool, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - turbostat, powertop
  - strace, ltrace, ethtool, iproute2, conntrack-tools, cgroup-tools
  - acct, audit, pcp
  - gdb, elfutils, binutils
  - python-pipx (py-spy), jdk-openjdk (async-profiler)
  - osquery (if available), intel-pcm (if available)
- Alpine (apk):
  - sysstat, perf, bpftrace, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - strace, ltrace, iproute2
  - conntrack-tools, cgroup-tools
  - acct (if available), audit (if available), pcp (if available)
  - gdb, binutils, elfutils (if available)
  - py3-pip + pipx (py-spy), openjdk (async-profiler) (if available)
  - osquery (if available), intel-pcm (if available)

macOS (Homebrew):
- core utils: lsof, iproute2mac (if needed), htop
- tracing/metrics: fs_usage, sample, nettop, powermetrics (native tools)
- if SIP allows: dtruss
- extra: sysstat (where available), gnu-time
- profilers: py-spy, rbspy, async-profiler, flamegraph tools (where available)
- native extras: spindump, vm_stat, sysctl, log show (system logs)

Install workflow:
- Detect OS + package manager.
- Attempt full install; if any package fails, continue installing the rest.
- Prefer non-interactive installs (no prompts) and assume sudo/admin is available for maximal instrumentation; do not trade away power/functionality to accommodate no-sudo environments.
- Record capabilities in a local cache (what is available vs missing).
- Prefer richer signals when available (eBPF/perf), but never fail if missing.
- If a tool is not available via package manager, download pinned upstream binaries (with checksums/signatures where available) into a tools cache and re-run capability detection.

Capability matrix (signal -> tool -> OS support -> fallback):
- syscalls/IO events: bpftrace/bcc (Linux), dtruss (macOS if permitted) -> fallback: strace
- CPU cycles/cache/branch: perf (Linux), powermetrics (macOS) -> fallback: sample
- per-PID IO bandwidth: iotop (Linux), fs_usage (macOS) -> fallback: /proc/PID/io
- per-PID network: nethogs/iftop (Linux), nettop (macOS) -> fallback: ss + lsof
- run-queue + CPU load: mpstat/vmstat/sar (Linux), powermetrics (macOS) -> fallback: uptime/loadavg
- FD churn + sockets: lsof (Linux/macOS) -> fallback: /proc/PID/fd
- scheduler latency: bpftrace/bcc (Linux) -> fallback: perf sched (Linux) or none
- PSI stall pressure: /proc/pressure/* (Linux) -> fallback: none
- cgroup pressure: systemd-cgtop/cgget (Linux) -> fallback: /sys/fs/cgroup
- stack sampling: sample/spindump (macOS), perf/ftrace (Linux) -> fallback: none
- stack traces (blocking/nonblocking): gdb/pstack/eu-stack (Linux), sample/spindump (macOS) -> fallback: none
- process accounting history: acct/psacct (Linux) -> fallback: none
- syscall audit stream: auditd (Linux) -> fallback: strace (limited)
- systemwide historical TSDB: pcp (Linux) -> fallback: sar (limited)
- memory bandwidth / uncore: intel-pcm (Linux) -> fallback: perf counters (if available) or none
- structured system inventory: osquery (Linux/macOS) -> fallback: ad-hoc commands

Data-to-math mapping (signal -> model layer):
- CPU bursts + syscall spikes -> Hawkes / marked point process intensities
- IO bandwidth + write/read deltas -> renewal reward model, Gamma-Poisson rates
- CPU% time series -> Kalman smoothing + BOCPD change-point detection
- PSI stall pressure -> queueing-theoretic cost term (Erlang-C) + hazard inflation
- Cache miss / branch mispredict -> tight-loop likelihood boost (useful-but-bad vs abandoned)
- Socket/client count -> dependency-weighted loss scaling + causal action cost
- Orphan PPID + dead TTY -> Bayesian genealogy prior shift toward abandoned
- PPID tree adjacency -> graph Laplacian smoothing / coupled priors
- Network bursts -> Hawkes cross-excitation + copula dependence
- Distribution drift vs baseline -> Wasserstein distance + large-deviation bounds
- Rare-event persistence -> martingale concentration bounds
- Many-PID scan decisions -> FDR / local fdr thresholding
- Instrumentation budget -> Whittle index / active sensing design
- Accounting history -> empirical Bayes priors on runtime/CPU distributions
- auditd/sysdig streams -> marked point processes / Hawkes cross-excitation
- Extreme spikes -> EVT (POT/GPD) + tail-risk penalties (CVaR)
- Periodic patterns -> wavelet/spectral features + survival priors
- Coupled tree inference -> belief propagation (sum-product) on PPID forest
- Memory bandwidth / uncore -> likelihood refinement for “useful heavy compute” vs “pathological spin”
- osquery inventory -> context priors (service classification, user/session context)

Telemetry and data governance are specified in sections 3.3–3.4; the phases below implement them end-to-end (Parquet-first writes + DuckDB queries + redaction/hashing policy).

### Phase 4: Inference Integration
- Combine evidence to compute P(C|x)
- Persist `proc_features`, `proc_inference`, and the per-process explainability ledger to Parquet (batched); generate DuckDB views/macros for standard “why” queries.
- Add Bayes factor ledger output
- Add confidence metrics
- Add Hawkes / marked point process layers for bursty events
- Add BOCPD run-length posterior for regime shifts
- Add robust statistics summaries for noise suppression
- Add copula dependence modeling, Kalman smoothing, and Wasserstein drift detection
- Add EVT tail modeling for extreme spikes
- Add streaming sketches/heavy-hitter summaries for high-rate event streams
- Add belief propagation for exact coupled-tree inference (PPID forests)
- Add wavelet/spectral periodicity features
- Add switching LDS (IMM) for regime-switching dynamics
- Add Bayesian model averaging over inference submodels
- Add posterior predictive checks for model misspecification
- Add DRO layer for worst-case expected-loss under drift
- Add submodular probe selection utilities for overlapping probes

### Phase 5: Decision Theory
- Implement expected loss, SPRT threshold, VOI
- Load-aware threshold via Erlang-C
- Add FDR-gated kill set selection across many PIDs
- Add active sensing policy (choose next best measurement per cost)
- Add Whittle/VOI index policy for budgeted instrumentation
- Add online FDR/alpha-investing safety budget for repeated scans
- Add DRO/worst-case loss gating when model criticism flags drift or misspecification

### Phase 6: Action Tray
- Generate an explicit action plan (per PID) with ordering, timeouts, and rollback hints.
- Default: present the plan in a TUI with recommended actions pre-toggled; require confirmation before executing destructive actions.
- Implement `--robot` to execute the pre-toggled plan without UI (subject to safety gates and `--dry-run`/`--shadow`).
- Add an execution protocol: pre-flight checks, staged application (pause/throttle -> observe -> kill if still warranted), and post-action verification + logging.

### Phase 7: UX Refinement
- Evidence glyphs and ledger
- Explainability line per process
- Add a single “Apply Plan” screen with drill-down and bulk toggle operations.

### Phase 8: Safety and Policy
- Guardrails for system services
- Rate limiting, quarantine policies
- Define robot-mode safety gates: minimum posterior odds, FDR/alpha-investing budgets, allowlists/denylists, and maximum blast radius per run.

### Phase 9: Shadow Mode and Calibration
- Advisory-only logging
- Compare decisions vs human choices and outcomes using DuckDB queries over the Parquet telemetry lake
- Compute PAC-Bayes bounds, FDR metrics, calibration curves, and posterior predictive check summaries as first-class artifacts
- Update priors with conjugate updates and (when enabled) empirical Bayes hyperparameter refits from shadow-mode logs

---

## 11) Tests and Validation

- Unit tests: math functions (BetaPDF, GammaPDF, Bayes factors)
- Integration tests: deterministic output for fixed inputs
- Telemetry tests: Parquet schema stability, batched writes, and DuckDB view/query correctness
- Redaction tests: confirm sensitive strings never appear in persisted telemetry
- Automation tests: `--robot`/`--shadow`/`--dry-run` behavior (no prompts; correct gating; no actions in shadow/dry-run)
- Shadow mode metrics: false kill rate, missed abandonment rate
- PAC-Bayes bound reporting on false-kill rate
- Calibration tests for empirical Bayes hyperparameters
- Hawkes/marked point process fit sanity tests
- BOCPD change-point detection regression tests
- FDR-gating tests (multiple-process safety)
- EVT tail-fitting regression tests
- Sketch/heavy-hitter tests (accuracy vs resource budget)
- Belief propagation correctness tests on PPID trees
- Periodicity feature regression tests
- IMM filter regression tests
- Online FDR/alpha-investing tests
- Posterior predictive check tests (detect misspecification)
- DRO gating tests (conservative under drift)
- Submodular probe selection tests (monotonicity/approx sanity)

---

## 12) Deliverables

- `pt` bash wrapper (maximal installer + launcher) and `pt-core` Rust monolith (scan/infer/decide/ui)
- `priors.json`, `policy.json`, and a versioned redaction/hashing policy used by telemetry
- Parquet-first telemetry lake (raw + derived + outcomes) with DuckDB views/macros for standard reports (calibration, PAC-Bayes bounds, FDR, “why” breakdown)
- Enhanced README with math, safety guarantees, telemetry governance, and reproducible analysis workflow
- Expanded tests: Rust unit/integration + wrapper smoke tests (BATS or equivalent)

---

## 13) Final Safety Statement
This system never auto-kills by default. By default it runs full-auto analysis and then requires an explicit TUI confirmation before executing destructive actions. A `--robot` flag allows non-interactive execution of the pre-toggled recommended plan, but still enforces safety gates (policy allowlists/denylists, robust Bayes/DRO checks, FDR/alpha-investing budgets, and blast-radius limits).
