# PLAN_TO_MAKE_PROCESS_TRIAGE_INTO_AN_ALIEN_TECHNOLOGY_ARTIFACT.md

---

## Background Information and Context

This section provides complete context for understanding this specification. The goal is to make this document fully self-contained so that a reader with no prior exposure to Process Triage can understand the problem, the current state, and the proposed transformation.

### What is Process Triage?

**Process Triage** (`pt`) is an interactive command-line tool for identifying and killing abandoned, stuck, or zombie processes on developer workstations. It scans the process table, scores each process based on heuristics (runtime, CPU usage, command patterns, orphan status), and presents candidates for termination in an interactive UI.

The tool exists because modern development workflows generate an enormous number of long-running processes—test runners, dev servers, language servers, build watchers, AI coding assistants, background tasks—and these processes frequently outlive their usefulness. They accumulate silently, consuming memory, CPU, file descriptors, and ports until the developer notices their machine is sluggish or a port is unexpectedly occupied.

**Current implementation**: `pt` is a single-file bash script (~1600 lines) that uses `gum` for interactive UI components. It applies hand-tuned heuristic scoring rules and maintains a simple JSON-based "decision memory" to learn from user choices. It is functional but limited: the heuristics are ad-hoc, the scoring is not principled, and there is no formal notion of confidence, evidence, or risk.

### The Problem: Process Accumulation on Developer Machines

Developer workstations are uniquely hostile environments for process management:

1. **High process churn**: Developers start and stop processes constantly—running tests, launching dev servers, building projects, spawning language servers, running AI assistants. Many of these are designed to run indefinitely until manually stopped.

2. **Orphan accumulation**: When a terminal is closed, an SSH session drops, or a parent process crashes, child processes may be reparented to PID 1 (init/systemd) and continue running indefinitely with no controlling terminal and no user awareness.
   - Note: PPID=1 is not universally “orphan” (e.g., macOS `launchd` is PID 1 and legitimately parents many long-lived processes). Treat “reparented to init” as a weak signal that must be conditioned on supervision/session context.

3. **Test runner zombies**: Test frameworks (Jest, pytest, bats, bun test, go test) can hang indefinitely on deadlocks, infinite loops, or resource exhaustion. A developer may Ctrl+C the parent, but child processes or worker threads persist.

4. **Dev server proliferation**: `next dev`, `vite`, `webpack --watch`, `nodemon`, `flask run`—developers often start multiple dev servers across different projects and forget to stop them. Each consumes memory and binds ports.

5. **AI assistant sprawl**: Modern AI coding tools (Claude, Copilot, Cursor, Gemini) spawn multiple processes—language servers, inference workers, file watchers—that may not clean up properly when sessions end.

6. **Build system persistence**: Build tools (`cargo watch`, `tsc --watch`, `make -j`) may spawn worker processes that outlive the build session.

7. **Container/VM leakage**: Docker containers, VMs, and their associated shim processes can accumulate when development sessions are abandoned.

The result: a typical developer machine accumulates dozens of unnecessary processes over days or weeks of work, gradually degrading performance until the developer reboots or manually hunts down offenders.

### Why This Problem is Hard

Identifying which processes should be killed is a **classification problem under uncertainty** with **asymmetric costs**:

**The classification challenge:**
- A process running for 4 hours at 80% CPU might be a stuck test (should kill) or a legitimate long-running computation (should keep).
- A process with no TTY might be an orphaned leftover (should kill) or a deliberately backgrounded daemon (should keep).
- A process consuming 2GB of memory might be a memory leak (should kill) or a normal workload for that application (should keep).

There is no single observable feature that definitively distinguishes "useful" from "abandoned." The classification requires combining multiple weak signals probabilistically.

**The asymmetric cost challenge:**
- **False kill (Type I error)**: Killing a useful process can cause data loss, interrupt work, crash dependent services, or corrupt state. The cost can range from minor annoyance to hours of lost work.
- **False spare (Type II error)**: Leaving an abandoned process running wastes resources but usually causes no immediate harm.

This asymmetry means the system must be **conservative by default**—it is far better to miss an abandoned process than to kill a useful one. But excessive conservatism renders the tool useless (it never recommends killing anything).

**The observability challenge:**
The operating system provides many signals about process state, but they are noisy, indirect, and platform-dependent:
- CPU usage fluctuates based on scheduling and system load
- Memory usage depends on allocation patterns and OS reclamation
- I/O activity may be bursty or quiescent
- Network connections come and go
- Process state flags (R/S/D/Z/T) are coarse

Extracting meaningful behavioral patterns from these signals requires statistical modeling.

**The context challenge:**
Whether a process is "useful" depends on context that is not directly observable:
- Is this test runner part of a test suite the user is actively iterating on?
- Is this dev server serving a browser tab the user has open?
- Is this build process part of a CI run that hasn't finished?
- Did the user intentionally background this process?

The system must incorporate contextual signals (TTY attachment, working directory, recent user activity, process relationships) to make informed decisions.

### Current Approaches and Their Limitations

**Manual process management (`ps`, `top`, `htop`, `kill`):**
- Requires the user to know what they're looking for
- No guidance on what is safe to kill
- Time-consuming for complex process trees
- Easy to miss orphaned processes
- Easy to accidentally kill something important

**System-level monitors (systemd, launchd, supervisord):**
- Only manage processes they supervise
- Don't help with ad-hoc developer processes
- No intelligence about "stuck" vs "working"

**Simple heuristic tools (existing `pt`, custom scripts):**
- Ad-hoc rules ("kill anything running > 24 hours")
- No uncertainty quantification
- No principled way to combine evidence
- No learning from outcomes
- High false positive/negative rates

**Machine learning approaches:**
- Require labeled training data (hard to obtain)
- Black-box decisions (no explainability)
- Risk of unexpected failures on distribution shift
- Overkill for a problem with well-understood structure

What's missing is a **principled probabilistic framework** that:
1. Combines multiple weak signals into a coherent posterior belief
2. Quantifies uncertainty explicitly
3. Makes decisions based on expected costs, not arbitrary thresholds
4. Explains its reasoning in human-understandable terms
5. Learns from outcomes without requiring labeled data
6. Provides formal safety guarantees

### The Process Triage Vision: "Alien Technology Artifact"

The goal of this specification is to transform `pt` from a simple heuristic script into what we call an **"alien technology artifact"**—a tool so principled, so rigorous, and so well-designed that it feels like technology from a more advanced civilization.

This is not hyperbole or marketing. The term captures a specific aspiration:

**An alien technology artifact is characterized by:**
1. **Mathematical rigor**: Every decision is grounded in formal probability theory and decision theory, not ad-hoc heuristics.
2. **Complete explainability**: The system can show exactly why it made each recommendation, down to individual likelihood terms and Bayes factors.
3. **Formal safety guarantees**: The system provides provable bounds on error rates, not just empirical observations.
4. **Graceful degradation**: The system works with whatever information is available, getting better with more data but never failing catastrophically.
5. **Operational excellence**: The system is fast, reliable, and never becomes a problem itself (no hanging, no resource hogging, no silent failures).
6. **Beautiful UX**: The interface is polished, intuitive, and makes the underlying sophistication accessible rather than intimidating.

The "alien" quality comes from the combination: most tools have one or two of these properties; having all of them simultaneously is rare enough to feel otherworldly.

### Why Closed-Form Bayesian Inference (Not Machine Learning)?

A critical design decision in this specification is the commitment to **closed-form Bayesian inference** rather than machine learning. This is not anti-ML ideology; it is a pragmatic choice based on the problem structure:

**1. The problem has well-understood structure.**

We know what features matter (CPU, runtime, orphan status, command type, I/O activity, etc.) and we have reasonable prior beliefs about how they relate to process states. We don't need a neural network to discover that "high CPU + long runtime + orphan + no TTY" suggests abandonment—we can encode this directly.

**2. Explainability is essential for trust.**

A tool that kills processes must be explainable. "The model says kill" is not acceptable. Users need to understand *why* each recommendation is made so they can trust it, override it when appropriate, and debug false positives. Closed-form Bayesian inference produces a complete evidence ledger: "P(abandoned|evidence) = 0.94 because: runtime contributes +2.3 log-odds, orphan status contributes +1.8 log-odds, CPU pattern contributes -0.4 log-odds, ..."

**3. Conjugate priors enable online learning.**

With conjugate prior families (Beta-Binomial, Gamma-Poisson, Dirichlet-Multinomial), updating beliefs from new observations is a simple parameter update. The system can learn from user decisions and outcomes without retraining a model. This enables continuous calibration.

**4. Formal guarantees are tractable.**

With closed-form posteriors, we can compute exact credible intervals and exact Bayes factors. We can also apply formal error-control and calibration tools (PAC-Bayes bounds, conformal prediction for distribution-free coverage, FDR control, alpha-investing), but we must be explicit about their assumptions (e.g., approximate independence/exchangeability of trials); in always-on/optional-stopping settings we prefer anytime-valid e-values/e-process controls. ML models require empirical validation on held-out data; Bayesian models have built-in uncertainty quantification.

**5. Numerical stability is achievable.**

Log-domain computation with special functions (log-gamma, log-beta) is well-understood and numerically stable. We don't need to worry about vanishing gradients, mode collapse, or other pathologies of neural network training.

**6. The system is auditable.**

Every parameter (prior shape, likelihood model, loss matrix) is explicit and interpretable. If the system makes a mistake, we can trace it to a specific model assumption and fix it. ML models are opaque by comparison.

**What "closed-form" means in practice:**

- **Priors**: All prior distributions are from conjugate families (Beta, Gamma, Dirichlet).
- **Likelihoods**: All likelihood models use these conjugate families.
- **Posteriors**: All posteriors are analytically tractable (no MCMC, no variational inference).
- **Decisions**: Expected loss is computed exactly from the posterior.
- **Advanced layers**: More sophisticated models (Hawkes/marked point processes, BOCPD change-point detection, survival with time-varying covariates, EVT tail modeling, copula dependence, robust M-estimation) are used as **feature extractors** that feed deterministic summaries into the closed-form core—they do not replace the core inference. Separately, **conformal prediction** is used as a **calibration wrapper** that provides distribution-free coverage guarantees on prediction intervals without altering the core posteriors.

### The Four-State Classification Model

The core of the system is a four-state classification model for process states:

| State | Description | Typical Characteristics | Appropriate Action |
|-------|-------------|------------------------|-------------------|
| **Useful** | Process is doing productive work that the user cares about | Active CPU/IO, responding to requests, part of active workflow | Keep |
| **Useful-but-bad** | Process is doing something but is stuck, leaking, or misbehaving | High CPU but no progress, memory growth, spin-waiting | Investigate, possibly pause/restart |
| **Abandoned** | Process was once useful but is no longer needed | Orphaned, no TTY, stale working directory, no recent activity | Kill (with confirmation) |
| **Zombie** | Process has terminated but not been reaped | State = 'Z', exists only as process table entry | Cannot kill directly; must reap via parent |

This four-state model is richer than a simple binary "useful/not-useful" classification:

- **Useful-but-bad** captures processes that are technically running but exhibiting pathological behavior (infinite loops, memory leaks, deadlocks). These may benefit from intervention even though they are "in use."
- **Zombie** is a distinct technical state requiring different handling—you cannot kill a zombie process; you must address the parent that failed to reap it.

The posterior over these four states, combined with a loss matrix specifying the cost of each action in each state, yields a principled decision rule via expected loss minimization.

### Key Design Principles

**1. Safety by default, power on demand.**

The system never auto-kills by default. The default workflow is: scan → analyze → present recommendations → require human confirmation. Automated execution (`--robot` mode) is explicitly opt-in and still subject to safety gates.

**2. Progressive disclosure of complexity.**

The default UX shows a simple "recommended action" with a one-line explanation. Users can drill down to see the full evidence ledger, and further to "galaxy-brain mode" showing the complete mathematical derivation. The sophistication is there but doesn't overwhelm.

**3. Evidence over thresholds.**

Rather than "kill if score > 50," the system maintains a full posterior distribution and decides based on expected loss. This naturally handles uncertainty: e.g., P(abandoned)=0.6 with tight concentration (many consistent samples) is treated differently from P(abandoned)=0.6 from sparse/noisy evidence; and even a high posterior can be down-weighted when robustness checks (PPC/drift/DRO gates) indicate model mismatch. Where decisions are sequential, add anytime-valid e-values/e-process gates and conformal prediction intervals so the displayed uncertainty and action thresholds remain valid under optional stopping.

**4. Maximal instrumentation, budgeted execution.**

The system attempts to install and use every available diagnostic tool (perf, eBPF, strace, etc.) but carefully budgets their execution to avoid becoming a resource hog itself. More data is always better; the system gracefully degrades when tools are unavailable. Probe selection is driven by VOI/active-sensing and bandit-style scheduling (e.g., Whittle/Thompson) so deeper instrumentation is spent where it reduces uncertainty most.

**5. Everything is logged, everything is auditable.**

Every observation, every inference step, every decision is logged to a structured telemetry store (Parquet partitions). This enables debugging ("why did it recommend killing that?"), calibration ("what's our actual false-kill rate?"), and learning ("how should we adjust priors based on outcomes?").

**6. Formal safety guarantees where possible.**

The system uses Bayesian credible bounds, PAC-Bayes, and (online) FDR/alpha-investing to control error rates *under explicit assumptions* (e.g., approximate independence/exchangeability of trials). Where those assumptions are dubious (strong temporal dependence, selection effects), the system defaults to conservative gating and anytime-valid e-process/e-value style controls rather than over-claiming guarantees. These are essential for trusting the system in `--robot` mode.

### Target Users and Use Cases

**Primary users:**
- Software developers with long-running workstations (macOS, Linux)
- Developers who run many concurrent projects
- Users of AI coding assistants (which spawn many background processes)
- DevOps engineers managing development/staging environments
- **AI coding agents** managing machines via SSH (Claude, Cursor, Codex, etc.)
- **Fleet operators** managing multiple development/staging hosts

**Primary use cases:**

1. **Interactive triage**: "My machine is slow. Help me find and kill abandoned processes."
2. **Scheduled cleanup**: Run `pt` periodically (cron/launchd) to keep the process table clean.
3. **Automated hygiene**: Run `pt --robot` in CI/CD environments or development containers to automatically clean up after test runs.
4. **Investigation**: "This process is using a lot of CPU. Should I be worried?"
5. **Learning**: "I always kill processes matching pattern X. Remember that."
6. **Agent-driven maintenance**: AI agents SSH into machines and run `pt agent plan` to identify and remediate process issues as part of automated workflows.
7. **Fleet-wide hygiene**: Run `pt` across multiple hosts to identify common patterns, aggregate telemetry, and maintain consistent process health.
8. **Goal-oriented recovery**: "Free 4GB of RAM" or "Get CPU utilization below 70%"—resource-targeted triage rather than just "find bad processes."
9. **Differential monitoring**: "What changed since my last check?"—efficient repeated scans that surface deltas rather than re-processing everything.

**Non-goals:**
- Production server process management (use proper supervision)
- Security monitoring (use proper audit tools)
- General system administration (use proper admin tools)

### Technical Context: What Signals Are Available?

The operating system exposes rich information about processes, though the details vary by platform:

**Universal (Linux and macOS):**
- PID, PPID (parent process ID)
- UID (owner)
- Command line and arguments
- Process state (running, sleeping, zombie, etc.)
- CPU time (user + system)
- Memory usage (RSS, virtual)
- Context switches (voluntary/involuntary) and scheduler wait (when exposed)
- Page faults, swap activity, and per-process I/O counters (read/write bytes)
- Start time / elapsed time
- Controlling TTY (or none)
- Current working directory
- Open file descriptors (via lsof)
- Network connections (via ss/netstat/lsof)
- Child processes

**Linux-specific:**
- `/proc/PID/*` filesystem with detailed per-process info
- `/proc/PID/schedstat` and `/proc/PID/sched` for run-queue latency and scheduler behavior
- `/proc/PID/io` and `/proc/PID/fd` for per-process I/O deltas and FD churn
- cgroups (CPU/memory limits and accounting)
- PSI (Pressure Stall Information) for system-wide pressure
- perf (hardware performance counters)
- eBPF (programmable kernel instrumentation)
- systemd unit attribution
- process accounting (`acct`/`psacct`) and historical telemetry (`sysstat`/`sar`, `pcp`)

**macOS-specific:**
- `proc_pidinfo` API for detailed process info
- `powermetrics` for energy/performance data
- `sample`/`spindump` for stack sampling
- `fs_usage` for file system activity
- `nettop` for per-process network activity
- `vm_stat` for memory pressure and paging signals
- `dtruss`/DTrace for syscall-level traces (when SIP permits)
- launchd service attribution

The specification aims to use all available signals, with graceful degradation when specific tools are unavailable.

### What Success Looks Like

If this specification is fully realized, the result will be a tool that:

1. **Just works**: Run `pt` and get a clear, actionable recommendation in seconds.

2. **Earns trust**: Every recommendation comes with an explanation that makes sense. Users learn to trust the tool because they can verify its reasoning.

3. **Never damages**: The false-kill rate is vanishingly low (<1%), and even when wrong, the system errs on the side of caution.

4. **Improves over time**: The system learns from user decisions and outcomes, becoming more accurate with use.

5. **Scales to automation**: The `--robot` mode is reliable enough to run unattended in CI/CD, development containers, and scheduled jobs.

6. **Delights users**: The UX is polished, the output is beautiful, and the "galaxy-brain mode" makes the underlying mathematics accessible and even fun.

7. **Feels like magic**: The combination of rigor, safety, and usability produces an experience that feels qualitatively different from other tools—hence "alien technology artifact."

8. **First-class agent support**: AI agents can manage machines via `pt agent` with token-efficient outputs, fine-grained automation controls, resumable sessions, and human-friendly summaries for handoff.

9. **Fleet-aware**: The system can operate across multiple hosts, aggregate telemetry, detect cross-host patterns, and apply fleet-wide FDR controls.

10. **Goal-oriented**: Users can specify resource recovery targets ("free 4GB RAM") and the system optimizes candidate selection accordingly.

11. **Differential efficiency**: Repeated scans surface only what changed, dramatically reducing overhead for ongoing monitoring.

12. **Pattern-accelerated**: Known signatures (stuck jest workers, orphaned webpack, etc.) are recognized instantly without full Bayesian inference, while novel patterns get the full treatment.

### Document Structure

The remainder of this specification is organized as follows:

- **Section 0**: Non-negotiable requirements (constraints that must not be violated)
- **Section 1**: Mission and success criteria
- **Section 2**: Complete inventory of mathematical techniques incorporated
- **Section 3**: System architecture (collection, features, telemetry, CLI, UX, fleet mode, pattern library)
- **Section 4**: Inference engine (all Bayesian models and techniques, including trajectory prediction)
- **Section 5**: Decision theory and optimal stopping (including goal-oriented optimization)
- **Section 6**: Action space (beyond just "kill", including supervisor-aware actions)
- **Section 7**: UX and explainability design (including dependency visualization, genealogy narratives)
- **Section 8**: Real-world enhancements and pitfalls to avoid (including agent-specific considerations)
- **Section 9**: Applied interpretation of example processes
- **Section 10**: Phased implementation plan
- **Section 11**: Testing and validation requirements
- **Section 12**: Deliverables
- **Section 13**: Final safety statement

---

## 0) Non-Negotiable Requirement From User
This plan MUST incorporate every idea and math formula from the conversation. The sections below explicitly enumerate and embed all of them. This is a closed-form Bayesian and decision-theoretic system with no ML.
Operational requirement: `pt` must be able to run end-to-end in a full-auto mode (collect -> infer -> recommend -> (optionally) act) with no user interaction except (by default) a final TUI approval step for destructive actions. A `--robot` flag must exist to skip the approval UI and execute automatically.

---

## 1) Mission and Success Criteria

Mission: transform Process Triage (pt) into an "alien technology artifact" that combines rigorous closed-form Bayesian inference, optimal stopping, and system-level decision theory with a stunningly explainable UX.

Implementation stance (critical): keep `pt` as a thin bash wrapper/installer for cross-platform ergonomics, but move all inference, decisioning, logging, and UI into a monolithic Rust binary (`pt-core`) for numeric correctness, performance, and maintainability.

Operational stance (critical): make every run operationally improvable by recording both raw observations and derived quantities to append-only Parquet partitions, with DuckDB as the query engine over those partitions for debugging, calibration, and visualization.

Success criteria:
- Decision quality: in shadow mode, the estimated false-kill rate of "recommended kill" actions is <1% (report as a credible upper bound at a stated confidence level); high capture of abandoned/zombie processes as judged by user labels and/or post-run outcomes.
- Explainability: every decision has a full evidence ledger, posterior, and top Bayes factors.
- Safety: no auto-kill by default; multi-stage mitigations; guardrails enforced by policy; `--robot` explicitly opts into automated execution.
- Performance: quick scan <1s; targeted deep scan on top suspects <8s for typical process counts (full instrumentation is budgeted and may take longer when explicitly enabled).
- Closed-form Bayesian core: posterior/odds/expected-loss updates use conjugate priors; no ML.
- Formal guarantees: Bayesian credible bounds + PAC-Bayes bounds on false-kill rate (shadow-mode calibrated) with explicit assumptions called out (and an anytime-valid e-process/e-value fallback for sequential/always-on settings).
- Real-world impact weighting: kill-cost incorporates dependency and user-intent signals.
- Operational learning loop: every decision is explainable and auditable from stored telemetry (raw + derived + outcomes).
- Telemetry performance: logging is low-overhead (batched Parquet writes; no per-row inserts).
- Telemetry safety: secrets/PII are redacted or hashed by policy before persistence.
- Concurrency safety: Parquet-first storage supports concurrent runs without DB write-lock contention.
- Full-auto UX: default mode runs to a pre-toggled approval UI; `--robot` runs to completion without prompts.
- Agent ergonomics: `pt agent` provides token-efficient JSON/JSONL outputs, resumable sessions, fine-grained automation controls, and human-friendly summary formats suitable for handoff.
- Fleet support: multi-host operation with aggregated telemetry, cross-host pattern detection, and fleet-wide FDR control.
- Goal-oriented mode: users can specify resource recovery targets (memory, CPU, ports) and the system optimizes candidate selection to achieve those goals.
- Differential efficiency: delta mode surfaces only changes since a prior session, reducing token/compute overhead for repeated monitoring.
- Pattern acceleration: known signatures are recognized via fast lookup, bypassing full inference for high-confidence matches on common stuck/abandoned patterns.
- Predictive capability: trajectory analysis warns of processes likely to become problematic before they cross kill thresholds.
- Supervisor awareness: actions respect process supervision (systemd, launchd, pm2, Docker) and recommend supervisor-level commands when appropriate.

---

## 2) Source Idea Inventory (All Ideas and Formulas Captured)

This plan includes ALL of the following ideas and formulas from the conversation, verbatim or fully represented:

A) Basic closed-form Bayesian model (non-ML)
- Class set: C in {useful, useful-but-bad, abandoned, zombie}
- Bayes rule: P(C|x) proportional to P(C) * P(x|C)
- Features: CPU usage u, runtime t, PPID, command, CWD, state flags, child count, TTY, I/O wait, CPU trend
- Likelihoods (keep the runtime “decision core” conjugate and log-domain numerically stable):
  - CPU occupancy from tick deltas: k_ticks|C ~ Binomial(n_ticks, p_{u,C}), p_{u,C} ~ Beta(alpha_C, beta_C)
    - k_ticks = Δticks over window Δt (from /proc/PID/stat)
    - n_ticks = round(CLK_TCK * Δt * min(N_eff_cores, threads))  (where CLK_TCK = sysconf(_SC_CLK_TCK), and N_eff_cores accounts for affinity/cpuset/quota when available)
    - u = k_ticks / n_ticks (derived occupancy estimate; clamp to [0,1] if rounding/noise yields slight overflow); posterior for p_{u,C} is Beta(alpha_C+k_ticks, beta_C+n_ticks-k_ticks)
  - t|C ~ Gamma(k_C, theta_C)
  - orphan o|C ~ Bernoulli(p_{o,C}), p_{o,C} ~ Beta(a_{o,C}, b_{o,C})
  - state flags s|C ~ Categorical(pi_C), pi_C ~ Dirichlet(alpha^{state}_C)
  - command/CWD categories g|C ~ Categorical(rho_C), rho_C ~ Dirichlet(alpha^{cmd}_C)
- Posterior (Naive Bayes):
  P(C|x) proportional to P(C) * product_j P(x_j|C)
  (conditional-independence approximation; mitigate correlated-signal double counting via conservative calibration and dependence summaries)
- Log-posterior formula:
  log P(C|x) = log P(C) + log BetaBinomial(k_ticks; n_ticks, alpha_C, beta_C) + log GammaPDF(t; k_C, theta_C)
                + log BetaBernoulliPred(o; a_{o,C}, b_{o,C}) + log DirichletCatPred(g; alpha^{cmd}_C) + ...
  (DirichletCatPred(g; α_vec) = α_vec[g]/sum(α_vec); categorical terms use Dirichlet-Multinomial posterior-predictives; decision core uses log-domain Beta/Gamma/Dirichlet special functions, not heuristic approximations)

B) Decision rule via expected loss (Bayesian risk)
- a* = argmin_a sum_C L(a,C) P(C|x)
- Example loss matrix:
  - useful: keep=0, kill=100
  - useful-but-bad: keep=10, kill=20
  - abandoned: keep=30, kill=1
  - zombie: keep=50, kill=1
  (note: zombies can’t be killed directly; interpret “kill” here as “resolve via parent reaping / restart parent”, see section 6)

C) Survival analysis and hazards
- hazard lambda_C (constant-hazard special case)
- P(still running | t, C) = exp(-lambda_C * t)  (for competing hazards, lambda_total = sum of cause-specific hazards)
- Gamma prior on lambda_C yields closed-form posterior; marginal survival (Gamma-mixed exponential) is Lomax/Pareto-II:
  P(T>t) = (β/(β+t))^α (rate-parameterization)
- Time-varying covariates handled via piecewise-constant hazards (or stratified hazards) with conjugate Gamma updates per segment; yields closed-form posterior survival curves while capturing events like TTY loss, PPID reparenting, or IO flatlines.

D) Change-point detection (closed-form)
- Let k_t be the count of “busy” samples (or threshold exceedances) in a window of n_t samples.
- k_t ~ Binomial(n_t, p_1) before τ, and k_t ~ Binomial(n_t, p_2) after τ
- p_1 ~ Beta(alpha_1, beta_1), p_2 ~ Beta(alpha_2, beta_2)
- Geometric prior on τ; posterior computed via Beta-binomial

E) Hierarchical priors by command category
- Shrinkage by category (for CPU occupancy): p_{u,C,g} ~ Beta(alpha_{u,C,g}, beta_{u,C,g}), with empirical-Bayes shrinkage pulling (alpha_{u,C,g}, beta_{u,C,g}) toward a global class prior (alpha_C, beta_C).
- Optional (offline calibration only): alpha_{u,C,g}, beta_{u,C,g} hyperpriors (e.g., Gamma on shapes) fit numerically (Laplace/EB), while runtime inference stays on conjugate Beta-Binomial marginals.

F) Continuous-time hidden semi-Markov chain
- S_t in {useful, useful-bad, abandoned, zombie}
- durations D_S ~ Gamma(k_S, theta_S)

G) CPU model as Markov-modulated Poisson / Levy subordinator
- N(t) ~ Poisson(kappa_S * t)
- burst size X_i ~ Exp(beta_S)
- cumulative CPU: C(t) = sum_{i=1..N(t)} X_i
- yields a compound Poisson (finite-activity Lévy subordinator) with closed-form Laplace transform; treat this as a feature layer (fit via moment matching / EM / latent-count augmentation as needed) and feed burstiness summaries into the closed-form decision core

H) Bayes factors for model selection
- BF_{H1,H0} = [integral P(x|theta,H1)P(theta|H1) dtheta] / [integral P(x|theta,H0)P(theta|H0) dtheta]
- log posterior odds = log BF + log prior odds

I) Optimal stopping + SPRT
- Kill if log odds cross a boundary:
  log [P(abandoned|x) / P(useful|x)] > log [(L(kill,useful)-L(keep,useful)) / (L(keep,abandoned)-L(kill,abandoned))]

J) Queueing theory for system-level cost
- M/M/c or M/G/c model
- Erlang-C wait (M/M/c): W_q = C(c,ρ) / (c*μ - λ_arrival) with ρ = λ_arrival/(c*μ)

K) Value of Information
- VOI = E[loss_now - loss_after_measurement] - cost(measurement/waiting)
- If VOI <= 0, act now

L) Robust Bayes (imprecise priors)
- P(C) in [lower P(C), upper P(C)]
- only kill if even optimistic posterior favors abandoned

M) Information-theoretic abnormality
- KL divergence: D_KL(p_hat || p_useful)
- Large-deviation intuition: under the “useful” model, observing an empirical rate p_hat is roughly ≲ exp(-n * D_KL(p_hat || p_useful)) for an effective sample count n
- Large deviations / rate functions

N) Wonham filtering (continuous-time partial observability)
- filter hidden states in continuous-time

O) Gittins indices
- optimal scheduling / stopping index for CPU trade-offs

P) Process genealogy / Bayesian network
- PPID tree as Bayesian network or Galton-Watson branching process
- orphan/reparenting evidence: BF = P(unexpected_reparenting|abandoned) / P(unexpected_reparenting|useful)
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
- No silent deletion; transparent logs; explicit retention policy (summaries/ledger retained longer than raw high-volume traces)

S) Causal intervention layer (do-calculus)
- Compare interventions: P(recovery | do(kill)) vs P(recovery | do(pause)) vs P(recovery | do(throttle))
- Closed-form Bernoulli/Beta outcome models per action

T) Coupled process-tree model
- Graphical coupling on PPID tree (Ising-style prior or pairwise Potts)
- Correlated state model: pairwise Potts/Ising coupling on PPID edges; exact sum-product on the PPID forest, and (only if extra non-tree couplings exist) loopy BP or pseudolikelihood as a tractable approximation.

U) POMDP / belief-state decision
- Belief update: b_{t+1}(S) proportional to P(x_{t+1}|S) * sum_{S'} P(S|S') b_t(S')
- Myopic Bayes-optimal action under belief state (closed-form expected loss)

V) Generalization guarantees (PAC-Bayes + Bayesian credible bounds)
- Bayesian credible upper bound on false-kill rate from shadow-mode outcomes using a Beta posterior on the error rate
- PAC-Bayes: distribution-free generalization bound relating empirical false-kill rate to true false-kill rate via KL(Q||P) under standard i.i.d./exchangeability assumptions; report both

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
- Closed-form likelihood expression for exponential kernels; practical inference via fast EM/MLE (optionally using branching augmentation where Gamma priors are conditionally conjugate given latent parent counts). Treat Hawkes as a feature layer feeding summaries to the closed-form decision core.

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
- Closed-form likelihood expression for exponential kernels; treat as a feature layer (fast EM/MLE / augmented-count approximations), feeding cross-excitation summaries into the closed-form decision core.

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
- Distribution-shift detection with exact 1D OT distances via quantile functions (fast on empirical samples)

AP) Martingale concentration / sequential bounds
- Azuma/Freedman bounds for sustained anomaly detection

AQ) Graph signal processing / Laplacian regularization
- Smooth log-odds/natural parameters on the PPID tree via a Laplacian regularizer (a pragmatic denoising layer; if you relax to a Gaussian field it becomes a quadratic form)

AR) Renewal reward / semi-regenerative processes
- Model event rewards (CPU/IO) between renewals with conjugate updates

AS) Conformal prediction (distribution-free coverage)
- Prediction intervals for runtime/CPU with finite-sample guarantees under exchangeability (use time-blocked/online conformal variants for temporal dependence)

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
- Produces conservative expected-loss estimates (via analytic dual bounds where possible, otherwise conservative approximations used as gates); complements robust Bayes

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

BL) Anytime-valid inference (e-values / e-processes) for 24/7 monitoring
- Use nonnegative supermartingales / “betting” style tests to get time-uniform validity under optional stopping
- Natural fit for dormant mode: continuous monitoring without inflating false-alarm/false-kill risk over time

BM) Time-uniform concentration inequalities (modern martingale bounds)
- Always-valid confidence sequences for rates/drift (e.g., Freedman/Bernstein-style time-uniform bounds)
- Helps turn “sustained load for N seconds” into a principled sequential test with explicit error control

BN) Fast optimal-transport drift detection (Sinkhorn divergence)
- Practical, fast approximation of Wasserstein distances for distribution shift monitoring on streaming telemetry
- Keeps drift gates responsive without blowing the overhead budget

BO) Fleet mode architecture (multi-host operation)
- Aggregate telemetry across hosts into a central store (or federated queries)
- Cross-host pattern detection: "this signature appears on N of M hosts"
- Fleet-wide FDR control: prevent "1 false kill spread across 100 hosts" by treating the fleet as a single multiple-testing domain
- Host-group priors: transfer learned priors between similar machine profiles
- Parallel plan generation across hosts with unified reporting

BP) Delta/differential mode (session comparison)
- `--since <session-id>` or `--since <timestamp>` to surface only changes
- Track: new suspicious processes, newly-worsened (REVIEW→KILL), resolved (gone), persistent offenders (suspicious for N sessions)
- Dramatically reduces token/compute overhead for repeated monitoring by agents or scheduled jobs

BQ) Goal-oriented resource recovery optimization
- User specifies targets: `--goal "free 4GB RAM"`, `--goal "CPU < 70%"`, `--goal "free port 3000"`
- System ranks candidates by contribution to goal, not just by "badness"
- Optimization objective: minimize expected loss while achieving resource target
- Knapsack-style selection when multiple candidates needed to meet goal

BR) Pattern/signature library (known-pattern fast path)
- Curated signatures for common stuck/abandoned patterns (jest workers, webpack, next dev, gunicorn, etc.)
- Signature match yields high-confidence classification without full Bayesian inference
- Signatures include: match criteria (cmd regex, CPU range, runtime, orphan status), classification, confidence, remediation hints
- Sources: built-in, community-contributed, organization-specific
- Version-aware: patterns can specify tool versions where behavior differs
- "Unknown pattern" flag when nothing matches (triggers full inference with higher uncertainty)

BS) Process genealogy narrative (explain backstory)
- Reconstruct how a process reached its current state
- Timeline: started by X, parent died at T, orphaned to init, TTY detached, IO stalled since T+N
- Explains *why* the classification makes sense, not just *what* the classification is
- Stored as structured events enabling replay and debugging

BT) Supervisor-aware action routing
- Detect if process is under supervision: systemd, launchd, supervisord, pm2, nodemon, Docker, Kubernetes
- Recommend supervisor-level actions: `systemctl restart`, `pm2 restart`, `docker restart`
- Warn when raw PID kill will just trigger respawn
- Integrate restart policies into action cost (respawn → ineffective kill → prefer throttle/pause)

BU) Trajectory/predictive analysis
- Fit trend models to resource usage (memory growth rate, CPU trend)
- Predict: time until OOM, time until reclassification threshold crossed
- Surface early warnings: "likely problematic in ~N hours"
- Enables proactive intervention during maintenance windows

BV) Blast radius / dependency graph visualization
- ASCII/text process tree with annotations
- Show: child processes that would die, active connections, ports held, open file locks
- Compute total blast radius (memory freed, processes killed, clients disconnected)
- Critical for informed decision-making before applying actions

BW) Confidence-bounded automation controls
- Fine-grained `--robot` constraints:
  - `--min-posterior 0.99` (only kill if extremely confident)
  - `--max-blast-radius 2GB` (limit total impact per run)
  - `--max-kills 5` (limit action count)
  - `--require-known-signature` (only act on pattern matches)
  - `--exclude-categories agent,daemon` (protect specific categories)
- Provides a spectrum between full-manual and full-auto with explicit, auditable constraints

BX) Session resumability and idempotency
- Sessions are durable artifacts that survive connection interruptions
- `pt agent apply --resume-session <id>` continues from where it left off
- Track: plan, applied actions, pending actions, outcomes
- Idempotent execution: re-running a completed action is a no-op

BY) Learning transfer (prior export/import)
- `pt agent export-priors` exports learned priors to a portable file
- `pt agent import-priors --merge` imports priors to a new machine
- Enables fleet-wide shared priors and bootstrapping new machines from experienced ones
- Organization-level prior libraries with versioning

BZ) Agent-optimized output formats
- `--format summary` → one-line summary with counts and totals
- `--format metrics` → machine-parseable key=value pairs
- `--format slack` → human-friendly narrative suitable for chat handoff
- `--format exitcode` → minimal output, communicate via exit code
- Progressive verbosity levels for token efficiency

CA) Watch/alert mode for agents
- `pt agent watch --notify-exec "curl webhook..."` → structured webhook on threshold
- `pt agent watch --format jsonl` → streaming events for integration
- Enables push-based notification instead of polling
- Integrates with monitoring systems (Prometheus metrics endpoint possible)

CB) "What would change your mind" explanations
- For uncertain processes, show what additional evidence would shift the decision
- "If no network activity for 30 more minutes: P(abandoned) → 0.78"
- "If parent process dies: P(abandoned) → 0.89"
- Helps decide whether to wait/re-check or act now

CC) Per-machine learned baselines
- Track "normal" for each host: typical process count, baseline CPU, expected resource usage
- Anomaly detection relative to that machine's history, not global priors
- "This machine typically has 200 processes; now it has 450" is more informative than absolute counts

CD) Use-case interpretation of observed processes (see also Section 9)
- bun test at 91% CPU for 18m in /data/projects/flywheel_gateway
- gemini --yolo workers at 25m to 4h46m
- gunicorn workers at 45-50% CPU for ~1h
- several claude processes active

All of the above ideas (A through CD) are integrated in the system design below.

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
  - Inbox: `pt-core inbox` (list/open daemon-created sessions); wrapper `pt inbox`
- UX rule: `pt-core` exposes power, but `pt` must feel like one guided “run” by default (section 7.0). The verbose internal verbs should be discoverable for experts, but not required to use the tool.
- Modes:
  - Default: full-auto scan -> infer -> decide -> TUI approval with recommended actions pre-toggled.
  - `--robot`: skip TUI and execute the policy-approved action plan automatically (still subject to safety gates).
  - `--shadow`: run full-auto but never execute actions; log everything for calibration.
  - `--dry-run`: compute and print the action plan without executing (even if `--robot` is set).
- Default privilege/scope rule (very important):
  - By default, only recommend/execute actions on processes owned by the invoking user (same `uid`), since that is the common safe case and matches default OS permissions.
  - Non-owned processes (other users, root) can still be *observed* and shown for diagnosis, but are hard-gated from action execution unless explicitly enabled via policy + privileges (e.g., `sudo`) and are never eligible for auto-execution by default.
- Outputs:
  - Human: TUI + explainability ledger.
  - Machine: `--format json` (or `pt agent ...`) for integrations and unattended runs.
- Host coordination rule (very important):
  - Enforce a per-user “pt lock” (file lock) so only one `pt-core` run performs heavy probes and/or applies actions at a time.
  - Dormant mode (`ptd`) must respect the lock: if a manual/agent run is active, queue/inbox the escalation rather than competing for resources or racing actions.
- Design rule: all cross-process boundaries are for external system tools only (perf/eBPF/etc.); internal boundaries stay in-process for performance and coherence.

### 3.1 Data Collection Layer
- Collection is orchestrated in `pt-core` as a staged pipeline: quick scan -> candidate ranking -> deep scan/instrumentation (when warranted).
- Quick scans are multi-sample (short window) to compute deltas/trends (CPU ticks, IO deltas, scheduler latency proxies) rather than relying on a single snapshot.
- Every collector emits structured events with provenance (tool name/version, args, exit code, timing). Raw outputs are captured (subject to redaction) alongside parsed fields for auditability.
- Installation is maximal, execution is budgeted: even if all tools are installed, expensive probes are scheduled via VOI/Whittle/submodular policies to control overhead.
- Self-protection: `pt-core` runs with an overhead budget (caps concurrency, sampling rates, and optional nice/ionice) so the triage system does not become a new source of load.
- Quick scan inputs (fast): ps pid, ppid, etimes, rss, %cpu, tty, args, state
- Quick scan should also capture: uid, pgid, sid, and cgroup path (when available), since “who owns it?” and “what group/unit/container is it in?” strongly affect safe actions.
- Process identity safety: quick scan should also capture a stable per-process start identifier (Linux: `/proc/PID/stat` starttime ticks since boot; macOS: proc start time) so action execution can revalidate identity and avoid PID-reuse footguns.
- Deep scan inputs (slow):
  - OS note: Linux uses `/proc` collectors; macOS uses `ps`/`proc_pidinfo` + native tooling (`sample`, `fs_usage`, `nettop`, `spindump`) rather than `/proc`.
  - /proc/PID/io (read/write deltas)
  - /proc/PID/stat (CPU tick deltas)
  - /proc/PID/status (RSS, threads)
  - /proc/PID/wchan (wait channel)
  - /proc/PID/cgroup + /proc/PID/ns/* (namespaces) for containerization + unit attribution
  - ss -tnp (sockets) for network activity
  - pgrep -P (children)
  - who (TTY sessions)
  - cwd via /proc/PID/cwd
  - optional: git -C cwd status -sb
  - optional: lsof /proc/PID/fd for live dependency graph signals (open sockets, files)
  - optional: ss -ntp correlation for live client count
  - optional: systemd unit attribution (Linux): map PID -> unit/cgroup (systemctl/systemd-cgls) when available
  - optional: container attribution: detect docker/podman/kube cgroup patterns and capture container ID (when available)
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
- Δt: scan window duration (seconds), CLK_TCK: process CPU-time ticks per second (sysconf(_SC_CLK_TCK))
- N_eff_cores: effective core capacity available to the process (honor affinity/cpuset/quota when available; else total logical CPUs)
- k_ticks: CPU tick delta over Δt (utime+stime delta)
- n_ticks: integer tick budget over Δt: n_ticks = round(CLK_TCK * Δt * min(N_eff_cores, threads))
- u: CPU occupancy fraction (clamp to [0,1] if rounding/noise yields slight overflow): u = k_ticks / n_ticks
- u_cores: estimated cores used (can exceed 1): u_cores = k_ticks / (CLK_TCK * Δt)
- n_samp: number of quick-scan samples in the window (used for trend/change-point features)
- t: elapsed time (seconds)
- o: “unexpected reparenting” indicator (PPID=1 AND not managed-by-supervisor/job); treat PPID=1 as a weak, OS-dependent signal (e.g., macOS `launchd` makes PPID=1 common)
- s: state flags (R,S,Z,D)
- g: command category (test, dev, agent, shell, build, daemon, unknown)
- cwd category: repo root, temp, unknown
- tty: active/detached
- uid: owner uid (root vs user)
- pgid/sid: process group and session ID (job-control + “kill the whole tree” safety)
- cgroup/container: cgroup path, unit/container attribution (when available)
- start_id: stable process start identifier (Linux: `/proc/PID/stat` starttime ticks since boot; macOS: process start time from proc info); used to detect PID reuse and to revalidate before applying actions. When persisting, pair with a boot identifier so “starttime ticks” remain interpretable across reboots.
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
  - No silent deletion: any pruning is explicit, policy-driven, and recorded as retention events; keep plan + inference ledger + outcomes longer than raw high-volume traces.
  - Make retention configurable (including “keep everything”) so power users can trade disk for forensics.

What gets logged (raw + derived + outcomes):
- `runs`: `session_id`, host fingerprint, git commit, priors/policy snapshot hash, tool availability/capabilities, pt-core version.
- `system_samples`: timestamped loadavg, PSI, memory pressure, swap, CPU frequency/residency, queueing proxies.
- `proc_samples`: pid/ppid/pgid/sid/uid/state, cpu/rss/threads, tty/cwd/cmd categories, socket/client counts, cgroup identifiers, unit/container attribution (when available), and a stable start identifier (to guard against PID reuse).
- `proc_features`: Hawkes/BOCPD/Kalman/IMM state, copula params, EVT tail stats, periodicity features, sketches/heavy-hitter summaries.
- `proc_inference`: per-class log-likelihood terms, Bayes factors, posterior, lfdr, VOI, PPC flags, DRO drift scores.
- `decisions`: recommended action, expected loss, thresholds, FDR/alpha-investing state, safety gates triggered.
- `math_ledger`: optional “galaxy-brain” cards (equations + values + intuition) tied to `(session_id, pid, card_id)`; stored only when `--galaxy-brain` is requested.
- `actions` + `outcomes`: what was actually done (if anything), and what happened next (recovery, regressions, user override).

Partitioning rule (example):
- Partition by `date` and `session_id` (and optionally `host_id`) so each session writes its own files and concurrent runs do not contend.

### 3.4 Redaction, Hashing, and Data Governance
- Before persistence, apply a redaction policy to sensitive fields (full cmdlines, paths, endpoints, env values).
- Preserve analytical utility by logging: command/category tokens, stable hashes for grouping, and carefully scoped allowlists.
- Keep an explicit “telemetry schema + redaction version” in `runs` so old data remains interpretable.

### 3.5 Agent/Robot CLI Contract (No TUI)
Goal: give coding agents a hyper-ergonomic console interface that exposes everything a human can see/do in the TUI, but via token-efficient JSON/Markdown outputs and deterministic automation primitives. The agent CLI is designed with AI agents (Claude, Cursor, Copilot, etc.) as first-class users—optimizing for token efficiency, structured outputs, fine-grained control, and seamless integration into automated workflows.

Command surface (agent-optimized "session pipeline"; wrapper `pt` forwards to `pt-core agent ...`):

#### 1) Plan (create/compute)
```
pt agent plan [OPTIONS]
```
Core options:
- `--deep` - Force deep scan on all candidates (not just top suspects)
- `--min-age <seconds>` - Only consider processes older than threshold (default: 0)
- `--limit <N>` - Limit candidate count in output
- `--only kill|review|all` - Filter output by recommendation category
- `--format json|md|summary|metrics|slack` - Output format (see formats below)

**Differential mode** (session comparison):
- `--since <session-id>` - Compare against prior session, surface only changes
- `--since-time <timestamp|duration>` - Compare against time (e.g., `--since-time 2h`)
- Output includes: `new` (newly suspicious), `worsened` (escalated severity), `resolved` (no longer present), `persistent` (suspicious for N consecutive sessions)
- Dramatically reduces token overhead for repeated monitoring

**Goal-oriented mode** (resource recovery):
- `--goal "free <amount> RAM"` - Target memory recovery (e.g., `--goal "free 4GB RAM"`)
- `--goal "CPU < <percent>"` - Target CPU utilization (e.g., `--goal "CPU < 70%"`)
- `--goal "free port <port>"` - Target specific port recovery
- `--goal "free <N> processes"` - Reduce process count
- System optimizes candidate selection to achieve goal with minimum expected loss
- Output includes `goal_achievement` with projected vs actual recovery

**Predictive mode**:
- `--include-predictions` - Add trajectory analysis and time-to-threshold estimates
- Each candidate includes: current classification, predicted future classification, time until threshold crossing, trend direction

Behavior:
- Runs full-auto exploration (quick scan → targeted deep scan → infer → decide)
- Always returns: `session_id`, `schema_version`, system snapshot, candidates, and a pre-toggled recommended plan
- Each candidate/action includes a stable identity tuple (`pid`, `start_id`, `uid`) for revalidation

#### 2) Explain (drill-down)
```
pt agent explain --session <id> --pid <pid> [OPTIONS]
```
Core options:
- `--format json|md` - Output format
- `--include raw` - Include capped/redacted raw samples
- `--include ledger` - Include full evidence ledger (likelihood terms, Bayes factors)
- `--galaxy-brain` - Full mathematical derivation with equations and numbers

**Dependency/blast radius**:
- `--show-dependencies` - Show process tree with annotations
- `--show-blast-radius` - Compute total impact (memory freed, processes killed, connections dropped)
- Output includes ASCII tree visualization and structured dependency data

**Genealogy/backstory**:
- `--show-history` - Reconstruct process lifecycle narrative
- Timeline: started by X, parent died at T, orphaned to init, TTY detached, IO stalled since T+N
- Explains *how* the process reached its current state

**What-would-change-your-mind**:
- `--what-if` - Show hypothetical evidence that would shift the decision
- "If no network activity for 30 more minutes: P(abandoned) → 0.78"
- "If parent dies: P(abandoned) → 0.89"
- Helps decide whether to wait/re-check or act now

**Galaxy-brain math ledger (structured output)**:
- `--galaxy-brain` adds a `galaxy_brain` object with explicit equations, substituted numbers, and rendered outputs.
- Schema sketch (JSON):
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
          "log odds = log P(abandoned|x) - log P(useful|x)",
          "SPRT threshold = log[(L_kill,useful-L_keep,useful)/(L_keep,abandoned-L_kill,abandoned)]"
        ],
        "values": {
          "log_prior_useful": -2.11,
          "log_prior_abandoned": -3.02,
          "terms": {"cpu": 1.37, "tty": 0.84, "io": -0.25},
          "log_odds": 1.12,
          "threshold": 0.90
        },
        "intuition": "CPU+TTY dominate; IO softens confidence."
      },
      {
        "id": "hazard_time_varying",
        "title": "Time-Varying Hazard",
        "equations": [
          "λ_r | data ~ Gamma(α_r + N_r, β_r + E_r)",
          "S(t) = exp(-∑_r λ_r * E_r)"
        ],
        "values": {
          "regimes": [
            {"name":"tty_lost","alpha":2.0,"beta":1.0,"N":1,"E":3600,"lambda_mean":0.00083},
            {"name":"io_flatline","alpha":1.0,"beta":1.0,"N":0,"E":1800,"lambda_mean":0.00028}
          ],
          "survival_t": 0.41
        },
        "intuition": "TTY loss increases abandonment hazard."
      },
      {
        "id": "conformal_interval",
        "title": "Conformal Interval (Runtime/CPU)",
        "equations": [
          "s_i = |y_i - ŷ_i|",
          "q_{1-α} = quantile({s_i})",
          "[ŷ_{n+1} - q_{1-α}, ŷ_{n+1} + q_{1-α}]"
        ],
        "values": {
          "alpha": 0.1,
          "window": 200,
          "y_hat": 0.42,
          "q": 0.09,
          "interval": [0.33, 0.51]
        }
      },
      {
        "id": "conformal_class",
        "title": "Conformal Class Set",
        "equations": [
          "p_c = (1 + #{i: s_i(c) ≥ s_{n+1}(c)}) / (n + 1)",
          "Predict = {c : p_c > α}"
        ],
        "values": {
          "alpha": 0.1,
          "p_values": {"useful":0.04,"useful_bad":0.22,"abandoned":0.91,"zombie":0.03},
          "prediction_set": ["abandoned","useful_bad"]
        }
      },
      {
        "id": "e_fdr",
        "title": "e-FDR (Anytime-Valid)",
        "equations": [
          "e_i ≥ 0 with E[e_i | null] ≤ 1",
          "choose k s.t. (1/k) * Σ_{i=1..k} (1 / e_(i)) ≤ α"
        ],
        "values": {"alpha":0.05,"k":3,"included_in_set":true}
      },
      {
        "id": "alpha_investing",
        "title": "Alpha-Investing Budget",
        "equations": [
          "W_i = W_{i-1} - α_i + ω (if confirmed-correct)",
          "W_i = W_{i-1} - α_i (otherwise)"
        ],
        "values": {"W_prev":0.12,"alpha_spend":0.01,"omega_reward":0.03,"W_next":0.14}
      },
      {
        "id": "voi",
        "title": "Value of Information",
        "equations": [
          "VOI = E[loss_now - loss_after_measurement] - cost"
        ],
        "values": {"voi":0.7,"cost":0.2,"best_probe":"perf_sched"}
      }
    ]
  }
}
```

#### 3) Apply (execute, no UI)
```
pt agent apply --session <id> [OPTIONS]
```
Target selection:
- `--recommended` - Apply all recommended actions from the plan
- `--pids 123,456` - Apply to specific PIDs (must exist in session plan)
- `--targets 123:<start_id>,456:<start_id>` - Explicit identity tuples (preferred)

Confirmation:
- `--yes` - Required for execution (explicit confirmation)
- Must always respect `--shadow` and `--dry-run`

**Confidence-bounded automation** (fine-grained `--robot` controls):
- `--min-posterior <threshold>` - Only act if posterior probability exceeds threshold (e.g., `0.99`)
- `--max-blast-radius <amount>` - Limit total impact per run (e.g., `2GB`, `5 processes`)
- `--max-kills <N>` - Limit number of kill actions per run
- `--require-known-signature` - Only act on pattern library matches, not novel detections
- `--only-categories <list>` - Only act on specified categories (e.g., `test,devserver`)
- `--exclude-categories <list>` - Never act on specified categories (e.g., `agent,daemon`)
- `--abort-on-unknown` - Stop if any unexpected condition encountered

Resumability:
- `--resume-session <id>` - Resume an interrupted session from where it left off
- Sessions track: plan, applied actions, pending actions, outcomes
- Idempotent: re-running a completed action is a no-op

Safety:
- Must revalidate process identity immediately before applying any action
- If `(pid,start_id,uid)` mismatches, block and require fresh plan
- Supervisor-aware: detect supervised processes and suggest supervisor-level actions

#### 4) Status / sessions (automation primitives)
```
pt agent sessions [--limit N] [--format json|md]
pt agent show --session <id> [--format json|md]
pt agent status --session <id> [--format json|md]  # Applied vs pending actions
pt agent tail --session <id> [--format jsonl]       # Stream progress/outcomes
```

#### 5) Export / report (shareable artifacts)
```
pt agent export --session <id> --out bundle.ptb [OPTIONS]
pt agent report --session <id> --out report.html [OPTIONS]
```
Options:
- `--profile minimal|safe|forensic` - Redaction level
- `--galaxy-brain` - Include full math ledger in report
- `--embed-assets` - Inline CDN assets for offline viewing
- `--encrypt` - Encrypt bundle for secure transport

Report schema note:
- When `--galaxy-brain` is enabled, the HTML report embeds the same `galaxy_brain.cards[]` structure used by `pt agent explain`, allowing one renderer to power TUI, CLI, and report views.

**Human-friendly summaries** (for handoff to users):
- `--format slack` produces narrative suitable for chat:
  ```
  🧹 Process Triage Summary (devbox1.example.com)
  Scanned 247 processes, found 4 candidates.
  ✅ Killed 3 abandoned processes:
     • stuck jest worker (4h, 1.2GB)
     • orphaned next dev server (2d, 800MB)
     • zombie webpack watcher (6h, 400MB)
  📊 Recovered: 2.4GB RAM, 2.1 CPU cores
  ```

#### 6) Inbox (daemon-driven "plans ready for review")
```
pt agent inbox [--limit N] [--format json|md]
```
Lists pending sessions/plans created by dormant mode escalation.

#### 7) Watch (background monitoring for agents)
```
pt agent watch [OPTIONS]
```
Options:
- `--notify-exec <command>` - Execute command on threshold crossing (webhook, script)
- `--format jsonl` - Stream events for integration
- `--threshold <level>` - Trigger sensitivity (low|medium|high|critical)
- `--interval <seconds>` - Check frequency (default: 60)

Events emitted:
- `candidate_detected` - New process crosses recommendation threshold
- `severity_escalated` - Existing candidate worsens
- `goal_violated` - Resource target exceeded
- `baseline_anomaly` - Significant deviation from learned baseline

Enables push-based notification instead of polling; integrates with monitoring systems.

#### 8) Learning (prior management)
```
pt agent export-priors --out priors.json [--host-profile <name>]
pt agent import-priors --from priors.json [--merge|--replace]
pt agent list-priors [--format json|md]
```
- Export learned priors for transfer to other machines
- Import priors to bootstrap new machines from experienced ones
- Fleet-wide shared priors with versioning
- `--host-profile` tags priors with machine characteristics for smart matching

#### 9) Fleet operations (multi-host)
```
pt agent fleet plan --hosts <file|list> [OPTIONS]
pt agent fleet apply --session <fleet-session-id> [OPTIONS]
pt agent fleet report --session <fleet-session-id> [OPTIONS]
```
See section 3.8 for full fleet mode specification.

Output formats:
- `--format json` - Default; token-efficient, machine-stable, full structure
- `--format md` - Human-readable markdown, still concise
- `--format jsonl` - Streaming events for progress/integration
- `--format summary` - One-line summary: `candidates=4 kill=3 review=1 spare=243 recoverable_mb=2400`
- `--format metrics` - Key=value pairs for monitoring: `pt_candidates_total=4 pt_kill_recommended=3`
- `--format slack` - Human-friendly narrative for chat handoff
- `--format exitcode` - Minimal output; communicate via exit code only

Projection controls:
- `--fields <list>` - Include only specified fields
- `--compact` - Omit optional/verbose fields
- `--limit <N>` - Limit array sizes
- `--only kill|review|all` - Filter candidates

Token-efficiency rule: defaults return "just enough" (summary + recommended plan + top candidates); deeper details only on demand (`explain`, `--include`, `--galaxy-brain`).

Schema invariants (for agents):
- Every output includes: `schema_version`, `session_id`, `generated_at`, `host_id`, and a stable `summary`
- Avoid breaking changes: prefer additive fields; bump `schema_version` only when unavoidable
- "Pre-toggled" semantics are explicit:
  - `recommended.preselected_pids` and/or `recommended.actions[]` (with staged action chains and per-PID safety gates)
- Identity safety is explicit:
  - Every process reference includes `pid` plus a stable `start_id` (and `uid` at minimum)
  - Action execution uses these to revalidate targets and prevent PID-reuse mistakes
- Signature matching is explicit:
  - `matched_signature` field when a pattern library entry matched
  - `novel_pattern: true` when full inference was required
- Predictions are explicit (when `--include-predictions`):
  - `trajectory.trend`, `trajectory.time_to_threshold`, `trajectory.predicted_classification`
- Galaxy-brain math is structured (when `--galaxy-brain`):
  - `galaxy_brain.cards[]` uses stable `id` values and includes `equations`, `values`, and `intuition`
  - Report generation reuses the same schema to avoid duplicate render logic

Galaxy-brain JSON Schema sketch (agent/report outputs):
```json
{
  "type": "object",
  "required": ["schema_version", "session_id", "generated_at", "host_id", "summary"],
  "properties": {
    "schema_version": {"type": "string"},
    "session_id": {"type": "string"},
    "generated_at": {"type": "string", "format": "date-time"},
    "host_id": {"type": "string"},
    "summary": {"type": "object"},
    "galaxy_brain": {
      "type": "object",
      "required": ["enabled", "cards"],
      "properties": {
        "enabled": {"type": "boolean"},
        "cards": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["id", "title", "equations", "values"],
            "properties": {
              "id": {
                "type": "string",
                "enum": [
                  "posterior_core",
                  "hazard_time_varying",
                  "conformal_interval",
                  "conformal_class",
                  "e_fdr",
                  "alpha_investing",
                  "voi"
                ]
              },
              "title": {"type": "string"},
              "equations": {"type": "array", "items": {"type": "string"}},
              "values": {"type": "object"},
              "intuition": {"type": "string"}
            },
            "additionalProperties": false
          }
        }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": true
}
```

Exit codes are automation-friendly:
- `0` clean / nothing to do
- `1` candidates exist (plan produced) but no actions executed
- `2` actions executed successfully
- `3` partial failure executing actions
- `4` blocked by safety gates / policy
- `5` goal not achievable (not enough candidates to meet resource target)
- `6` session interrupted / resumable
- `>=10` tooling/internal error

Ergonomic escape hatches:
- `--exit-code always0` - Always exit 0 (for `set -e` workflows that parse JSON)
- `--timeout <seconds>` - Abort if operation exceeds time limit (predictable runtime for scripts)

### 3.6 Session Bundles & Rich HTML Reports (Shareable Artifacts)
Goal: one-command export/share of a complete session, and one-command generation of a premium, richly interactive HTML report.

Bundle format (`.ptb`):
- A single portable file that contains:
  - Container choice: prefer ZIP for maximum cross-platform + in-browser parsing; allow tar.zst for power users when size/speed matters.
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
  - Single `report.html` that works when opened directly (file://). Default: embed plan + derived summaries directly in the HTML (avoid relying on fetching local Parquet, which is often blocked by browser security).
  - Optional deep mode: include a “dropzone” that lets the user load a `.ptb` bundle via file picker; the report unpacks it in-memory (ZIP reader in JS; tar.zst only if explicitly supported) and (optionally) uses DuckDB-WASM to query the included Parquet.
  - Load UI/chart libraries from CDNs with pinned versions and SRI.
  - Visual polish: overview dashboard, sortable/searchable candidate table, per-process drilldown (timelines, evidence ledger, process tree, dependency impact), and actions/outcomes with before/after diffs.
  - Optional “power mode”: DuckDB-WASM in-browser for interactive queries over embedded/attached Parquet (when bundle profile permits).
  - Recommended CDN-loaded library stack (example; exact choices can evolve):
    - UI: Tailwind (or PicoCSS) + small custom CSS for premium spacing/typography
    - Tables: Tabulator (sorting/filtering/search, expandable rows)
    - Charts: ECharts or Plotly (time series + distributions + sparklines)
    - Graphs/trees: Mermaid (process tree + action DAG)
    - Code/math rendering: highlight.js + KaTeX/MathJax (for the galaxy-brain tab)
    - Optional advanced: DuckDB-WASM (query Parquet directly in-browser)
  - Security: pinned versions + SRI integrity hashes for all CDN assets.
  - Optional offline mode (extra): `--embed-assets` to inline third-party assets when CDNs are unavailable (default remains CDN-loaded).

### 3.7 Dormant Mode (Always-On Guardian)
Goal: keep pt running 24/7 with minimal overhead, automatically detecting when active triage is needed and escalating to full analysis.

Two operating modes:
- Active mode: full collection + inference + plan generation (resource-intensive; on-demand).
- Dormant mode (`ptd`, implemented as `pt-core daemon`): lightweight monitoring loop with strict overhead budget.

Dormant mode mechanics:
- Collect minimal signals at low frequency (loadavg, PSI, memory pressure, process count, top-N CPU by PID).
- Maintain baselines and detect triggers (sustained load, PSI stall, runaway top-N CPU, orphan spikes).
- Triggers should be time-aware and noise-robust (e.g., EWMA + change detection + “sustained for N seconds”), so the daemon does not flap.
- Advanced trigger math (optional but on-theme): use time-uniform concentration / e-process style tests so “spring into action” decisions have explicit sequential error control.
- Concurrency coordination: dormant escalation must acquire the per-user “pt lock” (section 3.0) before launching any heavier probes; if the lock is held by a manual/agent run, record the trigger and queue a pending inbox item instead of competing for CPU or racing actions.
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
- Inbox UX: dormant escalation writes sessions to an inbox so humans (`pt inbox` / TUI view) and agents (`pt agent inbox`) can list "plans ready for review".

### 3.8 Fleet Mode Architecture (Multi-Host Operation)
Goal: enable `pt` to operate across multiple hosts, aggregate telemetry, detect cross-host patterns, and apply fleet-wide safety controls. Fleet mode is essential for AI agents and DevOps workflows that manage many machines.

#### Fleet Topology Models
1. **Parallel execution** (default): Agent runs `pt` on each host independently via SSH, then aggregates results locally.
2. **Centralized controller**: A single `pt fleet` command orchestrates scans across multiple hosts, collecting telemetry to a central store.
3. **Federated queries**: Each host maintains local telemetry; fleet queries aggregate on-demand without central collection.

#### Fleet CLI Surface
```
pt agent fleet plan --hosts <file|comma-list> [OPTIONS]
pt agent fleet apply --fleet-session <id> [OPTIONS]
pt agent fleet report --fleet-session <id> [OPTIONS]
pt agent fleet status --fleet-session <id>
```

Options:
- `--hosts <file>` - File with one host per line (supports `user@host:port` format)
- `--hosts host1,host2,host3` - Comma-separated host list
- `--parallel <N>` - Max concurrent host connections (default: 10)
- `--timeout <seconds>` - Per-host timeout
- `--continue-on-error` - Don't abort fleet operation if one host fails
- `--host-profile <name>` - Apply host-group priors

#### Fleet Session Structure
A fleet session contains:
- `fleet_session_id` - Unique identifier for the fleet operation
- `hosts[]` - Array of host sessions, each with:
  - `host_id` - Hostname or identifier
  - `session_id` - Per-host session ID
  - `status` - pending|running|completed|failed
  - `candidates[]` - Per-host candidates
  - `summary` - Per-host summary
- `fleet_summary` - Aggregated statistics across all hosts
- `cross_host_patterns[]` - Patterns that appear on multiple hosts

#### Cross-Host Pattern Detection
The system detects patterns that span multiple hosts:
- "Signature X appears on 8 of 12 hosts" → likely a common issue (build tool, shared config)
- "Memory growth pattern on all staging hosts" → possible shared workload issue
- "Orphaned process from same parent command on multiple hosts" → deployment/orchestration issue

Pattern matching uses:
- Command signature similarity (fuzzy matching on cmdline)
- Timing correlation (processes started within same window)
- Resource usage profile similarity
- Working directory patterns

#### Fleet-Wide FDR Control
When operating across a fleet, FDR control must span all hosts:
- Single-host FDR might allow 1 false kill per 100 processes
- Fleet FDR prevents "1 false kill spread across 100 hosts" (unacceptable)
- Implementation: treat the entire fleet as one multiple-testing domain
- **Conservative option**: `α_per_host = α_fleet / n_hosts` (Bonferroni-style, provides strict guarantee)
- **Adaptive option** (heuristic): `α_per_host ≈ α_fleet / sqrt(n_hosts)` scales more gently but lacks formal FDR guarantee; use only when shadow-mode calibration validates it for your fleet size and dependence structure

#### Aggregated Telemetry
Fleet mode can aggregate telemetry to a central store:
- Central Parquet partitions with `host_id` column
- DuckDB queries span all hosts
- Enables: cross-host calibration, shared baseline learning, fleet-wide PAC-Bayes bounds

Storage options:
- Local aggregation (agent collects and merges)
- Shared filesystem (NFS, cloud storage)
- Object store (S3, GCS) with partition-by-host

#### Host-Group Priors (Transfer Learning)
Hosts with similar characteristics can share priors:
- `--host-profile webserver` - Apply priors learned from webserver-class machines
- `--host-profile devbox` - Apply priors learned from developer workstations
- Automatic profile detection based on: installed tools, running services, resource levels

Export/import for fleet learning:
```
pt agent export-priors --host-profile devbox --out devbox-priors.json
pt agent import-priors --from devbox-priors.json --host-profile devbox
```

#### Fleet Report Format
Fleet reports include:
- Overview: hosts scanned, total candidates, actions taken, fleet health score
- Per-host breakdown: candidates, actions, outcomes
- Cross-host patterns: common issues, fleet-wide trends
- Recommendations: "Consider addressing pattern X on all hosts"

### 3.9 Pattern/Signature Library (Known-Pattern Fast Path)
Goal: provide instant, high-confidence classification for known stuck/abandoned patterns without requiring full Bayesian inference. The pattern library accelerates common cases and provides stable, explainable matches.

#### Signature Structure
Each signature defines:
```json
{
  "id": "jest-worker-hang-v29",
  "name": "Stuck Jest Worker (v29+)",
  "description": "Jest worker process that has hung during test execution",
  "match": {
    "cmd_regex": "node.*jest.*--worker",
    "cpu_range": [90, 100],
    "runtime_min_seconds": 3600,
    "orphan": true,
    "tty": false,
    "io_idle_seconds": 600
  },
  "classification": "abandoned",
  "confidence": 0.98,
  "remediation": {
    "recommended_action": "kill",
    "hint": "Kill the parent test runner, not individual workers",
    "safe_restart": true
  },
  "metadata": {
    "tool": "jest",
    "tool_versions": ["29.x", "30.x"],
    "source": "builtin",
    "contributors": ["community"],
    "last_updated": "2025-01-15"
  }
}
```

#### Match Criteria
Signatures support flexible matching:
- `cmd_regex` - Regular expression on command line
- `cmd_contains` - Substring match (faster than regex)
- `binary_name` - Exact binary name match
- `cpu_range` - [min, max] CPU percentage
- `runtime_min_seconds` / `runtime_max_seconds` - Runtime bounds
- `memory_min_mb` / `memory_max_mb` - Memory bounds
- `orphan` - PPID=1 (reparented to init)
- `tty` - Has controlling TTY
- `io_idle_seconds` - No I/O for this duration
- `net_idle_seconds` - No network activity for this duration
- `state` - Process state (R, S, D, Z)
- `cwd_pattern` - Working directory regex
- `env_contains` - Environment variable patterns (when available)
- `parent_cmd_regex` - Parent process command pattern
- `child_count_range` - [min, max] child process count

Matching is conjunctive (all specified criteria must match). Partial matches are scored proportionally.

#### Signature Sources
1. **Builtin** - Ship with `pt-core`:
   - Jest workers, Mocha hangs, pytest stuck
   - Webpack watchers, Vite dev servers, Next.js dev
   - Node.js orphans, Python subprocess leaks
   - Docker shim processes, container leftovers
   - VS Code extension hosts, language servers
   - AI assistant workers (Copilot, Claude, Cursor)

2. **Community** - Fetched from central registry:
   - `pt agent signatures update` - Fetch latest community signatures
   - Versioned and signed for integrity
   - Opt-in with `--community-signatures`

3. **Organization** - Custom enterprise patterns:
   - `--signatures /path/to/org-signatures.json`
   - Internal tools, proprietary workloads
   - Distributed via config management

4. **User** - Personal additions:
   - `~/.config/pt/signatures.json`
   - "I always kill processes matching X"
   - Learn from user decisions over time

#### Signature Matching Flow
1. Quick scan collects basic features
2. Pattern matcher evaluates all signatures against each process
3. Matched signatures are ranked by confidence and specificity
4. Best match (if confidence > threshold) bypasses full inference
5. No match → full Bayesian inference with "novel pattern" flag

#### Signature vs. Inference Integration
- **Matched signature**: Use signature's confidence as prior, verify with quick inference
- **Partial match**: Boost prior toward signature's classification, run inference
- **No match**: Run full inference, flag as "novel pattern" (higher uncertainty)
- **Signature conflict**: Multiple signatures match → run inference to resolve

#### Learning from Decisions
User decisions can generate signature candidates:
- "You've killed 5 processes matching pattern X in the last week"
- "Would you like to add a signature for this pattern?"
- Generates draft signature for review/approval

#### Signature Management CLI
```
pt agent signatures list [--source builtin|community|org|user]
pt agent signatures show <id>
pt agent signatures add --file draft.json [--source user]
pt agent signatures update [--community]
pt agent signatures disable <id>
pt agent signatures stats  # Match frequency, false positive rates
```

#### Signature Telemetry
Track signature performance for calibration:
- Match frequency per signature
- User override rate (matched but user disagreed)
- False positive rate (matched, killed, user reported issue)
- Evolve signatures based on telemetry

---

## 4) Inference Engine (Closed-Form Bayesian Core)
Design constraint: all posterior/odds/expected-loss updates used for decisions must remain closed-form (conjugate, log-domain, numerically stable). Richer layers (Hawkes/EVT/copulas/wavelets/profilers) are allowed to produce deterministic summary statistics or analytic filter states, but they must feed the decision core as fixed features or via conjugate likelihood surrogates so the end-to-end decision remains auditable and non-ML.

### 4.1 State Space
C in {useful, useful-but-bad, abandoned, zombie}

### 4.2 Priors and Likelihoods (Conjugate)
- CPU occupancy from tick deltas: p_{u,C} ~ Beta(alpha_C, beta_C), k_ticks|p_{u,C},C ~ Binomial(n_ticks, p_{u,C}). (Use the Beta-Binomial posterior-predictive for k_ticks; u = k_ticks/n_ticks is a derived occupancy estimate. Posterior: p_{u,C}|data ~ Beta(alpha_C+k_ticks, beta_C+n_ticks-k_ticks).)
  - Modeling note: Binomial independence is an approximation (ticks are temporally correlated). To avoid overconfidence, optionally use an effective tick count n_eff (derived from autocorrelation/dispersion) in place of n_ticks; validate via shadow-mode calibration.
- Runtime t|C ~ Gamma(k_C, theta_C)
- Orphan o|C ~ Bernoulli(p_{o,C}), p_{o,C} ~ Beta(a_{o,C}, b_{o,C})
- State flags s|C ~ Categorical(pi_C), pi_C ~ Dirichlet(alpha^{state}_C)
- Command/CWD g|C ~ Categorical(rho_C), rho_C ~ Dirichlet(alpha^{cmd}_C)
- TTY activity y|C ~ Bernoulli(q_C), q_C ~ Beta(a_{tty,C}, b_{tty,C})
- Net activity nu|C ~ Bernoulli(r_C), r_C ~ Beta(a_{net,C}, b_{net,C})

### 4.3 Posterior Computation (Closed-form)
- P(C|x) proportional to P(C) * product_j P(x_j|C)
- Modeling note: the product assumes conditional independence of features given C. To avoid overconfident “double counting” when signals are correlated (CPU/PSI/IO, PPID/TTY, etc.), use conservative calibration (n_eff, shrinkage), feature collapsing, or a single dependence correction term (e.g., copula-based summaries) rather than multiplying many redundant terms.
- log posterior formula:
  log P(C|x) = log P(C)
               + log BetaBinomial(k_ticks; n_ticks, alpha_C, beta_C)
               + log GammaPDF(t; k_C, theta_C)
               + log BetaBernoulliPred(o; a_{o,C}, b_{o,C})
               + log DirichletCatPred(g; alpha^{cmd}_C) + ...
  where BetaBernoulliPred(o; a,b) = a/(a+b) if o=1 else b/(a+b), DirichletCatPred(g; α_vec) = α_vec[g]/sum(α_vec), and categorical terms use Dirichlet-Multinomial posterior-predictives
- Marginalize nuisance parameters with conjugate priors:
  - Beta-Binomial for CPU occupancy
  - Beta-Bernoulli for orphan, TTY, and net activity
  - Dirichlet-Multinomial for categorical features

### 4.4 Bayes Factors for Model Selection
- BF_{H1,H0} = [integral P(x|theta,H1)P(theta|H1) dtheta] / [integral P(x|theta,H0)P(theta|H0) dtheta]
- log odds = log BF + log prior odds

### 4.5 Semi-Markov and Competing Hazards
- hidden semi-Markov states S_t
- duration D_S ~ Gamma(k_S, theta_S)
- competing hazards (per class/state): lambda_finish,C, lambda_abandon,C, lambda_bad,C
- survival term (constant hazards): P(still running | t, C) = exp(-(lambda_finish,C+lambda_abandon,C+lambda_bad,C) * t)
- Gamma priors on hazard rates yield closed-form posterior
- With Gamma(α,β) prior on a (total) constant hazard λ (rate parameterization), the marginal survival is Lomax/Pareto-II: P(T>t) = (β/(β+t))^α
  - If modeling cause-specific hazards separately, either put the Gamma prior on λ_total,C directly (simplest) or constrain the priors so λ_total,C has a tractable form (e.g., shared rate parameterization).

### 4.6 Markov-Modulated Poisson / Levy Subordinator CPU
- N(t) ~ Poisson(kappa_S * t)
- burst sizes X_i ~ Exp(beta_S)
- C(t) = sum_{i=1..N(t)} X_i
- yields a compound Poisson (finite-activity Lévy subordinator) with closed-form Laplace transform; treat inference here as a feature layer (moment matching / EM / augmentation), then feed deterministic summaries to the closed-form decision core

### 4.7 Change-Point Detection
- Let k_t be the count of “busy” samples (or threshold exceedances) in a window of n_t samples.
- k_t ~ Binomial(n_t, p_1) before τ, and k_t ~ Binomial(n_t, p_2) after τ
- p_1 ~ Beta(alpha_1, beta_1), p_2 ~ Beta(alpha_2, beta_2)
- geometric prior on τ; posterior via Beta-binomial

### 4.7b Bayesian Online Change-Point Detection (BOCPD)
- Run-length recursion with conjugate updates for CPU/IO event rates
- Maintains posterior over change points for regime shifts

### 4.8 Information-Theoretic Abnormality
- compute D_KL(p_hat || p_useful) for event-rate / Bernoulli-style features
- large-deviation bound intuition: under the “useful” model, deviations with empirical rate p_hat have probability mass roughly ≲ exp(-n * D_KL(p_hat || p_useful)), where n is the effective sample count (window samples, events, or tick budget)
- use this as an interpretable “surprisal” evidence term (not a replacement for the conjugate core; it feeds it)

### 4.8b Large Deviations / Rate Functions
- Cramer/Chernoff bounds on event-rate deviations
- Quantifies probability of observing bursts under useful model

### 4.8c Copula Dependence Modeling
- Use Archimedean/vine copulas to model joint CPU/IO/net dependence
- Closed-form copula densities/likelihood evaluation for common families; fit parameters numerically (IFM/pseudo-likelihood) and feed dependence summaries into the decision core

### 4.9 Robust Bayes (Imprecise Priors)
- P(C) in [lower, upper]
- compute lower and upper posteriors; kill only if even optimistic posterior favors abandoned

### 4.10 Causal Intervention Models (do-calculus)
- For each action a in {pause, throttle, kill}, define outcome O in {recover, no_recover}
- O|a,C ~ Bernoulli(theta_{a,C}), theta_{a,C} ~ Beta(alpha_{a,C}, beta_{a,C})
- Compare P(O=recover | do(a)) using conjugate Beta-Bernoulli marginals
- Causal identification note: treat do(a) estimates as decision-analytic “what happens if we apply a” models; strict causal claims require assumptions (or explicit randomized experiments in shadow mode)

### 4.11 Wonham Filtering and Gittins Indices
- Wonham filtering for continuous-time partial observability of S_t
- Gittins index for optimal stopping / CPU scheduling of process decisions

### 4.12 Process Genealogy
- PPID tree as Bayesian network
- Galton-Watson branching model for expected child activity
- Orphan Bayes factor:
  BF_orphan = P(unexpected_reparenting|abandoned) / P(unexpected_reparenting|useful)
  (treat PPID=1 alone as weak evidence; condition on supervision/session context)
- "cobweb" model to represent process tree causality

### 4.13 Coupled Tree Priors (Correlated States)
- Pairwise coupling on PPID edges: P(S_u, S_v) proportional to exp(J * 1{S_u=S_v})
- Primary: exact sum-product belief propagation on the PPID forest (section 4.37). If extra non-tree couplings are added (shared resources, sockets, etc.) creating loops, use loopy BP or pseudolikelihood as a tractable approximation.

### 4.14 Belief-State Update (POMDP Approximation)
- b_{t+1}(S) proportional to P(x_{t+1}|S) * sum_{S'} P(S|S') b_t(S')
- Myopic decision: minimize expected loss under b_t with action set A

### 4.15 Bayesian Credible Bounds (Shadow Mode)
- Let e be false-kill rate; with Beta(a,b) prior and k errors in n trials, posterior is e|data ~ Beta(a+k, b+n-k)
- Credible upper bound: P(e <= eps) >= 1 - δ where eps = BetaInvCDF(1-δ; a+k, b+n-k)

### 4.15b PAC-Bayes Generalization Bounds (Shadow Mode)
- Use a PAC-Bayes bound to relate empirical false-kill rate to true false-kill rate with distribution-free guarantees under standard i.i.d./exchangeability assumptions across trials (use blocked/anytime variants or e-process controls when dependence is strong).
- One canonical form (Seeger-style): with probability ≥ 1-δ over n shadow-mode trials, for all posteriors Q over policies:
  KL( \hat{e}(Q) || e(Q) ) ≤ ( KL(Q||P) + ln( (2√n)/δ ) ) / n
  where P is a prior over policies, Q is the learned/selected posterior, \hat{e}(Q) is empirical false-kill rate, and e(Q) is true false-kill rate.
- Practical use in pt:
  - Treat each concrete “policy snapshot” (priors.json + policy.json + gates) as a hypothesis/policy.
  - Use Q as a delta mass at the current policy (then KL(Q||P) = -ln P(policy)), or as a distribution over a small set of candidate policies.
  - Report both: Bayesian credible bound (4.15) and PAC-Bayes bound (this section) as complementary safety evidence before enabling aggressive `--robot` thresholds.

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
- Closed-form likelihood expression for exponential kernels; practical inference via fast EM/MLE (optionally with branching augmentation where Gamma priors are conditionally conjugate given latent parent counts). Treat Hawkes outputs as deterministic summaries feeding the closed-form decision core.

### 4.20 Marked Point Process Layer
- Event times with magnitudes (bytes read/write, syscall cost)
- Likelihood in exponential family; summarizes burst severity

### 4.21 Bayesian Nonparametric Survival (Beta-Stacy)
- Discrete-time hazard h_t with Beta priors; closed-form updates per bin
- Captures long-tail stuckness beyond Gamma assumptions
- Explicit discrete-time form:
  - Bin time into t = 1..T with exposure n_t (e.g., number of samples or elapsed time in bin) and event indicator d_t in {0,1}
  - Prior: h_t ~ Beta(a_t, b_t)
  - Posterior: h_t | data ~ Beta(a_t + d_t, b_t + n_t - d_t)
  - Survival: S(t) = ∏_{j=1..t} (1 - h_j)
- Time-varying covariates via piecewise-constant hazards (closed-form):
  - Define regimes r based on covariate patterns (e.g., TTY lost, PPID=1, IO flatline)
  - For each regime r, hazard λ_r ~ Gamma(α_r, β_r)
  - With exposure E_r (time spent in regime r) and event count N_r, posterior:
    λ_r | data ~ Gamma(α_r + N_r, β_r + E_r)
  - Survival over a path of regimes: S(t) = exp(-∑_r λ_r * E_r)
  - This yields a closed-form, interpretable hazard inflation when regimes shift (e.g., TTY loss increases λ_r)

### 4.22 Robust Statistics (Huberized Likelihoods)
- Huber loss on log-CPU/IO residuals to reduce noise sensitivity
- Keeps inference stable under outliers and kernel noise

### 4.23 Linear Gaussian State-Space (Kalman)
- Smooth CPU/load signals; closed-form filtering and smoothing

### 4.24 Optimal Transport Shift Detection
- Use 1D Wasserstein distance between observed and baseline distributions
- In 1D, W1 is exactly computable via quantile functions (fast on empirical samples); use it as a drift score feeding conservative gates (PPC/DRO)

### 4.25 Martingale Sequential Bounds
- Azuma/Freedman bounds for sustained anomaly evidence over time

### 4.26 Graph Signal Regularization
- Laplacian smoothing on the PPID tree (applied to log-odds / natural parameters, not raw probabilities) to reduce noisy per-process estimates

### 4.27 Renewal Reward Modeling
- CPU/IO rewards per renewal interval; conjugate updates for reward rates

### 4.28 Risk-Sensitive Control
- CVaR and entropic risk to penalize tail outcomes in action selection

### 4.29 Bayesian Model Averaging (BMA)
- Combine models by marginal likelihood weights; robust to misspecification

### 4.30 Composite-Hypothesis Testing
- Mixture SPRT / GLR for composite alternatives with conjugate mixtures

### 4.31 Conformal Prediction
- Distribution-free (under exchangeability) prediction intervals for runtime/CPU; use time-blocked / online conformal variants to reduce temporal dependence issues
- Regression-style conformal interval (runtime/CPU):
  - Choose a point predictor ŷ_i and nonconformity score s_i = |y_i - ŷ_i| (or s_i = -log p(y_i|x_i))
  - Let q_{1-α} be the (1-α) empirical quantile of {s_i} over a calibration window
  - For new x_{n+1}, output interval: [ŷ_{n+1} - q_{1-α}, ŷ_{n+1} + q_{1-α}]
  - Guarantees: P(y_{n+1} in interval) ≥ 1 - α under exchangeability
- Classification-style conformal set (process state):
  - Nonconformity for class c: s_i(c) = 1 - P(C=c | x_i) (or NLL)
  - p-value for class c: p_c = (1 + #{i: s_i(c) ≥ s_{n+1}(c)}) / (n + 1)
  - Predict set: {c : p_c > α}, providing finite-sample coverage
- Time dependence handling:
  - Use blocked or rolling-window conformal (calibration on recent window), or online conformal with decaying weights to reduce drift sensitivity
  - Report window size and coverage target in the explainability ledger

### 4.32 FDR Control (Many-Process Safety)
- Treat “kill-recommended” as multiple hypothesis tests across many PIDs
- Use local false discovery rate: lfdr_i = P(useful_i | x_i)
- Bayesian FDR rule of thumb: sort by lfdr_i (ascending) and take the largest prefix K such that (1/|K|) * Σ_{i∈K} lfdr_i ≤ α
- If additionally emitting p-values/e-values from Bayes factors/likelihood ratios, apply the corresponding BH/BY (p-values) or e-FDR (e-values) procedure consistently
- Dependence matters: process hypotheses are not independent (shared PPID tree, shared cgroups/units, shared IO bottlenecks). The default should be conservative under dependence (e.g., Benjamini–Yekutieli) or hierarchical/group FDR (family = process group / systemd unit / container).
- Modern “anytime” framing (fits pt well): use e-values/e-processes derived from likelihood ratios/Bayes factors so optional stopping and sequential scanning remain valid, then apply an e-FDR control procedure (and connect it directly to online alpha-investing in section 4.40).
- e-value definition and e-FDR rule (explicit):
  - e_i ≥ 0 with E[e_i | null] ≤ 1 (e.g., e_i = BayesFactor_i or likelihood-ratio martingale)
  - Sort e-values descending: e_(1) ≥ e_(2) ≥ ... ≥ e_(m)
  - e-BH (one valid form): choose largest k such that (1/k) * Σ_{i=1..k} (1 / e_(i)) ≤ α
  - Reject/kill the top k; this controls FDR under arbitrary dependence when e-values are valid

### 4.33 Restless Bandits / Whittle Index Scheduling
- Each PID is an arm; actions are {quick-scan, deep-scan, instrument, pause, throttle}
- Compute an index per PID approximating marginal value of deep inspection (VOI per cost)
- Prioritize limited-overhead probes (perf/eBPF/stack sampling) on highest-index PIDs

### 4.34 Bayesian Optimal Experimental Design (Active Sensing)
- Choose next measurement m to maximize expected posterior entropy reduction per cost:
  argmax_m E_x [ H(P(S|x)) - H(P(S|x, new=m)) ] / cost(m)
- For exponential-family likelihoods, use Fisher information approximations as a closed-form proxy

### 4.35 Extreme Value Theory (POT/GPD) Tail Modeling
- Model exceedances of CPU/IO/network bursts above a high threshold u0
- Fit generalized Pareto tail parameters (numeric MLE/PWM); treat heavy-tail behavior as evidence of pathological bursts (or known spiky workloads)

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
- Simple alpha-investing update (one canonical form):
  - Maintain wealth W_t > 0, choose test level α_t ≤ W_{t-1}
  - If decision is a “discovery” (kill validated in shadow/feedback): W_t = W_{t-1} - α_t + ω
  - Otherwise: W_t = W_{t-1} - α_t
  - ω sets the reward for correct actions; choose ω to target a long-run FDR bound
- e-process integration:
  - Use e-values as sequential evidence and update wealth with e-FDR control to ensure optional stopping validity
  - Emit current wealth, spend, and reward in the audit ledger so the safety budget is transparent

### 4.41 Posterior Predictive Checks
- Compare observed traces to posterior predictive distributions to detect misspecification
- If PPC fails, widen priors / switch to more robust layers (Huberization, DRO, robust Bayes)

### 4.42 Distributionally Robust Optimization (DRO)
- Replace expected loss with worst-case expected loss over an ambiguity set (e.g., Wasserstein ball)
- Produces conservative “don’t kill unless safe” decisions under distribution shift; implement via analytic dual bounds where available (else conservative approximations feeding a gate, not the core posterior)

### 4.43 Submodular Probe Selection
- When probes overlap (redundant info) and have overhead, pick a near-optimal set maximizing information gain
- Greedy selection yields approximation guarantees; integrates with 4.34 active sensing

### 4.44 Trajectory Prediction and Time-to-Threshold Analysis
Goal: predict future process state based on current trends, enabling proactive intervention before problems become acute.

#### Trend Models
For each resource metric (CPU, memory, IO rate), fit a trend model:
- **Linear trend**: y(t) = a + b*t, estimated via Bayesian linear regression
- **Exponential trend**: y(t) = a * exp(b*t), for memory leaks and growth patterns
- **Plateau detection**: identify if metric is stabilizing or continuing to grow

Use Kalman filtering (4.23) to smooth noisy observations before trend fitting.

#### Time-to-Threshold Prediction
Given current value y_0, trend parameters, and a threshold θ (e.g., OOM limit, CPU saturation):
- Compute expected time until y(t) > θ
- Report as: "Memory growing at +50MB/hour; will hit 4GB limit in ~8 hours"
- Include prediction uncertainty (credible interval on time-to-threshold)

#### Classification Trajectory
Predict when a process will cross classification thresholds:
- "P(abandoned) currently 0.45; if trend continues, will reach 0.8 in ~2 hours"
- "CPU pattern suggests this will not self-terminate"

Use BOCPD (4.7b) to detect regime changes that would invalidate trend extrapolation.

#### Proactive Alerting
When `--include-predictions` is enabled:
- Each candidate includes: `trajectory.trend` (rising/falling/stable), `trajectory.time_to_threshold`, `trajectory.predicted_classification`, `trajectory.confidence`
- Enables early intervention during maintenance windows
- Supports "preemptive restart" recommendations for processes on bad trajectories

### 4.45 Per-Machine Learned Baselines
Goal: detect anomalies relative to each machine's normal behavior, not just global priors.

#### Baseline Learning
Track "normal" for each host over time:
- Typical process count distribution
- Baseline CPU/memory utilization
- Expected resource usage by time of day (diurnal patterns)
- Command category distributions (what processes normally run)

Use exponentially weighted moving averages with seasonal adjustments.

#### Anomaly Detection vs Baseline
Report deviations from learned baseline:
- "This machine typically has 200-250 processes; now it has 450"
- "CPU baseline is 20%; current is 85%"
- "Unusual process: 'custom_build' never seen before on this host"

Baseline anomalies boost prior toward "investigate" even if absolute values seem normal.

#### Baseline Persistence
- Store baselines in per-host telemetry partitions
- Update baselines from shadow-mode observations
- Cold start: use global priors until sufficient local data

#### Fleet Baseline Sharing
- Pool baselines across similar hosts (same `--host-profile`)
- New machine can bootstrap from fleet baseline
- Detect hosts that are outliers relative to their cohort

### 4.46 Signature-Informed Inference
Goal: integrate pattern library matches (section 3.9) with Bayesian inference.

#### When Signature Matches
- Use signature confidence as an informative prior: P(C=signature.classification) boosted
- Run quick inference to verify (don't blindly trust signatures)
- If inference agrees: high confidence, fast path
- If inference disagrees: flag for review, report conflict

#### When No Signature Matches
- Flag as "novel pattern" in output
- Use conservative priors (higher uncertainty)
- Candidate for signature learning if user makes consistent decisions

#### Partial Signature Matches
- Multiple criteria match, but not all
- Proportionally boost prior based on match score
- Full inference resolves final classification

---

## 5) Decision Theory and Optimal Stopping

### 5.1 Expected Loss Decision
- a* = argmin_a sum_C L(a,C) P(C|x)
- loss matrix:
  - useful: keep=0, kill=100
  - useful-but-bad: keep=10, kill=20
  - abandoned: keep=30, kill=1
  - zombie: keep=50, kill=1
  (note: zombies can’t be killed directly; interpret “kill” here as “resolve via parent reaping / restart parent”, see section 6)

### 5.2 Sequential Probability Ratio Test (SPRT)
- kill if:
  log [P(abandoned|x)/P(useful|x)] > log [(L(kill,useful)-L(keep,useful)) / (L(keep,abandoned)-L(kill,abandoned))]
  (i.e., kill when posterior odds exceed the Bayes-risk threshold implied by the loss matrix; equivalently compare Bayes factors + prior odds to this threshold)

### 5.3 Value of Information (VOI)
- VOI = E[loss_now - loss_after_measurement] - cost(measurement/waiting)
- if VOI <= 0 then act now; otherwise spend budget on the next measurement (or pause+observe)

### 5.4 Queueing-theoretic Threshold Adjustment
- model CPU contention as M/M/c or M/G/c
- Erlang-C wait (M/M/c): W_q = C(c,ρ) / (c*μ - λ_arrival) with ρ = λ_arrival/(c*μ)
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
- Choose the largest set K such that estimated FDR(K) <= alpha (e.g., estimated FDR(K) = (1/|K|) * Σ_{i∈K} lfdr_i; shadow-mode calibration can tighten/validate this)
- This prevents “scan many processes and inevitably kill one useful one”
- Under dependence (shared PPID/cgroups), default to conservative or structured FDR control (BY, group/hierarchical FDR by unit/container/process-group) rather than assuming independence.
- If using e-values (anytime-valid), replace lfdr ranking with e-value ranking:
  - Sort e_i descending; choose largest k such that (1/k) * Σ_{i=1..k} (1 / e_(i)) ≤ α
  - Kill only that top-k set; this keeps the batch decision valid under optional stopping and repeated scans

### 5.9 Budgeted Instrumentation Policy (Whittle / VOI)
- Under overhead constraints, allocate expensive probes to the highest expected VOI per unit cost
- Prefer: pause -> observe -> deep-scan -> throttle -> kill (as confidence increases)

### 5.10 Active Sensing Action Selection
- Choose measurement/action jointly to maximize expected improvement in decision quality per cost
- Guarantees: if VOI is low, stop measuring and act (or pause)

### 5.11 Online FDR Risk Budget (Alpha-Investing)
- Maintain a global false-kill risk budget across time and across repeated scans
- Spend budget only on extremely strong posterior odds; replenish with confirmed-correct actions
- Canonical update (one valid scheme):
  - Wealth W_0 set by policy (robot mode uses a small initial wealth)
  - For decision i, choose α_i ≤ W_{i-1}
  - If confirmed-correct: W_i = W_{i-1} - α_i + ω; else W_i = W_{i-1} - α_i
  - Use ω to target a long-run FDR bound; clamp W_i ≥ 0 to avoid overspending

### 5.12 DRO / Worst-Case Expected Loss
- When model misspecification is detected (via PPC) or drift is high (Wasserstein), switch to worst-case loss estimates
- This tightens kill thresholds under uncertainty

### 5.13 Submodular Probe Set Selection
- If "install everything" is possible but "run everything at once" is too heavy, select a probe subset maximizing incremental value
- Provides a principled way to be maximal over time while staying safe on overhead

### 5.14 Goal-Oriented Resource Recovery Optimization
Goal: when the user specifies a resource target (e.g., "free 4GB RAM"), optimize candidate selection to achieve that target with minimum expected loss.

#### Goal Specification
Supported goals:
- `--goal "free <N> RAM"` - Target memory recovery (MB/GB)
- `--goal "CPU < <N>%"` - Target CPU utilization
- `--goal "free port <N>"` - Free a specific port
- `--goal "processes < <N>"` - Reduce total process count

Goals can be combined: `--goal "free 2GB RAM" --goal "CPU < 80%"`

#### Optimization Formulation
Given:
- Set of candidate processes P, each with expected resource recovery r_i and expected loss L_i
- Resource target R (e.g., 4GB)

Solve the constrained optimization:
```
minimize: Σ_{i ∈ S} L_i           (total expected loss)
subject to: Σ_{i ∈ S} r_i ≥ R    (achieve resource target)
            S ⊆ {candidates with P(kill-ok) > threshold}
```

This is a variant of the knapsack problem. Use:
- Greedy approximation: sort by loss/recovery ratio, select until target met
- Dynamic programming for exact solution on small candidate sets
- Report if goal is not achievable: "Cannot free 4GB; max recoverable is 2.1GB"

#### Recovery Estimates
For each candidate, estimate recoverable resources:
- **Memory**: RSS (or USS if available) freed on kill
- **CPU**: cores freed = current CPU% / 100
- **Port**: port freed if process holds it
- **Child resources**: include resources of child processes that would also terminate

Handle uncertainty:
- Memory may not be immediately freed (caching, shared pages)
- CPU may be picked up by other processes
- Report expected vs conservative estimates

#### Goal Achievement Reporting
Output includes:
```json
{
  "goal": "free 4GB RAM",
  "achievable": true,
  "projected_recovery": "4.2GB",
  "required_candidates": 3,
  "total_expected_loss": 42.5,
  "alternative_plans": [
    {"candidates": 2, "recovery": "3.1GB", "loss": 28.0},
    {"candidates": 5, "recovery": "5.8GB", "loss": 61.2}
  ]
}
```

#### Tradeoff Visualization
When multiple plans achieve the goal, show the Pareto frontier:
- "Kill 2 processes: recover 3.5GB, risk 0.02 false kills"
- "Kill 4 processes: recover 5.2GB, risk 0.05 false kills"
- User chooses based on risk tolerance

### 5.15 Differential Session Comparison
Goal: when comparing against a prior session, compute only the delta and surface changes efficiently.

#### Delta Categories
- **New candidates**: processes not in prior session that are now suspicious
- **Worsened**: processes that were REVIEW, now KILL; or SPARE, now REVIEW
- **Improved**: processes that were suspicious, now less so
- **Resolved**: suspicious processes that no longer exist
- **Persistent offenders**: suspicious in N consecutive sessions

#### Efficiency Gains
- Skip full inference for unchanged processes (use cached posteriors)
- Only deep-scan new or changed candidates
- Reduce output size to delta only

#### Token-Efficient Delta Output
```json
{
  "comparison": {
    "prior_session": "abc123",
    "prior_candidates": 5,
    "current_candidates": 7
  },
  "delta": {
    "new": [{"pid": 1234, "classification": "abandoned", ...}],
    "worsened": [{"pid": 5678, "prior": "review", "current": "kill", ...}],
    "resolved": [{"pid": 9012, "reason": "exited"}],
    "persistent": [{"pid": 3456, "consecutive_sessions": 3, ...}]
  }
}
```

### 5.16 Fleet-Wide Decision Coordination
Goal: coordinate decisions across multiple hosts to maintain fleet-level safety invariants.

#### Fleet FDR Control
When applying FDR control across a fleet:
- Pool all candidates across all hosts into a single FDR domain
- Stricter per-host thresholds to maintain fleet-level guarantee
- Conservative: `α_per_host = α_fleet / n_hosts` (Bonferroni-style, strict guarantee)
- Adaptive (heuristic, requires shadow-mode validation): `α_per_host ≈ α_fleet / sqrt(n_hosts)`

#### Cross-Host Correlation
Detect correlated patterns:
- "3 hosts have processes from the same parent command"
- "Memory growth pattern appears on all staging hosts"
- Correlated patterns may indicate a common root cause → coordinate action

#### Fleet-Level Actions
Some actions should be fleet-wide:
- "Restart service X on all affected hosts"
- "Apply the same fix everywhere the pattern appears"
- Reduce repetitive per-host decisions

---

## 6) Action Space (Beyond Kill)

- keep
- pause (SIGSTOP) and observe (PID or process group)
- resume (SIGCONT)
- renice
- cgroup freeze/quarantine (cgroup v2 freezer, when available)
- cgroup CPU throttle
- cpuset quarantine
- stop supervisor/service (systemd/launchd/pm2/etc.) when the PID is managed and would respawn
- restart (for known services)
- reap / resolve zombies (state `Z`): cannot “kill” a zombie; instead identify the parent chain and recommend restart/kill-parent so the zombie is reaped
- kill (SIGTERM -> SIGKILL) (PID or process group; prefer group-aware actions when children exist)

Operational realism notes:
- Zombie processes (`Z`) are already dead; signals don’t remove them. Treat zombies as symptoms and route actions to the parent (or “report only”).
- Uninterruptible sleep (`D`) may not respond to SIGKILL until the kernel unblocks; default to investigation (wchan, IO device, dependency impact) rather than blind killing.
- Supervised processes often respawn: if a PID is under systemd/launchd/supervisord/nodemon/etc., killing the PID alone may be ineffective or harmful; prefer unit/supervisor actions and log “respawn detected” in after-action outcomes.
- Process groups matter: many “rogue” workloads are actually a tree; staged actions should be group-aware (pause group → observe → term group → observe → kill group) to avoid leaving orphans.
- Session safety: protect the active login/session chain by default (current shell, tmux/screen, SSH server/client, controlling TTY) so triage never cuts off the user running it.
- PID reuse / TOCTOU safety: always revalidate a target immediately before action (at minimum: `(pid,start_id,uid)` from section 3.5). If identity mismatches, block and require a fresh plan; never “best-effort” kill by PID alone.
- Privilege/UID safety: by default, only execute actions against processes owned by the invoking user. Cross-UID (other users/root) actions require explicit privileges + policy allowlists; do not allow cross-UID auto-execution by default even if `sudo` is available.

### 6.1 Supervisor Detection and Supervisor-Aware Actions

Many processes on modern systems are managed by supervisors that will restart them if killed directly. Killing a supervised process without stopping the supervisor results in an immediate respawn—wasted effort at best, a confusing loop at worst. For AI agents managing remote systems, this is especially problematic: the agent may repeatedly kill a process thinking it's stuck when it's actually being correctly respawned by design.

**Supervisor detection heuristics:**

| Supervisor | Detection Method |
|------------|------------------|
| **systemd** | `systemctl status <pid>` returns unit info; or parent is `systemd` with a matching cgroup in `/sys/fs/cgroup/system.slice/` |
| **launchd** | `launchctl list` + plist matching; or parent is `launchd` with `XPC_SERVICE_NAME` env var |
| **supervisord** | Parent is `supervisord`; or matches entry in `/etc/supervisor/conf.d/*.conf` |
| **pm2** | `pm2 jlist` returns process info; or matches `PM2_HOME` env pattern |
| **Docker** | Process has docker-specific cgroup (`/docker/`); or `docker inspect` by container ID from cgroup |
| **containerd/CRI** | Cgroup pattern `/kubepods/` or `/containerd/` |
| **nodemon/forever/pm2** | Parent command matches known watcher patterns; env vars like `NODEMON` |
| **tmux/screen** | Session attachment via `/proc/<pid>/fd` inspection or parent hierarchy |
| **nohup/disown** | No controlling TTY + specific parent patterns |

**Supervisor-aware action strategies:**

For each detected supervisor type, the action space expands beyond raw signals:

```
systemd-supervised process:
  - systemctl stop <unit>      # Graceful stop, supervisor-aware
  - systemctl restart <unit>   # Restart via supervisor (for stuck services)
  - systemctl reload <unit>    # Config reload without restart
  - systemctl mask <unit>      # Prevent auto-restart (temporary disable)

launchd-supervised process:
  - launchctl stop <label>     # Graceful stop
  - launchctl unload <plist>   # Remove from supervision
  - launchctl kickstart -k <label>  # Force restart

pm2-supervised process:
  - pm2 stop <id|name>         # Graceful stop
  - pm2 restart <id|name>      # Restart via pm2
  - pm2 delete <id|name>       # Remove from pm2 entirely

Docker container:
  - docker stop <container>    # SIGTERM + grace period + SIGKILL
  - docker restart <container> # Restart container
  - docker pause <container>   # Freeze without killing (cgroup freezer)
  - docker kill <container>    # Immediate SIGKILL

supervisord-managed process:
  - supervisorctl stop <name>  # Graceful stop
  - supervisorctl restart <name>
```

**Output contract for supervisor detection:**

The `pt agent plan` output includes supervisor information when detected:

```json
{
  "candidates": [{
    "pid": 12345,
    "supervised": true,
    "supervisor": {
      "type": "systemd",
      "unit": "myapp.service",
      "can_restart": true,
      "restart_policy": "always"
    },
    "recommended_action": "systemctl_stop",
    "fallback_action": "kill",
    "supervisor_action_command": "systemctl stop myapp.service",
    "why_supervisor": "Process will respawn within 100ms if killed directly; supervisor action is more effective"
  }]
}
```

**Agent behavior implications:**

When an AI agent receives supervisor information:
1. **Prefer supervisor actions over raw kill** when the goal is to stop the process permanently
2. **Use raw kill with pause observation** when investigating whether a process is actually stuck (the respawn itself provides signal)
3. **Use supervisor restart** when the goal is recovery from a bad state, not termination
4. **Never repeatedly kill a supervised process** without either stopping the supervisor or acknowledging the respawn-by-design pattern

**Respawn tracking:**

To detect "kill-respawn loops", track `(command_pattern, cgroup, supervisor_unit)` tuples across time:

```json
{
  "respawn_events": [
    {"pattern": "myapp --worker", "supervisor": "systemd:myapp.service",
     "kills": 3, "respawns": 3, "window_minutes": 5,
     "recommendation": "Use systemctl stop instead of kill"}
  ]
}
```

Decision engine selects action with minimum expected loss. Destructive actions (especially kill) require explicit confirmation by default via the TUI, but can be executed automatically under an explicit `--robot` flag and only when all safety gates pass (robust Bayes/DRO/FDR/alpha-investing/policy allowlists).

---

## 7) UX and Explainability (Alien Artifact)

### 7.0 Golden Path (One Coherent Run; Hide Complexity)
- Avoid “a pile of verbs” (scan/deep/infer/decide/apply/report/export/daemon) as the *primary* user experience.
- Default `pt` behavior is a single coherent run:
  1) quick multi-sample scan (deltas, not a single snapshot)
  2) infer + generate a plan (with safety gates + staged actions)
  3) show “Apply Plan” TUI (pre-toggled recommendations)
  4) execute in stages (pause/throttle → verify → kill as last resort)
  5) show “After” diff + session summary + export/report affordances
- Everything else remains available as subcommands/flags for experts and automation, but the default path must feel like one guided workflow.
- Every run has a durable `session_id` and an artifact directory (plan + samples + derived + outcomes), even for scan-only runs.

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
- Persistent system bar: current load/memory/pressure + “overhead budget used” so the tool never feels opaque or scary.
- Two-pane layout: left = candidates/actions table; right = drilldown (why summary, evidence ledger, process tree, dependency impact, “what would change my mind”).
- Bottom action bar: Apply Plan, Export Bundle, Render Report, Toggle View, Help (so users always know the next move).
- Progressive disclosure: default to a one-line “why”; expand to full ledger only on demand.
- Visual language (consistent tokens):
  - Action badge: KEEP / PAUSE / THROTTLE / KILL
  - Risk badge: SAFE / CAUTION / DANGER (stable colors)
  - Confidence badge: LOW / MED / HIGH (stable colors)
  - Protected processes are visually unmistakable (locked badge) and hard-gated.

### 7.6 Interaction Design (Fast, Keyboard-First)
- One-keystroke actions: `/` search, `f` filter, `s` sort, `enter` details, `space` toggle, `a` apply plan, `e` export bundle, `r` render report, `g` galaxy-brain, `?` help.
- Bulk operations: “select recommended”, “select none”, and guarded “select all kills” behind an explicit confirmation step.
- After-action diff: always show a “before/after” snapshot and outcomes (killed/failed/still-running) to make the tool feel complete.
- Micro-interactions that make it feel premium:
  - Visible staged progress: quick scan → deep scan → infer → decide → plan ready.
  - Smooth transitions between list/detail.
  - Inline sparklines for the highlighted process (CPU/IO deltas over the sampling window).

### 7.7 Sharing & Reporting UX
- One command / one keybinding: export a `.ptb` bundle for sharing and render a single-file HTML report for premium postmortems.
- Reports should look like an incident dashboard: overview metrics, timelines, candidate table, drilldowns, and action outcomes.

### 7.8 “Galaxy-Brain Mode” (Math Transparency + Fun)
Requirement: at any time, the user can toggle a “galaxy-brain” view (keybinding) or pass a flag to see the full scary math and its concrete numeric impact on decisions.
- Purpose:
  - Educational/fun: show the “alien artifact” internals.
  - Debuggable: make it obvious when a term dominates, when a safety gate triggers, or when the model is uncertain.
- TUI behavior:
  - Keybinding: `g` toggles “galaxy-brain” mode in the detail pane.
  - Shows: posterior by class, posterior odds vs thresholds (SPRT), expected-loss table, top Bayes factors, per-feature log-likelihood contributions, FDR/alpha-investing budget state, VOI calculations, and any robust/DRO tightening that changed the decision.
  - Shows both: formal equations + a short intuition line (“this term dominates because…”).
  - Math cards (each rendered as equation + substituted numbers + output):
    - **Posterior core**:
      - log P(C|x) = log P(C) + Σ_j log P(x_j|C); display each term with numeric value
      - Posterior odds + SPRT threshold with the exact loss-matrix-derived boundary
    - **Time-varying hazard**:
      - Regime hazards: λ_r | data ~ Gamma(α_r + N_r, β_r + E_r)
      - Survival: S(t) = exp(-∑_r λ_r * E_r), with per-regime E_r and inferred λ_r shown
      - “Hazard inflation” callout when regime switches (e.g., TTY lost, PPID=1, IO flatline)
    - **Conformal interval** (runtime/CPU):
      - s_i = |y_i - ŷ_i|; q_{1-α} = quantile({s_i})
      - Interval: [ŷ_{n+1} - q_{1-α}, ŷ_{n+1} + q_{1-α}]
      - Display calibration window size, α target, and achieved coverage estimate
    - **Conformal class set** (state prediction):
      - p_c = (1 + #{i: s_i(c) ≥ s_{n+1}(c)}) / (n + 1)
      - Predicted set: {c : p_c > α}; show p_c per class
    - **e-values / e-FDR** (anytime-valid selection):
      - e_i (from Bayes factor or likelihood-ratio martingale)
      - e-BH rule: choose largest k with (1/k) * Σ_{i=1..k} (1 / e_(i)) ≤ α
      - Show current k, α, and whether the PID is inside the accepted set
    - **Alpha-investing** (online budget):
      - Wealth update: W_i = W_{i-1} - α_i + ω (if confirmed-correct), else W_i = W_{i-1} - α_i
      - Show W_{i-1}, α_i spend, ω reward, and resulting W_i
    - **VOI**:
      - VOI = E[loss_now - loss_after_measurement] - cost
      - Show the best next probe and whether VOI > 0
- CLI behavior:
  - Flag: `--galaxy-brain` (or `--explain full`) adds the same math ledger to `pt agent explain` and to report generation.
- Report behavior:
  - Include a “Galaxy-Brain” tab that renders the same ledger with equations and numbers (still respecting redaction policies).

---

## 8) Real-World Usefulness Enhancements (All Included)

- Rich observability: IO, syscalls, context switches, page faults, swap, run-queue delay, fd churn, lock contention, socket backlog
- Context priors: TTY, tmux, git status, recent shell activity, open editor
- Human-in-the-loop updates: decisions update priors (conjugate updates)
- Shadow mode: advisory only, log decisions for calibration
- Safety rails: rate-limit kill actions, never kill system services
- Data-loss gate: detect open write FDs (sqlite WAL/journal, git locks, package managers, DB sockets) and inflate kill loss or hard-block in `--robot` unless explicitly overridden by policy.
- Runbooks: suggest safe restart or pause for known services
- Incident integration: logging, rollback hooks
- Systemd/Kubernetes plugins for service-aware control
- Data governance: explicit retention policy + full audit trail (no silent deletions)
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

### 8.1 Biggest Conceptual Pitfalls to Avoid (So It Stays Premium)
- Sudo + installs: never hang on prompts; always emit a capabilities report and degrade gracefully when permissions/tools are missing.
- Too much raw data: enforce caps + explicit retention; keep summaries/ledger longer than raw high-volume traces; always redact/hash before persistence.
- Robot mode safety: `--robot` must be explicit and still gated (protected denylist, blast radius limits, confidence thresholds, robust/DRO tightening, FDR/alpha-investing budgets).
- UI overload: progressive disclosure is everything (one-line “why” by default; ledger + galaxy-brain on demand).
- “Tool becomes the hog”: hard overhead budgets, cooldowns, and safe-by-default dormant mode.

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
- Define the user-visible golden path and reduce “mode overload”: `pt` feels like one coherent run by default; expert verbs remain discoverable but not required (section 7.0).
- Define the durable session model: `session_id` generation, artifact directory layout, and which artifacts exist even in scan-only runs.
- Create priors.json schema for alpha/beta, gamma, dirichlet, hazard priors
- Create policy.json for loss matrix and guardrails
- Define command categories and CWD categories
- Define telemetry schema + partitioning rules (section 3.3) and redaction/hashing policy (section 3.4); version these in `runs`.
- Define a capabilities cache schema: tool availability, versions, permissions, and “safe fallbacks” per signal.
- Define the agent/robot contract: schema versioning, exit codes, pre-toggled plan semantics, and gating behavior.
- Define target identity + privilege contracts: `(pid,start_id,uid,...)` revalidation rules for apply, default same-UID action scope, and the per-user “pt lock” coordination semantics (manual/agent/daemon).
- Define the bundle/report contract: `.ptb` contents, export profiles, and the single-file CDN-loaded HTML report spec.
- Define dormant-mode daemon spec: triggers, escalation policy, cooldowns, and service integration (systemd/launchd).
- Define “galaxy-brain mode” contract: what math to show, how to render equations + numbers, and how to expose it in TUI/agent/report (section 7.8).
- Define an inbox contract for daemon-driven “plans ready for review” (agent and human surfaces).

### Phase 2: Math Utilities
- Implement BetaBinomial and Beta-Bernoulli/Dirichlet-multinomial posterior-predictives (plus Beta PDF/CDF utilities for posterior reporting/galaxy-brain views), GammaPDF
- Implement Bayes factors, log-odds, posterior computation
- Implement numerically-stable primitives (log-sum-exp, log-domain densities, stable special functions) to prevent underflow in Bayes factors/posteriors.
- Implement Arrow/Parquet schemas for telemetry tables and a batched Parquet writer (append-only).

### Phase 3: Evidence Collection
- Quick scan: ps + basic features
- Deep scan: /proc IO, /proc/PID/schedstat + sched, CPU deltas, wchan, cgroup stats, fd churn, net, children, TTY (plus stack/IO sampling on macOS when available)
- Implement a tool runner in `pt-core` with timeouts, output-size caps, and backpressure so “collect everything” does not destabilize the machine.
- Emit structured progress events (JSONL) so both the TUI and `pt agent tail` can show staged progress (scan → deep scan → infer → decide).
- Persist raw tool events + parsed samples to Parquet as the scan runs (batched), so failures still leave an analyzable trail.
- Maximal system tools (auto-install; attempt all, degrade gracefully):
  - Linux: sysstat, perf (incl. perf sched), bpftrace/bcc/bpftool, iotop, nethogs/iftop, lsof, atop, sysdig, smem, numactl/numastat, turbostat/powertop, strace/ltrace, acct/psacct, auditd, pcp
  - macOS: fs_usage, sample, spindump, nettop, powermetrics, lsof, dtruss (if permitted), vm_stat

### Phase 3a: Tooling Install Strategy (Maximal Instrumentation by Default)
Policy: always try to install everything and collect as much data as possible.
Implementation note: `pt` (bash) performs installation and capability discovery; it then launches `pt-core` with a cached capabilities manifest so inference/decisioning can gracefully degrade when tools are missing.
Non-invasiveness rule: install tools aggressively, but avoid enabling persistent daemons or making irreversible system configuration changes by default; prefer on-demand sampling/tracing and record what could not be accessed due to permissions.
Daemonized-package note: some packages (e.g., `auditd`, `pcp`) may start services on install. Default behavior should avoid surprise persistent daemons: prefer using them only if already running, or require an explicit opt-in policy/flag to enable/start them.

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
- Full-auto rule: never hang on a sudo password prompt. Use non-interactive `sudo -n` (or a dedicated “install” step) and, if elevation is unavailable, record missing capabilities and continue with degraded collection.
- Record capabilities in a local cache (what is available vs missing).
- Prefer richer signals when available (eBPF/perf), but never fail if missing.
- If a tool is not available via package manager, download pinned upstream binaries (with checksums/signatures where available) into a tools cache and re-run capability detection.

Capability matrix (signal -> tool -> OS support -> fallback):
- syscalls/IO events: bpftrace/bcc (Linux), dtruss (macOS if permitted) -> fallback: strace
- CPU cycles/cache/branch: perf (Linux), powermetrics (macOS) -> fallback: sample
- per-PID IO bandwidth: iotop (Linux), fs_usage (macOS) -> fallback: Linux: /proc/PID/io; macOS: none (fs_usage is the primary)
- per-PID network: nethogs/iftop (Linux), nettop (macOS) -> fallback: Linux: ss + lsof; macOS: lsof -i + netstat (coarse)
- run-queue + CPU load: mpstat/vmstat/sar (Linux), powermetrics (macOS) -> fallback: uptime/loadavg
- FD churn + sockets: lsof (Linux/macOS) -> fallback: Linux: /proc/PID/fd; macOS: lsof -p
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
- Scheduler wait / run-queue latency / context-switch bursts -> useful-but-bad likelihood boost + hazard inflation
- PSI stall pressure -> queueing-theoretic cost term (Erlang-C) + hazard inflation
- Cache miss / branch mispredict -> tight-loop likelihood boost (useful-but-bad vs abandoned)
- Socket/client count -> dependency-weighted loss scaling + causal action cost
- Unexpected reparenting (PPID=1) + dead TTY (and not a managed service) -> Bayesian genealogy prior shift toward abandoned
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
- Enforce action safety invariants: acquire the per-user “pt lock”, revalidate `(pid,start_id,uid,...)` immediately before each action step, and enforce default same-UID action scope (cross-UID requires explicit policy + privileges).
- Always end the run with an “After” view + session summary + first-class export/report affordances (so it feels like a complete product, not a script).

### Phase 7: UX Refinement
- Evidence glyphs and ledger
- Explainability line per process
- Add a single “Apply Plan” screen with drill-down and bulk toggle operations.
- Implement the premium TUI spec (section 7.5–7.6): plan-first layout, system bar + action bar, consistent badges, keyboard-first operations, progress stages, and sparklines.
- Implement “galaxy-brain mode” in the detail pane (section 7.8).
- Implement the agent/robot CLI parity layer (section 3.5): plan/explain/apply/sessions/tail/inbox/export/report with token-efficient defaults.
- Implement export bundles + single-file CDN-loaded HTML report generation (section 3.6), including the galaxy-brain tab.

### Phase 8: Safety and Policy
- Guardrails for system services
- Rate limiting, quarantine policies
- Define robot-mode safety gates: minimum posterior odds, FDR/alpha-investing budgets, allowlists/denylists, and maximum blast radius per run.
- Add “data-loss” safety gates: open write FDs (sqlite WAL/journal, git locks, package manager locks) inflate kill loss and can hard-block `--robot` unless policy explicitly allows.
- Add “unkillable state” handling: zombies (`Z`) route to parent reaping; uninterruptible sleep (`D`) defaults to investigate/mitigate rather than blind kill.
- Add “identity/privilege” safety gates: PID reuse/identity mismatch blocks, and default same-UID enforcement (cross-UID requires explicit allowlist + `sudo`/root).
- Implement dormant mode daemon + service integration (section 3.7), ensuring it never becomes the hog (strict overhead budget, cooldowns, and safe escalation).

### Phase 9: Shadow Mode and Calibration
- Advisory-only logging
- Compare decisions vs human choices and outcomes using DuckDB queries over the Parquet telemetry lake
- Compute PAC-Bayes bounds, FDR metrics, calibration curves, and posterior predictive check summaries as first-class artifacts
- Update priors with conjugate updates and (when enabled) empirical Bayes hyperparameter refits from shadow-mode logs

### Phase 10: Supervisor Detection and Supervisor-Aware Actions
- Implement supervisor detection heuristics (section 6.1):
  - systemd: `systemctl status <pid>` + cgroup inspection
  - launchd: `launchctl list` + plist matching + `XPC_SERVICE_NAME` env var
  - supervisord: parent process + config file matching
  - pm2: `pm2 jlist` + env var patterns
  - Docker/containerd: cgroup path inspection (`/docker/`, `/kubepods/`, `/containerd/`)
  - nodemon/forever: parent command matching + env vars
  - tmux/screen: session attachment via `/proc/<pid>/fd`
- Implement supervisor-aware action generation:
  - Map detected supervisor to appropriate stop/restart/reload commands
  - Include supervisor information in `pt agent plan` output
  - Add `supervisor_action_command` field with ready-to-execute command
- Implement respawn tracking:
  - Track `(command_pattern, cgroup, supervisor_unit)` tuples across sessions
  - Detect kill-respawn loops and recommend supervisor actions
  - Persist respawn events to telemetry for pattern learning

### Phase 11: Pattern/Signature Library
- Implement signature schema and storage (section 3.9):
  - Define pattern matching DSL (command regex, cgroup pattern, behavior vector)
  - Create curated library of known signatures (test runners, dev servers, AI tools, etc.)
  - Implement signature matching engine with confidence scores
- Implement signature-informed inference fast path:
  - Skip full Bayesian inference when high-confidence signature match
  - Use signature-provided priors when partial match
  - Track signature match rates in telemetry for library refinement
- Implement user signature customization:
  - Allow users to define custom signatures in `~/.config/process_triage/signatures.json`
  - Provide `pt signature add/remove/list` commands
  - Support signature sharing via `.ptb` bundles

### Phase 12: Trajectory Prediction and Time-to-Threshold
- Implement trajectory models (section 4.44):
  - Memory growth rate estimation with confidence intervals
  - CPU trend analysis (increasing, stable, decreasing)
  - Resource exhaustion time-to-threshold prediction
- Implement time-based alerts:
  - Predict when process will exceed configurable thresholds
  - Generate warnings with lead time estimates
  - Support `pt agent plan --include-predictions` output
- Implement per-machine baseline computation (section 4.45):
  - Fit baseline distributions from historical data per machine/host
  - Compute z-scores and anomaly detection relative to baseline
  - Handle cold-start with conservative default priors

### Phase 13: Goal-Oriented Optimization
- Implement goal parsing and constraint specification (section 5.14):
  - Parse `--goal "free 4GB RAM"` style constraints
  - Support resource targets (memory, CPU, ports, file descriptors)
  - Support composite goals (e.g., "free 2GB AND release port 3000")
- Implement goal-directed candidate selection:
  - Score candidates by expected contribution to goal
  - Optimize kill set for maximum goal progress with minimum risk
  - Handle infeasible goals gracefully (report shortfall)
- Implement progress tracking:
  - Show expected vs actual goal progress in plan output
  - Track goal achievement in session outcomes

### Phase 14: Fleet Mode and Multi-Host Coordination
- Implement fleet session management (section 3.8):
  - Fleet session schema with per-host sub-sessions
  - Parallel scanning across hosts via SSH
  - Result aggregation and cross-host comparison
- Implement fleet-specific CLI commands:
  - `pt agent fleet-plan --hosts <file>`
  - `pt agent fleet-apply --session <id>`
  - `pt agent fleet-status`
- Implement fleet-wide decision coordination (section 5.16):
  - Shared FDR budget across fleet
  - Cross-host pattern correlation
  - Coordinated action timing to avoid cascading failures
- Implement fleet learning transfer (section 3.8.4):
  - Export/import learned priors between machines
  - Fleet-wide signature sharing
  - Per-machine baseline normalization

### Phase 15: Enhanced UX for Agents
- Implement genealogy narrative generation (section 7.9):
  - Build process ancestry chain with role annotations
  - Generate human-readable story from genealogy
  - Include genealogy in `pt agent explain --genealogy` output
- Implement blast radius visualization (section 7.10):
  - Analyze children, port dependents, file dependents, shared memory
  - Compute cumulative risk score
  - Include blast radius in plan output and TUI
- Implement "what would change your mind" (section 7.11):
  - Identify flip conditions for each recommendation
  - Compute delta_p for each potential evidence change
  - Support `pt agent explain --what-if` output
- Implement human-friendly summary modes (section 7.12):
  - `--brief` mode for concise output
  - `--narrative` mode for prose explanations
  - Structured summary in default `pt agent plan` output

### Phase 16: Differential and Resumable Sessions
- Implement differential mode:
  - Track baseline snapshots per session
  - Compute deltas between scans (`--since` flag)
  - Identify new/changed/resolved candidates
- Implement session resumability:
  - Persist session state to artifact directory
  - Support `pt agent resume --session <id>`
  - Maintain full context across session boundaries
- Implement session comparison:
  - Compare two sessions to identify trends
  - Track action outcomes across sessions
  - Generate session-over-session reports

---

## 11) Tests and Validation

- Unit tests: math functions (BetaBinomial, Beta posterior utilities, GammaPDF, Bayes factors)
- Integration tests: deterministic output for fixed inputs
- Telemetry tests: Parquet schema stability, batched writes, and DuckDB view/query correctness
- Redaction tests: confirm sensitive strings never appear in persisted telemetry
- Automation tests: `--robot`/`--shadow`/`--dry-run` behavior (no prompts; correct gating; no actions in shadow/dry-run)
- Safety gate tests: data-loss gate (open write handles), zombie handling (`Z`), and uninterruptible sleep (`D`) behavior.
- Identity/coordination tests: PID reuse protection via `(pid,start_id,uid)` revalidation, default same-UID enforcement, and per-user “pt lock” behavior (manual vs daemon vs agent runs).
- Agent CLI contract tests: schema invariants + exit codes + token-efficiency flags (`--compact`, `--fields`, `--only`) + JSONL progress stream.
- Bundle/report tests: `.ptb` manifest/checksums, profile redaction guarantees, and report generator outputs (single HTML file with pinned CDN assets + SRI).
- Offline report tests: `--embed-assets` produces a self-contained HTML file with no network fetch requirements.
- Galaxy-brain mode tests: math ledger includes equations + concrete numbers and matches the underlying inference outputs.
- Dormant daemon tests: low overhead, trigger correctness, cooldown/backoff behavior, escalation produces a session + inbox entry.
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

### Agent and Fleet-Specific Tests
- Supervisor detection tests:
  - Mock systemd/launchd/pm2/Docker environments
  - Verify correct supervisor type identification
  - Test supervisor action command generation
  - Test respawn loop detection across sessions
- Pattern/signature library tests:
  - Signature matching accuracy on known process types
  - Fast-path inference bypass verification
  - Custom signature loading and merging
  - Signature confidence score calibration
- Trajectory prediction tests:
  - Memory growth rate estimation accuracy
  - Time-to-threshold prediction calibration
  - Trend analysis (increasing/stable/decreasing) correctness
  - Confidence interval coverage
- Goal-oriented optimization tests:
  - Goal parsing (memory, CPU, ports, composite)
  - Candidate scoring for goal contribution
  - Kill set optimization for maximum goal progress
  - Infeasible goal handling and shortfall reporting
- Fleet mode tests:
  - Multi-host session creation and management
  - Parallel scan aggregation correctness
  - Cross-host pattern correlation
  - Fleet-wide FDR budget enforcement
  - Learning transfer export/import
- Per-machine baseline tests:
  - Baseline distribution fitting from historical data
  - Z-score computation relative to baseline
  - Cold-start handling with default priors
  - Baseline drift detection
- Genealogy narrative tests:
  - Ancestry chain construction correctness
  - Role annotation accuracy (worker, test_runner, user_shell, etc.)
  - Narrative generation quality (human-readable, accurate)
  - `--genealogy` output schema compliance
- Blast radius tests:
  - Children enumeration completeness
  - Port dependent detection via lsof/ss
  - File dependent detection via /proc/<pid>/fd
  - Cumulative risk score computation
  - `--blast-radius` output schema compliance
- What-if explanation tests:
  - Flip condition identification correctness
  - Delta_p estimation accuracy
  - Most likely flip scenario ranking
  - `--what-if` output schema compliance
- Summary mode tests:
  - `--brief` output format and content
  - `--narrative` output readability and accuracy
  - Structured summary field completeness
- Differential session tests:
  - Delta computation between scans
  - New/changed/resolved candidate detection
  - `--since` flag behavior
- Session resumability tests:
  - Session state persistence
  - Resume from artifact directory
  - Context preservation across resume

---

## 12) Deliverables

### Core Deliverables
- `pt` bash wrapper (maximal installer + launcher) and `pt-core` Rust monolith (scan/infer/decide/ui)
- `priors.json`, `policy.json`, and a versioned redaction/hashing policy used by telemetry
- Parquet-first telemetry lake (raw + derived + outcomes) with DuckDB views/macros for standard reports (calibration, PAC-Bayes bounds, FDR, "why" breakdown)
- Agent/robot CLI contract (plan/explain/apply/sessions/tail/inbox/export/report) with stable schemas and automation-friendly exit codes.
- Shareable `.ptb` session bundles (profiles + optional encryption) and premium single-file HTML report generation (CDN-loaded, pinned + SRI, includes galaxy-brain view, optional `--embed-assets` offline fallback).
- Dormant-mode daemon (`ptd`) + systemd/launchd units and an inbox UX for pending triage plans.
- Enhanced README with math, safety guarantees, telemetry governance, and reproducible analysis workflow
- Expanded tests: Rust unit/integration + wrapper smoke tests (BATS or equivalent)

### Agent-Specific Deliverables
- **Supervisor detection module**: Detection heuristics for systemd, launchd, pm2, Docker, supervisord, nodemon, tmux/screen with supervisor-aware action generation and respawn tracking.
- **Pattern/signature library**: Curated signatures for common process types (test runners, dev servers, AI tools, build systems) with pattern matching DSL, fast-path inference, and user customization support.
- **Trajectory prediction engine**: Memory/CPU trend analysis, time-to-threshold prediction with confidence intervals, and per-machine baseline computation.
- **Goal-oriented optimizer**: Goal parsing (`--goal "free 4GB RAM"`), candidate scoring by goal contribution, kill set optimization, and progress tracking.
- **Genealogy narrative generator**: Process ancestry chain construction, role annotation, human-readable story generation, and structured JSON output for agents.
- **Blast radius analyzer**: Children enumeration, port/file/memory dependent detection, cumulative risk scoring, and visualization (TUI and JSON).
- **What-if explainer**: Flip condition identification, delta_p estimation, and detailed "what would change my mind" output.
- **Human-friendly summary modes**: Brief, narrative, and structured summary output formats for different consumption contexts.
- **Differential session support**: Baseline tracking, delta computation, `--since` flag, and session-over-session comparison.
- **Session resumability**: State persistence, `pt agent resume --session <id>`, and context preservation.

### Fleet-Specific Deliverables
- **Fleet session manager**: Multi-host session schema, parallel scanning, result aggregation, and cross-host comparison.
- **Fleet CLI commands**: `pt agent fleet-plan`, `pt agent fleet-apply`, `pt agent fleet-status` with host file support.
- **Fleet decision coordinator**: Shared FDR budget, cross-host pattern correlation, and coordinated action timing.
- **Learning transfer system**: Prior export/import, fleet-wide signature sharing, and per-machine baseline normalization.
- **Fleet reporting**: Aggregated fleet-wide HTML reports, per-host comparison views, and cross-host anomaly detection.

### Documentation Deliverables
- **Agent integration guide**: Complete documentation for AI agents consuming `pt agent` commands, including schema reference, exit codes, error handling, and best practices.
- **Fleet operations guide**: Documentation for multi-host deployment, SSH configuration, parallel execution, and coordinated remediation.
- **Signature authoring guide**: How to create custom signatures, pattern DSL reference, and contribution guidelines for the curated library.

---

## 13) Final Safety Statement
This system never auto-kills by default. By default it runs full-auto analysis and then requires an explicit TUI confirmation before executing destructive actions. A `--robot` flag allows non-interactive execution of the pre-toggled recommended plan, but still enforces safety gates (policy allowlists/denylists, robust Bayes/DRO checks, FDR/alpha-investing budgets, and blast-radius limits).
