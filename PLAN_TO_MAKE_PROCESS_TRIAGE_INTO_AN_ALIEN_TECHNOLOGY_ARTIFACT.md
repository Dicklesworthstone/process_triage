# PLAN_TO_MAKE_PROCESS_TRIAGE_INTO_AN_ALIEN_TECHNOLOGY_ARTIFACT.md

## 0) Non-Negotiable Requirement From User
This plan MUST incorporate every idea and math formula from the conversation. The sections below explicitly enumerate and embed all of them. This is a closed-form Bayesian and decision-theoretic system with no ML.

---

## 1) Mission and Success Criteria

Mission: transform Process Triage (pt) into an "alien technology artifact" that combines rigorous closed-form Bayesian inference, optimal stopping, and system-level decision theory with a stunningly explainable UX.

Success criteria:
- Decision quality: <1% false-kill rate in shadow mode, high capture of abandoned/zombie processes.
- Explainability: every decision has a full evidence ledger, posterior, and top Bayes factors.
- Safety: never auto-kill; multi-stage mitigations; guardrails enforced by policy.
- Performance: quick scan <1s, deep scan <8s for typical process counts.
- Fully closed-form updates: conjugate priors only; no ML.
- Formal guarantees: PAC-Bayes bound on false-kill rate with explicit confidence.
- Real-world impact weighting: kill-cost incorporates dependency and user-intent signals.

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

R) Use-case interpretation of observed processes
- bun test at 91% CPU for 18m in /data/projects/flywheel_gateway
- gemini --yolo workers at 25m to 4h46m
- gunicorn workers at 45-50% CPU for ~1h
- several claude processes active

All of these are integrated in the system design below.

---

## 3) System Architecture (Full Stack)

### 3.1 Data Collection Layer
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
- OS-level metrics for queueing cost and VOI:
  - loadavg, run-queue delay, iowait, memory pressure, swap activity

### 3.2 Feature Layer
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

---

## 4) Inference Engine (Closed-Form Bayesian Core)

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

Decision engine selects action with minimum expected loss; kill requires explicit confirmation.

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
- Create priors.json schema for alpha/beta, gamma, dirichlet, hazard priors
- Create policy.json for loss matrix and guardrails
- Define command categories and CWD categories

### Phase 2: Math Utilities
- Implement BetaPDF, GammaPDF, Dirichlet-multinomial, Beta-Bernoulli
- Implement Bayes factors, log-odds, posterior computation

### Phase 3: Evidence Collection
- Quick scan: ps + basic features
- Deep scan: /proc IO, CPU deltas, wchan, net, children, TTY
- Optional system tools (auto-install):
  - Linux: sysstat (pidstat/iostat/mpstat/vmstat/sar), perf, bpftrace/bcc, iotop, nethogs/iftop, lsof
  - macOS: fs_usage, sample, nettop, powermetrics, dtruss (if permitted), lsof

### Phase 3a: Tooling Install Strategy (Maximal Instrumentation by Default)
Policy: always try to install everything and collect as much data as possible.

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
- Fedora/RHEL (dnf):
  - sysstat, perf, bpftrace, bcc, bpftool, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - turbostat, powertop
  - strace, ltrace, ethtool, iproute, conntrack-tools, cgroup-tools
- Arch (pacman):
  - sysstat, perf, bpftrace, bcc, bpftool, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - turbostat, powertop
  - strace, ltrace, ethtool, iproute2, conntrack-tools, cgroup-tools
- Alpine (apk):
  - sysstat, perf, bpftrace, iotop, nethogs, iftop, lsof
  - atop, sysdig, smem, numactl
  - strace, ltrace, iproute2
  - conntrack-tools, cgroup-tools

macOS (Homebrew):
- core utils: lsof, iproute2mac (if needed), htop
- tracing/metrics: fs_usage, sample, nettop, powermetrics (native tools)
- if SIP allows: dtruss
 - extra: sysstat (where available), gnu-time

Install workflow:
- Detect OS + package manager.
- Attempt full install; if any package fails, continue installing the rest.
- Record capabilities in a local cache (what is available vs missing).
- Prefer richer signals when available (eBPF/perf), but never fail if missing.

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

### Phase 4: Inference Integration
- Combine evidence to compute P(C|x)
- Add Bayes factor ledger output
- Add confidence metrics
- Add Hawkes / marked point process layers for bursty events
- Add BOCPD run-length posterior for regime shifts
- Add robust statistics summaries for noise suppression

### Phase 5: Decision Theory
- Implement expected loss, SPRT threshold, VOI
- Load-aware threshold via Erlang-C

### Phase 6: Action Tray
- Keep/pause/throttle/kill suggestions
- Confirm before kill

### Phase 7: UX Refinement
- Evidence glyphs and ledger
- Explainability line per process

### Phase 8: Safety and Policy
- Guardrails for system services
- Rate limiting, quarantine policies

### Phase 9: Shadow Mode and Calibration
- Advisory-only logging
- Compare decisions vs human choices
- Update priors with conjugate updates

---

## 11) Tests and Validation

- Unit tests: math functions (BetaPDF, GammaPDF, Bayes factors)
- Integration tests: deterministic output for fixed inputs
- Shadow mode metrics: false kill rate, missed abandonment rate
- PAC-Bayes bound reporting on false-kill rate
- Calibration tests for empirical Bayes hyperparameters
- Hawkes/marked point process fit sanity tests
- BOCPD change-point detection regression tests

---

## 12) Deliverables

- Updated pt with full Bayesian inference, evidence ledger, and action tray
- priors.json and policy.json
- Enhanced README with all math and safety guarantees
- Expanded BATS tests for new modes

---

## 13) Final Safety Statement
This system never auto-kills by default. It only recommends, with full evidence and loss-based reasoning, and requires explicit confirmation for any destructive action.
