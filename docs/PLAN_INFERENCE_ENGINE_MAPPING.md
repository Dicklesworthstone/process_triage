# Plan Inference Engine Mapping (Section 4)

This file is a self-contained mapping of Plan Section 4 (Inference Engine) to canonical beads.
It exists so implementation and review do not require re-opening the long plan document.

## Non-negotiable design constraints
- All decisions must be auditable closed-form Bayesian + decision theory.
- Advanced models are allowed only as deterministic feature extractors that feed the closed-form core.
- Implementations must be log-domain and numerically stable.

## Mapping (Plan Section 4 -> canonical beads)

### 4.1 State space
Plan requirement: four-state classification:
- C in {useful, useful-but-bad, abandoned, zombie}

Canonical beads
- State definitions + priors schema: process_triage-2f3
- Posterior computation over the 4 states: process_triage-e48
- Decision semantics (losses per state): process_triage-bg5, process_triage-d88

Notes
- "zombie" cannot be killed directly; interpret kill decision as "resolve via parent reaping / supervisor action" (Plan Section 6).

---

### 4.2 Priors and likelihoods (conjugate)
Plan requirement: conjugate priors/likelihoods for core evidence terms:
- CPU occupancy from tick deltas via Beta-Binomial.
- Runtime/hazard via Gamma (with right-censoring caveats).
- Orphan / TTY / net activity via Beta-Bernoulli.
- Categorical state flags, command/CWD categories via Dirichlet-Categorical (Dirichlet-Multinomial predictive).

Canonical beads
- priors.json schema (Beta/Gamma/Dirichlet hyperparams, parameterization conventions): process_triage-2f3
- Core math primitives (closed-form, log-domain): process_triage-iau and children
  (process_triage-rqn, process_triage-3ot, process_triage-m99, process_triage-5s5, process_triage-22q, process_triage-00b)
- CPU tick-delta feature collection + n_eff: process_triage-3ir.1.1

Notes
- The plan explicitly warns ticks are correlated; n_eff must be carried through to avoid overconfidence.

---

### 4.3 Posterior computation (closed-form)
Plan requirement: P(C|x) proportional to P(C) * product of P(x_j|C) with explicit modeling notes:
- Avoid double-counting correlated signals.
- Do not include both naive runtime likelihood and survival/hazard evidence at once.

Canonical beads
- Core posterior computation P(C|x): process_triage-e48
- Log-odds and normalization (log-sum-exp): process_triage-wb3, process_triage-00b
- Evidence ledger generation (per-term contributions): process_triage-myq
- Feature layer hygiene + provenance (avoid redundant evidence): process_triage-cfon

---

### 4.4 Bayes factors for model selection
Plan requirement: closed-form marginal likelihoods + MDL bridge:
- log BF = log p(data|H1) - log p(data|H0)
- Connect BF to code-length gaps in explainability.

Canonical beads
- Bayes factor computation + Jeffreys evidence categories: process_triage-0ij
- Ledger surfacing of BF and code-length deltas: process_triage-myq, process_triage-cfon.7

---

### 4.5 Semi-Markov and competing hazards
Plan requirement: hazard/survival modeling with Gamma priors; right-censoring awareness.

Canonical beads
- Gamma hazards + survival primitives: process_triage-22q
- Time-varying / regime hazards (hazard inflation when regime changes): process_triage-y4a
- HSMM (Gamma durations) feature extractor: process_triage-nao.13

---

### 4.6 Markov-modulated Poisson / Levy subordinator CPU
Plan requirement: compound Poisson burst modeling as a feature layer.

Canonical beads
- CPU burst Levy/compound Poisson summaries: process_triage-nao.14

---

### 4.7 Change-point detection
Plan requirement: closed-form change-point evidence and CTW/prequential complements.

Canonical beads
- Change-point detection (BOCPD framing, run-length recursion): process_triage-lfrb
- CTW/prequential regret and code-length anomaly features: process_triage-cfon.7

---

### 4.7b Bayesian online change-point detection (BOCPD)
Canonical beads
- BOCPD implementation: process_triage-lfrb

---

### 4.8 Information-theoretic abnormality
### 4.8b Large deviations / rate functions
Plan requirement: KL surprisal / Chernoff-Cramer style bounds as interpretable evidence.

Canonical beads
- KL surprisal + large-deviation evidence features: process_triage-nao.12

---

### 4.8c Copula dependence modeling
Plan requirement: dependence correction via copula summaries (fit numerically, feed summaries).

Canonical beads
- Copula dependence summaries: process_triage-nao.1

---

### 4.9 Robust Bayes (imprecise priors)
Plan requirement: credal intervals; "kill only if robust under optimistic posterior"; Safe-Bayes eta tempering.

Canonical beads
- Imprecise priors + Safe-Bayes eta tempering: process_triage-nao.11
- Least-favorable / minimax prior gating: process_triage-nao.20

---

### 4.10 Causal intervention models (do-calculus)
Plan requirement: action outcomes modeled as Beta-Bernoulli by (action,state); used for decisioning.

Canonical beads
- Causal action selection model P(recover | do(a)): process_triage-p15.4

---

### 4.11 Wonham filtering and Gittins indices
Plan requirement: advanced/optional continuous-time partial observability filtering + index policies.

Canonical beads
- Wonham + Gittins scheduling (advanced/optional): process_triage-p15.9

---

### 4.12 Process genealogy
Plan requirement: PPID forest as Bayesian network; orphan BF is contextual.

Canonical beads
- Genealogy priors + orphan evidence framing: process_triage-nao.15
- Orphan conditioning with supervision/session context: process_triage-cfon.4
- Belief propagation over PPID trees: process_triage-d7s
- Agent-facing genealogy narrative: process_triage-s8s

---

### 4.13 Coupled tree priors (correlated states)
Plan requirement: pairwise coupling on PPID edges; exact BP on forests; note loopy couplings if non-tree edges added.

Canonical beads
- PPID-tree belief propagation with coupled prior: process_triage-d7s
- Graph/Laplacian smoothing beyond pure trees: process_triage-nao.9

---

### 4.14 Belief-state update (POMDP approximation)
Canonical beads
- Belief-state update utilities: process_triage-nao.16

---

### 4.15 Bayesian credible bounds (shadow mode)
Plan requirement: Beta posterior bounds on false-kill rate; used as safety evidence.

Canonical beads
- Shadow mode + calibration epic: process_triage-21f
- Credible bounds on false-kill rate: process_triage-21f.1

---

### 4.15b PAC-Bayes generalization bounds (shadow mode)
Plan requirement: PAC-Bayes bound reporting (with clear assumptions; anytime/dependence caveats).

Canonical beads
- PAC-Bayes style bounds reporting: process_triage-72j.2

---

### 4.16 Empirical Bayes hyperparameter calibration
Plan requirement: optional EB refits from shadow logs; versioning + rollback.

Canonical beads
- Hierarchical priors + EB shrinkage mechanics: process_triage-nao.10
- EB refits from shadow logs + rollback: process_triage-72j.3

---

### 4.17 Minimax / least-favorable priors
Canonical beads
- Least-favorable/minimax prior gating: process_triage-nao.20

---

### 4.18 Time-to-decision bound
Plan requirement: define T_max; default-to-pause when no threshold crossing.

Canonical beads
- Time-to-decision bound and default-to-pause: process_triage-p15.6
- Sequential stopping rules for evidence gathering: process_triage-of3n

---

### 4.19 Hawkes process layer
Canonical beads
- Hawkes process layer summaries: process_triage-hxh
- Multivariate Hawkes cross-excitation summaries: process_triage-nao.18

---

### 4.20 Marked point process layer
Canonical beads
- Marked point process summary features: process_triage-cfon.8

---

### 4.21 Bayesian nonparametric survival (Beta-Stacy)
Canonical beads
- Beta-Stacy discrete-time survival model: process_triage-nao.17

---

### 4.22 Robust statistics (Huberized likelihoods)
Canonical beads
- Robust statistics summaries / outlier suppression: process_triage-nao.8

---

### 4.23 Linear Gaussian state-space (Kalman)
Canonical beads
- Kalman smoothing/filtering utilities: process_triage-0io

---

### 4.24 Optimal transport shift detection
Canonical beads
- Wasserstein drift detection: process_triage-9kk3

---

### 4.25 Martingale sequential bounds
Canonical beads
- Time-uniform martingale/e-process gates: process_triage-p15.8
- Martingale deviation feature summaries: process_triage-cfon.9

---

### 4.26 Graph signal regularization
Canonical beads
- Graph/Laplacian smoothing priors/features: process_triage-nao.9

---

### 4.27 Renewal reward modeling
Canonical beads
- Renewal-reward/semi-regenerative summaries: process_triage-nao.21

---

### 4.28 Risk-sensitive control
Canonical beads
- Risk-sensitive control (CVaR): process_triage-ctb

---

### 4.29 Bayesian model averaging (BMA)
Canonical beads
- Bayesian model averaging across submodels: process_triage-nao.7

---

### 4.30 Composite-hypothesis testing
Canonical beads
- Composite-hypothesis testing (mixture SPRT / GLR): process_triage-p15.7

---

### 4.31 Conformal prediction
Canonical beads
- Conformal prediction for robust intervals/sets: process_triage-tcf

---

### 4.32 FDR control (many-process safety)
Canonical beads
- FDR via e-values + BH/BY (default conservative): process_triage-sqe

---

### 4.33 Restless bandits / Whittle index scheduling
### 4.34 Bayesian optimal experimental design (active sensing)
### 4.43 Submodular probe selection
Canonical beads
- VOI and probe budgeting policy: process_triage-p15.2
- Submodular probe selection utilities: process_triage-p15.3

---

### 4.35 Extreme value theory (POT/GPD)
Canonical beads
- EVT tail modeling: process_triage-fh0d

---

### 4.36 Streaming sketches / heavy-hitter summaries
Canonical beads
- Streaming sketches/heavy-hitter summaries: process_triage-nao.5

---

### 4.37 Belief propagation on PPID trees
Canonical beads
- Tree belief propagation implementation: process_triage-d7s

---

### 4.38 Wavelet / spectral periodicity features
Canonical beads
- Wavelet/spectral periodicity features: process_triage-nao.2

---

### 4.39 Switching linear dynamical systems (IMM)
Canonical beads
- Switching state-space (IMM) feature extractor: process_triage-nao.6

---

### 4.40 Online FDR / alpha-investing
Canonical beads
- Alpha-investing wealth accounting: process_triage-cpm
- Time-uniform martingale/e-process gates (complementary): process_triage-p15.8

---

### 4.41 Posterior predictive checks
Canonical beads
- PPC / misspecification checks: process_triage-0uy

---

### 4.42 Distributionally robust optimization (DRO)
Canonical beads
- DRO/worst-case loss gating: process_triage-6a1

---

### 4.44 Trajectory prediction and time-to-threshold
### 4.45 Per-machine learned baselines
Canonical beads
- Trajectory prediction + baselines epic: process_triage-mpi (and children)

---

### 4.46 Signature-informed inference
Canonical beads
- Signature-informed inference fast-path and prior overrides: process_triage-ed3.2

---

## Coverage checklist (Plan Section 4)
- [x] 4.1-4.46 are mapped above to canonical beads (no subsection left unmapped).
- [x] Any implementation that touches decision outputs (plan/apply) remains closed-form and ledgered.
- [x] Tests exist for the highest-risk inference components (posterior, Bayes factors, FDR, shadow calibration).

## Acceptance criteria
- [x] Canonical mapping remains accurate (no missing plan subsection).
- [x] All referenced canonical bead IDs exist and are the intended owners.
- [x] Coverage checklist items in this bead are satisfied.
