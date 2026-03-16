# Mathematical Proof Artifacts & Formal Guarantees

> Unified ledger of mathematical claims, derivations, and invariants backing
> the process_triage inference and decision engine.

---

## Table of Contents

1. [Posterior Computation & Log-Domain Arithmetic](#1-posterior-computation--log-domain-arithmetic)
2. [Active Sensing via Value of Information](#2-active-sensing-via-value-of-information)
3. [Queueing-Theoretic Stall Detection](#3-queueing-theoretic-stall-detection)
4. [Conformal Prediction & Safety Guarantees](#4-conformal-prediction--safety-guarantees)
5. [FDR Control for Kill-Set Selection](#5-fdr-control-for-kill-set-selection)
6. [Distributed Causal Snapshots](#6-distributed-causal-snapshots)
7. [Invariant Ledger](#7-invariant-ledger)

---

## 1. Posterior Computation & Log-Domain Arithmetic

**Source:** `crates/pt-core/src/inference/posterior.rs`, `crates/pt-math/src/math/stable.rs`

### 1.1 Four-Class Bayesian Model

We classify each process into one of four states
`C in {Useful, UsefulBad, Abandoned, Zombie}` via Bayes' rule:

```
P(C | x) = P(x | C) P(C) / P(x)
```

where `x = (x_cpu, x_runtime, x_orphan, x_tty, x_net, x_io, x_queue, x_state, x_cmd)`
is the evidence vector.

### 1.2 Log-Domain Computation

All computation proceeds in log-domain to prevent underflow:

```
log P(C | x) = log P(C) + sum_i log P(x_i | C) - log Z
```

where `Z = sum_C exp(log P(C) + sum_i log P(x_i | C))`.

**Log-Sum-Exp Stability.**  The normalizing constant is computed via:

```
log_sum_exp(v_1, ..., v_k) = m + log( sum_i exp(v_i - m) )
  where m = max(v_1, ..., v_k)
```

**Proof of correctness:**  Subtracting `m` ensures the largest exponent is
`exp(0) = 1`, preventing overflow.  The sum is bounded in `[1, k]`, so
`log(sum)` is bounded in `[0, log k]`.  The final result equals `log(sum_i exp(v_i))`
by algebra.

### 1.3 Likelihood Functions

| Evidence       | Distribution              | Log-likelihood                            |
|----------------|---------------------------|-------------------------------------------|
| CPU fraction   | Beta(alpha, beta)         | `log_beta_pdf(x, alpha, beta)`            |
| CPU binomial   | Beta-Binomial(n, k, eta)  | `log C(n',k') + log B(alpha+k', beta+n'-k') - log B(alpha, beta)` |
| Runtime        | Gamma(shape, rate)        | `gamma_log_pdf(x, shape, rate)`           |
| Binary (orphan, tty, net, io, queue) | Beta-Bernoulli | `log(alpha/(alpha+beta))` if true, `log(beta/(alpha+beta))` if false |
| Categorical (state, command) | Dirichlet-Categorical | `log(alpha_i) - log(sum alpha_j)` |

### 1.4 Invariant: Posterior Sums to 1

**Claim:** For all valid inputs, `sum_C P(C | x) = 1`.

**Proof:** By construction `log P(C | x) = v_C - log_sum_exp(v)` where
`v_C = log P(C) + sum_i log P(x_i | C)`.  Therefore:

```
sum_C P(C|x) = sum_C exp(v_C - log_sum_exp(v))
             = exp(-log_sum_exp(v)) * sum_C exp(v_C)
             = exp(-log_sum_exp(v)) * exp(log_sum_exp(v))
             = 1
```

This holds exactly in infinite precision; in floating point, the implementation
guards against NaN with an explicit check after normalization.

---

## 2. Active Sensing via Value of Information

**Source:** `crates/pt-core/src/decision/voi.rs`, `crates/pt-core/src/decision/active_sensing.rs`

### 2.1 VoI Formula

For a measurement `m` with possible outcomes `y`, the Value of Information is:

```
VoI(m) = E_y[ min_a E[L(a,S) | b + (m,y)] ] - min_a E[L(a,S) | b] - cost(m)
```

where:
- `L(a, S)` is the loss of action `a` in state `S`
- `b` is the current belief state
- `b + (m,y)` is the updated belief after observing outcome `y` from probe `m`
- `cost(m)` is the resource cost of the probe

**Decision rule:**
- If `VoI(m) >= 0` for all `m`: act now (no probe is worth its cost)
- If `VoI(m*) < 0` for some `m*`: probe with `m* = argmin_m VoI(m)`

### 2.2 Cost-Offset Bound

**Claim:** A probe is only worthwhile if its expected loss reduction exceeds its cost.

**Proof:** Define `Delta(m) = min_a E[L | b] - E_y[ min_a E[L | b+(m,y)] ]` as
the expected loss reduction.  Then `VoI(m) = -Delta(m) + cost(m)`.
VoI < 0 iff `Delta(m) > cost(m)`.

### 2.3 Whittle Index Ranking

Probes are ranked by a Whittle-style index for budget-constrained allocation:

```
score(m) = Delta(m) / cost(m) = -VoI(m) / cost(m)
```

Greedy selection by descending score subject to budget constraints yields a
constant-factor approximation to the optimal probe allocation (by submodularity
of information gain under mild conditions).

### 2.4 Adaptive Damping

To prevent "probe oscillation" for processes hovering at the VoI threshold,
the implementation applies a `min_ratio` filter: probes with
`score < min_ratio` are skipped even if their VoI is technically negative.

---

## 3. Queueing-Theoretic Stall Detection

**Source:** `crates/pt-core/src/inference/queueing.rs`

### 3.1 M/M/1 Model

Each process's network I/O is modeled as an M/M/1 queue:
- lambda: data arrival rate (bytes/sec into socket buffers)
- mu: service rate (bytes/sec the process drains)
- rho = lambda / mu: traffic intensity

**Stability condition:** The queue is stable iff `rho < 1`.

### 3.2 Stall Probability

For a stable M/M/1 queue in steady state:

```
P(N >= L) = rho^L
```

When `rho >= 1`, the queue is unstable: `P(N >= L) = 1` for all `L >= 0`.

**Proof:** In steady state, the M/M/1 queue has geometric distribution
`P(N = k) = (1 - rho) * rho^k` for `k = 0, 1, 2, ...`.  Therefore:

```
P(N >= L) = sum_{k=L}^{inf} (1-rho) rho^k
          = (1-rho) rho^L / (1-rho)
          = rho^L
```

The implementation uses `rho^L` where `L` is a configurable abstract queue-length
parameter (`probability_queue_length`, default 8), distinct from the byte-level
`saturation_threshold`.  This preserves the monotonicity in rho while keeping the
probability in a meaningful range.

### 3.3 EWMA Estimation

Queue depths are smoothed via exponentially weighted moving average:

```
S_0 = x_0
S_t = alpha * x_t + (1 - alpha) * S_{t-1}    for t >= 1
```

where `alpha in (0, 1]` is the smoothing factor.

**Properties:**
- Effective window: `~1/alpha` observations
- Convergence: If `x_t = c` for all `t`, then `S_t -> c` geometrically
- Bias: `E[S_t] = alpha * sum_{k=0}^{t-1} (1-alpha)^k * E[x_{t-k}]`

### 3.4 Rho Estimation via Logistic Mapping

Since we observe queue depth rather than arrival/service rates directly,
we estimate rho via a logistic mapping:

```
x = (smoothed_depth / threshold) + clamp(smoothed_delta / threshold, -2, 2)
rho = sigmoid(x) = 1 / (1 + exp(-k * (x - midpoint)))
```

with `k = 3.0` and `midpoint = 1.0`.

**Properties:**
- `rho(0, 0, T) < 0.05` (empty queues map to low rho)
- `rho(T, 0, T) ~ 0.5` (queue at threshold maps to moderate rho)
- `rho >> 1` when depth >> threshold with positive growth

### 3.5 Bayesian Integration

Queue saturation is integrated as a Beta-Bernoulli evidence term:

```
queue_saturated = (total_rx > threshold) OR (total_tx > threshold)
log P(queue_saturated | C) = log_lik_beta_bernoulli(queue_saturated, alpha_C, beta_C)
```

The per-class priors encode the prior belief about queue saturation
frequency for each process class.  Useful-Bad processes are expected
to have `alpha >> beta` (high probability of saturated queues).

---

## 4. Conformal Prediction & Safety Guarantees

**Source:** `crates/pt-core/src/inference/conformal.rs`

### 4.1 Split Conformal Prediction (Regression)

Given calibration residuals `s_1, ..., s_n` where `s_i = |y_i - yhat_i|`:

1. Sort residuals: `s_(1) <= s_(2) <= ... <= s_(n)`
2. Compute quantile index: `q = ceil((n+1)(1-alpha))`
3. Prediction interval: `[yhat_{n+1} - s_(q), yhat_{n+1} + s_(q)]`

### 4.2 Coverage Guarantee (Finite-Sample)

**Theorem (Vovk et al., 2005):** If `(X_1,Y_1), ..., (X_n,Y_n), (X_{n+1},Y_{n+1})`
are exchangeable, then:

```
P(Y_{n+1} in C(X_{n+1})) >= 1 - alpha
```

**Proof sketch:** By exchangeability, the rank of `s_{n+1}` among
`{s_1, ..., s_n, s_{n+1}}` is uniformly distributed over `{1, ..., n+1}`.
The prediction set includes `Y_{n+1}` iff `s_{n+1} <= s_(q)`, which occurs
with probability `q / (n+1) >= 1 - alpha` by choice of `q = ceil((n+1)(1-alpha))`.

### 4.3 Mondrian Conformal Classification

For classification, the nonconformity score is `s_i = 1 - P_hat(C = y_i | x_i)`.

**Mondrian variant:** Calibration scores are partitioned by class label.
The p-value for candidate class `c` uses only scores from examples with
true label `c`:

```
p_c = (1 + |{i : y_i = c, s_i >= s_{n+1}(c)}|) / (|{i : y_i = c}| + 1)
```

Prediction set: `{c : p_c > alpha}`.

**Coverage guarantee:** The Mondrian variant provides class-conditional
coverage: `P(Y in C(X) | Y = c) >= 1 - alpha` for each class `c`,
assuming class-conditional exchangeability.

### 4.4 Exchangeability Invariant

**Critical assumption:** The coverage guarantee requires exchangeability
of the calibration and test data.  In process triage, this holds when:

- The process population is stationary (no distribution shift)
- Calibration data is representative of the test distribution

The implementation provides two mitigations for non-exchangeability:

1. **Blocked conformal:** Groups residuals into temporal blocks, computing
   block-level scores (max residual per block).  This handles short-range
   temporal dependence.

2. **Adaptive conformal:** Adjusts alpha based on empirical coverage:
   `alpha_t+1 = alpha_t + lr * (target_error - empirical_error)`,
   providing asymptotic coverage under distribution shift.

---

## 5. FDR Control for Kill-Set Selection

**Source:** `crates/pt-core/src/decision/fdr_selection.rs`

### 5.1 e-value Benjamini-Hochberg (eBH)

Given e-values `e_1, ..., e_m` (calibrated so `E[e_i] <= 1` under the null):

1. Sort by e-value descending: `e_(1) >= e_(2) >= ... >= e_(m)`
2. Find largest `k` where: `e_(k) >= m / (alpha * k)`
3. Select top `k` candidates

**FDR Guarantee (under PRDS):**

```
E[FDP] = E[V / max(R, 1)] <= alpha
```

where V = false discoveries, R = total discoveries.

**Proof:** Follows from the e-BH procedure of Wang & Ramdas (2022).
Under positive regression dependency on each subset (PRDS), the
e-value formulation provides valid FDR control.

### 5.2 e-value Benjamini-Yekutieli (eBY)

For arbitrary dependence, apply the harmonic correction:

```
c(m) = H_m = sum_{j=1}^{m} 1/j     (m-th harmonic number)
effective_alpha = alpha / c(m)
```

Then apply eBH with `effective_alpha`.

**FDR Guarantee (arbitrary dependence):**

```
E[FDP] <= alpha
```

The factor `c(m) ~ ln(m) + gamma` (Euler-Mascheroni) makes eBY
more conservative but valid without independence assumptions.

### 5.3 p-value Derivation

e-values convert to p-values via Markov's inequality:

```
p_i = min(1, 1 / e_i)
```

This provides a valid (conservative) p-value from any e-value.

---

## 6. Distributed Causal Snapshots

**Source:** `crates/pt-core/src/decision/causal_snapshot.rs`

### 6.1 Chandy-Lamport Protocol

**Consistency definition:** A cut `C = (S_1, ..., S_n)` of local states
across `n` hosts is **consistent** if for every message `m` sent by
host `i` and received by host `j`:

```
(m sent before S_i recorded) => (m received before S_j recorded)
```

No message crosses the cut boundary from future to past.

**Marker protocol:**
1. Initiator records local state, sends `Marker` on all outgoing channels
2. On receiving first `Marker`, a host records its local state and
   forwards `Marker` on all outgoing channels
3. Channel state between sender and receiver is recorded as messages
   received after the sender's snapshot but before the receiver's

### 6.2 Safety Properties

**Claim (No False Kills):** If the cut is `Complete` (all hosts confirmed)
and the causal safety gate passes, then killing the target process cannot
break any `Useful` process on any host.

**Proof:** The gate checks all confirmed host snapshots for remote
dependencies pointing to the target.  If no `Useful` process depends
on the target (directly), the kill is safe under the snapshot state.

**Limitation:** Transitive dependencies are not checked — if A depends on B
depends on target, only the B->target edge is detected.  This is conservative
in practice since B would also be checked before killing.

### 6.3 Tentative Cut Safety

When hosts are `Tentative` (no confirmed state), the default behavior is
to block all kill actions (`allow_kills_on_partial_cut = false`).

**Claim (Conservative Fallback):** With the default configuration, any
process that has a dependency on a tentative host is protected from
automated killing.

This follows directly from the gate blocking all kills when the cut is
`Partial` and `allow_kills_on_partial_cut` is false.

---

## 7. Invariant Ledger

Non-negotiable invariants that must hold across all components:

| ID | Invariant | Module | Enforcement |
|----|-----------|--------|-------------|
| I1 | `sum_C P(C\|x) = 1.0` | posterior.rs | NaN check after normalization |
| I2 | `FDR <= alpha` | fdr_selection.rs | eBH/eBY procedure correctness |
| I3 | `P(Y in C(X)) >= 1-alpha` | conformal.rs | Finite-sample coverage theorem |
| I4 | `VoI < 0 => Delta > cost` | voi.rs | Algebraic identity |
| I5 | `rho in [0, 1]` | queueing.rs | Logistic sigmoid range |
| I6 | `EWMA convergence` | queueing.rs | Geometric convergence to constant input |
| I7 | `Invalid cut => no auto-kills` | causal_snapshot.rs | Gate returns `allowed=false` |
| I8 | `log_sum_exp(v) = log(sum exp(v_i))` | pt-math/stable.rs | Algebraic identity with max subtraction |
| I9 | `e-value >= 0` | fdr_selection.rs | Input validation |
| I10 | `0 < prior_prob <= 1` for all classes | posterior.rs | `ln_checked` validation |

### Numerical Stability Guarantees

- **No overflow:** Log-domain arithmetic ensures all intermediate values are finite
  for valid inputs (positive priors, bounded evidence)
- **No underflow:** Log-sum-exp with max-subtraction prevents exp() underflow
- **No division by zero:** Beta-Bernoulli denominators are `alpha + beta > 0`
  (enforced by prior validation)
- **Deterministic output:** All computations are deterministic given the same
  inputs; no randomness in inference or decision paths (except UUID generation
  for snapshot IDs)

---

*Last updated: 2026-03-16. See individual module documentation for implementation details.*
