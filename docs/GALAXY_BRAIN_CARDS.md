# Galaxy-Brain Mode: Math Card Specifications

This document defines the 7 math transparency cards exposed in galaxy-brain mode. Each card shows a specific aspect of the Bayesian inference engine.

## Overview

Galaxy-brain mode (activated via `g` keybinding in TUI or `--galaxy-brain` flag) exposes the full mathematical reasoning behind process classification decisions. This serves dual purposes:

1. **Educational**: Understanding the "alien artifact" math
2. **Debugging**: Verifying inference is behaving correctly

## Card Schema

Each card has the following structure:

```json
{
  "id": "card_identifier",
  "title": "Human-Readable Title",
  "equations": [{"latex": "...", "ascii_fallback": "..."}],
  "values": {"key": {"value": 0.95, "label": "...", "symbol": "..."}},
  "intuition": "One-line plain-English explanation"
}
```

See `specs/schemas/galaxy-brain.schema.json` for the full JSON Schema.

---

## Card 1: `posterior_core`

**Title**: Posterior Class Probabilities

**Purpose**: Shows the full Bayesian posterior breakdown: log P(C|x) with all terms.

### Equations

```latex
\log P(C|x) = \log P(x|C) + \log P(C) - \log P(x)
```

```latex
P(C|x) = \frac{P(x|C) \cdot P(C)}{\sum_{c'} P(x|c') \cdot P(c')}
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `log_likelihood_useful` | `log P(x|useful)` | Log-likelihood under useful class |
| `log_likelihood_abandoned` | `log P(x|abandoned)` | Log-likelihood under abandoned class |
| `log_likelihood_zombie` | `log P(x|zombie)` | Log-likelihood under zombie class |
| `log_prior_useful` | `log P(useful)` | Log prior probability of useful |
| `log_prior_abandoned` | `log P(abandoned)` | Log prior for abandoned |
| `log_prior_zombie` | `log P(zombie)` | Log prior for zombie |
| `log_evidence` | `log P(x)` | Log marginal likelihood (normalizer) |
| `posterior_useful` | `P(useful|x)` | Final posterior probability |
| `posterior_abandoned` | `P(abandoned|x)` | Final posterior probability |
| `posterior_zombie` | `P(zombie|x)` | Final posterior probability |
| `max_class` | - | Highest probability class |

### Intuition

> "Given this process's evidence, there's a {posterior_abandoned}% chance it's abandoned."

---

## Card 2: `hazard_time_varying`

**Title**: Time-Varying Hazard Rates

**Purpose**: Shows regime-specific hazard rates with Gamma posteriors, modeling how the probability of abandonment changes over time.

### Equations

```latex
h(t) = \frac{f(t)}{S(t)} = \text{instantaneous failure rate}
```

```latex
h(t) \sim \text{Gamma}(\alpha_t, \beta_t) \quad \text{(posterior)}
```

```latex
E[h(t)] = \frac{\alpha_t}{\beta_t}, \quad \text{Var}[h(t)] = \frac{\alpha_t}{\beta_t^2}
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `current_regime` | - | Current time regime (startup/active/aged) |
| `regime_boundaries_sec` | - | Time thresholds between regimes |
| `hazard_rate_startup` | `h_{startup}` | Hazard rate in startup regime |
| `hazard_rate_active` | `h_{active}` | Hazard rate in active regime |
| `hazard_rate_aged` | `h_{aged}` | Hazard rate in aged regime |
| `gamma_alpha` | `α` | Gamma posterior shape parameter |
| `gamma_beta` | `β` | Gamma posterior rate parameter |
| `survival_prob` | `S(t)` | Current survival probability |

### Intuition

> "Process has been running {runtime}, now in '{current_regime}' regime with hazard rate {hazard_rate}."

---

## Card 3: `conformal_interval`

**Title**: Conformal Prediction Intervals

**Purpose**: Shows prediction intervals for runtime and CPU usage using conformal prediction (distribution-free coverage guarantees).

### Equations

```latex
\hat{C}_\alpha(x) = \{y : s(x, y) \leq Q_{1-\alpha}(\{s_i\}_{i=1}^n)\}
```

```latex
P(Y_{n+1} \in \hat{C}_\alpha(X_{n+1})) \geq 1 - \alpha
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `runtime_interval_lower` | - | Lower bound of runtime interval (seconds) |
| `runtime_interval_upper` | - | Upper bound of runtime interval (seconds) |
| `runtime_interval_coverage` | `1-α` | Nominal coverage (e.g., 0.90) |
| `cpu_interval_lower` | - | Lower bound of CPU usage interval |
| `cpu_interval_upper` | - | Upper bound of CPU usage interval |
| `conformity_score` | `s(x,y)` | Non-conformity score for this process |
| `calibration_set_size` | `n` | Number of calibration examples |

### Intuition

> "With 90% confidence, this process will run between {runtime_lower} and {runtime_upper}."

---

## Card 4: `conformal_class_set`

**Title**: Conformal Classification Set

**Purpose**: Shows the prediction set for classification with calibrated p-values.

### Equations

```latex
\hat{C}_\alpha(x) = \{c : p(c|x) \geq \alpha\}
```

```latex
p(c|x) = \frac{|\{i : s(x_i, c) \geq s(x, c)\}| + 1}{n + 1}
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `prediction_set` | `Ĉ(x)` | Set of classes in prediction set |
| `p_value_useful` | `p(useful|x)` | Conformal p-value for useful |
| `p_value_abandoned` | `p(abandoned|x)` | Conformal p-value for abandoned |
| `p_value_zombie` | `p(zombie|x)` | Conformal p-value for zombie |
| `alpha_level` | `α` | Significance level |
| `set_size` | - | Size of prediction set |

### Intuition

> "At α={alpha}, the prediction set is {prediction_set}. {set_size == 1 ? 'High confidence!' : 'Multiple plausible classes.'}"

---

## Card 5: `e_values_fdr`

**Title**: E-values and Anytime-Valid FDR Control

**Purpose**: Shows e-values for sequential testing and e-FDR control.

### Equations

```latex
e(x) = \frac{P(x|H_1)}{P(x|H_0)} \quad \text{(likelihood ratio e-value)}
```

```latex
\text{e-BH threshold}: e_i \geq \frac{n}{k \cdot \alpha} \quad \text{for } k \text{-th smallest}
```

```latex
E[\#\text{false discoveries} / e_{\text{sum}}] \leq \alpha
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `e_value` | `e(x)` | E-value for this process |
| `log_e_value` | `log e(x)` | Log e-value |
| `e_fdr_threshold` | - | Current e-BH rejection threshold |
| `rejected` | - | Whether this process is rejected (abandoned) |
| `running_e_sum` | `Σe` | Running sum of e-values |
| `false_discovery_bound` | - | Bound on expected false discoveries |

### Intuition

> "E-value of {e_value}: evidence against 'useful' hypothesis is {strong/weak}."

---

## Card 6: `alpha_investing`

**Title**: Alpha-Investing Budget State

**Purpose**: Shows the current state of the alpha-investing algorithm for online hypothesis testing.

### Equations

```latex
W_t = W_0 + \sum_{i=1}^{t-1} (\phi_i \cdot R_i - \alpha_i)
```

```latex
\alpha_t = \min(\psi(W_t), \alpha_{\max})
```

```latex
\text{mFDR} = E\left[\frac{V}{R \vee 1}\right] \leq \alpha
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `current_wealth` | `W_t` | Current wealth/budget |
| `initial_wealth` | `W_0` | Initial wealth |
| `alpha_spent` | `Σα` | Total alpha spent so far |
| `rejections` | `R` | Number of rejections so far |
| `current_alpha` | `α_t` | Alpha level for current test |
| `wealth_earned` | - | Wealth earned from rejections |
| `mfdr_guarantee` | - | Modified FDR guarantee |

### Intuition

> "Budget: {current_wealth}. Can test {n_remaining} more hypotheses before budget depletes."

---

## Card 7: `voi`

**Title**: Value of Information

**Purpose**: Shows which additional probes (deep scans, syscall traces) would provide the most information gain.

### Equations

```latex
\text{VOI}(\text{probe}) = E[\text{max}_a U(a | x, \text{probe})] - \text{max}_a U(a | x)
```

```latex
\text{VOI}(\text{probe}) \approx H(C|x) - E[H(C|x, \text{probe})]
```

### Values

| Key | Symbol | Description |
|-----|--------|-------------|
| `current_entropy` | `H(C|x)` | Current posterior entropy (uncertainty) |
| `voi_deep_scan` | - | Expected info gain from deep scan |
| `voi_syscall_trace` | - | Expected info gain from syscall trace |
| `voi_network_probe` | - | Expected info gain from network probe |
| `recommended_probe` | - | Highest-VOI probe |
| `cost_benefit` | - | VOI / cost ratio for each probe |

### Intuition

> "Current uncertainty: {entropy} bits. A {recommended_probe} would reduce uncertainty by ~{expected_reduction} bits."

---

## Rendering Specifications

### TUI Rendering

- Toggle with `g` keybinding
- Use Unicode math symbols when terminal supports it: α, β, Σ, ∈
- ASCII fallbacks: alpha, beta, sum, in
- Color scheme: equations in cyan, values in yellow, intuition in green
- Collapsible cards with expand/collapse toggle

### CLI Rendering

```
$ pt show --galaxy-brain --pid 12345

=== Galaxy-Brain: Mathematical Transparency ===

[1/7] Posterior Class Probabilities
  log P(useful|x)    = -2.34
  log P(abandoned|x) = -0.89  ← MAX
  log P(zombie|x)    = -4.12

  Intuition: 58% chance this process is abandoned.

[2/7] Time-Varying Hazard Rates
  ...
```

### Report Tab

- Dedicated "Galaxy Brain" tab in HTML reports
- KaTeX rendering for equations
- Interactive: click equation to see derivation
- Expandable details for each card
- Chart visualizations where applicable (hazard curves, intervals)

---

## Implementation Notes

1. **Caching**: Galaxy-brain data can be regenerated from stored inference state
2. **Performance**: Compute lazily on toggle, cache for responsive switching
3. **Versioning**: Card IDs are stable; add new cards with new IDs
4. **Localization**: Intuition strings should support i18n
