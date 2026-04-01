//! Core posterior computation P(C|x).
//!
//! Combines class priors with per-feature likelihoods in log-domain and
//! returns normalized posteriors plus log-odds.

use crate::config::priors::{ClassParams, CommandCategories, DirichletParams, Priors, StateFlags};
use pt_math::math::precomputed::{CachedBetaPrior, CachedGammaPrior};
use pt_math::{log_beta, log_beta_pdf, log_gamma, normalize_log_probs_array};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;

/// Evidence for CPU activity.
#[derive(Debug, Clone)]
pub enum CpuEvidence {
    /// Use a fraction in \[0,1\] and a Beta likelihood.
    Fraction { occupancy: f64 },
    /// Use a Beta-Binomial marginal likelihood for k successes out of n.
    Binomial { k: f64, n: f64, eta: Option<f64> },
}

/// Evidence inputs for posterior computation.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub cpu: Option<CpuEvidence>,
    pub runtime_seconds: Option<f64>,
    pub orphan: Option<bool>,
    pub tty: Option<bool>,
    pub net: Option<bool>,
    pub io_active: Option<bool>,
    pub state_flag: Option<usize>,
    pub command_category: Option<usize>,
    /// Queue saturation signal from queueing-theoretic stall detection.
    /// `true` when at least one socket has a deep rx/tx queue, indicating
    /// the process may be stalled or deadlocked (useful-bad evidence).
    pub queue_saturated: Option<bool>,
}

/// Per-class scores for the 4-state model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClassScores {
    pub useful: f64,
    pub useful_bad: f64,
    pub abandoned: f64,
    pub zombie: f64,
}

impl ClassScores {
    fn from_vec(values: &[f64]) -> Self {
        Self {
            useful: values[0],
            useful_bad: values[1],
            abandoned: values[2],
            zombie: values[3],
        }
    }

    fn as_vec(&self) -> [f64; 4] {
        [self.useful, self.useful_bad, self.abandoned, self.zombie]
    }
}

/// Evidence term contribution per class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceTerm {
    pub feature: String,
    pub log_likelihood: ClassScores,
}

/// Posterior computation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PosteriorResult {
    pub posterior: ClassScores,
    pub log_posterior: ClassScores,
    pub log_odds_abandoned_useful: f64,
    pub evidence_terms: Vec<EvidenceTerm>,
}

/// Apply additional derived log-likelihood terms to an existing posterior.
///
/// This keeps higher-level features in the same evidence ledger instead of
/// forcing downstream callers to bolt on opaque score tweaks.
pub fn apply_evidence_terms(
    base: &PosteriorResult,
    extra_terms: impl IntoIterator<Item = EvidenceTerm>,
) -> Result<PosteriorResult, PosteriorError> {
    let extra_terms: Vec<EvidenceTerm> = extra_terms.into_iter().collect();
    if extra_terms.is_empty() {
        return Ok(base.clone());
    }

    let mut log_unnormalized = base.log_posterior;
    for term in &extra_terms {
        log_unnormalized = add_scores(log_unnormalized, term.log_likelihood);
    }

    let log_arr = log_unnormalized.as_vec();
    let log_post_arr = normalize_log_probs_array(&log_arr);
    if log_post_arr.iter().any(|v| v.is_nan()) {
        return Err(PosteriorError::InvalidEvidence {
            field: "posterior",
            message: "normalization with derived evidence produced NaN".to_string(),
        });
    }

    let log_posterior = ClassScores::from_vec(&log_post_arr);
    let posterior = ClassScores::from_vec(&[
        log_post_arr[0].exp(),
        log_post_arr[1].exp(),
        log_post_arr[2].exp(),
        log_post_arr[3].exp(),
    ]);

    let mut evidence_terms = base.evidence_terms.clone();
    evidence_terms.extend(extra_terms);

    Ok(PosteriorResult {
        posterior,
        log_posterior,
        log_odds_abandoned_useful: log_posterior.abandoned - log_posterior.useful,
        evidence_terms,
    })
}

/// Errors raised during posterior computation.
#[derive(Debug, Error)]
pub enum PosteriorError {
    #[error("invalid evidence for {field}: {message}")]
    InvalidEvidence {
        field: &'static str,
        message: String,
    },
    #[error("invalid priors for {field}: {message}")]
    InvalidPriors {
        field: &'static str,
        message: String,
    },
}

#[derive(Debug, Clone)]
struct PriorsHotPathCache {
    useful: ClassHotPathCache,
    useful_bad: ClassHotPathCache,
    abandoned: ClassHotPathCache,
    zombie: ClassHotPathCache,
}

impl PriorsHotPathCache {
    fn new(priors: &Priors) -> Self {
        Self {
            useful: ClassHotPathCache::new(&priors.classes.useful),
            useful_bad: ClassHotPathCache::new(&priors.classes.useful_bad),
            abandoned: ClassHotPathCache::new(&priors.classes.abandoned),
            zombie: ClassHotPathCache::new(&priors.classes.zombie),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ClassHotPathCache {
    cpu_beta: Option<CachedBetaPrior>,
    runtime_gamma: Option<CachedGammaPrior>,
}

impl ClassHotPathCache {
    fn new(params: &ClassParams) -> Self {
        Self {
            cpu_beta: (params.cpu_beta.alpha > 0.0 && params.cpu_beta.beta > 0.0)
                .then(|| CachedBetaPrior::new(params.cpu_beta.alpha, params.cpu_beta.beta)),
            runtime_gamma: params.runtime_gamma.as_ref().and_then(|gamma| {
                (gamma.shape > 0.0 && gamma.rate > 0.0)
                    .then(|| CachedGammaPrior::new(gamma.shape, gamma.rate))
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PriorsHotPathKey {
    useful: ClassHotPathKey,
    useful_bad: ClassHotPathKey,
    abandoned: ClassHotPathKey,
    zombie: ClassHotPathKey,
}

impl PriorsHotPathKey {
    fn from_priors(priors: &Priors) -> Self {
        Self {
            useful: ClassHotPathKey::from_params(&priors.classes.useful),
            useful_bad: ClassHotPathKey::from_params(&priors.classes.useful_bad),
            abandoned: ClassHotPathKey::from_params(&priors.classes.abandoned),
            zombie: ClassHotPathKey::from_params(&priors.classes.zombie),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClassHotPathKey {
    cpu_alpha_bits: u64,
    cpu_beta_bits: u64,
    runtime_present: bool,
    runtime_shape_bits: u64,
    runtime_rate_bits: u64,
}

impl ClassHotPathKey {
    fn from_params(params: &ClassParams) -> Self {
        let (runtime_present, runtime_shape_bits, runtime_rate_bits) = params
            .runtime_gamma
            .as_ref()
            .map(|gamma| (true, gamma.shape.to_bits(), gamma.rate.to_bits()))
            .unwrap_or((false, 0, 0));

        Self {
            cpu_alpha_bits: params.cpu_beta.alpha.to_bits(),
            cpu_beta_bits: params.cpu_beta.beta.to_bits(),
            runtime_present,
            runtime_shape_bits,
            runtime_rate_bits,
        }
    }
}

fn hot_path_cache(priors: &Priors) -> Arc<PriorsHotPathCache> {
    static HOT_PATH_CACHE: OnceLock<Mutex<HashMap<PriorsHotPathKey, Arc<PriorsHotPathCache>>>> =
        OnceLock::new();

    let key = PriorsHotPathKey::from_priors(priors);
    let cache = HOT_PATH_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .expect("posterior hot-path cache lock poisoned");
    cache
        .entry(key)
        .or_insert_with(|| Arc::new(PriorsHotPathCache::new(priors)))
        .clone()
}

/// Compute the posterior P(C|x) for the 4-class model.
pub fn compute_posterior(
    priors: &Priors,
    evidence: &Evidence,
) -> Result<PosteriorResult, PosteriorError> {
    let cache = hot_path_cache(priors);
    let prior_scores = ClassScores {
        useful: ln_checked(priors.classes.useful.prior_prob, "priors.useful")?,
        useful_bad: ln_checked(priors.classes.useful_bad.prior_prob, "priors.useful_bad")?,
        abandoned: ln_checked(priors.classes.abandoned.prior_prob, "priors.abandoned")?,
        zombie: ln_checked(priors.classes.zombie.prior_prob, "priors.zombie")?,
    };

    let mut log_unnormalized = prior_scores;
    let mut evidence_terms = Vec::new();
    evidence_terms.push(EvidenceTerm {
        feature: "prior".to_string(),
        log_likelihood: prior_scores,
    });

    if let Some(cpu) = &evidence.cpu {
        let term = ClassScores {
            useful: log_lik_cpu(
                cpu,
                &priors.classes.useful,
                priors,
                cache.useful.cpu_beta.as_ref(),
            )?,
            useful_bad: log_lik_cpu(
                cpu,
                &priors.classes.useful_bad,
                priors,
                cache.useful_bad.cpu_beta.as_ref(),
            )?,
            abandoned: log_lik_cpu(
                cpu,
                &priors.classes.abandoned,
                priors,
                cache.abandoned.cpu_beta.as_ref(),
            )?,
            zombie: log_lik_cpu(
                cpu,
                &priors.classes.zombie,
                priors,
                cache.zombie.cpu_beta.as_ref(),
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "cpu".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(runtime) = evidence.runtime_seconds {
        let term = ClassScores {
            useful: log_lik_runtime(
                runtime,
                &priors.classes.useful,
                cache.useful.runtime_gamma.as_ref(),
            )?,
            useful_bad: log_lik_runtime(
                runtime,
                &priors.classes.useful_bad,
                cache.useful_bad.runtime_gamma.as_ref(),
            )?,
            abandoned: log_lik_runtime(
                runtime,
                &priors.classes.abandoned,
                cache.abandoned.runtime_gamma.as_ref(),
            )?,
            zombie: log_lik_runtime(
                runtime,
                &priors.classes.zombie,
                cache.zombie.runtime_gamma.as_ref(),
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "runtime".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(orphan) = evidence.orphan {
        let term = ClassScores {
            useful: log_lik_beta_bernoulli(orphan, &priors.classes.useful.orphan_beta, "orphan")?,
            useful_bad: log_lik_beta_bernoulli(
                orphan,
                &priors.classes.useful_bad.orphan_beta,
                "orphan",
            )?,
            abandoned: log_lik_beta_bernoulli(
                orphan,
                &priors.classes.abandoned.orphan_beta,
                "orphan",
            )?,
            zombie: log_lik_beta_bernoulli(orphan, &priors.classes.zombie.orphan_beta, "orphan")?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "orphan".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(tty) = evidence.tty {
        let term = ClassScores {
            useful: log_lik_beta_bernoulli(tty, &priors.classes.useful.tty_beta, "tty")?,
            useful_bad: log_lik_beta_bernoulli(tty, &priors.classes.useful_bad.tty_beta, "tty")?,
            abandoned: log_lik_beta_bernoulli(tty, &priors.classes.abandoned.tty_beta, "tty")?,
            zombie: log_lik_beta_bernoulli(tty, &priors.classes.zombie.tty_beta, "tty")?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "tty".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(net) = evidence.net {
        let term = ClassScores {
            useful: log_lik_beta_bernoulli(net, &priors.classes.useful.net_beta, "net")?,
            useful_bad: log_lik_beta_bernoulli(net, &priors.classes.useful_bad.net_beta, "net")?,
            abandoned: log_lik_beta_bernoulli(net, &priors.classes.abandoned.net_beta, "net")?,
            zombie: log_lik_beta_bernoulli(net, &priors.classes.zombie.net_beta, "net")?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "net".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(io_active) = evidence.io_active {
        let term = ClassScores {
            useful: log_lik_optional_beta_bernoulli(
                io_active,
                priors.classes.useful.io_active_beta.as_ref(),
                "io_active",
            )?,
            useful_bad: log_lik_optional_beta_bernoulli(
                io_active,
                priors.classes.useful_bad.io_active_beta.as_ref(),
                "io_active",
            )?,
            abandoned: log_lik_optional_beta_bernoulli(
                io_active,
                priors.classes.abandoned.io_active_beta.as_ref(),
                "io_active",
            )?,
            zombie: log_lik_optional_beta_bernoulli(
                io_active,
                priors.classes.zombie.io_active_beta.as_ref(),
                "io_active",
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "io_active".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(queue_sat) = evidence.queue_saturated {
        let term = ClassScores {
            useful: log_lik_optional_beta_bernoulli(
                queue_sat,
                priors.classes.useful.queue_saturation_beta.as_ref(),
                "queue_saturated",
            )?,
            useful_bad: log_lik_optional_beta_bernoulli(
                queue_sat,
                priors.classes.useful_bad.queue_saturation_beta.as_ref(),
                "queue_saturated",
            )?,
            abandoned: log_lik_optional_beta_bernoulli(
                queue_sat,
                priors.classes.abandoned.queue_saturation_beta.as_ref(),
                "queue_saturated",
            )?,
            zombie: log_lik_optional_beta_bernoulli(
                queue_sat,
                priors.classes.zombie.queue_saturation_beta.as_ref(),
                "queue_saturated",
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "queue_saturated".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(flag_index) = evidence.state_flag {
        let term = ClassScores {
            useful: log_lik_dirichlet(
                flag_index,
                priors.state_flags.as_ref(),
                "state_flags",
                "useful",
            )?,
            useful_bad: log_lik_dirichlet(
                flag_index,
                priors.state_flags.as_ref(),
                "state_flags",
                "useful_bad",
            )?,
            abandoned: log_lik_dirichlet(
                flag_index,
                priors.state_flags.as_ref(),
                "state_flags",
                "abandoned",
            )?,
            zombie: log_lik_dirichlet(
                flag_index,
                priors.state_flags.as_ref(),
                "state_flags",
                "zombie",
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "state_flag".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(category_index) = evidence.command_category {
        let term = ClassScores {
            useful: log_lik_dirichlet(
                category_index,
                priors.command_categories.as_ref(),
                "command_categories",
                "useful",
            )?,
            useful_bad: log_lik_dirichlet(
                category_index,
                priors.command_categories.as_ref(),
                "command_categories",
                "useful_bad",
            )?,
            abandoned: log_lik_dirichlet(
                category_index,
                priors.command_categories.as_ref(),
                "command_categories",
                "abandoned",
            )?,
            zombie: log_lik_dirichlet(
                category_index,
                priors.command_categories.as_ref(),
                "command_categories",
                "zombie",
            )?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "command_category".to_string(),
            log_likelihood: term,
        });
    }

    let log_arr = log_unnormalized.as_vec();
    let log_post_arr = normalize_log_probs_array(&log_arr);
    if log_post_arr.iter().any(|v| v.is_nan()) {
        return Err(PosteriorError::InvalidEvidence {
            field: "posterior",
            message: "normalization produced NaN".to_string(),
        });
    }
    let log_posterior = ClassScores::from_vec(&log_post_arr);
    let posterior = ClassScores::from_vec(&[
        log_post_arr[0].exp(),
        log_post_arr[1].exp(),
        log_post_arr[2].exp(),
        log_post_arr[3].exp(),
    ]);

    Ok(PosteriorResult {
        posterior,
        log_posterior,
        log_odds_abandoned_useful: log_posterior.abandoned - log_posterior.useful,
        evidence_terms,
    })
}

fn add_scores(a: ClassScores, b: ClassScores) -> ClassScores {
    ClassScores {
        useful: a.useful + b.useful,
        useful_bad: a.useful_bad + b.useful_bad,
        abandoned: a.abandoned + b.abandoned,
        zombie: a.zombie + b.zombie,
    }
}

fn ln_checked(value: f64, field: &'static str) -> Result<f64, PosteriorError> {
    if value <= 0.0 || value.is_nan() {
        return Err(PosteriorError::InvalidPriors {
            field,
            message: format!("expected > 0, got {value}"),
        });
    }
    Ok(value.ln())
}

fn log_lik_cpu(
    cpu: &CpuEvidence,
    priors: &ClassParams,
    config: &Priors,
    cached_beta: Option<&CachedBetaPrior>,
) -> Result<f64, PosteriorError> {
    match cpu {
        CpuEvidence::Fraction { occupancy } => {
            if *occupancy < 0.0 || *occupancy > 1.0 || occupancy.is_nan() {
                return Err(PosteriorError::InvalidEvidence {
                    field: "cpu.occupancy",
                    message: format!("expected in [0,1], got {occupancy}"),
                });
            }
            // Clamp occupancy to avoid -inf at boundaries when alpha/beta > 1
            // 1e-6 corresponds to very low but non-zero probability density
            let clamped = occupancy.clamp(1e-6, 1.0 - 1e-6);
            Ok(match cached_beta {
                Some(beta) => beta.log_pdf(clamped),
                None => log_beta_pdf(clamped, priors.cpu_beta.alpha, priors.cpu_beta.beta),
            })
        }
        CpuEvidence::Binomial { k, n, eta } => {
            if *n <= 0.0 || *k < 0.0 || *k > *n || n.is_nan() || k.is_nan() {
                return Err(PosteriorError::InvalidEvidence {
                    field: "cpu.binomial",
                    message: format!("invalid k/n (k={k}, n={n})"),
                });
            }
            let eta_value = eta.unwrap_or_else(|| {
                config
                    .robust_bayes
                    .as_ref()
                    .and_then(|rb| rb.safe_bayes_eta)
                    .unwrap_or(1.0)
            });
            if eta_value <= 0.0 || eta_value.is_nan() {
                return Err(PosteriorError::InvalidEvidence {
                    field: "cpu.eta",
                    message: format!("eta must be > 0 (got {eta_value})"),
                });
            }
            let k_eff = k * eta_value;
            let n_eff = n * eta_value;
            let log_c = log_binomial_continuous(n_eff, k_eff)?;
            let log_b = log_beta(
                priors.cpu_beta.alpha + k_eff,
                priors.cpu_beta.beta + (n_eff - k_eff),
            );
            Ok(log_c + log_b - log_beta(priors.cpu_beta.alpha, priors.cpu_beta.beta))
        }
    }
}

fn log_lik_runtime(
    runtime: f64,
    priors: &ClassParams,
    cached_gamma: Option<&CachedGammaPrior>,
) -> Result<f64, PosteriorError> {
    let gamma = match &priors.runtime_gamma {
        Some(g) => g,
        None => return Ok(0.0),
    };
    if runtime <= 0.0 || runtime.is_nan() {
        return Err(PosteriorError::InvalidEvidence {
            field: "runtime_seconds",
            message: format!("expected > 0, got {runtime}"),
        });
    }
    if gamma.shape <= 0.0 || gamma.rate <= 0.0 {
        return Err(PosteriorError::InvalidPriors {
            field: "runtime_gamma",
            message: format!(
                "shape and rate must be > 0 (shape={}, rate={})",
                gamma.shape, gamma.rate
            ),
        });
    }
    Ok(match cached_gamma {
        Some(cached) => cached.log_pdf(runtime),
        None => pt_math::gamma_log_pdf(runtime, gamma.shape, gamma.rate),
    })
}

fn log_lik_beta_bernoulli(
    value: bool,
    params: &crate::config::priors::BetaParams,
    field: &'static str,
) -> Result<f64, PosteriorError> {
    if params.alpha <= 0.0 || params.beta <= 0.0 {
        return Err(PosteriorError::InvalidPriors {
            field,
            message: format!(
                "alpha and beta must be > 0 (alpha={}, beta={})",
                params.alpha, params.beta
            ),
        });
    }
    let denom = params.alpha + params.beta;
    let prob = if value {
        params.alpha / denom
    } else {
        params.beta / denom
    };
    Ok(prob.ln())
}

fn log_lik_optional_beta_bernoulli(
    value: bool,
    params: Option<&crate::config::priors::BetaParams>,
    field: &'static str,
) -> Result<f64, PosteriorError> {
    match params {
        Some(p) => log_lik_beta_bernoulli(value, p, field),
        None => Ok(0.0),
    }
}

fn log_lik_dirichlet(
    index: usize,
    params: Option<&impl DirichletAccess>,
    field: &'static str,
    class: &'static str,
) -> Result<f64, PosteriorError> {
    let dirichlet = match params {
        Some(p) => p.get_class_dirichlet(class),
        None => None,
    };
    let dirichlet = match dirichlet {
        Some(d) => d,
        None => return Ok(0.0),
    };
    log_dirichlet_categorical(index, dirichlet, field)
}

fn log_dirichlet_categorical(
    index: usize,
    params: &DirichletParams,
    field: &'static str,
) -> Result<f64, PosteriorError> {
    if index >= params.alpha.len() {
        return Err(PosteriorError::InvalidEvidence {
            field,
            message: format!(
                "index {index} out of range for {} categories",
                params.alpha.len()
            ),
        });
    }
    let sum: f64 = params.alpha.iter().sum();
    if sum <= 0.0 {
        return Err(PosteriorError::InvalidPriors {
            field,
            message: "dirichlet alpha sum must be > 0".to_string(),
        });
    }
    let alpha_i = params.alpha[index];
    if alpha_i <= 0.0 {
        return Err(PosteriorError::InvalidPriors {
            field,
            message: format!("dirichlet alpha[{index}] must be > 0"),
        });
    }
    Ok(alpha_i.ln() - sum.ln())
}

fn log_binomial_continuous(n: f64, k: f64) -> Result<f64, PosteriorError> {
    if n < 0.0 || k < 0.0 || k > n || n.is_nan() || k.is_nan() {
        return Err(PosteriorError::InvalidEvidence {
            field: "binomial",
            message: format!("invalid n/k (n={n}, k={k})"),
        });
    }
    Ok(log_gamma(n + 1.0) - log_gamma(k + 1.0) - log_gamma(n - k + 1.0))
}

trait DirichletAccess {
    fn get_class_dirichlet(&self, class: &'static str) -> Option<&DirichletParams>;
}

impl DirichletAccess for StateFlags {
    fn get_class_dirichlet(&self, class: &'static str) -> Option<&DirichletParams> {
        match class {
            "useful" => self.useful.as_ref(),
            "useful_bad" => self.useful_bad.as_ref(),
            "abandoned" => self.abandoned.as_ref(),
            "zombie" => self.zombie.as_ref(),
            _ => None,
        }
    }
}

impl DirichletAccess for CommandCategories {
    fn get_class_dirichlet(&self, class: &'static str) -> Option<&DirichletParams> {
        match class {
            "useful" => self.useful.as_ref(),
            "useful_bad" => self.useful_bad.as_ref(),
            "abandoned" => self.abandoned.as_ref(),
            "zombie" => self.zombie.as_ref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::priors::{BetaParams, ClassPriors, GammaParams, Priors};

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    fn base_priors() -> Priors {
        let class = ClassParams {
            prior_prob: 0.25,
            cpu_beta: BetaParams::new(1.0, 1.0),
            runtime_gamma: Some(GammaParams::new(2.0, 1.0)),
            orphan_beta: BetaParams::new(1.0, 1.0),
            tty_beta: BetaParams::new(1.0, 1.0),
            net_beta: BetaParams::new(1.0, 1.0),
            io_active_beta: Some(BetaParams::new(1.0, 1.0)),
            queue_saturation_beta: None,
            hazard_gamma: None,
            competing_hazards: None,
        };
        Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: ClassPriors {
                useful: class.clone(),
                useful_bad: class.clone(),
                abandoned: class.clone(),
                zombie: class,
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: None,
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        }
    }

    #[test]
    fn prior_only_posterior_matches_priors() {
        let priors = base_priors();
        let evidence = Evidence::default();
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(approx_eq(result.posterior.useful, 0.25, 1e-12));
        assert!(approx_eq(result.posterior.useful_bad, 0.25, 1e-12));
        assert!(approx_eq(result.posterior.abandoned, 0.25, 1e-12));
        assert!(approx_eq(result.posterior.zombie, 0.25, 1e-12));
    }

    #[test]
    fn cpu_uniform_fraction_does_not_shift_priors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.42 }),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(approx_eq(result.posterior.useful, 0.25, 1e-12));
    }

    #[test]
    fn log_odds_matches_ratio() {
        let mut priors = base_priors();
        priors.classes.useful.prior_prob = 0.8;
        priors.classes.abandoned.prior_prob = 0.1;
        priors.classes.useful_bad.prior_prob = 0.05;
        priors.classes.zombie.prior_prob = 0.05;
        let evidence = Evidence::default();
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let expected = (0.1f64 / 0.8f64).ln();
        assert!(approx_eq(result.log_odds_abandoned_useful, expected, 1e-12));
    }

    #[test]
    fn invalid_cpu_fraction_errors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 1.5 }),
            ..Evidence::default()
        };
        let err = compute_posterior(&priors, &evidence).unwrap_err();
        match err {
            PosteriorError::InvalidEvidence { field, .. } => assert_eq!(field, "cpu.occupancy"),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn runtime_gamma_increases_weight_for_long_runtime() {
        let priors = base_priors();
        let evidence = Evidence {
            runtime_seconds: Some(2.0),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(result.posterior.useful.is_finite());
    }

    #[test]
    fn cached_cpu_fraction_matches_uncached() {
        let priors = base_priors();
        let cache = hot_path_cache(&priors);
        let cpu = CpuEvidence::Fraction { occupancy: 0.37 };

        let useful_uncached = log_lik_cpu(&cpu, &priors.classes.useful, &priors, None).unwrap();
        let useful_cached = log_lik_cpu(
            &cpu,
            &priors.classes.useful,
            &priors,
            cache.useful.cpu_beta.as_ref(),
        )
        .unwrap();
        assert!(approx_eq(useful_uncached, useful_cached, 1e-12));

        let abandoned_uncached =
            log_lik_cpu(&cpu, &priors.classes.abandoned, &priors, None).unwrap();
        let abandoned_cached = log_lik_cpu(
            &cpu,
            &priors.classes.abandoned,
            &priors,
            cache.abandoned.cpu_beta.as_ref(),
        )
        .unwrap();
        assert!(approx_eq(abandoned_uncached, abandoned_cached, 1e-12));
    }

    #[test]
    fn cached_runtime_matches_uncached() {
        let priors = base_priors();
        let cache = hot_path_cache(&priors);

        let useful_uncached = log_lik_runtime(42.0, &priors.classes.useful, None).unwrap();
        let useful_cached = log_lik_runtime(
            42.0,
            &priors.classes.useful,
            cache.useful.runtime_gamma.as_ref(),
        )
        .unwrap();
        assert!(approx_eq(useful_uncached, useful_cached, 1e-12));

        let zombie_uncached = log_lik_runtime(42.0, &priors.classes.zombie, None).unwrap();
        let zombie_cached = log_lik_runtime(
            42.0,
            &priors.classes.zombie,
            cache.zombie.runtime_gamma.as_ref(),
        )
        .unwrap();
        assert!(approx_eq(zombie_uncached, zombie_cached, 1e-12));
    }

    // ── ClassScores ─────────────────────────────────────────────────

    #[test]
    fn class_scores_default_is_zero() {
        let s = ClassScores::default();
        assert_eq!(s.useful, 0.0);
        assert_eq!(s.useful_bad, 0.0);
        assert_eq!(s.abandoned, 0.0);
        assert_eq!(s.zombie, 0.0);
    }

    #[test]
    fn class_scores_from_vec() {
        let s = ClassScores::from_vec(&[0.1, 0.2, 0.3, 0.4]);
        assert!(approx_eq(s.useful, 0.1, 1e-15));
        assert!(approx_eq(s.useful_bad, 0.2, 1e-15));
        assert!(approx_eq(s.abandoned, 0.3, 1e-15));
        assert!(approx_eq(s.zombie, 0.4, 1e-15));
    }

    #[test]
    fn class_scores_as_vec_roundtrip() {
        let s = ClassScores {
            useful: 1.0,
            useful_bad: 2.0,
            abandoned: 3.0,
            zombie: 4.0,
        };
        let v = s.as_vec();
        assert_eq!(v, [1.0, 2.0, 3.0, 4.0]);
    }

    #[test]
    fn class_scores_serde_roundtrip() {
        let s = ClassScores {
            useful: 0.5,
            useful_bad: 0.2,
            abandoned: 0.2,
            zombie: 0.1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let deser: ClassScores = serde_json::from_str(&json).unwrap();
        assert_eq!(s, deser);
    }

    // ── EvidenceTerm / PosteriorResult serde ────────────────────────

    #[test]
    fn evidence_term_serde_roundtrip() {
        let term = EvidenceTerm {
            feature: "cpu".to_string(),
            log_likelihood: ClassScores {
                useful: -1.0,
                useful_bad: -2.0,
                abandoned: -0.5,
                zombie: -3.0,
            },
        };
        let json = serde_json::to_string(&term).unwrap();
        let deser: EvidenceTerm = serde_json::from_str(&json).unwrap();
        assert_eq!(term, deser);
    }

    #[test]
    fn posterior_result_serde_roundtrip() {
        let result = PosteriorResult {
            posterior: ClassScores {
                useful: 0.4,
                useful_bad: 0.1,
                abandoned: 0.3,
                zombie: 0.2,
            },
            log_posterior: ClassScores {
                useful: -0.9,
                useful_bad: -2.3,
                abandoned: -1.2,
                zombie: -1.6,
            },
            log_odds_abandoned_useful: 0.3,
            evidence_terms: vec![EvidenceTerm {
                feature: "prior".to_string(),
                log_likelihood: ClassScores::default(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: PosteriorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deser);
    }

    #[test]
    fn apply_evidence_terms_shifts_posterior() {
        let priors = base_priors();
        let base = compute_posterior(&priors, &Evidence::default()).expect("base posterior");
        let adjusted = apply_evidence_terms(
            &base,
            [EvidenceTerm {
                feature: "derived_provenance".to_string(),
                log_likelihood: ClassScores {
                    useful: -0.8,
                    useful_bad: -0.2,
                    abandoned: 0.9,
                    zombie: 0.1,
                },
            }],
        )
        .expect("adjusted posterior");

        assert!(adjusted.posterior.abandoned > base.posterior.abandoned);
        assert!(adjusted.posterior.useful < base.posterior.useful);
        assert_eq!(adjusted.evidence_terms.len(), base.evidence_terms.len() + 1);
        assert_eq!(
            adjusted.evidence_terms.last().map(|t| t.feature.as_str()),
            Some("derived_provenance")
        );
    }

    #[test]
    fn apply_evidence_terms_empty_is_identity() {
        let priors = base_priors();
        let base = compute_posterior(&priors, &Evidence::default()).expect("base posterior");
        let adjusted = apply_evidence_terms(&base, std::iter::empty()).expect("identity");
        assert_eq!(adjusted, base);
    }

    // ── PosteriorError ──────────────────────────────────────────────

    #[test]
    fn error_invalid_evidence_display() {
        let err = PosteriorError::InvalidEvidence {
            field: "cpu.occupancy",
            message: "expected in [0,1], got 2".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("cpu.occupancy"));
        assert!(msg.contains("expected in [0,1]"));
    }

    #[test]
    fn error_invalid_priors_display() {
        let err = PosteriorError::InvalidPriors {
            field: "runtime_gamma",
            message: "shape must be > 0".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("runtime_gamma"));
        assert!(msg.contains("shape must be > 0"));
    }

    // ── Evidence default ────────────────────────────────────────────

    #[test]
    fn evidence_default_all_none() {
        let e = Evidence::default();
        assert!(e.cpu.is_none());
        assert!(e.runtime_seconds.is_none());
        assert!(e.orphan.is_none());
        assert!(e.tty.is_none());
        assert!(e.net.is_none());
        assert!(e.io_active.is_none());
        assert!(e.state_flag.is_none());
        assert!(e.command_category.is_none());
    }

    // ── add_scores ──────────────────────────────────────────────────

    #[test]
    fn add_scores_sums_elementwise() {
        let a = ClassScores {
            useful: 1.0,
            useful_bad: 2.0,
            abandoned: 3.0,
            zombie: 4.0,
        };
        let b = ClassScores {
            useful: 10.0,
            useful_bad: 20.0,
            abandoned: 30.0,
            zombie: 40.0,
        };
        let c = add_scores(a, b);
        assert!(approx_eq(c.useful, 11.0, 1e-15));
        assert!(approx_eq(c.useful_bad, 22.0, 1e-15));
        assert!(approx_eq(c.abandoned, 33.0, 1e-15));
        assert!(approx_eq(c.zombie, 44.0, 1e-15));
    }

    #[test]
    fn add_scores_identity_with_zeros() {
        let a = ClassScores {
            useful: 5.0,
            useful_bad: 6.0,
            abandoned: 7.0,
            zombie: 8.0,
        };
        let zero = ClassScores::default();
        let c = add_scores(a, zero);
        assert_eq!(c.useful, 5.0);
        assert_eq!(c.useful_bad, 6.0);
    }

    // ── ln_checked ──────────────────────────────────────────────────

    #[test]
    fn ln_checked_positive_value() {
        let result = ln_checked(1.0, "test").unwrap();
        assert!(approx_eq(result, 0.0, 1e-15));
    }

    #[test]
    fn ln_checked_large_value() {
        let result = ln_checked(std::f64::consts::E, "test").unwrap();
        assert!(approx_eq(result, 1.0, 1e-15));
    }

    #[test]
    fn ln_checked_zero_errors() {
        let err = ln_checked(0.0, "test_field").unwrap_err();
        match err {
            PosteriorError::InvalidPriors { field, .. } => assert_eq!(field, "test_field"),
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn ln_checked_negative_errors() {
        assert!(ln_checked(-1.0, "test").is_err());
    }

    #[test]
    fn ln_checked_nan_errors() {
        assert!(ln_checked(f64::NAN, "test").is_err());
    }

    // ── log_lik_beta_bernoulli ──────────────────────────────────────

    #[test]
    fn beta_bernoulli_true_uniform() {
        let params = BetaParams::new(1.0, 1.0);
        let result = log_lik_beta_bernoulli(true, &params, "test").unwrap();
        // With uniform Beta(1,1), P(true) = alpha/(alpha+beta) = 0.5
        assert!(approx_eq(result, (0.5f64).ln(), 1e-12));
    }

    #[test]
    fn beta_bernoulli_false_uniform() {
        let params = BetaParams::new(1.0, 1.0);
        let result = log_lik_beta_bernoulli(false, &params, "test").unwrap();
        assert!(approx_eq(result, (0.5f64).ln(), 1e-12));
    }

    #[test]
    fn beta_bernoulli_asymmetric() {
        let params = BetaParams::new(9.0, 1.0);
        let result_true = log_lik_beta_bernoulli(true, &params, "test").unwrap();
        let result_false = log_lik_beta_bernoulli(false, &params, "test").unwrap();
        // P(true) = 9/10 = 0.9, P(false) = 1/10 = 0.1
        assert!(approx_eq(result_true, (0.9f64).ln(), 1e-12));
        assert!(approx_eq(result_false, (0.1f64).ln(), 1e-12));
    }

    #[test]
    fn beta_bernoulli_invalid_alpha_errors() {
        let params = BetaParams::new(0.0, 1.0);
        assert!(log_lik_beta_bernoulli(true, &params, "test").is_err());
    }

    #[test]
    fn beta_bernoulli_invalid_beta_errors() {
        let params = BetaParams::new(1.0, -1.0);
        assert!(log_lik_beta_bernoulli(true, &params, "test").is_err());
    }

    // ── log_lik_optional_beta_bernoulli ─────────────────────────────

    #[test]
    fn optional_beta_bernoulli_none_returns_zero() {
        let result = log_lik_optional_beta_bernoulli(true, None, "test").unwrap();
        assert_eq!(result, 0.0);
    }

    #[test]
    fn optional_beta_bernoulli_some_delegates() {
        let params = BetaParams::new(1.0, 1.0);
        let result = log_lik_optional_beta_bernoulli(true, Some(&params), "test").unwrap();
        assert!(approx_eq(result, (0.5f64).ln(), 1e-12));
    }

    // ── log_dirichlet_categorical ───────────────────────────────────

    #[test]
    fn dirichlet_categorical_uniform() {
        let params = DirichletParams {
            alpha: vec![1.0, 1.0, 1.0],
        };
        let result = log_dirichlet_categorical(0, &params, "test").unwrap();
        // P(0) = 1/3
        assert!(approx_eq(result, (1.0f64 / 3.0).ln(), 1e-12));
    }

    #[test]
    fn dirichlet_categorical_asymmetric() {
        let params = DirichletParams {
            alpha: vec![3.0, 1.0],
        };
        let result = log_dirichlet_categorical(0, &params, "test").unwrap();
        // P(0) = 3/4 = 0.75
        assert!(approx_eq(result, (0.75f64).ln(), 1e-12));
    }

    #[test]
    fn dirichlet_categorical_out_of_range_errors() {
        let params = DirichletParams {
            alpha: vec![1.0, 1.0],
        };
        assert!(log_dirichlet_categorical(5, &params, "test").is_err());
    }

    #[test]
    fn dirichlet_categorical_zero_alpha_errors() {
        let params = DirichletParams {
            alpha: vec![0.0, 1.0],
        };
        assert!(log_dirichlet_categorical(0, &params, "test").is_err());
    }

    // ── log_binomial_continuous ──────────────────────────────────────

    #[test]
    fn binomial_continuous_valid() {
        let result = log_binomial_continuous(10.0, 3.0).unwrap();
        assert!(result.is_finite());
    }

    #[test]
    fn binomial_continuous_k_equals_n() {
        let result = log_binomial_continuous(5.0, 5.0).unwrap();
        // C(5,5) = 1, log(1) = 0
        assert!(approx_eq(result, 0.0, 1e-10));
    }

    #[test]
    fn binomial_continuous_k_zero() {
        let result = log_binomial_continuous(5.0, 0.0).unwrap();
        // C(5,0) = 1, log(1) = 0
        assert!(approx_eq(result, 0.0, 1e-10));
    }

    #[test]
    fn binomial_continuous_negative_n_errors() {
        assert!(log_binomial_continuous(-1.0, 0.0).is_err());
    }

    #[test]
    fn binomial_continuous_k_greater_than_n_errors() {
        assert!(log_binomial_continuous(3.0, 5.0).is_err());
    }

    // ── log_lik_runtime ─────────────────────────────────────────────

    #[test]
    fn runtime_no_gamma_returns_zero() {
        let class = ClassParams {
            prior_prob: 0.25,
            cpu_beta: BetaParams::new(1.0, 1.0),
            runtime_gamma: None,
            orphan_beta: BetaParams::new(1.0, 1.0),
            tty_beta: BetaParams::new(1.0, 1.0),
            net_beta: BetaParams::new(1.0, 1.0),
            io_active_beta: None,
            queue_saturation_beta: None,
            hazard_gamma: None,
            competing_hazards: None,
        };
        assert_eq!(log_lik_runtime(100.0, &class, None).unwrap(), 0.0);
    }

    #[test]
    fn runtime_negative_errors() {
        let priors = base_priors();
        assert!(log_lik_runtime(-1.0, &priors.classes.useful, None).is_err());
    }

    #[test]
    fn runtime_zero_errors() {
        let priors = base_priors();
        assert!(log_lik_runtime(0.0, &priors.classes.useful, None).is_err());
    }

    #[test]
    fn runtime_nan_errors() {
        let priors = base_priors();
        assert!(log_lik_runtime(f64::NAN, &priors.classes.useful, None).is_err());
    }

    // ── compute_posterior additional tests ───────────────────────────

    #[test]
    fn posterior_sums_to_one() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.3 }),
            runtime_seconds: Some(100.0),
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let sum = result.posterior.useful
            + result.posterior.useful_bad
            + result.posterior.abandoned
            + result.posterior.zombie;
        assert!(approx_eq(sum, 1.0, 1e-10));
    }

    #[test]
    fn posterior_includes_evidence_terms() {
        let priors = base_priors();
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let feature_names: Vec<&str> = result
            .evidence_terms
            .iter()
            .map(|t| t.feature.as_str())
            .collect();
        assert!(feature_names.contains(&"prior"));
        assert!(feature_names.contains(&"orphan"));
        assert!(feature_names.contains(&"tty"));
    }

    #[test]
    fn posterior_with_io_active_evidence() {
        let priors = base_priors();
        let evidence = Evidence {
            io_active: Some(true),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(result.posterior.useful.is_finite());
        let sum = result.posterior.useful
            + result.posterior.useful_bad
            + result.posterior.abandoned
            + result.posterior.zombie;
        assert!(approx_eq(sum, 1.0, 1e-10));
    }

    #[test]
    fn posterior_with_net_evidence() {
        let priors = base_priors();
        let evidence = Evidence {
            net: Some(false),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(result.posterior.useful.is_finite());
    }

    #[test]
    fn posterior_zero_prior_errors() {
        let mut priors = base_priors();
        priors.classes.useful.prior_prob = 0.0;
        let evidence = Evidence::default();
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_negative_prior_errors() {
        let mut priors = base_priors();
        priors.classes.zombie.prior_prob = -0.1;
        let evidence = Evidence::default();
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_cpu_nan_errors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction {
                occupancy: f64::NAN,
            }),
            ..Evidence::default()
        };
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_cpu_negative_errors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: -0.1 }),
            ..Evidence::default()
        };
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_cpu_binomial_valid() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Binomial {
                k: 3.0,
                n: 10.0,
                eta: None,
            }),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let sum = result.posterior.useful
            + result.posterior.useful_bad
            + result.posterior.abandoned
            + result.posterior.zombie;
        assert!(approx_eq(sum, 1.0, 1e-10));
    }

    #[test]
    fn posterior_cpu_binomial_invalid_k_errors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Binomial {
                k: 15.0,
                n: 10.0,
                eta: None,
            }),
            ..Evidence::default()
        };
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_cpu_binomial_with_eta() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Binomial {
                k: 3.0,
                n: 10.0,
                eta: Some(0.5),
            }),
            ..Evidence::default()
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(result.posterior.useful.is_finite());
    }

    #[test]
    fn posterior_cpu_binomial_zero_eta_errors() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Binomial {
                k: 3.0,
                n: 10.0,
                eta: Some(0.0),
            }),
            ..Evidence::default()
        };
        assert!(compute_posterior(&priors, &evidence).is_err());
    }

    #[test]
    fn posterior_all_evidence_types() {
        let priors = base_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.5 }),
            runtime_seconds: Some(3600.0),
            orphan: Some(true),
            tty: Some(false),
            net: Some(true),
            io_active: Some(false),
            state_flag: None,
            command_category: None,
            queue_saturated: None,
        };
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        // 7 evidence terms: prior + cpu + runtime + orphan + tty + net + io_active
        assert_eq!(result.evidence_terms.len(), 7);
        let sum = result.posterior.useful
            + result.posterior.useful_bad
            + result.posterior.abandoned
            + result.posterior.zombie;
        assert!(approx_eq(sum, 1.0, 1e-10));
    }

    #[test]
    fn queue_saturated_evidence_boosts_useful_bad_when_configured() {
        let mut priors = base_priors();
        priors.classes.useful.queue_saturation_beta = Some(BetaParams::new(1.0, 6.0));
        priors.classes.useful_bad.queue_saturation_beta = Some(BetaParams::new(6.0, 1.0));
        priors.classes.abandoned.queue_saturation_beta = Some(BetaParams::new(2.0, 3.0));
        priors.classes.zombie.queue_saturation_beta = Some(BetaParams::new(1.0, 4.0));

        let evidence = Evidence {
            queue_saturated: Some(true),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");
        assert!(result.posterior.useful_bad > result.posterior.useful);
        assert!(result.posterior.useful_bad > result.posterior.abandoned);
        assert!(result
            .evidence_terms
            .iter()
            .any(|term| term.feature == "queue_saturated"));
    }

    #[test]
    fn posterior_asymmetric_priors_shift_result() {
        let mut priors = base_priors();
        priors.classes.abandoned.prior_prob = 0.9;
        priors.classes.useful.prior_prob = 0.03;
        priors.classes.useful_bad.prior_prob = 0.03;
        priors.classes.zombie.prior_prob = 0.04;
        let evidence = Evidence::default();
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        // Abandoned should dominate
        assert!(result.posterior.abandoned > result.posterior.useful);
        assert!(result.posterior.abandoned > 0.8);
    }

    #[test]
    fn log_odds_sign_matches_ratio() {
        let mut priors = base_priors();
        priors.classes.abandoned.prior_prob = 0.6;
        priors.classes.useful.prior_prob = 0.2;
        priors.classes.useful_bad.prior_prob = 0.1;
        priors.classes.zombie.prior_prob = 0.1;
        let result = compute_posterior(&priors, &Evidence::default()).expect("posterior");
        // abandoned > useful => log_odds > 0
        assert!(result.log_odds_abandoned_useful > 0.0);
    }
}
