//! Core posterior computation P(C|x).
//!
//! Combines class priors with per-feature likelihoods in log-domain and
//! returns normalized posteriors plus log-odds.

use crate::config::priors::{ClassPriors, CommandCategories, DirichletParams, Priors, StateFlags};
use pt_math::{log_beta, log_beta_pdf, log_gamma, normalize_log_probs};
use serde::Serialize;
use thiserror::Error;

/// Evidence for CPU activity.
#[derive(Debug, Clone)]
pub enum CpuEvidence {
    /// Use a fraction in [0,1] and a Beta likelihood.
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
}

/// Per-class scores for the 4-state model.
#[derive(Debug, Clone, Copy, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceTerm {
    pub feature: String,
    pub log_likelihood: ClassScores,
}

/// Posterior computation result.
#[derive(Debug, Clone, Serialize)]
pub struct PosteriorResult {
    pub posterior: ClassScores,
    pub log_posterior: ClassScores,
    pub log_odds_abandoned_useful: f64,
    pub evidence_terms: Vec<EvidenceTerm>,
}

/// Errors raised during posterior computation.
#[derive(Debug, Error)]
pub enum PosteriorError {
    #[error("invalid evidence for {field}: {message}")]
    InvalidEvidence { field: &'static str, message: String },
    #[error("invalid priors for {field}: {message}")]
    InvalidPriors { field: &'static str, message: String },
}

/// Compute the posterior P(C|x) for the 4-class model.
pub fn compute_posterior(priors: &Priors, evidence: &Evidence) -> Result<PosteriorResult, PosteriorError> {
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
            useful: log_lik_cpu(cpu, &priors.classes.useful, priors)?,
            useful_bad: log_lik_cpu(cpu, &priors.classes.useful_bad, priors)?,
            abandoned: log_lik_cpu(cpu, &priors.classes.abandoned, priors)?,
            zombie: log_lik_cpu(cpu, &priors.classes.zombie, priors)?,
        };
        log_unnormalized = add_scores(log_unnormalized, term);
        evidence_terms.push(EvidenceTerm {
            feature: "cpu".to_string(),
            log_likelihood: term,
        });
    }

    if let Some(runtime) = evidence.runtime_seconds {
        let term = ClassScores {
            useful: log_lik_runtime(runtime, &priors.classes.useful)?,
            useful_bad: log_lik_runtime(runtime, &priors.classes.useful_bad)?,
            abandoned: log_lik_runtime(runtime, &priors.classes.abandoned)?,
            zombie: log_lik_runtime(runtime, &priors.classes.zombie)?,
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
            useful_bad: log_lik_beta_bernoulli(orphan, &priors.classes.useful_bad.orphan_beta, "orphan")?,
            abandoned: log_lik_beta_bernoulli(orphan, &priors.classes.abandoned.orphan_beta, "orphan")?,
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

    if let Some(flag_index) = evidence.state_flag {
        let term = ClassScores {
            useful: log_lik_dirichlet(flag_index, priors.state_flags.as_ref(), "state_flags", "useful")?,
            useful_bad: log_lik_dirichlet(flag_index, priors.state_flags.as_ref(), "state_flags", "useful_bad")?,
            abandoned: log_lik_dirichlet(flag_index, priors.state_flags.as_ref(), "state_flags", "abandoned")?,
            zombie: log_lik_dirichlet(flag_index, priors.state_flags.as_ref(), "state_flags", "zombie")?,
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

    let log_vec = log_unnormalized.as_vec();
    let log_post_vec = normalize_log_probs(&log_vec);
    if log_post_vec.iter().any(|v| v.is_nan()) {
        return Err(PosteriorError::InvalidEvidence {
            field: "posterior",
            message: "normalization produced NaN".to_string(),
        });
    }
    let log_posterior = ClassScores::from_vec(&log_post_vec);
    let posterior = ClassScores::from_vec(&[
        log_post_vec[0].exp(),
        log_post_vec[1].exp(),
        log_post_vec[2].exp(),
        log_post_vec[3].exp(),
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

fn log_lik_cpu(cpu: &CpuEvidence, priors: &ClassPriors, config: &Priors) -> Result<f64, PosteriorError> {
    match cpu {
        CpuEvidence::Fraction { occupancy } => {
            if *occupancy < 0.0 || *occupancy > 1.0 || occupancy.is_nan() {
                return Err(PosteriorError::InvalidEvidence {
                    field: "cpu.occupancy",
                    message: format!("expected in [0,1], got {occupancy}"),
                });
            }
            Ok(log_beta_pdf(*occupancy, priors.cpu_beta.alpha, priors.cpu_beta.beta))
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

fn log_lik_runtime(runtime: f64, priors: &ClassPriors) -> Result<f64, PosteriorError> {
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
    let log_pdf = gamma.shape * gamma.rate.ln()
        + (gamma.shape - 1.0) * runtime.ln()
        - gamma.rate * runtime
        - log_gamma(gamma.shape);
    Ok(log_pdf)
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
            message: format!("index {index} out of range for {} categories", params.alpha.len()),
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
    use crate::config::priors::{BetaParams, ClassPriors, Classes, GammaParams, Priors};

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    fn base_priors() -> Priors {
        let class = ClassPriors {
            prior_prob: 0.25,
            cpu_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            runtime_gamma: Some(GammaParams { shape: 2.0, rate: 1.0 }),
            orphan_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            tty_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            net_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            io_active_beta: Some(BetaParams { alpha: 1.0, beta: 1.0 }),
            hazard_gamma: None,
            competing_hazards: None,
        };
        Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: Classes {
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
}
