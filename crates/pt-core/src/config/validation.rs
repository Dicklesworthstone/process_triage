//! Semantic validation for configuration files.
//!
//! This module validates that config values are not just syntactically correct
//! but also semantically valid (e.g., probabilities sum to 1, parameters are positive).

use thiserror::Error;

use super::policy::Policy;
use super::priors::{BetaParams, ClassParams, DirichletParams, GammaParams, Priors};

/// Tolerance for floating point comparisons.
const PROB_TOLERANCE: f64 = 0.001;

/// Errors that can occur during semantic validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Class prior probabilities must sum to 1.0 (got {sum:.4})")]
    PriorProbabilitySum { sum: f64 },

    #[error("Prior probability for {class} must be in [0, 1] (got {value:.4})")]
    PriorProbabilityRange { class: String, value: f64 },

    #[error("Beta parameter {param} for {field} must be positive (got {value:.6})")]
    BetaParamNonPositive {
        field: String,
        param: String,
        value: f64,
    },

    #[error("Gamma parameter {param} for {field} must be positive (got {value:.6})")]
    GammaParamNonPositive {
        field: String,
        param: String,
        value: f64,
    },

    #[error("Dirichlet alpha for {field} must all be positive")]
    DirichletParamNonPositive { field: String },

    #[error("Dirichlet alpha for {field} must have at least 2 elements")]
    DirichletTooFewElements { field: String },

    #[error("Loss matrix value for {class}.{action} must be non-negative (got {value:.4})")]
    LossMatrixNegative {
        class: String,
        action: String,
        value: f64,
    },

    #[error("Loss matrix for {class} is incomplete: missing {action}")]
    LossMatrixIncomplete { class: String, action: String },

    #[error("FDR alpha must be in (0, 1] (got {value:.4})")]
    FdrAlphaRange { value: f64 },

    #[error("Robot mode min_posterior must be in (0, 1] (got {value:.4})")]
    RobotPosteriorRange { value: f64 },

    #[error("Prior bounds for {class}: lower ({lower:.4}) must be <= upper ({upper:.4})")]
    PriorBoundsInverted {
        class: String,
        lower: f64,
        upper: f64,
    },

    #[error("Prior bounds for {class}: values must be in [0, 1]")]
    PriorBoundsRange { class: String },

    #[error("Shrinkage strength must be in [0, 1] (got {value:.4})")]
    ShrinkageStrengthRange { value: f64 },

    #[error("Safe Bayes eta must be in (0, 1] (got {value:.4})")]
    SafeBayesEtaRange { value: f64 },

    #[error("BOCPD hazard_lambda must be positive (got {value:.6})")]
    BocpdHazardNonPositive { value: f64 },

    #[error("Geometric p for change-point must be in (0, 1] (got {value:.4})")]
    ChangePointGeometricRange { value: f64 },

    #[error("Invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },
}

/// Validate priors configuration semantically.
pub fn validate_priors(priors: &Priors) -> Result<(), ValidationError> {
    // Validate class prior probabilities sum to 1
    let sum = priors.classes.useful.prior_prob
        + priors.classes.useful_bad.prior_prob
        + priors.classes.abandoned.prior_prob
        + priors.classes.zombie.prior_prob;

    if (sum - 1.0).abs() > PROB_TOLERANCE {
        return Err(ValidationError::PriorProbabilitySum { sum });
    }

    // Validate each class
    validate_class_priors(&priors.classes.useful, "useful")?;
    validate_class_priors(&priors.classes.useful_bad, "useful_bad")?;
    validate_class_priors(&priors.classes.abandoned, "abandoned")?;
    validate_class_priors(&priors.classes.zombie, "zombie")?;

    // Validate hazard regimes
    for regime in &priors.hazard_regimes {
        validate_gamma(&regime.gamma, &format!("hazard_regime.{}", regime.name))?;
    }

    // Validate semi-Markov parameters
    if let Some(sm) = &priors.semi_markov {
        if let Some(g) = &sm.useful_duration {
            validate_gamma(g, "semi_markov.useful_duration")?;
        }
        if let Some(g) = &sm.useful_bad_duration {
            validate_gamma(g, "semi_markov.useful_bad_duration")?;
        }
        if let Some(g) = &sm.abandoned_duration {
            validate_gamma(g, "semi_markov.abandoned_duration")?;
        }
        if let Some(g) = &sm.zombie_duration {
            validate_gamma(g, "semi_markov.zombie_duration")?;
        }
    }

    // Validate change-point priors
    if let Some(cp) = &priors.change_point {
        if let Some(b) = &cp.p_before {
            validate_beta(b, "change_point.p_before")?;
        }
        if let Some(b) = &cp.p_after {
            validate_beta(b, "change_point.p_after")?;
        }
        if let Some(p) = cp.tau_geometric_p {
            if p <= 0.0 || p > 1.0 {
                return Err(ValidationError::ChangePointGeometricRange { value: p });
            }
        }
    }

    // Validate command categories
    if let Some(cc) = &priors.command_categories {
        if let Some(d) = &cc.useful {
            validate_dirichlet(d, "command_categories.useful")?;
        }
        if let Some(d) = &cc.useful_bad {
            validate_dirichlet(d, "command_categories.useful_bad")?;
        }
        if let Some(d) = &cc.abandoned {
            validate_dirichlet(d, "command_categories.abandoned")?;
        }
        if let Some(d) = &cc.zombie {
            validate_dirichlet(d, "command_categories.zombie")?;
        }
    }

    // Validate state flags
    if let Some(sf) = &priors.state_flags {
        if let Some(d) = &sf.useful {
            validate_dirichlet(d, "state_flags.useful")?;
        }
        if let Some(d) = &sf.useful_bad {
            validate_dirichlet(d, "state_flags.useful_bad")?;
        }
        if let Some(d) = &sf.abandoned {
            validate_dirichlet(d, "state_flags.abandoned")?;
        }
        if let Some(d) = &sf.zombie {
            validate_dirichlet(d, "state_flags.zombie")?;
        }
    }

    // Validate hierarchical settings
    if let Some(h) = &priors.hierarchical {
        if let Some(s) = h.shrinkage_strength {
            if !(0.0..=1.0).contains(&s) {
                return Err(ValidationError::ShrinkageStrengthRange { value: s });
            }
        }
    }

    // Validate robust Bayes settings
    if let Some(rb) = &priors.robust_bayes {
        if let Some(eta) = rb.safe_bayes_eta {
            if eta <= 0.0 || eta > 1.0 {
                return Err(ValidationError::SafeBayesEtaRange { value: eta });
            }
        }
        if let Some(bounds) = &rb.class_prior_bounds {
            if let Some(b) = &bounds.useful {
                validate_prior_bounds(b.lower, b.upper, "useful")?;
            }
            if let Some(b) = &bounds.useful_bad {
                validate_prior_bounds(b.lower, b.upper, "useful_bad")?;
            }
            if let Some(b) = &bounds.abandoned {
                validate_prior_bounds(b.lower, b.upper, "abandoned")?;
            }
            if let Some(b) = &bounds.zombie {
                validate_prior_bounds(b.lower, b.upper, "zombie")?;
            }
        }
    }

    // Validate error rate
    if let Some(er) = &priors.error_rate {
        if let Some(b) = &er.false_kill {
            validate_beta(b, "error_rate.false_kill")?;
        }
        if let Some(b) = &er.false_spare {
            validate_beta(b, "error_rate.false_spare")?;
        }
    }

    // Validate BOCPD
    if let Some(bocpd) = &priors.bocpd {
        if let Some(lambda) = bocpd.hazard_lambda {
            if lambda <= 0.0 {
                return Err(ValidationError::BocpdHazardNonPositive { value: lambda });
            }
        }
    }

    Ok(())
}

/// Validate class priors.
fn validate_class_priors(
    class: &ClassParams,
    name: &str,
) -> Result<(), ValidationError> {
    // Validate prior probability range
    if !(0.0..=1.0).contains(&class.prior_prob) {
        return Err(ValidationError::PriorProbabilityRange {
            class: name.to_string(),
            value: class.prior_prob,
        });
    }

    // Validate Beta parameters
    validate_beta(&class.cpu_beta, &format!("{}.cpu_beta", name))?;
    validate_beta(&class.orphan_beta, &format!("{}.orphan_beta", name))?;
    validate_beta(&class.tty_beta, &format!("{}.tty_beta", name))?;
    validate_beta(&class.net_beta, &format!("{}.net_beta", name))?;

    if let Some(b) = &class.io_active_beta {
        validate_beta(b, &format!("{}.io_active_beta", name))?;
    }

    // Validate Gamma parameters
    if let Some(g) = &class.runtime_gamma {
        validate_gamma(g, &format!("{}.runtime_gamma", name))?;
    }
    if let Some(g) = &class.hazard_gamma {
        validate_gamma(g, &format!("{}.hazard_gamma", name))?;
    }

    // Validate competing hazards
    if let Some(ch) = &class.competing_hazards {
        if let Some(g) = &ch.finish {
            validate_gamma(g, &format!("{}.competing_hazards.finish", name))?;
        }
        if let Some(g) = &ch.abandon {
            validate_gamma(g, &format!("{}.competing_hazards.abandon", name))?;
        }
        if let Some(g) = &ch.degrade {
            validate_gamma(g, &format!("{}.competing_hazards.degrade", name))?;
        }
    }

    Ok(())
}

/// Validate Beta distribution parameters.
fn validate_beta(beta: &BetaParams, field: &str) -> Result<(), ValidationError> {
    if beta.alpha <= 0.0 {
        return Err(ValidationError::BetaParamNonPositive {
            field: field.to_string(),
            param: "alpha".to_string(),
            value: beta.alpha,
        });
    }
    if beta.beta <= 0.0 {
        return Err(ValidationError::BetaParamNonPositive {
            field: field.to_string(),
            param: "beta".to_string(),
            value: beta.beta,
        });
    }
    Ok(())
}

/// Validate Gamma distribution parameters.
fn validate_gamma(gamma: &GammaParams, field: &str) -> Result<(), ValidationError> {
    if gamma.shape <= 0.0 {
        return Err(ValidationError::GammaParamNonPositive {
            field: field.to_string(),
            param: "shape".to_string(),
            value: gamma.shape,
        });
    }
    if gamma.rate <= 0.0 {
        return Err(ValidationError::GammaParamNonPositive {
            field: field.to_string(),
            param: "rate".to_string(),
            value: gamma.rate,
        });
    }
    Ok(())
}

/// Validate Dirichlet distribution parameters.
fn validate_dirichlet(dirichlet: &DirichletParams, field: &str) -> Result<(), ValidationError> {
    if dirichlet.alpha.len() < 2 {
        return Err(ValidationError::DirichletTooFewElements {
            field: field.to_string(),
        });
    }
    if !dirichlet.alpha.iter().all(|&a| a > 0.0) {
        return Err(ValidationError::DirichletParamNonPositive {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Validate prior bounds.
fn validate_prior_bounds(lower: f64, upper: f64, class: &str) -> Result<(), ValidationError> {
    if !(0.0..=1.0).contains(&lower) || !(0.0..=1.0).contains(&upper) {
        return Err(ValidationError::PriorBoundsRange {
            class: class.to_string(),
        });
    }
    if lower > upper {
        return Err(ValidationError::PriorBoundsInverted {
            class: class.to_string(),
            lower,
            upper,
        });
    }
    Ok(())
}

/// Validate policy configuration semantically.
pub fn validate_policy(policy: &Policy) -> Result<(), ValidationError> {
    // Validate loss matrix
    validate_loss_row(&policy.loss_matrix.useful, "useful")?;
    validate_loss_row(&policy.loss_matrix.useful_bad, "useful_bad")?;
    validate_loss_row(&policy.loss_matrix.abandoned, "abandoned")?;
    validate_loss_row(&policy.loss_matrix.zombie, "zombie")?;

    // Validate FDR alpha
    if policy.fdr_control.alpha <= 0.0 || policy.fdr_control.alpha > 1.0 {
        return Err(ValidationError::FdrAlphaRange {
            value: policy.fdr_control.alpha,
        });
    }

    // Validate robot mode posterior
    if policy.robot_mode.min_posterior <= 0.0 || policy.robot_mode.min_posterior > 1.0 {
        return Err(ValidationError::RobotPosteriorRange {
            value: policy.robot_mode.min_posterior,
        });
    }

    validate_load_aware(&policy.load_aware)?;

    Ok(())
}

fn validate_load_aware(
    load_aware: &super::policy::LoadAwareDecision,
) -> Result<(), ValidationError> {
    if !load_aware.enabled {
        return Ok(());
    }

    let weight_sum =
        load_aware.weights.queue + load_aware.weights.load + load_aware.weights.memory + load_aware.weights.psi;
    if weight_sum <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.weights".to_string(),
            message: "weights must have positive sum".to_string(),
        });
    }

    if load_aware.weights.queue > 0.0 && load_aware.queue_high == 0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.queue_high".to_string(),
            message: "must be > 0 when queue weight is set".to_string(),
        });
    }

    if load_aware.weights.load > 0.0 && load_aware.load_per_core_high <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.load_per_core_high".to_string(),
            message: "must be > 0 when load weight is set".to_string(),
        });
    }

    if load_aware.weights.memory > 0.0
        && (load_aware.memory_used_fraction_high <= 0.0
            || load_aware.memory_used_fraction_high > 1.0)
    {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.memory_used_fraction_high".to_string(),
            message: "must be in (0, 1] when memory weight is set".to_string(),
        });
    }

    if load_aware.weights.psi > 0.0 && load_aware.psi_avg10_high <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.psi_avg10_high".to_string(),
            message: "must be > 0 when psi weight is set".to_string(),
        });
    }

    if load_aware.multipliers.keep_max < 1.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.multipliers.keep_max".to_string(),
            message: "must be >= 1.0".to_string(),
        });
    }
    if load_aware.multipliers.risky_max < 1.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.multipliers.risky_max".to_string(),
            message: "must be >= 1.0".to_string(),
        });
    }
    if load_aware.multipliers.reversible_min <= 0.0 || load_aware.multipliers.reversible_min > 1.0
    {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.multipliers.reversible_min".to_string(),
            message: "must be in (0, 1]".to_string(),
        });
    }

    Ok(())
}

/// Validate loss matrix row.
fn validate_loss_row(row: &super::policy::LossRow, class: &str) -> Result<(), ValidationError> {
    if row.keep < 0.0 {
        return Err(ValidationError::LossMatrixNegative {
            class: class.to_string(),
            action: "keep".to_string(),
            value: row.keep,
        });
    }
    if row.kill < 0.0 {
        return Err(ValidationError::LossMatrixNegative {
            class: class.to_string(),
            action: "kill".to_string(),
            value: row.kill,
        });
    }
    if let Some(pause) = row.pause {
        if pause < 0.0 {
            return Err(ValidationError::LossMatrixNegative {
                class: class.to_string(),
                action: "pause".to_string(),
                value: pause,
            });
        }
    }
    if let Some(throttle) = row.throttle {
        if throttle < 0.0 {
            return Err(ValidationError::LossMatrixNegative {
                class: class.to_string(),
                action: "throttle".to_string(),
                value: throttle,
            });
        }
    }
    if let Some(renice) = row.renice {
        if renice < 0.0 {
            return Err(ValidationError::LossMatrixNegative {
                class: class.to_string(),
                action: "renice".to_string(),
                value: renice,
            });
        }
    }
    if let Some(restart) = row.restart {
        if restart < 0.0 {
            return Err(ValidationError::LossMatrixNegative {
                class: class.to_string(),
                action: "restart".to_string(),
                value: restart,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_priors_valid() {
        let priors = Priors::default();
        assert!(validate_priors(&priors).is_ok());
    }

    #[test]
    fn test_default_policy_valid() {
        let policy = Policy::default();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_invalid_prior_sum() {
        let mut priors = Priors::default();
        priors.classes.useful.prior_prob = 0.9; // Sum will be > 1
        let result = validate_priors(&priors);
        assert!(matches!(
            result,
            Err(ValidationError::PriorProbabilitySum { .. })
        ));
    }

    #[test]
    fn test_invalid_beta_alpha() {
        let mut priors = Priors::default();
        priors.classes.useful.cpu_beta.alpha = -1.0;
        let result = validate_priors(&priors);
        assert!(matches!(
            result,
            Err(ValidationError::BetaParamNonPositive { .. })
        ));
    }

    #[test]
    fn test_invalid_fdr_alpha() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 1.5;
        let result = validate_policy(&policy);
        assert!(matches!(result, Err(ValidationError::FdrAlphaRange { .. })));
    }

    #[test]
    fn test_invalid_robot_posterior() {
        let mut policy = Policy::default();
        policy.robot_mode.min_posterior = 0.0;
        let result = validate_policy(&policy);
        assert!(matches!(
            result,
            Err(ValidationError::RobotPosteriorRange { .. })
        ));
    }
}
