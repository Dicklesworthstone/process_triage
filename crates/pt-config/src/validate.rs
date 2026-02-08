//! Configuration validation errors and semantic validation.

use thiserror::Error;

/// Validation result type.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Configuration validation errors.
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Schema validation failed: {0}")]
    SchemaError(String),

    #[error("Semantic validation failed: {0}")]
    SemanticError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },
}

impl ValidationError {
    /// Error code for structured error reporting.
    pub fn code(&self) -> u32 {
        match self {
            ValidationError::IoError(_) => 60,
            ValidationError::ParseError(_) => 61,
            ValidationError::SchemaError(_) => 62,
            ValidationError::SemanticError(_) => 63,
            ValidationError::MissingField(_) => 64,
            ValidationError::InvalidValue { .. } => 65,
            ValidationError::VersionMismatch { .. } => 66,
        }
    }
}

/// Validate priors configuration semantically.
pub fn validate_priors(priors: &crate::priors::Priors) -> ValidationResult<()> {
    // Check schema version
    if priors.schema_version != crate::CONFIG_SCHEMA_VERSION {
        return Err(ValidationError::VersionMismatch {
            expected: crate::CONFIG_SCHEMA_VERSION.to_string(),
            actual: priors.schema_version.clone(),
        });
    }

    // Check that class priors sum to 1.0 (within tolerance)
    let prior_sum = priors.classes.useful.prior_prob
        + priors.classes.useful_bad.prior_prob
        + priors.classes.abandoned.prior_prob
        + priors.classes.zombie.prior_prob;

    if (prior_sum - 1.0).abs() > 0.01 {
        return Err(ValidationError::SemanticError(format!(
            "Class priors must sum to 1.0, got {} (useful={}, useful_bad={}, abandoned={}, zombie={})",
            prior_sum,
            priors.classes.useful.prior_prob,
            priors.classes.useful_bad.prior_prob,
            priors.classes.abandoned.prior_prob,
            priors.classes.zombie.prior_prob,
        )));
    }

    // Validate each class
    validate_class_params("useful", &priors.classes.useful)?;
    validate_class_params("useful_bad", &priors.classes.useful_bad)?;
    validate_class_params("abandoned", &priors.classes.abandoned)?;
    validate_class_params("zombie", &priors.classes.zombie)?;

    // Validate Beta params in hazard regimes
    for regime in &priors.hazard_regimes {
        validate_gamma_params(
            &format!("hazard_regimes.{}.gamma", regime.name),
            &regime.gamma,
        )?;
    }

    Ok(())
}

/// Validate a single class's parameters.
fn validate_class_params(name: &str, params: &crate::priors::ClassParams) -> ValidationResult<()> {
    // Prior probability must be in [0, 1]
    if params.prior_prob < 0.0 || params.prior_prob > 1.0 {
        return Err(ValidationError::InvalidValue {
            field: format!("classes.{}.prior_prob", name),
            message: format!("Must be in [0, 1], got {}", params.prior_prob),
        });
    }

    // Validate Beta parameters
    validate_beta_params(&format!("classes.{}.cpu_beta", name), &params.cpu_beta)?;
    validate_beta_params(
        &format!("classes.{}.orphan_beta", name),
        &params.orphan_beta,
    )?;
    validate_beta_params(&format!("classes.{}.tty_beta", name), &params.tty_beta)?;
    validate_beta_params(&format!("classes.{}.net_beta", name), &params.net_beta)?;

    if let Some(ref beta) = params.io_active_beta {
        validate_beta_params(&format!("classes.{}.io_active_beta", name), beta)?;
    }

    // Validate Gamma parameters
    if let Some(ref gamma) = params.runtime_gamma {
        validate_gamma_params(&format!("classes.{}.runtime_gamma", name), gamma)?;
    }

    if let Some(ref gamma) = params.hazard_gamma {
        validate_gamma_params(&format!("classes.{}.hazard_gamma", name), gamma)?;
    }

    Ok(())
}

/// Validate Beta distribution parameters.
fn validate_beta_params(field: &str, params: &crate::priors::BetaParams) -> ValidationResult<()> {
    if params.alpha <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: format!("{}.alpha", field),
            message: format!("Must be positive, got {}", params.alpha),
        });
    }

    if params.beta <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: format!("{}.beta", field),
            message: format!("Must be positive, got {}", params.beta),
        });
    }

    Ok(())
}

/// Validate Gamma distribution parameters.
fn validate_gamma_params(field: &str, params: &crate::priors::GammaParams) -> ValidationResult<()> {
    if params.shape <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: format!("{}.shape", field),
            message: format!("Must be positive, got {}", params.shape),
        });
    }

    if params.rate <= 0.0 {
        return Err(ValidationError::InvalidValue {
            field: format!("{}.rate", field),
            message: format!("Must be positive, got {}", params.rate),
        });
    }

    Ok(())
}

/// Validate policy configuration semantically.
pub fn validate_policy(policy: &crate::policy::Policy) -> ValidationResult<()> {
    // Check schema version
    if policy.schema_version != crate::CONFIG_SCHEMA_VERSION {
        return Err(ValidationError::VersionMismatch {
            expected: crate::CONFIG_SCHEMA_VERSION.to_string(),
            actual: policy.schema_version.clone(),
        });
    }

    // Validate loss matrix completeness
    validate_loss_matrix(&policy.loss_matrix)?;

    // Validate FDR alpha is in valid range
    if policy.fdr_control.alpha < 0.0 || policy.fdr_control.alpha > 1.0 {
        return Err(ValidationError::InvalidValue {
            field: "fdr_control.alpha".to_string(),
            message: format!("Must be in [0, 1], got {}", policy.fdr_control.alpha),
        });
    }

    // Validate robot mode settings
    if policy.robot_mode.min_posterior < 0.0 || policy.robot_mode.min_posterior > 1.0 {
        return Err(ValidationError::InvalidValue {
            field: "robot_mode.min_posterior".to_string(),
            message: format!("Must be in [0, 1], got {}", policy.robot_mode.min_posterior),
        });
    }

    // Validate guardrails
    if policy.guardrails.never_kill_ppid.is_empty() {
        return Err(ValidationError::SemanticError(
            "guardrails.never_kill_ppid must contain at least PID 1".to_string(),
        ));
    }

    if !policy.guardrails.never_kill_ppid.contains(&1) {
        return Err(ValidationError::SemanticError(
            "guardrails.never_kill_ppid must contain PID 1 (init)".to_string(),
        ));
    }

    validate_load_aware(&policy.load_aware)?;

    Ok(())
}

fn validate_load_aware(load_aware: &crate::policy::LoadAwareDecision) -> ValidationResult<()> {
    if !load_aware.enabled {
        return Ok(());
    }

    let weight_sum = load_aware.weights.queue
        + load_aware.weights.load
        + load_aware.weights.memory
        + load_aware.weights.psi;
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
    if load_aware.multipliers.reversible_min <= 0.0 || load_aware.multipliers.reversible_min > 1.0 {
        return Err(ValidationError::InvalidValue {
            field: "load_aware.multipliers.reversible_min".to_string(),
            message: "must be in (0, 1]".to_string(),
        });
    }

    Ok(())
}

/// Validate loss matrix has all required values.
fn validate_loss_matrix(matrix: &crate::policy::LossMatrix) -> ValidationResult<()> {
    // All losses must be non-negative
    let classes = [
        ("useful", &matrix.useful),
        ("useful_bad", &matrix.useful_bad),
        ("abandoned", &matrix.abandoned),
        ("zombie", &matrix.zombie),
    ];

    for (name, row) in classes {
        if row.keep < 0.0 {
            return Err(ValidationError::InvalidValue {
                field: format!("loss_matrix.{}.keep", name),
                message: "Must be non-negative".to_string(),
            });
        }
        if row.kill < 0.0 {
            return Err(ValidationError::InvalidValue {
                field: format!("loss_matrix.{}.kill", name),
                message: "Must be non-negative".to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beta_validation() {
        let valid = crate::priors::BetaParams {
            alpha: 2.0,
            beta: 5.0,
            comment: None,
        };
        assert!(validate_beta_params("test", &valid).is_ok());

        let invalid = crate::priors::BetaParams {
            alpha: -1.0,
            beta: 5.0,
            comment: None,
        };
        assert!(validate_beta_params("test", &invalid).is_err());
    }

    #[test]
    fn test_gamma_validation() {
        let valid = crate::priors::GammaParams {
            shape: 2.0,
            rate: 0.001,
            comment: None,
        };
        assert!(validate_gamma_params("test", &valid).is_ok());

        let invalid = crate::priors::GammaParams {
            shape: 0.0,
            rate: 0.001,
            comment: None,
        };
        assert!(validate_gamma_params("test", &invalid).is_err());
    }

    // ── validate_beta_params ────────────────────────────────────

    #[test]
    fn beta_zero_beta_param() {
        let b = crate::priors::BetaParams {
            alpha: 1.0,
            beta: 0.0,
            comment: None,
        };
        let err = validate_beta_params("f", &b).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("beta"))
        );
    }

    #[test]
    fn beta_negative_alpha() {
        let b = crate::priors::BetaParams {
            alpha: -0.5,
            beta: 1.0,
            comment: None,
        };
        let err = validate_beta_params("f", &b).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("alpha"))
        );
    }

    #[test]
    fn beta_both_negative() {
        let b = crate::priors::BetaParams {
            alpha: -1.0,
            beta: -1.0,
            comment: None,
        };
        // alpha checked first
        let err = validate_beta_params("f", &b).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("alpha"))
        );
    }

    // ── validate_gamma_params ───────────────────────────────────

    #[test]
    fn gamma_negative_rate() {
        let g = crate::priors::GammaParams {
            shape: 1.0,
            rate: -1.0,
            comment: None,
        };
        let err = validate_gamma_params("f", &g).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("rate"))
        );
    }

    #[test]
    fn gamma_negative_shape() {
        let g = crate::priors::GammaParams {
            shape: -1.0,
            rate: 1.0,
            comment: None,
        };
        let err = validate_gamma_params("f", &g).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("shape"))
        );
    }

    // ── ValidationError ─────────────────────────────────────────

    #[test]
    fn error_code_io() {
        assert_eq!(ValidationError::IoError("x".into()).code(), 60);
    }

    #[test]
    fn error_code_parse() {
        assert_eq!(ValidationError::ParseError("x".into()).code(), 61);
    }

    #[test]
    fn error_code_schema() {
        assert_eq!(ValidationError::SchemaError("x".into()).code(), 62);
    }

    #[test]
    fn error_code_semantic() {
        assert_eq!(ValidationError::SemanticError("x".into()).code(), 63);
    }

    #[test]
    fn error_code_missing_field() {
        assert_eq!(ValidationError::MissingField("x".into()).code(), 64);
    }

    #[test]
    fn error_code_invalid_value() {
        let e = ValidationError::InvalidValue {
            field: "f".into(),
            message: "m".into(),
        };
        assert_eq!(e.code(), 65);
    }

    #[test]
    fn error_code_version_mismatch() {
        let e = ValidationError::VersionMismatch {
            expected: "1".into(),
            actual: "2".into(),
        };
        assert_eq!(e.code(), 66);
    }

    #[test]
    fn error_display_io() {
        let e = ValidationError::IoError("disk full".into());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn error_display_parse() {
        let e = ValidationError::ParseError("bad json".into());
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn error_display_version_mismatch() {
        let e = ValidationError::VersionMismatch {
            expected: "1.0".into(),
            actual: "2.0".into(),
        };
        let s = e.to_string();
        assert!(s.contains("1.0"));
        assert!(s.contains("2.0"));
    }

    // ── validate_priors ─────────────────────────────────────────

    #[test]
    fn default_priors_pass() {
        let priors = crate::priors::Priors::default();
        assert!(validate_priors(&priors).is_ok());
    }

    #[test]
    fn priors_bad_sum() {
        let mut priors = crate::priors::Priors::default();
        priors.classes.useful.prior_prob = 0.9;
        let err = validate_priors(&priors).unwrap_err();
        assert!(matches!(err, ValidationError::SemanticError(ref s) if s.contains("sum")));
    }

    #[test]
    fn priors_negative_prior_prob() {
        let mut priors = crate::priors::Priors::default();
        let orig = priors.classes.zombie.prior_prob;
        priors.classes.zombie.prior_prob = -0.01;
        // compensate sum: add back orig and the negative value
        priors.classes.useful.prior_prob += orig + 0.01;
        let err = validate_priors(&priors).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("zombie"))
        );
    }

    #[test]
    fn priors_bad_cpu_beta() {
        let mut priors = crate::priors::Priors::default();
        priors.classes.useful.cpu_beta.alpha = 0.0;
        let err = validate_priors(&priors).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("cpu_beta"))
        );
    }

    #[test]
    fn priors_bad_orphan_beta() {
        let mut priors = crate::priors::Priors::default();
        priors.classes.abandoned.orphan_beta.beta = -1.0;
        let err = validate_priors(&priors).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("orphan_beta"))
        );
    }

    #[test]
    fn priors_bad_tty_beta() {
        let mut priors = crate::priors::Priors::default();
        priors.classes.useful_bad.tty_beta.alpha = 0.0;
        let err = validate_priors(&priors).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("tty_beta"))
        );
    }

    #[test]
    fn priors_bad_net_beta() {
        let mut priors = crate::priors::Priors::default();
        priors.classes.zombie.net_beta.beta = -1.0;
        let err = validate_priors(&priors).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("net_beta"))
        );
    }

    #[test]
    fn priors_wrong_schema_version() {
        let mut priors = crate::priors::Priors::default();
        priors.schema_version = "0.0.0".into();
        let err = validate_priors(&priors).unwrap_err();
        assert!(matches!(err, ValidationError::VersionMismatch { .. }));
    }

    // ── validate_policy ─────────────────────────────────────────

    #[test]
    fn default_policy_pass() {
        let policy = crate::policy::Policy::default();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn policy_bad_fdr_alpha() {
        let mut policy = crate::policy::Policy::default();
        policy.fdr_control.alpha = -0.1;
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("fdr_control"))
        );
    }

    #[test]
    fn policy_fdr_alpha_above_one() {
        let mut policy = crate::policy::Policy::default();
        policy.fdr_control.alpha = 1.5;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_bad_robot_posterior() {
        let mut policy = crate::policy::Policy::default();
        policy.robot_mode.min_posterior = -0.1;
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            matches!(err, ValidationError::InvalidValue { ref field, .. } if field.contains("robot_mode"))
        );
    }

    #[test]
    fn policy_robot_posterior_above_one() {
        let mut policy = crate::policy::Policy::default();
        policy.robot_mode.min_posterior = 1.5;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_guardrails_empty() {
        let mut policy = crate::policy::Policy::default();
        policy.guardrails.never_kill_ppid = vec![];
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_guardrails_missing_pid1() {
        let mut policy = crate::policy::Policy::default();
        policy.guardrails.never_kill_ppid = vec![2, 3];
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_wrong_schema_version() {
        let mut policy = crate::policy::Policy::default();
        policy.schema_version = "0.0.0".into();
        let err = validate_policy(&policy).unwrap_err();
        assert!(matches!(err, ValidationError::VersionMismatch { .. }));
    }

    #[test]
    fn policy_negative_loss_keep() {
        let mut policy = crate::policy::Policy::default();
        policy.loss_matrix.useful.keep = -1.0;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_negative_loss_kill() {
        let mut policy = crate::policy::Policy::default();
        policy.loss_matrix.zombie.kill = -1.0;
        assert!(validate_policy(&policy).is_err());
    }

    // ── validate_load_aware ─────────────────────────────────────

    #[test]
    fn load_aware_disabled_always_ok() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = false;
        policy.load_aware.weights.queue = 0.0;
        policy.load_aware.weights.load = 0.0;
        policy.load_aware.weights.memory = 0.0;
        policy.load_aware.weights.psi = 0.0;
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn load_aware_enabled_defaults_valid() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn load_aware_zero_weight_sum() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.weights.queue = 0.0;
        policy.load_aware.weights.load = 0.0;
        policy.load_aware.weights.memory = 0.0;
        policy.load_aware.weights.psi = 0.0;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn load_aware_queue_high_zero() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.queue_high = 0;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn load_aware_keep_max_below_one() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.multipliers.keep_max = 0.5;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn load_aware_risky_max_below_one() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.multipliers.risky_max = 0.5;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn load_aware_reversible_min_zero() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.multipliers.reversible_min = 0.0;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn load_aware_reversible_min_above_one() {
        let mut policy = crate::policy::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.multipliers.reversible_min = 1.5;
        assert!(validate_policy(&policy).is_err());
    }
}
