//! Decision policy configuration types for Process Triage.
//!
//! These types correspond to policy.schema.json and define:
//! - Loss matrix for decision theory
//! - Safety guardrails and protected patterns
//! - Robot mode gates for automated operation
//! - FDR control parameters

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Schema version for policy configuration.
pub const POLICY_SCHEMA_VERSION: &str = "1.0.0";

/// Root configuration for decision policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version for compatibility checking
    pub schema_version: String,

    /// Optional identifier for this policy snapshot
    #[serde(default)]
    pub policy_id: Option<String>,

    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,

    /// Loss matrix for decision theory
    pub loss_matrix: LossMatrix,

    /// Safety guardrails and protected patterns
    pub guardrails: Guardrails,

    /// Robot mode gates
    pub robot_mode: RobotMode,

    /// Signature-informed fast-path controls for inference
    #[serde(default)]
    pub signature_fast_path: SignatureFastPath,

    /// False discovery rate control
    pub fdr_control: FdrControl,

    /// Data-loss prevention gates
    pub data_loss_gates: DataLossGates,
    /// Load-aware decision tuning
    #[serde(default)]
    pub load_aware: LoadAwareDecision,

    /// Policy inheritance chain
    #[serde(default)]
    pub inherits: Vec<String>,

    /// Freeform notes
    #[serde(default)]
    pub notes: Option<String>,
}

impl Policy {
    /// Validate policy semantically.
    pub fn validate(&self) -> Result<()> {
        // Check schema version
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(Error::InvalidPolicy(format!(
                "schema version mismatch: expected {}, got {}",
                POLICY_SCHEMA_VERSION, self.schema_version
            )));
        }

        // Validate loss matrix is complete and finite
        self.loss_matrix.validate()?;

        // Validate guardrails
        self.guardrails.validate()?;

        // Validate robot mode
        self.robot_mode.validate()?;

        // Validate signature fast-path controls
        self.signature_fast_path.validate()?;

        // Validate FDR control
        self.fdr_control.validate()?;

        // Validate load-aware decision tuning
        self.load_aware.validate()?;

        Ok(())
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            policy_id: Some("default-conservative".to_string()),
            description: Some("Conservative default policy for Process Triage".to_string()),
            loss_matrix: LossMatrix::default(),
            guardrails: Guardrails::default(),
            robot_mode: RobotMode::default(),
            signature_fast_path: SignatureFastPath::default(),
            fdr_control: FdrControl::default(),
            data_loss_gates: DataLossGates::default(),
            load_aware: LoadAwareDecision::default(),
            inherits: vec![],
            notes: None,
        }
    }
}

/// Signature-informed inference fast-path controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFastPath {
    /// Whether high-confidence signature matches may bypass full inference.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum signature match score required for fast-path.
    #[serde(default = "default_fast_path_threshold")]
    pub min_confidence_threshold: f64,

    /// Require explicit signature priors for fast-path eligibility.
    #[serde(default = "default_true")]
    pub require_explicit_priors: bool,
}

fn default_fast_path_threshold() -> f64 {
    0.9
}

impl SignatureFastPath {
    /// Validate signature fast-path settings.
    pub fn validate(&self) -> Result<()> {
        if !(0.0..=1.0).contains(&self.min_confidence_threshold) {
            return Err(Error::InvalidPolicy(format!(
                "signature_fast_path.min_confidence_threshold must be in [0, 1] (got {})",
                self.min_confidence_threshold
            )));
        }
        Ok(())
    }
}

impl Default for SignatureFastPath {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_threshold: default_fast_path_threshold(),
            require_explicit_priors: true,
        }
    }
}

/// Loss matrix for all actions across all classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossMatrix {
    pub useful: LossRow,
    pub useful_bad: LossRow,
    pub abandoned: LossRow,
    pub zombie: LossRow,
}

impl LossMatrix {
    /// Validate that loss matrix is complete and all values are finite.
    pub fn validate(&self) -> Result<()> {
        self.useful.validate("loss_matrix.useful")?;
        self.useful_bad.validate("loss_matrix.useful_bad")?;
        self.abandoned.validate("loss_matrix.abandoned")?;
        self.zombie.validate("loss_matrix.zombie")?;
        Ok(())
    }
}

impl Default for LossMatrix {
    fn default() -> Self {
        LossMatrix {
            useful: LossRow {
                keep: 0.0,
                pause: Some(5.0),
                throttle: Some(8.0),
                kill: 100.0,
                restart: Some(60.0),
            },
            useful_bad: LossRow {
                keep: 10.0,
                pause: Some(6.0),
                throttle: Some(8.0),
                kill: 20.0,
                restart: Some(12.0),
            },
            abandoned: LossRow {
                keep: 30.0,
                pause: Some(15.0),
                throttle: Some(10.0),
                kill: 1.0,
                restart: Some(8.0),
            },
            zombie: LossRow {
                keep: 50.0,
                pause: Some(20.0),
                throttle: Some(15.0),
                kill: 1.0,
                restart: Some(5.0),
            },
        }
    }
}

/// Loss values for a single class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossRow {
    pub keep: f64,
    #[serde(default)]
    pub pause: Option<f64>,
    #[serde(default)]
    pub throttle: Option<f64>,
    pub kill: f64,
    #[serde(default)]
    pub restart: Option<f64>,
}

impl LossRow {
    /// Validate that all loss values are non-negative and finite.
    pub fn validate(&self, path: &str) -> Result<()> {
        if !self.keep.is_finite() || self.keep < 0.0 {
            return Err(Error::InvalidPolicy(format!(
                "{}.keep must be non-negative and finite (got {})",
                path, self.keep
            )));
        }
        if !self.kill.is_finite() || self.kill < 0.0 {
            return Err(Error::InvalidPolicy(format!(
                "{}.kill must be non-negative and finite (got {})",
                path, self.kill
            )));
        }
        if let Some(pause) = self.pause {
            if !pause.is_finite() || pause < 0.0 {
                return Err(Error::InvalidPolicy(format!(
                    "{}.pause must be non-negative and finite (got {})",
                    path, pause
                )));
            }
        }
        if let Some(throttle) = self.throttle {
            if !throttle.is_finite() || throttle < 0.0 {
                return Err(Error::InvalidPolicy(format!(
                    "{}.throttle must be non-negative and finite (got {})",
                    path, throttle
                )));
            }
        }
        if let Some(restart) = self.restart {
            if !restart.is_finite() || restart < 0.0 {
                return Err(Error::InvalidPolicy(format!(
                    "{}.restart must be non-negative and finite (got {})",
                    path, restart
                )));
            }
        }
        Ok(())
    }
}

impl LoadAwareDecision {
    /// Validate load-aware configuration.
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let weight_sum =
            self.weights.queue + self.weights.load + self.weights.memory + self.weights.psi;
        if weight_sum <= 0.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.weights must have positive sum".to_string(),
            ));
        }

        if self.weights.queue > 0.0 && self.queue_high == 0 {
            return Err(Error::InvalidPolicy(
                "load_aware.queue_high must be > 0 when queue weight is set".to_string(),
            ));
        }

        if self.weights.load > 0.0 && self.load_per_core_high <= 0.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.load_per_core_high must be > 0 when load weight is set".to_string(),
            ));
        }

        if self.weights.memory > 0.0
            && (self.memory_used_fraction_high <= 0.0 || self.memory_used_fraction_high > 1.0)
        {
            return Err(Error::InvalidPolicy(
                "load_aware.memory_used_fraction_high must be in (0, 1] when memory weight is set"
                    .to_string(),
            ));
        }

        if self.weights.psi > 0.0 && self.psi_avg10_high <= 0.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.psi_avg10_high must be > 0 when psi weight is set".to_string(),
            ));
        }

        if self.multipliers.keep_max < 1.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.multipliers.keep_max must be >= 1.0".to_string(),
            ));
        }
        if self.multipliers.risky_max < 1.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.multipliers.risky_max must be >= 1.0".to_string(),
            ));
        }
        if self.multipliers.reversible_min <= 0.0 || self.multipliers.reversible_min > 1.0 {
            return Err(Error::InvalidPolicy(
                "load_aware.multipliers.reversible_min must be in (0, 1]".to_string(),
            ));
        }

        Ok(())
    }
}

/// Safety guardrails and protected patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardrails {
    /// Patterns that are always protected from killing
    pub protected_patterns: Vec<PatternEntry>,

    /// Patterns that force manual review
    #[serde(default)]
    pub force_review_patterns: Vec<PatternEntry>,

    /// Protected user names
    #[serde(default)]
    pub protected_users: Vec<String>,

    /// Protected group names
    #[serde(default)]
    pub protected_groups: Vec<String>,

    /// Protected process categories
    #[serde(default)]
    pub protected_categories: Vec<String>,

    /// PPIDs that should never be killed (e.g., [1] for init)
    pub never_kill_ppid: Vec<i32>,

    /// PIDs that should never be killed
    #[serde(default)]
    pub never_kill_pid: Vec<i32>,

    /// Maximum kills allowed per run
    pub max_kills_per_run: u32,

    /// Maximum kills per hour
    #[serde(default)]
    pub max_kills_per_hour: Option<u32>,

    /// Maximum kills per day
    #[serde(default)]
    pub max_kills_per_day: Option<u32>,

    /// Minimum process age in seconds
    pub min_process_age_seconds: u64,

    /// Whether to require confirmation before killing
    #[serde(default = "default_true")]
    pub require_confirmation: bool,
}

fn default_true() -> bool {
    true
}

impl Guardrails {
    /// Validate guardrails.
    pub fn validate(&self) -> Result<()> {
        // Protected patterns should be valid
        for (i, pattern) in self.protected_patterns.iter().enumerate() {
            pattern.validate(&format!("guardrails.protected_patterns[{}]", i))?;
        }
        for (i, pattern) in self.force_review_patterns.iter().enumerate() {
            pattern.validate(&format!("guardrails.force_review_patterns[{}]", i))?;
        }
        Ok(())
    }
}

impl Default for Guardrails {
    fn default() -> Self {
        Guardrails {
            protected_patterns: vec![
                PatternEntry {
                    pattern: r"\b(systemd|journald|logind|dbus-daemon)\b".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("core system services".to_string()),
                },
                PatternEntry {
                    pattern: r"\b(sshd|cron|crond)\b".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("remote access and schedulers".to_string()),
                },
                PatternEntry {
                    pattern: r"\b(dockerd|containerd)\b".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("containers".to_string()),
                },
                PatternEntry {
                    pattern: r"\b(postgres|redis|nginx|elasticsearch)\b".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("databases and proxies".to_string()),
                },
            ],
            force_review_patterns: vec![PatternEntry {
                pattern: r"\b(kube|k8s|etcd)\b".to_string(),
                kind: PatternKind::Regex,
                case_insensitive: true,
                notes: Some("cluster components".to_string()),
            }],
            protected_users: vec!["root".to_string()],
            protected_groups: vec![],
            protected_categories: vec!["daemon".to_string(), "system".to_string()],
            never_kill_ppid: vec![1],
            never_kill_pid: vec![1],
            max_kills_per_run: 5,
            max_kills_per_hour: Some(20),
            max_kills_per_day: Some(100),
            min_process_age_seconds: 3600,
            require_confirmation: true,
        }
    }
}

/// A pattern entry for matching process commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    pub pattern: String,
    #[serde(default)]
    pub kind: PatternKind,
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
    #[serde(default)]
    pub notes: Option<String>,
}

impl PatternEntry {
    /// Validate the pattern entry.
    pub fn validate(&self, path: &str) -> Result<()> {
        if self.pattern.is_empty() {
            return Err(Error::InvalidPolicy(format!(
                "{}.pattern must not be empty",
                path
            )));
        }
        // Try to compile regex patterns
        if self.kind == PatternKind::Regex {
            let _ = regex::Regex::new(&self.pattern).map_err(|e| {
                Error::InvalidPolicy(format!("{}.pattern is invalid regex: {}", path, e))
            })?;
        }
        Ok(())
    }
}

/// Type of pattern matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    #[default]
    Regex,
    Glob,
    Literal,
}

/// Robot mode gates for automated operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotMode {
    /// Whether robot mode is enabled
    pub enabled: bool,

    /// Minimum posterior probability required
    pub min_posterior: f64,

    /// Minimum confidence level
    #[serde(default)]
    pub min_confidence: Option<ConfidenceLevel>,

    /// Maximum blast radius in MB
    pub max_blast_radius_mb: f64,

    /// Maximum kills allowed in robot mode
    pub max_kills: u32,

    /// Whether to require known signature match
    pub require_known_signature: bool,

    /// Whether to require policy snapshot
    #[serde(default)]
    pub require_policy_snapshot: Option<bool>,

    /// Allowed categories in robot mode
    #[serde(default)]
    pub allow_categories: Vec<String>,

    /// Excluded categories in robot mode
    #[serde(default)]
    pub exclude_categories: Vec<String>,
}

impl RobotMode {
    /// Validate robot mode settings.
    pub fn validate(&self) -> Result<()> {
        if !(0.0..=1.0).contains(&self.min_posterior) {
            return Err(Error::InvalidPolicy(format!(
                "robot_mode.min_posterior must be in [0, 1] (got {})",
                self.min_posterior
            )));
        }
        if self.max_blast_radius_mb < 0.0 {
            return Err(Error::InvalidPolicy(format!(
                "robot_mode.max_blast_radius_mb must be non-negative (got {})",
                self.max_blast_radius_mb
            )));
        }
        Ok(())
    }
}

impl Default for RobotMode {
    fn default() -> Self {
        RobotMode {
            enabled: false,
            min_posterior: 0.99,
            min_confidence: Some(ConfidenceLevel::High),
            max_blast_radius_mb: 4096.0,
            max_kills: 5,
            require_known_signature: false,
            require_policy_snapshot: Some(true),
            allow_categories: vec![],
            exclude_categories: vec!["daemon".to_string(), "system".to_string()],
        }
    }
}

/// Confidence level for decision making.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// FDR control settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdrControl {
    /// Whether FDR control is enabled
    pub enabled: bool,

    /// FDR control method
    pub method: FdrMethod,

    /// Target FDR level
    pub alpha: f64,

    /// Minimum candidates for FDR control
    #[serde(default)]
    pub min_candidates: Option<u32>,

    /// Null hypothesis classes for local FDR
    #[serde(default)]
    pub lfdr_null: Vec<String>,

    /// Alpha investing parameters
    #[serde(default)]
    pub alpha_investing: Option<AlphaInvesting>,
}

impl FdrControl {
    /// Validate FDR control settings.
    pub fn validate(&self) -> Result<()> {
        if !(0.0..=1.0).contains(&self.alpha) {
            return Err(Error::InvalidPolicy(format!(
                "fdr_control.alpha must be in [0, 1] (got {})",
                self.alpha
            )));
        }
        Ok(())
    }
}

impl Default for FdrControl {
    fn default() -> Self {
        FdrControl {
            enabled: true,
            method: FdrMethod::Bh,
            alpha: 0.05,
            min_candidates: Some(3),
            lfdr_null: vec!["useful".to_string()],
            alpha_investing: Some(AlphaInvesting::default()),
        }
    }
}

/// FDR control method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FdrMethod {
    /// Benjamini-Hochberg
    Bh,
    /// Benjamini-Yekutieli
    By,
    /// Alpha investing (online)
    #[serde(rename = "alpha_investing")]
    AlphaInvesting,
    /// No FDR control
    None,
}

/// Alpha investing parameters for online FDR control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlphaInvesting {
    /// Initial wealth
    pub w0: f64,
    /// Alpha to spend per test
    pub alpha_spend: f64,
    /// Alpha to earn per rejection
    pub alpha_earn: f64,
}

impl Default for AlphaInvesting {
    fn default() -> Self {
        AlphaInvesting {
            w0: 0.05,
            alpha_spend: 0.02,
            alpha_earn: 0.01,
        }
    }
}

/// Data-loss prevention gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLossGates {
    /// Block if process has open write file descriptors
    pub block_if_open_write_fds: bool,

    /// Maximum open write FDs allowed
    #[serde(default)]
    pub max_open_write_fds: Option<u32>,

    /// Block if process has locked files
    pub block_if_locked_files: bool,

    /// Block if process has deleted CWD
    #[serde(default)]
    pub block_if_deleted_cwd: Option<bool>,

    /// Block if process has active TTY
    pub block_if_active_tty: bool,

    /// Block if recent I/O (seconds)
    #[serde(default)]
    pub block_if_recent_io_seconds: Option<u32>,
}

impl Default for DataLossGates {
    fn default() -> Self {
        DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: Some(0),
            block_if_locked_files: true,
            block_if_deleted_cwd: Some(true),
            block_if_active_tty: true,
            block_if_recent_io_seconds: Some(60),
        }
    }
}

/// Load-aware decision configuration for adaptive thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAwareDecision {
    /// Whether load-aware adjustments are enabled.
    pub enabled: bool,
    /// Candidate queue length considered "high load".
    #[serde(default = "default_queue_high")]
    pub queue_high: u32,
    /// Load average per core considered "high load".
    #[serde(default = "default_load_per_core_high")]
    pub load_per_core_high: f64,
    /// Memory used fraction considered "high load".
    #[serde(default = "default_memory_used_fraction_high")]
    pub memory_used_fraction_high: f64,
    /// PSI avg10 threshold considered "high load".
    #[serde(default = "default_psi_avg10_high")]
    pub psi_avg10_high: f64,
    /// Weights for combining load signals.
    #[serde(default)]
    pub weights: LoadWeights,
    /// Loss multipliers applied under load.
    #[serde(default)]
    pub multipliers: LoadMultipliers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadWeights {
    pub queue: f64,
    pub load: f64,
    pub memory: f64,
    pub psi: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadMultipliers {
    /// Maximum multiplier applied to keep losses at high load.
    pub keep_max: f64,
    /// Minimum multiplier applied to reversible actions at high load.
    pub reversible_min: f64,
    /// Maximum multiplier applied to risky actions (kill/restart) at high load.
    pub risky_max: f64,
}

fn default_queue_high() -> u32 {
    50
}

fn default_load_per_core_high() -> f64 {
    1.0
}

fn default_memory_used_fraction_high() -> f64 {
    0.85
}

fn default_psi_avg10_high() -> f64 {
    20.0
}

impl Default for LoadWeights {
    fn default() -> Self {
        Self {
            queue: 0.25,
            load: 0.35,
            memory: 0.25,
            psi: 0.15,
        }
    }
}

impl Default for LoadMultipliers {
    fn default() -> Self {
        Self {
            keep_max: 1.4,
            reversible_min: 0.6,
            risky_max: 1.8,
        }
    }
}

impl Default for LoadAwareDecision {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_high: default_queue_high(),
            load_per_core_high: default_load_per_core_high(),
            memory_used_fraction_high: default_memory_used_fraction_high(),
            psi_avg10_high: default_psi_avg10_high(),
            weights: LoadWeights::default(),
            multipliers: LoadMultipliers::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_valid() {
        let policy = Policy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_loss_row_validation() {
        let valid = LossRow {
            keep: 0.0,
            pause: Some(5.0),
            throttle: Some(8.0),
            kill: 100.0,
            restart: Some(60.0),
        };
        assert!(valid.validate("test").is_ok());

        let invalid = LossRow {
            keep: -1.0,
            pause: None,
            throttle: None,
            kill: 100.0,
            restart: None,
        };
        assert!(invalid.validate("test").is_err());
    }

    #[test]
    fn test_robot_mode_validation() {
        let valid = RobotMode::default();
        assert!(valid.validate().is_ok());

        let invalid = RobotMode {
            min_posterior: 1.5,
            ..RobotMode::default()
        };
        assert!(invalid.validate().is_err());
    }

    // ── Policy ─────────────────────────────────────────────────────

    #[test]
    fn policy_default_schema_version() {
        let p = Policy::default();
        assert_eq!(p.schema_version, POLICY_SCHEMA_VERSION);
    }

    #[test]
    fn policy_default_policy_id() {
        let p = Policy::default();
        assert_eq!(p.policy_id.as_deref(), Some("default-conservative"));
    }

    #[test]
    fn policy_validate_wrong_schema() {
        let mut p = Policy::default();
        p.schema_version = "2.0.0".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = Policy::default();
        let json = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, POLICY_SCHEMA_VERSION);
        assert!(back.validate().is_ok());
    }

    // ── LossRow validation ─────────────────────────────────────────

    #[test]
    fn loss_row_kill_negative() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: None,
            kill: -1.0,
            restart: None,
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_kill_nan() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: None,
            kill: f64::NAN,
            restart: None,
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_kill_inf() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: None,
            kill: f64::INFINITY,
            restart: None,
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_pause_negative() {
        let lr = LossRow {
            keep: 0.0,
            pause: Some(-0.1),
            throttle: None,
            kill: 1.0,
            restart: None,
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_throttle_nan() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: Some(f64::NAN),
            kill: 1.0,
            restart: None,
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_restart_negative() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: None,
            kill: 1.0,
            restart: Some(-5.0),
        };
        assert!(lr.validate("test").is_err());
    }

    #[test]
    fn loss_row_none_optionals_valid() {
        let lr = LossRow {
            keep: 0.0,
            pause: None,
            throttle: None,
            kill: 0.0,
            restart: None,
        };
        assert!(lr.validate("test").is_ok());
    }

    // ── LossMatrix ─────────────────────────────────────────────────

    #[test]
    fn loss_matrix_default_valid() {
        let lm = LossMatrix::default();
        assert!(lm.validate().is_ok());
    }

    #[test]
    fn loss_matrix_invalid_useful() {
        let mut lm = LossMatrix::default();
        lm.useful.keep = -1.0;
        assert!(lm.validate().is_err());
    }

    #[test]
    fn loss_matrix_invalid_zombie() {
        let mut lm = LossMatrix::default();
        lm.zombie.kill = f64::NAN;
        assert!(lm.validate().is_err());
    }

    // ── Guardrails ─────────────────────────────────────────────────

    #[test]
    fn guardrails_default_valid() {
        let g = Guardrails::default();
        assert!(g.validate().is_ok());
    }

    #[test]
    fn guardrails_default_protected_count() {
        let g = Guardrails::default();
        assert_eq!(g.protected_patterns.len(), 4);
    }

    #[test]
    fn guardrails_default_force_review() {
        let g = Guardrails::default();
        assert_eq!(g.force_review_patterns.len(), 1);
    }

    #[test]
    fn guardrails_default_never_kill_ppid() {
        let g = Guardrails::default();
        assert_eq!(g.never_kill_ppid, vec![1]);
    }

    #[test]
    fn guardrails_default_confirmation() {
        let g = Guardrails::default();
        assert!(g.require_confirmation);
    }

    #[test]
    fn guardrails_empty_pattern_error() {
        let g = Guardrails {
            protected_patterns: vec![PatternEntry {
                pattern: "".to_string(),
                kind: PatternKind::Regex,
                case_insensitive: true,
                notes: None,
            }],
            ..Guardrails::default()
        };
        assert!(g.validate().is_err());
    }

    #[test]
    fn guardrails_invalid_regex_error() {
        let g = Guardrails {
            protected_patterns: vec![PatternEntry {
                pattern: "[invalid(regex".to_string(),
                kind: PatternKind::Regex,
                case_insensitive: true,
                notes: None,
            }],
            force_review_patterns: Vec::new(),
            ..Guardrails::default()
        };
        assert!(g.validate().is_err());
    }

    // ── PatternEntry ───────────────────────────────────────────────

    #[test]
    fn pattern_entry_valid_regex() {
        let pe = PatternEntry {
            pattern: r"\btest\b".to_string(),
            kind: PatternKind::Regex,
            case_insensitive: true,
            notes: None,
        };
        assert!(pe.validate("test").is_ok());
    }

    #[test]
    fn pattern_entry_valid_glob() {
        let pe = PatternEntry {
            pattern: "*.py".to_string(),
            kind: PatternKind::Glob,
            case_insensitive: false,
            notes: None,
        };
        assert!(pe.validate("test").is_ok());
    }

    #[test]
    fn pattern_entry_valid_literal() {
        let pe = PatternEntry {
            pattern: "sshd".to_string(),
            kind: PatternKind::Literal,
            case_insensitive: true,
            notes: None,
        };
        assert!(pe.validate("test").is_ok());
    }

    #[test]
    fn pattern_entry_empty_error() {
        let pe = PatternEntry {
            pattern: "".to_string(),
            kind: PatternKind::Literal,
            case_insensitive: true,
            notes: None,
        };
        assert!(pe.validate("test").is_err());
    }

    // ── PatternKind ────────────────────────────────────────────────

    #[test]
    fn pattern_kind_default_regex() {
        assert_eq!(PatternKind::default(), PatternKind::Regex);
    }

    #[test]
    fn pattern_kind_serde() {
        for kind in &[PatternKind::Regex, PatternKind::Glob, PatternKind::Literal] {
            let json = serde_json::to_string(kind).unwrap();
            let back: PatternKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // ── RobotMode ──────────────────────────────────────────────────

    #[test]
    fn robot_mode_default_disabled() {
        let rm = RobotMode::default();
        assert!(!rm.enabled);
    }

    #[test]
    fn robot_mode_default_min_posterior() {
        let rm = RobotMode::default();
        assert!((rm.min_posterior - 0.99).abs() < f64::EPSILON);
    }

    #[test]
    fn robot_mode_negative_posterior_error() {
        let rm = RobotMode {
            min_posterior: -0.1,
            ..RobotMode::default()
        };
        assert!(rm.validate().is_err());
    }

    #[test]
    fn robot_mode_negative_blast_radius_error() {
        let rm = RobotMode {
            max_blast_radius_mb: -1.0,
            ..RobotMode::default()
        };
        assert!(rm.validate().is_err());
    }

    #[test]
    fn robot_mode_zero_posterior_ok() {
        let rm = RobotMode {
            min_posterior: 0.0,
            ..RobotMode::default()
        };
        assert!(rm.validate().is_ok());
    }

    // ── FdrControl ─────────────────────────────────────────────────

    #[test]
    fn fdr_control_default_valid() {
        let fc = FdrControl::default();
        assert!(fc.validate().is_ok());
    }

    #[test]
    fn fdr_control_alpha_negative_error() {
        let fc = FdrControl {
            alpha: -0.1,
            ..FdrControl::default()
        };
        assert!(fc.validate().is_err());
    }

    #[test]
    fn fdr_control_alpha_above_one_error() {
        let fc = FdrControl {
            alpha: 1.5,
            ..FdrControl::default()
        };
        assert!(fc.validate().is_err());
    }

    #[test]
    fn fdr_control_alpha_one_ok() {
        let fc = FdrControl {
            alpha: 1.0,
            ..FdrControl::default()
        };
        assert!(fc.validate().is_ok());
    }

    #[test]
    fn fdr_control_default_has_alpha_investing() {
        let fc = FdrControl::default();
        assert!(fc.alpha_investing.is_some());
    }

    // ── FdrMethod ──────────────────────────────────────────────────

    #[test]
    fn fdr_method_serde() {
        for method in &[
            FdrMethod::Bh,
            FdrMethod::By,
            FdrMethod::AlphaInvesting,
            FdrMethod::None,
        ] {
            let json = serde_json::to_string(method).unwrap();
            let back: FdrMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(*method, back);
        }
    }

    // ── ConfidenceLevel ────────────────────────────────────────────

    #[test]
    fn confidence_level_serde() {
        for level in &[
            ConfidenceLevel::Low,
            ConfidenceLevel::Medium,
            ConfidenceLevel::High,
        ] {
            let json = serde_json::to_string(level).unwrap();
            let back: ConfidenceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, back);
        }
    }

    // ── AlphaInvesting ─────────────────────────────────────────────

    #[test]
    fn alpha_investing_default() {
        let ai = AlphaInvesting::default();
        assert!((ai.w0 - 0.05).abs() < f64::EPSILON);
        assert!((ai.alpha_spend - 0.02).abs() < f64::EPSILON);
        assert!((ai.alpha_earn - 0.01).abs() < f64::EPSILON);
    }

    // ── SignatureFastPath ──────────────────────────────────────────

    #[test]
    fn signature_fast_path_default_valid() {
        let sfp = SignatureFastPath::default();
        assert!(sfp.validate().is_ok());
    }

    #[test]
    fn signature_fast_path_default_values() {
        let sfp = SignatureFastPath::default();
        assert!(sfp.enabled);
        assert!((sfp.min_confidence_threshold - 0.9).abs() < f64::EPSILON);
        assert!(sfp.require_explicit_priors);
    }

    #[test]
    fn signature_fast_path_above_one_error() {
        let sfp = SignatureFastPath {
            min_confidence_threshold: 1.1,
            ..SignatureFastPath::default()
        };
        assert!(sfp.validate().is_err());
    }

    #[test]
    fn signature_fast_path_negative_error() {
        let sfp = SignatureFastPath {
            min_confidence_threshold: -0.1,
            ..SignatureFastPath::default()
        };
        assert!(sfp.validate().is_err());
    }

    #[test]
    fn signature_fast_path_zero_ok() {
        let sfp = SignatureFastPath {
            min_confidence_threshold: 0.0,
            ..SignatureFastPath::default()
        };
        assert!(sfp.validate().is_ok());
    }

    // ── LoadAwareDecision ──────────────────────────────────────────

    #[test]
    fn load_aware_default_disabled() {
        let la = LoadAwareDecision::default();
        assert!(!la.enabled);
    }

    #[test]
    fn load_aware_disabled_skips_validation() {
        let la = LoadAwareDecision {
            enabled: false,
            queue_high: 0, // Would fail if enabled
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_ok());
    }

    #[test]
    fn load_aware_default_valid_when_enabled() {
        let la = LoadAwareDecision {
            enabled: true,
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_ok());
    }

    #[test]
    fn load_aware_zero_weight_sum_error() {
        let la = LoadAwareDecision {
            enabled: true,
            weights: LoadWeights {
                queue: 0.0,
                load: 0.0,
                memory: 0.0,
                psi: 0.0,
            },
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_queue_high_zero_with_weight_error() {
        let la = LoadAwareDecision {
            enabled: true,
            queue_high: 0,
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_load_per_core_zero_error() {
        let la = LoadAwareDecision {
            enabled: true,
            load_per_core_high: 0.0,
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_memory_above_one_error() {
        let la = LoadAwareDecision {
            enabled: true,
            memory_used_fraction_high: 1.5,
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_psi_zero_error() {
        let la = LoadAwareDecision {
            enabled: true,
            psi_avg10_high: 0.0,
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_keep_max_below_one_error() {
        let la = LoadAwareDecision {
            enabled: true,
            multipliers: LoadMultipliers {
                keep_max: 0.5,
                ..LoadMultipliers::default()
            },
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_risky_max_below_one_error() {
        let la = LoadAwareDecision {
            enabled: true,
            multipliers: LoadMultipliers {
                risky_max: 0.5,
                ..LoadMultipliers::default()
            },
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_reversible_min_zero_error() {
        let la = LoadAwareDecision {
            enabled: true,
            multipliers: LoadMultipliers {
                reversible_min: 0.0,
                ..LoadMultipliers::default()
            },
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    #[test]
    fn load_aware_reversible_min_above_one_error() {
        let la = LoadAwareDecision {
            enabled: true,
            multipliers: LoadMultipliers {
                reversible_min: 1.5,
                ..LoadMultipliers::default()
            },
            ..LoadAwareDecision::default()
        };
        assert!(la.validate().is_err());
    }

    // ── LoadWeights / LoadMultipliers ──────────────────────────────

    #[test]
    fn load_weights_default_sum_one() {
        let lw = LoadWeights::default();
        let sum = lw.queue + lw.load + lw.memory + lw.psi;
        assert!((sum - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn load_multipliers_default_values() {
        let lm = LoadMultipliers::default();
        assert!((lm.keep_max - 1.4).abs() < f64::EPSILON);
        assert!((lm.reversible_min - 0.6).abs() < f64::EPSILON);
        assert!((lm.risky_max - 1.8).abs() < f64::EPSILON);
    }

    // ── DataLossGates ──────────────────────────────────────────────

    #[test]
    fn data_loss_gates_default() {
        let dlg = DataLossGates::default();
        assert!(dlg.block_if_open_write_fds);
        assert!(dlg.block_if_locked_files);
        assert!(dlg.block_if_active_tty);
        assert_eq!(dlg.max_open_write_fds, Some(0));
        assert_eq!(dlg.block_if_deleted_cwd, Some(true));
        assert_eq!(dlg.block_if_recent_io_seconds, Some(60));
    }

    #[test]
    fn data_loss_gates_serde() {
        let dlg = DataLossGates::default();
        let json = serde_json::to_string(&dlg).unwrap();
        let back: DataLossGates = serde_json::from_str(&json).unwrap();
        assert!(back.block_if_open_write_fds);
        assert_eq!(back.block_if_recent_io_seconds, Some(60));
    }
}
