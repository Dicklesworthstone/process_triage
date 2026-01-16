//! Policy configuration types.
//!
//! These types match the policy.schema.json specification.

use serde::{Deserialize, Serialize};

/// Complete policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub schema_version: String,

    #[serde(default)]
    pub policy_id: Option<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub created_at: Option<String>,

    #[serde(default)]
    pub updated_at: Option<String>,

    #[serde(default)]
    pub inherits: Vec<String>,

    pub loss_matrix: LossMatrix,
    pub guardrails: Guardrails,
    pub robot_mode: RobotMode,
    pub fdr_control: FdrControl,
    pub data_loss_gates: DataLossGates,
    #[serde(default)]
    pub load_aware: LoadAwareDecision,
    #[serde(default)]
    pub decision_time_bound: DecisionTimeBound,

    #[serde(default)]
    pub notes: Option<String>,
}

/// Time-to-decision bound configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTimeBound {
    pub enabled: bool,
    pub min_seconds: u64,
    pub max_seconds: u64,
    pub voi_decay_half_life_seconds: u64,
    pub voi_floor: f64,
    pub overhead_budget_seconds: u64,
    pub fallback_action: String,
}

impl Default for DecisionTimeBound {
    fn default() -> Self {
        Self {
            enabled: true,
            min_seconds: 60,
            max_seconds: 600,
            voi_decay_half_life_seconds: 120,
            voi_floor: 0.01,
            overhead_budget_seconds: 300,
            fallback_action: "pause".to_string(),
        }
    }
}

/// Loss matrix by class for each action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossMatrix {
    pub useful: LossRow,
    pub useful_bad: LossRow,
    pub abandoned: LossRow,
    pub zombie: LossRow,
}

/// Loss values for each action against a class.
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

    #[serde(default)]
    pub renice: Option<f64>,
}

impl Default for LossRow {
    fn default() -> Self {
        Self {
            keep: 0.0,
            pause: Some(0.5),
            throttle: Some(1.0),
            kill: 100.0,
            restart: Some(50.0),
            renice: None,
        }
    }
}

impl Default for LossMatrix {
    fn default() -> Self {
        Self {
            useful: LossRow {
                keep: 0.0,
                pause: Some(0.5),
                throttle: Some(1.0),
                kill: 500.0,
                restart: Some(10.0),
                renice: Some(0.2),
            },
            useful_bad: LossRow {
                keep: 0.0,
                pause: Some(0.3),
                throttle: Some(0.5),
                kill: 100.0,
                restart: Some(5.0),
                renice: Some(0.1),
            },
            abandoned: LossRow {
                keep: 5.0,
                pause: Some(0.2),
                throttle: Some(0.3),
                kill: 0.1,
                restart: Some(1.0),
                renice: Some(0.1),
            },
            zombie: LossRow {
                keep: 1.0,
                pause: Some(0.1),
                throttle: Some(0.1),
                kill: 0.1,
                restart: Some(0.1),
                renice: Some(0.1),
            },
        }
    }
}

/// Safety guardrails and protected patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardrails {
    pub protected_patterns: Vec<PatternEntry>,

    #[serde(default)]
    pub force_review_patterns: Vec<PatternEntry>,

    #[serde(default)]
    pub protected_users: Vec<String>,

    #[serde(default)]
    pub protected_groups: Vec<String>,

    #[serde(default)]
    pub protected_categories: Vec<String>,

    pub never_kill_ppid: Vec<u32>,

    #[serde(default)]
    pub never_kill_pid: Vec<u32>,

    pub max_kills_per_run: u32,

    #[serde(default)]
    pub max_kills_per_minute: Option<u32>,

    #[serde(default)]
    pub max_kills_per_hour: Option<u32>,

    #[serde(default)]
    pub max_kills_per_day: Option<u32>,

    pub min_process_age_seconds: u64,

    #[serde(default)]
    pub require_confirmation: Option<bool>,
}

impl Default for Guardrails {
    fn default() -> Self {
        Self {
            protected_patterns: vec![
                PatternEntry {
                    pattern: "^systemd$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Init system".to_string()),
                },
                PatternEntry {
                    pattern: "^sshd$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("SSH daemon".to_string()),
                },
            ],
            force_review_patterns: Vec::new(),
            protected_users: vec!["root".to_string()],
            protected_groups: Vec::new(),
            protected_categories: vec!["database".to_string(), "webserver".to_string()],
            never_kill_ppid: vec![1],
            never_kill_pid: Vec::new(),
            max_kills_per_run: 10,
            max_kills_per_minute: Some(5),
            max_kills_per_hour: Some(20),
            max_kills_per_day: Some(100),
            min_process_age_seconds: 300,
            require_confirmation: Some(true),
        }
    }
}

/// Pattern entry for matching commands/processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    pub pattern: String,

    #[serde(default = "default_pattern_kind")]
    pub kind: PatternKind,

    #[serde(default = "default_true")]
    pub case_insensitive: bool,

    #[serde(default)]
    pub notes: Option<String>,
}

fn default_pattern_kind() -> PatternKind {
    PatternKind::Regex
}

fn default_true() -> bool {
    true
}

/// Pattern matching type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    Regex,
    Glob,
    Literal,
}

impl PatternKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Glob => "glob",
            Self::Literal => "literal",
        }
    }
}

/// Robot/agent automation gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotMode {
    pub enabled: bool,
    pub min_posterior: f64,

    #[serde(default)]
    pub min_confidence: Option<ConfidenceLevel>,

    pub max_blast_radius_mb: f64,
    pub max_kills: u32,
    pub require_known_signature: bool,

    #[serde(default)]
    pub require_policy_snapshot: Option<bool>,

    #[serde(default)]
    pub allow_categories: Vec<String>,

    #[serde(default)]
    pub exclude_categories: Vec<String>,

    #[serde(default = "default_true")]
    pub require_human_for_supervised: bool,
}

/// Confidence level enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// False discovery rate control settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdrControl {
    pub enabled: bool,
    pub method: FdrMethod,
    pub alpha: f64,

    #[serde(default)]
    pub min_candidates: Option<u32>,

    #[serde(default)]
    pub lfdr_null: Vec<String>,

    #[serde(default)]
    pub alpha_investing: Option<AlphaInvesting>,
}

/// FDR control method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FdrMethod {
    /// Benjamini-Hochberg
    Bh,
    /// Benjamini-Yekutieli
    By,
    /// Alpha-investing
    #[serde(rename = "alpha_investing")]
    AlphaInvesting,
    /// No FDR control
    None,
}

impl FdrMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            FdrMethod::Bh => "bh",
            FdrMethod::By => "by",
            FdrMethod::AlphaInvesting => "alpha_investing",
            FdrMethod::None => "none",
        }
    }
}

/// Alpha-investing parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlphaInvesting {
    #[serde(default)]
    pub w0: Option<f64>,

    #[serde(default)]
    pub alpha_spend: Option<f64>,

    #[serde(default)]
    pub alpha_earn: Option<f64>,
}

/// Data loss prevention gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLossGates {
    pub block_if_open_write_fds: bool,

    #[serde(default)]
    pub max_open_write_fds: Option<u32>,

    pub block_if_locked_files: bool,

    #[serde(default)]
    pub block_if_deleted_cwd: Option<bool>,

    pub block_if_active_tty: bool,

    #[serde(default)]
    pub block_if_recent_io_seconds: Option<u64>,
}

/// Load-aware decision configuration for adaptive thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAwareDecision {
    pub enabled: bool,
    #[serde(default = "default_queue_high")]
    pub queue_high: u32,
    #[serde(default = "default_load_per_core_high")]
    pub load_per_core_high: f64,
    #[serde(default = "default_memory_used_fraction_high")]
    pub memory_used_fraction_high: f64,
    #[serde(default = "default_psi_avg10_high")]
    pub psi_avg10_high: f64,
    #[serde(default)]
    pub weights: LoadWeights,
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
    pub keep_max: f64,
    pub reversible_min: f64,
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

impl Default for RobotMode {
    fn default() -> Self {
        Self {
            enabled: false,
            min_posterior: 0.95,
            min_confidence: None,
            max_blast_radius_mb: 4096.0,
            max_kills: 5,
            require_known_signature: false,
            require_policy_snapshot: None,
            allow_categories: Vec::new(),
            exclude_categories: Vec::new(),
            require_human_for_supervised: true,
        }
    }
}

impl Default for FdrControl {
    fn default() -> Self {
        Self {
            enabled: true,
            method: FdrMethod::Bh,
            alpha: 0.05,
            min_candidates: None,
            lfdr_null: Vec::new(),
            alpha_investing: None,
        }
    }
}

impl Default for DataLossGates {
    fn default() -> Self {
        Self {
            block_if_open_write_fds: true,
            max_open_write_fds: None,
            block_if_locked_files: true,
            block_if_deleted_cwd: None,
            block_if_active_tty: true,
            block_if_recent_io_seconds: None,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            policy_id: None,
            description: None,
            created_at: None,
            updated_at: None,
            inherits: Vec::new(),
            loss_matrix: LossMatrix::default(),
            guardrails: Guardrails::default(),
            robot_mode: RobotMode::default(),
            fdr_control: FdrControl::default(),
            data_loss_gates: DataLossGates::default(),
            load_aware: LoadAwareDecision::default(),
            decision_time_bound: DecisionTimeBound::default(),
            notes: None,
        }
    }
}

impl Policy {
    /// Load policy from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::validate::ValidationError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::validate::ValidationError::IoError(format!(
                "Failed to read {}: {}",
                path.display(),
                e
            ))
        })?;

        Self::parse_json(&content)
    }

    /// Parse policy from a JSON string.
    pub fn parse_json(json: &str) -> Result<Self, crate::validate::ValidationError> {
        serde_json::from_str(json).map_err(|e| {
            crate::validate::ValidationError::ParseError(format!("Invalid JSON: {}", e))
        })
    }

    /// Get the loss for a given class and action.
    pub fn loss(&self, class: &str, action: &str) -> Option<f64> {
        let row = match class {
            "useful" => &self.loss_matrix.useful,
            "useful_bad" => &self.loss_matrix.useful_bad,
            "abandoned" => &self.loss_matrix.abandoned,
            "zombie" => &self.loss_matrix.zombie,
            _ => return None,
        };

        match action {
            "keep" => Some(row.keep),
            "pause" => row.pause,
            "throttle" => row.throttle,
            "kill" => Some(row.kill),
            "restart" => row.restart,
            _ => None,
        }
    }

    /// Check if robot mode is enabled and properly configured.
    pub fn is_robot_enabled(&self) -> bool {
        self.robot_mode.enabled
    }

    /// Check if a command matches any protected pattern.
    pub fn is_protected(&self, command: &str) -> bool {
        self.guardrails.protected_patterns.iter().any(|p| {
            match p.kind {
                PatternKind::Literal => {
                    if p.case_insensitive {
                        command.to_lowercase().contains(&p.pattern.to_lowercase())
                    } else {
                        command.contains(&p.pattern)
                    }
                }
                PatternKind::Regex => {
                    // Basic regex check (full implementation would use regex crate)
                    // For now, just check if pattern appears in command
                    command.contains(&p.pattern.replace("\\b", ""))
                }
                PatternKind::Glob => {
                    // Simplified glob matching
                    command.contains(&p.pattern.replace("*", ""))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_policy() {
        let json = r#"{
            "schema_version": "1.0.0",
            "loss_matrix": {
                "useful": {"keep": 0, "kill": 100},
                "useful_bad": {"keep": 10, "kill": 20},
                "abandoned": {"keep": 30, "kill": 1},
                "zombie": {"keep": 50, "kill": 1}
            },
            "guardrails": {
                "protected_patterns": [],
                "never_kill_ppid": [1],
                "max_kills_per_run": 5,
                "min_process_age_seconds": 3600
            },
            "robot_mode": {
                "enabled": false,
                "min_posterior": 0.99,
                "max_blast_radius_mb": 4096,
                "max_kills": 5,
                "require_known_signature": false
            },
            "fdr_control": {
                "enabled": true,
                "method": "bh",
                "alpha": 0.05
            },
            "data_loss_gates": {
                "block_if_open_write_fds": true,
                "block_if_locked_files": true,
                "block_if_active_tty": true
            }
        }"#;

        let policy = Policy::parse_json(json).unwrap();
        assert_eq!(policy.schema_version, "1.0.0");
        assert!(!policy.is_robot_enabled());
        assert_eq!(policy.loss("useful", "kill"), Some(100.0));
        assert_eq!(policy.loss("zombie", "kill"), Some(1.0));
    }

    #[test]
    fn test_protected_pattern_matching() {
        let json = r#"{
            "schema_version": "1.0.0",
            "loss_matrix": {
                "useful": {"keep": 0, "kill": 100},
                "useful_bad": {"keep": 10, "kill": 20},
                "abandoned": {"keep": 30, "kill": 1},
                "zombie": {"keep": 50, "kill": 1}
            },
            "guardrails": {
                "protected_patterns": [
                    {"pattern": "systemd", "kind": "literal"}
                ],
                "never_kill_ppid": [1],
                "max_kills_per_run": 5,
                "min_process_age_seconds": 3600
            },
            "robot_mode": {
                "enabled": false,
                "min_posterior": 0.99,
                "max_blast_radius_mb": 4096,
                "max_kills": 5,
                "require_known_signature": false
            },
            "fdr_control": {
                "enabled": true,
                "method": "bh",
                "alpha": 0.05
            },
            "data_loss_gates": {
                "block_if_open_write_fds": true,
                "block_if_locked_files": true,
                "block_if_active_tty": true
            }
        }"#;

        let policy = Policy::parse_json(json).unwrap();
        assert!(policy.is_protected("/usr/lib/systemd/systemd-logind"));
        assert!(!policy.is_protected("python my_script.py"));
    }
}
