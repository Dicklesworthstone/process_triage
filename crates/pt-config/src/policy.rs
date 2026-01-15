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
    pub notes: Option<String>,
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
    pub max_kills_per_hour: Option<u32>,

    #[serde(default)]
    pub max_kills_per_day: Option<u32>,

    pub min_process_age_seconds: u64,

    #[serde(default)]
    pub require_confirmation: Option<bool>,
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

impl Policy {
    /// Load policy from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::validate::ValidationError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::validate::ValidationError::IoError(format!("Failed to read {}: {}", path.display(), e))
        })?;

        Self::from_str(&content)
    }

    /// Parse policy from a JSON string.
    pub fn from_str(json: &str) -> Result<Self, crate::validate::ValidationError> {
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

        let policy = Policy::from_str(json).unwrap();
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

        let policy = Policy::from_str(json).unwrap();
        assert!(policy.is_protected("/usr/lib/systemd/systemd-logind"));
        assert!(!policy.is_protected("python my_script.py"));
    }
}
