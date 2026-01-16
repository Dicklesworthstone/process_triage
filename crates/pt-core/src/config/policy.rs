//! Policy configuration types.
//!
//! These types match the policy.schema.json specification.

use serde::{Deserialize, Serialize};

/// Loss values for a single class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossRow {
    /// Loss for keeping the process.
    pub keep: f64,
    /// Loss for pausing the process.
    #[serde(default)]
    pub pause: Option<f64>,
    /// Loss for throttling the process.
    #[serde(default)]
    pub throttle: Option<f64>,
    /// Loss for renicing the process.
    #[serde(default)]
    pub renice: Option<f64>,
    /// Loss for killing the process.
    pub kill: f64,
    /// Loss for restarting the process.
    #[serde(default)]
    pub restart: Option<f64>,
}

/// Loss matrix by class for each action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossMatrix {
    pub useful: LossRow,
    pub useful_bad: LossRow,
    pub abandoned: LossRow,
    pub zombie: LossRow,
}

/// Pattern matching entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    /// Pattern used for matching.
    pub pattern: String,
    /// Pattern kind: regex, glob, or literal.
    #[serde(default = "default_pattern_kind")]
    pub kind: String,
    /// Whether matching is case-insensitive.
    #[serde(default = "default_case_insensitive")]
    pub case_insensitive: bool,
    /// Optional notes.
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_pattern_kind() -> String {
    "regex".to_string()
}

fn default_case_insensitive() -> bool {
    true
}

/// Safety guardrails and protected patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardrails {
    /// Patterns for protected processes (never kill).
    pub protected_patterns: Vec<PatternEntry>,
    /// Patterns for processes that require review.
    #[serde(default)]
    pub force_review_patterns: Vec<PatternEntry>,
    /// Protected users (never kill their processes).
    #[serde(default)]
    pub protected_users: Vec<String>,
    /// Protected groups.
    #[serde(default)]
    pub protected_groups: Vec<String>,
    /// Protected categories.
    #[serde(default)]
    pub protected_categories: Vec<String>,
    /// Parent PIDs whose children should never be killed.
    pub never_kill_ppid: Vec<i32>,
    /// Specific PIDs that should never be killed.
    #[serde(default)]
    pub never_kill_pid: Vec<i32>,
    /// Maximum kills per run.
    pub max_kills_per_run: u32,
    /// Maximum kills per hour.
    #[serde(default)]
    pub max_kills_per_hour: Option<u32>,
    /// Maximum kills per day.
    #[serde(default)]
    pub max_kills_per_day: Option<u32>,
    /// Minimum process age in seconds before considering for action.
    pub min_process_age_seconds: u64,
    /// Whether to require confirmation before actions.
    #[serde(default)]
    pub require_confirmation: Option<bool>,
}

/// Robot/agent automation gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotMode {
    /// Whether robot mode is enabled.
    pub enabled: bool,
    /// Minimum posterior probability for automatic action.
    pub min_posterior: f64,
    /// Minimum confidence level.
    #[serde(default)]
    pub min_confidence: Option<String>,
    /// Maximum blast radius in MB.
    pub max_blast_radius_mb: f64,
    /// Maximum kills in robot mode.
    pub max_kills: u32,
    /// Whether to require known signature for action.
    pub require_known_signature: bool,
    /// Whether to require policy snapshot.
    #[serde(default)]
    pub require_policy_snapshot: Option<bool>,
    /// Categories allowed for robot action.
    #[serde(default)]
    pub allow_categories: Vec<String>,
    /// Categories excluded from robot action.
    #[serde(default)]
    pub exclude_categories: Vec<String>,
}

/// Alpha investing parameters for FDR control.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlphaInvesting {
    /// Initial wealth.
    #[serde(default)]
    pub w0: Option<f64>,
    /// Alpha spend rate.
    #[serde(default)]
    pub alpha_spend: Option<f64>,
    /// Alpha earn rate.
    #[serde(default)]
    pub alpha_earn: Option<f64>,
}

/// False discovery rate control settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdrControl {
    /// Whether FDR control is enabled.
    pub enabled: bool,
    /// FDR control method: bh, by, alpha_investing, none.
    pub method: String,
    /// Target alpha level.
    pub alpha: f64,
    /// Minimum candidates for FDR control to apply.
    #[serde(default)]
    pub min_candidates: Option<u32>,
    /// Classes considered null for local FDR.
    #[serde(default)]
    pub lfdr_null: Vec<String>,
    /// Alpha investing parameters.
    #[serde(default)]
    pub alpha_investing: Option<AlphaInvesting>,
}

/// Gates that block destructive actions when data-loss risk is high.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLossGates {
    /// Block if process has open write file descriptors.
    pub block_if_open_write_fds: bool,
    /// Maximum open write FDs allowed.
    #[serde(default)]
    pub max_open_write_fds: Option<u32>,
    /// Block if process has locked files.
    pub block_if_locked_files: bool,
    /// Block if process CWD is deleted.
    #[serde(default)]
    pub block_if_deleted_cwd: Option<bool>,
    /// Block if process has active TTY.
    pub block_if_active_tty: bool,
    /// Block if recent I/O activity within N seconds.
    #[serde(default)]
    pub block_if_recent_io_seconds: Option<u64>,
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

/// Time-to-decision bound configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTimeBound {
    /// Enable time-bounded decision making.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum probe time before applying fallback (seconds).
    #[serde(default = "default_time_bound_min")]
    pub min_seconds: u64,
    /// Maximum probe time before forcing fallback (seconds).
    #[serde(default = "default_time_bound_max")]
    pub max_seconds: u64,
    /// Half-life for VOI decay (seconds).
    #[serde(default = "default_voi_half_life")]
    pub voi_decay_half_life_seconds: u64,
    /// VOI floor below which probing is not worthwhile.
    #[serde(default = "default_voi_floor")]
    pub voi_floor: f64,
    /// Overhead budget for probe operations (seconds).
    #[serde(default = "default_overhead_budget")]
    pub overhead_budget_seconds: u64,
    /// Fallback action when time bound is exceeded: keep, pause, freeze, etc.
    #[serde(default = "default_fallback_action")]
    pub fallback_action: String,
}

fn default_time_bound_min() -> u64 {
    30
}
fn default_time_bound_max() -> u64 {
    300
}
fn default_voi_half_life() -> u64 {
    60
}
fn default_voi_floor() -> f64 {
    0.01
}
fn default_overhead_budget() -> u64 {
    120
}
fn default_fallback_action() -> String {
    "pause".to_string()
}

impl Default for DecisionTimeBound {
    fn default() -> Self {
        Self {
            enabled: false,
            min_seconds: default_time_bound_min(),
            max_seconds: default_time_bound_max(),
            voi_decay_half_life_seconds: default_voi_half_life(),
            voi_floor: default_voi_floor(),
            overhead_budget_seconds: default_overhead_budget(),
            fallback_action: default_fallback_action(),
        }
    }
}

/// Complete policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version for compatibility checks.
    pub schema_version: String,
    /// Optional identifier for this policy snapshot.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Last update timestamp.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Optional policy inheritance chain.
    #[serde(default)]
    pub inherits: Vec<String>,
    /// Loss matrix by class.
    pub loss_matrix: LossMatrix,
    /// Safety guardrails.
    pub guardrails: Guardrails,
    /// Robot mode settings.
    pub robot_mode: RobotMode,
    /// FDR control settings.
    pub fdr_control: FdrControl,
    /// Data loss gates.
    pub data_loss_gates: DataLossGates,
    /// Load-aware decision tuning.
    #[serde(default)]
    pub load_aware: LoadAwareDecision,
    /// Decision time-bound settings.
    #[serde(default)]
    pub decision_time_bound: DecisionTimeBound,
    /// Freeform notes.
    #[serde(default)]
    pub notes: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: super::CONFIG_SCHEMA_VERSION.to_string(),
            policy_id: Some("default-conservative".to_string()),
            description: Some("Conservative default policy (built-in)".to_string()),
            created_at: None,
            updated_at: None,
            inherits: vec![],
            loss_matrix: LossMatrix {
                useful: LossRow {
                    keep: 0.0,
                    renice: Some(2.0),
                    pause: Some(5.0),
                    throttle: Some(8.0),
                    kill: 100.0,
                    restart: Some(60.0),
                },
                useful_bad: LossRow {
                    keep: 10.0,
                    renice: Some(4.0),
                    pause: Some(6.0),
                    throttle: Some(8.0),
                    kill: 20.0,
                    restart: Some(12.0),
                },
                abandoned: LossRow {
                    keep: 30.0,
                    renice: Some(12.0),
                    pause: Some(15.0),
                    throttle: Some(10.0),
                    kill: 1.0,
                    restart: Some(8.0),
                },
                zombie: LossRow {
                    keep: 50.0,
                    renice: Some(18.0),
                    pause: Some(20.0),
                    throttle: Some(15.0),
                    kill: 1.0,
                    restart: Some(5.0),
                },
            },
            guardrails: Guardrails {
                protected_patterns: vec![
                    PatternEntry {
                        pattern: r"\b(systemd|journald|logind|dbus-daemon)\b".to_string(),
                        kind: "regex".to_string(),
                        case_insensitive: true,
                        notes: Some("core system services".to_string()),
                    },
                    PatternEntry {
                        pattern: r"\b(sshd|cron|crond)\b".to_string(),
                        kind: "regex".to_string(),
                        case_insensitive: true,
                        notes: Some("remote access and schedulers".to_string()),
                    },
                    PatternEntry {
                        pattern: r"\b(dockerd|containerd)\b".to_string(),
                        kind: "regex".to_string(),
                        case_insensitive: true,
                        notes: Some("containers".to_string()),
                    },
                    PatternEntry {
                        pattern: r"\b(postgres|redis|nginx|elasticsearch)\b".to_string(),
                        kind: "regex".to_string(),
                        case_insensitive: true,
                        notes: Some("databases and proxies".to_string()),
                    },
                ],
                force_review_patterns: vec![],
                protected_users: vec!["root".to_string()],
                protected_groups: vec![],
                protected_categories: vec!["daemon".to_string(), "system".to_string()],
                never_kill_ppid: vec![1],
                never_kill_pid: vec![1],
                max_kills_per_run: 5,
                max_kills_per_hour: Some(20),
                max_kills_per_day: Some(100),
                min_process_age_seconds: 3600,
                require_confirmation: Some(true),
            },
            robot_mode: RobotMode {
                enabled: false,
                min_posterior: 0.99,
                min_confidence: Some("high".to_string()),
                max_blast_radius_mb: 4096.0,
                max_kills: 5,
                require_known_signature: false,
                require_policy_snapshot: Some(true),
                allow_categories: vec![],
                exclude_categories: vec!["daemon".to_string(), "system".to_string()],
            },
            fdr_control: FdrControl {
                enabled: true,
                method: "bh".to_string(),
                alpha: 0.05,
                min_candidates: Some(3),
                lfdr_null: vec!["useful".to_string()],
                alpha_investing: Some(AlphaInvesting {
                    w0: Some(0.05),
                    alpha_spend: Some(0.02),
                    alpha_earn: Some(0.01),
                }),
            },
            data_loss_gates: DataLossGates {
                block_if_open_write_fds: true,
                max_open_write_fds: Some(0),
                block_if_locked_files: true,
                block_if_deleted_cwd: Some(true),
                block_if_active_tty: true,
                block_if_recent_io_seconds: Some(60),
            },
            load_aware: LoadAwareDecision::default(),
            decision_time_bound: DecisionTimeBound::default(),
            notes: None,
        }
    }
}
