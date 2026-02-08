//! Configuration presets for common deployment scenarios.
//!
//! Provides pre-built configurations for:
//! - Developer: Aggressive detection, lower thresholds, interactive
//! - Server: Conservative detection, higher thresholds, strict protection
//! - CI: Headless operation, JSON only, automation-friendly
//! - Paranoid: Maximum safety, extra confirmation, detailed logging

use crate::policy::{
    AlphaInvesting, ConfidenceLevel, DataLossGates, DecisionTimeBound, FdrControl, FdrMethod,
    Guardrails, LoadAwareDecision, LossMatrix, LossRow, PatternEntry, PatternKind, Policy,
    RobotMode, SignatureFastPath,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Available configuration presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresetName {
    /// Aggressive detection, lower thresholds, interactive mode
    Developer,
    /// Conservative detection, strict protection, shadow mode recommended
    Server,
    /// Headless operation, JSON output, automation-friendly
    Ci,
    /// Maximum safety, extra confirmation, detailed audit logging
    Paranoid,
}

impl PresetName {
    /// All available preset names.
    pub const ALL: &'static [PresetName] = &[
        PresetName::Developer,
        PresetName::Server,
        PresetName::Ci,
        PresetName::Paranoid,
    ];

    /// Get preset name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            PresetName::Developer => "developer",
            PresetName::Server => "server",
            PresetName::Ci => "ci",
            PresetName::Paranoid => "paranoid",
        }
    }

    /// Parse preset name from string.
    pub fn parse(s: &str) -> Option<PresetName> {
        match s.to_lowercase().as_str() {
            "developer" | "dev" => Some(PresetName::Developer),
            "server" | "srv" | "production" | "prod" => Some(PresetName::Server),
            "ci" | "automation" | "headless" => Some(PresetName::Ci),
            "paranoid" | "safe" | "cautious" => Some(PresetName::Paranoid),
            _ => None,
        }
    }

    /// Get a description of the preset.
    pub fn description(&self) -> &'static str {
        match self {
            PresetName::Developer => "Aggressive detection, lower thresholds, focus on dev tools",
            PresetName::Server => {
                "Conservative detection, strict protection, recommended for production"
            }
            PresetName::Ci => "Headless operation, JSON output, specific exit codes for automation",
            PresetName::Paranoid => "Maximum safety, extra confirmation, detailed audit logging",
        }
    }
}

impl fmt::Display for PresetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for PresetName {
    type Err = PresetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PresetName::parse(s).ok_or_else(|| PresetError::UnknownPreset(s.to_string()))
    }
}

/// Errors related to preset operations.
#[derive(Debug, Clone)]
pub enum PresetError {
    /// Unknown preset name.
    UnknownPreset(String),
    /// Invalid override value.
    InvalidOverride(String),
    /// Preset file corrupted.
    CorruptPresetFile(String),
}

impl fmt::Display for PresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresetError::UnknownPreset(name) => {
                write!(
                    f,
                    "Unknown preset '{}'. Available: {}",
                    name,
                    PresetName::ALL
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            PresetError::InvalidOverride(msg) => write!(f, "Invalid override: {}", msg),
            PresetError::CorruptPresetFile(msg) => write!(f, "Corrupt preset file: {}", msg),
        }
    }
}

impl std::error::Error for PresetError {}

/// Get the policy for a preset.
pub fn get_preset(name: PresetName) -> Policy {
    match name {
        PresetName::Developer => developer_preset(),
        PresetName::Server => server_preset(),
        PresetName::Ci => ci_preset(),
        PresetName::Paranoid => paranoid_preset(),
    }
}

/// Developer preset: aggressive detection, lower thresholds.
///
/// Characteristics:
/// - Minimum process age: 30 minutes (1800 seconds)
/// - Focus on test runners, dev servers, build tools
/// - Higher risk tolerance (more false positives acceptable)
/// - Interactive mode default
/// - Relaxed data loss gates
fn developer_preset() -> Policy {
    Policy {
        schema_version: "1.0.0".to_string(),
        policy_id: Some("preset:developer".to_string()),
        description: Some(
            "Developer preset: aggressive detection for dev environments".to_string(),
        ),
        created_at: None,
        updated_at: None,
        inherits: Vec::new(),
        notes: Some(
            "Optimized for catching stuck test runners, dev servers, and build tools".to_string(),
        ),

        loss_matrix: LossMatrix {
            // Lower penalty for killing useful processes (accept more false positives)
            useful: LossRow {
                keep: 0.0,
                pause: Some(0.3),
                throttle: Some(0.5),
                kill: 50.0, // Lower than default (100) - accept some risk
                restart: Some(5.0),
                renice: Some(0.1),
            },
            useful_bad: LossRow {
                keep: 0.0,
                pause: Some(0.2),
                throttle: Some(0.3),
                kill: 20.0,
                restart: Some(3.0),
                renice: Some(0.05),
            },
            abandoned: LossRow {
                keep: 10.0, // Higher penalty for keeping abandoned (want to catch them)
                pause: Some(0.1),
                throttle: Some(0.2),
                kill: 0.05, // Very low penalty for killing abandoned
                restart: Some(0.5),
                renice: Some(0.05),
            },
            zombie: LossRow {
                keep: 5.0,
                pause: Some(0.05),
                throttle: Some(0.05),
                kill: 0.01,
                restart: Some(0.05),
                renice: Some(0.01),
            },
        },

        guardrails: Guardrails {
            protected_patterns: vec![
                // Core system services only
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
            protected_categories: vec!["database".to_string()], // Only databases strictly protected
            never_kill_ppid: vec![1],
            never_kill_pid: Vec::new(),
            max_kills_per_run: 20, // Higher limit for dev cleanup sessions
            max_kills_per_minute: Some(10),
            max_kills_per_hour: Some(50),
            max_kills_per_day: Some(200),
            min_process_age_seconds: 1800, // 30 minutes (shorter than default)
            require_confirmation: Some(true), // Still interactive by default
        },

        robot_mode: RobotMode {
            enabled: false,      // Interactive by default
            min_posterior: 0.90, // Lower threshold
            min_confidence: Some(ConfidenceLevel::Medium),
            max_blast_radius_mb: 8192.0, // Higher limit
            max_kills: 15,
            require_known_signature: false,
            require_policy_snapshot: None,
            allow_categories: vec![
                "test_runner".to_string(),
                "dev_server".to_string(),
                "build_tool".to_string(),
            ],
            exclude_categories: Vec::new(),
            require_human_for_supervised: false, // Can kill supervised dev tools
        },
        signature_fast_path: SignatureFastPath::default(),

        fdr_control: FdrControl {
            enabled: true,
            method: FdrMethod::Bh,
            alpha: 0.10, // Higher FDR tolerance (10%)
            min_candidates: None,
            lfdr_null: Vec::new(),
            alpha_investing: None,
        },

        data_loss_gates: DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: Some(5), // Allow some open FDs
            block_if_locked_files: true,
            block_if_deleted_cwd: None,
            block_if_active_tty: false, // Don't block on TTY - devs often have multiple terminals
            block_if_recent_io_seconds: Some(30), // Only block if very recent I/O
        },

        load_aware: LoadAwareDecision::default(),
        decision_time_bound: DecisionTimeBound::default(),
    }
}

/// Server preset: conservative detection, strict protection.
///
/// Characteristics:
/// - Minimum process age: 4 hours (14400 seconds)
/// - Strict protected process list
/// - Lower risk tolerance
/// - Shadow mode recommended initially
/// - Strict data loss gates
fn server_preset() -> Policy {
    Policy {
        schema_version: "1.0.0".to_string(),
        policy_id: Some("preset:server".to_string()),
        description: Some(
            "Server preset: conservative detection for production environments".to_string(),
        ),
        created_at: None,
        updated_at: None,
        inherits: Vec::new(),
        notes: Some(
            "Recommended for production servers - prioritizes safety over cleanup".to_string(),
        ),

        loss_matrix: LossMatrix {
            // Very high penalty for killing useful processes
            useful: LossRow {
                keep: 0.0,
                pause: Some(1.0),
                throttle: Some(2.0),
                kill: 1000.0, // Very high penalty
                restart: Some(50.0),
                renice: Some(0.5),
            },
            useful_bad: LossRow {
                keep: 0.0,
                pause: Some(0.5),
                throttle: Some(1.0),
                kill: 200.0,
                restart: Some(20.0),
                renice: Some(0.3),
            },
            abandoned: LossRow {
                keep: 3.0, // Lower penalty for keeping abandoned (prefer false negatives)
                pause: Some(0.3),
                throttle: Some(0.5),
                kill: 0.5, // Still prefer killing abandoned, but carefully
                restart: Some(2.0),
                renice: Some(0.2),
            },
            zombie: LossRow {
                keep: 2.0,
                pause: Some(0.2),
                throttle: Some(0.2),
                kill: 0.2,
                restart: Some(0.5),
                renice: Some(0.1),
            },
        },

        guardrails: Guardrails {
            protected_patterns: vec![
                // Comprehensive protection for production services
                PatternEntry {
                    pattern: "^systemd".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Init system and services".to_string()),
                },
                PatternEntry {
                    pattern: "^sshd$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("SSH daemon".to_string()),
                },
                PatternEntry {
                    pattern: "^nginx$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Web server".to_string()),
                },
                PatternEntry {
                    pattern: "^postgres".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("PostgreSQL".to_string()),
                },
                PatternEntry {
                    pattern: "^mysql".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("MySQL".to_string()),
                },
                PatternEntry {
                    pattern: "^redis".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Redis".to_string()),
                },
                PatternEntry {
                    pattern: "^docker".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Docker daemon".to_string()),
                },
                PatternEntry {
                    pattern: "^containerd".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Container runtime".to_string()),
                },
                PatternEntry {
                    pattern: "^kubelet".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Kubernetes node agent".to_string()),
                },
                PatternEntry {
                    pattern: "^cron".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Cron scheduler".to_string()),
                },
            ],
            force_review_patterns: vec![
                // Force review for production-critical patterns
                PatternEntry {
                    pattern: "worker".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Background workers".to_string()),
                },
                PatternEntry {
                    pattern: "queue".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Queue processors".to_string()),
                },
            ],
            protected_users: vec!["root".to_string()],
            protected_groups: Vec::new(),
            protected_categories: vec![
                "database".to_string(),
                "webserver".to_string(),
                "container".to_string(),
                "init".to_string(),
            ],
            never_kill_ppid: vec![1],
            never_kill_pid: Vec::new(),
            max_kills_per_run: 5, // Very conservative
            max_kills_per_minute: Some(2),
            max_kills_per_hour: Some(10),
            max_kills_per_day: Some(30),
            min_process_age_seconds: 14400, // 4 hours
            require_confirmation: Some(true),
        },

        robot_mode: RobotMode {
            enabled: false,
            min_posterior: 0.99, // Very high confidence required
            min_confidence: Some(ConfidenceLevel::High),
            max_blast_radius_mb: 2048.0, // Conservative
            max_kills: 3,
            require_known_signature: true, // Only kill known patterns
            require_policy_snapshot: Some(true),
            allow_categories: Vec::new(), // Empty = only explicitly allowed
            exclude_categories: vec![
                "database".to_string(),
                "webserver".to_string(),
                "container".to_string(),
            ],
            require_human_for_supervised: true,
        },
        signature_fast_path: SignatureFastPath::default(),

        fdr_control: FdrControl {
            enabled: true,
            method: FdrMethod::By,   // Benjamini-Yekutieli (stricter)
            alpha: 0.01,             // Very low FDR tolerance (1%)
            min_candidates: Some(3), // Require multiple candidates
            lfdr_null: Vec::new(),
            alpha_investing: Some(AlphaInvesting {
                w0: Some(0.01),
                alpha_spend: Some(0.001),
                alpha_earn: Some(0.005),
            }),
        },

        data_loss_gates: DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: None, // Any open write FDs block
            block_if_locked_files: true,
            block_if_deleted_cwd: Some(true),
            block_if_active_tty: true,
            block_if_recent_io_seconds: Some(300), // Block if any I/O in last 5 minutes
        },

        load_aware: LoadAwareDecision {
            enabled: true,
            queue_high: 100,
            load_per_core_high: 0.8,
            memory_used_fraction_high: 0.90,
            psi_avg10_high: 30.0,
            weights: crate::policy::LoadWeights::default(),
            multipliers: crate::policy::LoadMultipliers::default(),
        },

        decision_time_bound: DecisionTimeBound {
            enabled: true,
            min_seconds: 120,
            max_seconds: 900,
            voi_decay_half_life_seconds: 180,
            voi_floor: 0.02,
            overhead_budget_seconds: 600,
            fallback_action: "keep".to_string(), // Default to keeping on timeout
        },
    }
}

/// CI preset: headless operation, JSON output, automation-friendly.
///
/// Characteristics:
/// - No prompts or interactive elements
/// - JSON output only
/// - Specific exit codes for automation
/// - Conservative to avoid breaking builds
fn ci_preset() -> Policy {
    Policy {
        schema_version: "1.0.0".to_string(),
        policy_id: Some("preset:ci".to_string()),
        description: Some("CI preset: headless operation for CI/CD pipelines".to_string()),
        created_at: None,
        updated_at: None,
        inherits: Vec::new(),
        notes: Some(
            "Designed for CI/CD automation - no interactive prompts, specific exit codes"
                .to_string(),
        ),

        loss_matrix: LossMatrix {
            // Conservative - CI should not break builds
            useful: LossRow {
                keep: 0.0,
                pause: Some(0.5),
                throttle: Some(1.0),
                kill: 500.0,
                restart: Some(30.0),
                renice: Some(0.3),
            },
            useful_bad: LossRow {
                keep: 0.0,
                pause: Some(0.3),
                throttle: Some(0.5),
                kill: 100.0,
                restart: Some(15.0),
                renice: Some(0.2),
            },
            abandoned: LossRow {
                keep: 5.0,
                pause: Some(0.2),
                throttle: Some(0.3),
                kill: 0.2,
                restart: Some(1.0),
                renice: Some(0.1),
            },
            zombie: LossRow {
                keep: 3.0,
                pause: Some(0.1),
                throttle: Some(0.1),
                kill: 0.1,
                restart: Some(0.2),
                renice: Some(0.05),
            },
        },

        guardrails: Guardrails {
            protected_patterns: vec![
                PatternEntry {
                    pattern: "^systemd$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Init system".to_string()),
                },
                PatternEntry {
                    pattern: "^docker$".to_string(),
                    kind: PatternKind::Regex,
                    case_insensitive: true,
                    notes: Some("Docker daemon".to_string()),
                },
                PatternEntry {
                    pattern: "gitlab-runner".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("GitLab CI runner".to_string()),
                },
                PatternEntry {
                    pattern: "actions-runner".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("GitHub Actions runner".to_string()),
                },
                PatternEntry {
                    pattern: "jenkins".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Jenkins".to_string()),
                },
            ],
            force_review_patterns: Vec::new(), // No interactive review in CI
            protected_users: vec!["root".to_string()],
            protected_groups: Vec::new(),
            protected_categories: vec!["ci_runner".to_string(), "container".to_string()],
            never_kill_ppid: vec![1],
            never_kill_pid: Vec::new(),
            max_kills_per_run: 10,
            max_kills_per_minute: Some(5),
            max_kills_per_hour: Some(30),
            max_kills_per_day: Some(100),
            min_process_age_seconds: 3600, // 1 hour (long enough for most CI jobs)
            require_confirmation: Some(false), // NO interactive prompts
        },

        robot_mode: RobotMode {
            enabled: true, // Robot mode ON for CI
            min_posterior: 0.95,
            min_confidence: Some(ConfidenceLevel::High),
            max_blast_radius_mb: 4096.0,
            max_kills: 10,
            require_known_signature: false,
            require_policy_snapshot: None,
            allow_categories: vec!["test_runner".to_string(), "build_tool".to_string()],
            exclude_categories: vec!["ci_runner".to_string()],
            require_human_for_supervised: false, // Fully automated
        },
        signature_fast_path: SignatureFastPath::default(),

        fdr_control: FdrControl {
            enabled: true,
            method: FdrMethod::Bh,
            alpha: 0.05,
            min_candidates: None,
            lfdr_null: Vec::new(),
            alpha_investing: None,
        },

        data_loss_gates: DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: Some(3),
            block_if_locked_files: true,
            block_if_deleted_cwd: None,
            block_if_active_tty: false, // No TTY in CI
            block_if_recent_io_seconds: Some(60),
        },

        load_aware: LoadAwareDecision::default(),
        decision_time_bound: DecisionTimeBound {
            enabled: true,
            min_seconds: 30,
            max_seconds: 300, // CI shouldn't wait too long
            voi_decay_half_life_seconds: 60,
            voi_floor: 0.01,
            overhead_budget_seconds: 120,
            fallback_action: "keep".to_string(),
        },
    }
}

/// Paranoid preset: maximum safety, extra confirmation.
///
/// Characteristics:
/// - Very high confidence thresholds
/// - Extended minimum process age (24 hours)
/// - Extended protected list
/// - Require explicit confirmation for every action
/// - Detailed audit logging
fn paranoid_preset() -> Policy {
    Policy {
        schema_version: "1.0.0".to_string(),
        policy_id: Some("preset:paranoid".to_string()),
        description: Some("Paranoid preset: maximum safety for critical systems".to_string()),
        created_at: None,
        updated_at: None,
        inherits: Vec::new(),
        notes: Some("For critical systems where any false positive is unacceptable".to_string()),

        loss_matrix: LossMatrix {
            // Extremely high penalty for false positives
            useful: LossRow {
                keep: 0.0,
                pause: Some(5.0),
                throttle: Some(10.0),
                kill: 10000.0, // Extremely high
                restart: Some(500.0),
                renice: Some(2.0),
            },
            useful_bad: LossRow {
                keep: 0.0,
                pause: Some(2.0),
                throttle: Some(5.0),
                kill: 1000.0,
                restart: Some(100.0),
                renice: Some(1.0),
            },
            abandoned: LossRow {
                keep: 1.0, // Very low penalty for keeping abandoned
                pause: Some(0.5),
                throttle: Some(1.0),
                kill: 2.0, // Higher penalty even for killing abandoned
                restart: Some(5.0),
                renice: Some(0.5),
            },
            zombie: LossRow {
                keep: 0.5,
                pause: Some(0.3),
                throttle: Some(0.3),
                kill: 0.5,
                restart: Some(1.0),
                renice: Some(0.2),
            },
        },

        guardrails: Guardrails {
            protected_patterns: vec![
                // Extensive protection list
                PatternEntry {
                    pattern: "systemd".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Init system and services".to_string()),
                },
                PatternEntry {
                    pattern: "dbus".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("D-Bus".to_string()),
                },
                PatternEntry {
                    pattern: "sshd".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("SSH daemon".to_string()),
                },
                PatternEntry {
                    pattern: "nginx".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Nginx".to_string()),
                },
                PatternEntry {
                    pattern: "apache".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Apache".to_string()),
                },
                PatternEntry {
                    pattern: "postgres".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("PostgreSQL".to_string()),
                },
                PatternEntry {
                    pattern: "mysql".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("MySQL".to_string()),
                },
                PatternEntry {
                    pattern: "mariadb".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("MariaDB".to_string()),
                },
                PatternEntry {
                    pattern: "redis".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Redis".to_string()),
                },
                PatternEntry {
                    pattern: "memcached".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Memcached".to_string()),
                },
                PatternEntry {
                    pattern: "docker".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Docker".to_string()),
                },
                PatternEntry {
                    pattern: "containerd".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("containerd".to_string()),
                },
                PatternEntry {
                    pattern: "kubelet".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Kubernetes".to_string()),
                },
                PatternEntry {
                    pattern: "etcd".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("etcd".to_string()),
                },
                PatternEntry {
                    pattern: "vault".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("HashiCorp Vault".to_string()),
                },
                PatternEntry {
                    pattern: "consul".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("HashiCorp Consul".to_string()),
                },
                PatternEntry {
                    pattern: "elasticsearch".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Elasticsearch".to_string()),
                },
                PatternEntry {
                    pattern: "kafka".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("Kafka".to_string()),
                },
                PatternEntry {
                    pattern: "zookeeper".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("ZooKeeper".to_string()),
                },
                PatternEntry {
                    pattern: "pulseaudio".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("PulseAudio".to_string()),
                },
                PatternEntry {
                    pattern: "pipewire".to_string(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    notes: Some("PipeWire".to_string()),
                },
            ],
            force_review_patterns: vec![PatternEntry {
                pattern: ".*".to_string(), // Force review for ALL processes
                kind: PatternKind::Regex,
                case_insensitive: true,
                notes: Some("Force review all".to_string()),
            }],
            protected_users: vec!["root".to_string()],
            protected_groups: Vec::new(),
            protected_categories: vec![
                "database".to_string(),
                "webserver".to_string(),
                "container".to_string(),
                "init".to_string(),
                "message_queue".to_string(),
                "cache".to_string(),
            ],
            never_kill_ppid: vec![1],
            never_kill_pid: Vec::new(),
            max_kills_per_run: 3, // Very limited
            max_kills_per_minute: Some(1),
            max_kills_per_hour: Some(5),
            max_kills_per_day: Some(10),
            min_process_age_seconds: 86400, // 24 hours
            require_confirmation: Some(true),
        },

        robot_mode: RobotMode {
            enabled: false,       // Robot mode OFF
            min_posterior: 0.999, // Extremely high confidence required
            min_confidence: Some(ConfidenceLevel::High),
            max_blast_radius_mb: 512.0, // Very conservative
            max_kills: 1,               // Only one at a time
            require_known_signature: true,
            require_policy_snapshot: Some(true),
            allow_categories: Vec::new(),
            exclude_categories: vec![
                "database".to_string(),
                "webserver".to_string(),
                "container".to_string(),
                "init".to_string(),
            ],
            require_human_for_supervised: true,
        },
        signature_fast_path: SignatureFastPath::default(),

        fdr_control: FdrControl {
            enabled: true,
            method: FdrMethod::By,   // Strictest method
            alpha: 0.001,            // Extremely low FDR tolerance (0.1%)
            min_candidates: Some(5), // Require many candidates before acting
            lfdr_null: Vec::new(),
            alpha_investing: Some(AlphaInvesting {
                w0: Some(0.001),
                alpha_spend: Some(0.0001),
                alpha_earn: Some(0.0005),
            }),
        },

        data_loss_gates: DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: None, // Any open FDs block
            block_if_locked_files: true,
            block_if_deleted_cwd: Some(true),
            block_if_active_tty: true,
            block_if_recent_io_seconds: Some(3600), // Block if any I/O in last hour
        },

        load_aware: LoadAwareDecision {
            enabled: true,
            queue_high: 200,
            load_per_core_high: 0.5, // More sensitive
            memory_used_fraction_high: 0.95,
            psi_avg10_high: 50.0,
            weights: crate::policy::LoadWeights::default(),
            multipliers: crate::policy::LoadMultipliers {
                keep_max: 2.0,
                reversible_min: 0.3,
                risky_max: 3.0,
            },
        },

        decision_time_bound: DecisionTimeBound {
            enabled: true,
            min_seconds: 300,  // Wait at least 5 minutes
            max_seconds: 1800, // Wait up to 30 minutes
            voi_decay_half_life_seconds: 600,
            voi_floor: 0.05,
            overhead_budget_seconds: 1200,
            fallback_action: "keep".to_string(), // Always default to keeping
        },
    }
}

/// Information about a preset for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetInfo {
    pub name: String,
    pub description: String,
    pub min_process_age_seconds: u64,
    pub max_kills_per_run: u32,
    pub robot_mode_enabled: bool,
    pub min_posterior: f64,
    pub fdr_alpha: f64,
}

impl PresetInfo {
    /// Create info from a preset.
    pub fn from_preset(name: PresetName) -> Self {
        let policy = get_preset(name);
        Self {
            name: name.as_str().to_string(),
            description: name.description().to_string(),
            min_process_age_seconds: policy.guardrails.min_process_age_seconds,
            max_kills_per_run: policy.guardrails.max_kills_per_run,
            robot_mode_enabled: policy.robot_mode.enabled,
            min_posterior: policy.robot_mode.min_posterior,
            fdr_alpha: policy.fdr_control.alpha,
        }
    }
}

/// List all available presets with summary information.
pub fn list_presets() -> Vec<PresetInfo> {
    PresetName::ALL
        .iter()
        .map(|&name| PresetInfo::from_preset(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_name_parsing() {
        assert_eq!(PresetName::parse("developer"), Some(PresetName::Developer));
        assert_eq!(PresetName::parse("dev"), Some(PresetName::Developer));
        assert_eq!(PresetName::parse("server"), Some(PresetName::Server));
        assert_eq!(PresetName::parse("prod"), Some(PresetName::Server));
        assert_eq!(PresetName::parse("ci"), Some(PresetName::Ci));
        assert_eq!(PresetName::parse("paranoid"), Some(PresetName::Paranoid));
        assert_eq!(PresetName::parse("unknown"), None);
    }

    #[test]
    fn test_preset_name_display() {
        assert_eq!(PresetName::Developer.as_str(), "developer");
        assert_eq!(PresetName::Server.as_str(), "server");
        assert_eq!(PresetName::Ci.as_str(), "ci");
        assert_eq!(PresetName::Paranoid.as_str(), "paranoid");
    }

    #[test]
    fn test_developer_preset() {
        let policy = developer_preset();
        assert_eq!(policy.guardrails.min_process_age_seconds, 1800);
        assert_eq!(policy.guardrails.max_kills_per_run, 20);
        assert!(!policy.robot_mode.enabled);
        assert_eq!(policy.fdr_control.alpha, 0.10);
    }

    #[test]
    fn test_server_preset() {
        let policy = server_preset();
        assert_eq!(policy.guardrails.min_process_age_seconds, 14400);
        assert_eq!(policy.guardrails.max_kills_per_run, 5);
        assert!(!policy.robot_mode.enabled);
        assert!(policy.robot_mode.require_known_signature);
        assert_eq!(policy.fdr_control.alpha, 0.01);
    }

    #[test]
    fn test_ci_preset() {
        let policy = ci_preset();
        assert_eq!(policy.guardrails.min_process_age_seconds, 3600);
        assert!(policy.robot_mode.enabled);
        assert_eq!(policy.guardrails.require_confirmation, Some(false));
    }

    #[test]
    fn test_paranoid_preset() {
        let policy = paranoid_preset();
        assert_eq!(policy.guardrails.min_process_age_seconds, 86400);
        assert_eq!(policy.guardrails.max_kills_per_run, 3);
        assert!(!policy.robot_mode.enabled);
        assert_eq!(policy.robot_mode.min_posterior, 0.999);
        assert_eq!(policy.fdr_control.alpha, 0.001);
    }

    #[test]
    fn test_list_presets() {
        let presets = list_presets();
        assert_eq!(presets.len(), 4);
        assert!(presets.iter().any(|p| p.name == "developer"));
        assert!(presets.iter().any(|p| p.name == "server"));
        assert!(presets.iter().any(|p| p.name == "ci"));
        assert!(presets.iter().any(|p| p.name == "paranoid"));
    }

    #[test]
    fn test_preset_error_display() {
        let err = PresetError::UnknownPreset("test".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Unknown preset"));
        assert!(msg.contains("developer"));
    }

    #[test]
    fn test_preset_serialization() {
        let policy = get_preset(PresetName::Developer);
        let json = serde_json::to_string_pretty(&policy).unwrap();
        assert!(json.contains("preset:developer"));
    }

    // ── PresetName parse aliases ──────────────────────────────────────

    #[test]
    fn parse_srv_alias() {
        assert_eq!(PresetName::parse("srv"), Some(PresetName::Server));
    }

    #[test]
    fn parse_production_alias() {
        assert_eq!(PresetName::parse("production"), Some(PresetName::Server));
    }

    #[test]
    fn parse_automation_alias() {
        assert_eq!(PresetName::parse("automation"), Some(PresetName::Ci));
    }

    #[test]
    fn parse_headless_alias() {
        assert_eq!(PresetName::parse("headless"), Some(PresetName::Ci));
    }

    #[test]
    fn parse_safe_alias() {
        assert_eq!(PresetName::parse("safe"), Some(PresetName::Paranoid));
    }

    #[test]
    fn parse_cautious_alias() {
        assert_eq!(PresetName::parse("cautious"), Some(PresetName::Paranoid));
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(PresetName::parse("DEVELOPER"), Some(PresetName::Developer));
        assert_eq!(PresetName::parse("Server"), Some(PresetName::Server));
        assert_eq!(PresetName::parse("CI"), Some(PresetName::Ci));
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(PresetName::parse("").is_none());
        assert!(PresetName::parse("enterprise").is_none());
    }

    // ── PresetName Display / FromStr ──────────────────────────────────

    #[test]
    fn display_matches_as_str() {
        for &p in PresetName::ALL {
            assert_eq!(format!("{}", p), p.as_str());
        }
    }

    #[test]
    fn from_str_roundtrip() {
        for &p in PresetName::ALL {
            let parsed: PresetName = p.as_str().parse().unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn from_str_unknown_error() {
        let err = "nope".parse::<PresetName>().unwrap_err();
        assert!(format!("{}", err).contains("Unknown preset"));
        assert!(format!("{}", err).contains("nope"));
    }

    // ── PresetName ALL constant ───────────────────────────────────────

    #[test]
    fn all_has_four_entries() {
        assert_eq!(PresetName::ALL.len(), 4);
    }

    // ── PresetName description ────────────────────────────────────────

    #[test]
    fn every_preset_has_description() {
        for &p in PresetName::ALL {
            assert!(!p.description().is_empty());
        }
    }

    // ── PresetError variants ──────────────────────────────────────────

    #[test]
    fn preset_error_invalid_override_display() {
        let err = PresetError::InvalidOverride("bad value".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid override"));
        assert!(msg.contains("bad value"));
    }

    #[test]
    fn preset_error_corrupt_file_display() {
        let err = PresetError::CorruptPresetFile("truncated".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Corrupt preset file"));
        assert!(msg.contains("truncated"));
    }

    #[test]
    fn preset_error_is_std_error() {
        let err = PresetError::UnknownPreset("x".to_string());
        let _: &dyn std::error::Error = &err;
    }

    // ── PresetName serde ──────────────────────────────────────────────

    #[test]
    fn preset_name_serde_roundtrip() {
        for &p in PresetName::ALL {
            let json = serde_json::to_string(&p).unwrap();
            let back: PresetName = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn preset_name_serde_lowercase() {
        let json = serde_json::to_string(&PresetName::Ci).unwrap();
        assert_eq!(json, "\"ci\"");
    }

    // ── get_preset dispatches ─────────────────────────────────────────

    #[test]
    fn get_preset_returns_correct_policy_id() {
        for &p in PresetName::ALL {
            let policy = get_preset(p);
            let expected = format!("preset:{}", p.as_str());
            assert_eq!(policy.policy_id.as_deref(), Some(expected.as_str()));
        }
    }

    #[test]
    fn get_preset_all_schema_1_0() {
        for &p in PresetName::ALL {
            assert_eq!(get_preset(p).schema_version, "1.0.0");
        }
    }

    // ── Developer preset specifics ────────────────────────────────────

    #[test]
    fn developer_loss_matrix_aggressive() {
        let p = get_preset(PresetName::Developer);
        // Kill penalty for useful = 50 (lower than server)
        assert!(p.loss_matrix.useful.kill < 100.0);
        // High penalty for keeping abandoned
        assert!(p.loss_matrix.abandoned.keep > 5.0);
    }

    #[test]
    fn developer_guardrails_relaxed() {
        let p = get_preset(PresetName::Developer);
        assert_eq!(p.guardrails.max_kills_per_run, 20);
        assert_eq!(p.guardrails.min_process_age_seconds, 1800);
        assert!(p.guardrails.protected_patterns.len() <= 3);
    }

    #[test]
    fn developer_robot_mode_disabled() {
        let p = get_preset(PresetName::Developer);
        assert!(!p.robot_mode.enabled);
        assert_eq!(p.robot_mode.min_posterior, 0.90);
        assert!(!p.robot_mode.require_known_signature);
    }

    #[test]
    fn developer_fdr_10pct() {
        let p = get_preset(PresetName::Developer);
        assert_eq!(p.fdr_control.method, FdrMethod::Bh);
        assert!((p.fdr_control.alpha - 0.10).abs() < 1e-9);
    }

    #[test]
    fn developer_data_loss_tty_not_blocked() {
        let p = get_preset(PresetName::Developer);
        assert!(!p.data_loss_gates.block_if_active_tty);
    }

    // ── Server preset specifics ───────────────────────────────────────

    #[test]
    fn server_loss_matrix_conservative() {
        let p = get_preset(PresetName::Server);
        assert!(p.loss_matrix.useful.kill >= 1000.0);
        assert!(p.loss_matrix.abandoned.keep < 5.0);
    }

    #[test]
    fn server_guardrails_strict() {
        let p = get_preset(PresetName::Server);
        assert_eq!(p.guardrails.max_kills_per_run, 5);
        assert_eq!(p.guardrails.min_process_age_seconds, 14400);
        assert!(p.guardrails.protected_patterns.len() >= 8);
        assert!(p.guardrails.force_review_patterns.len() >= 2);
    }

    #[test]
    fn server_robot_mode_high_bar() {
        let p = get_preset(PresetName::Server);
        assert!(!p.robot_mode.enabled);
        assert_eq!(p.robot_mode.min_posterior, 0.99);
        assert!(p.robot_mode.require_known_signature);
        assert!(p.robot_mode.require_human_for_supervised);
    }

    #[test]
    fn server_fdr_1pct() {
        let p = get_preset(PresetName::Server);
        assert_eq!(p.fdr_control.method, FdrMethod::By);
        assert!((p.fdr_control.alpha - 0.01).abs() < 1e-9);
        assert!(p.fdr_control.alpha_investing.is_some());
    }

    #[test]
    fn server_load_aware_enabled() {
        let p = get_preset(PresetName::Server);
        assert!(p.load_aware.enabled);
    }

    #[test]
    fn server_decision_time_bound_enabled() {
        let p = get_preset(PresetName::Server);
        assert!(p.decision_time_bound.enabled);
        assert_eq!(p.decision_time_bound.fallback_action, "keep");
    }

    // ── CI preset specifics ───────────────────────────────────────────

    #[test]
    fn ci_robot_mode_enabled() {
        let p = get_preset(PresetName::Ci);
        assert!(p.robot_mode.enabled);
        assert_eq!(p.robot_mode.min_posterior, 0.95);
        assert!(!p.robot_mode.require_human_for_supervised);
    }

    #[test]
    fn ci_no_confirmation() {
        let p = get_preset(PresetName::Ci);
        assert_eq!(p.guardrails.require_confirmation, Some(false));
    }

    #[test]
    fn ci_protects_ci_runners() {
        let p = get_preset(PresetName::Ci);
        let names: Vec<&str> = p
            .guardrails
            .protected_patterns
            .iter()
            .map(|pe| pe.pattern.as_str())
            .collect();
        assert!(names
            .iter()
            .any(|n| n.contains("gitlab-runner") || n.contains("actions-runner")));
    }

    #[test]
    fn ci_force_review_empty() {
        let p = get_preset(PresetName::Ci);
        assert!(p.guardrails.force_review_patterns.is_empty());
    }

    #[test]
    fn ci_fdr_5pct() {
        let p = get_preset(PresetName::Ci);
        assert!((p.fdr_control.alpha - 0.05).abs() < 1e-9);
    }

    #[test]
    fn ci_decision_time_short() {
        let p = get_preset(PresetName::Ci);
        assert!(p.decision_time_bound.max_seconds <= 300);
    }

    // ── Paranoid preset specifics ─────────────────────────────────────

    #[test]
    fn paranoid_loss_matrix_extreme() {
        let p = get_preset(PresetName::Paranoid);
        assert!(p.loss_matrix.useful.kill >= 10000.0);
        assert!(p.loss_matrix.abandoned.kill >= 1.0);
    }

    #[test]
    fn paranoid_guardrails_extreme() {
        let p = get_preset(PresetName::Paranoid);
        assert_eq!(p.guardrails.max_kills_per_run, 3);
        assert_eq!(p.guardrails.min_process_age_seconds, 86400);
        assert!(p.guardrails.protected_patterns.len() >= 15);
    }

    #[test]
    fn paranoid_force_review_all() {
        let p = get_preset(PresetName::Paranoid);
        assert!(!p.guardrails.force_review_patterns.is_empty());
        // The wildcard .* pattern forces review for everything
        let has_wildcard = p
            .guardrails
            .force_review_patterns
            .iter()
            .any(|pe| pe.pattern == ".*");
        assert!(has_wildcard);
    }

    #[test]
    fn paranoid_robot_mode_extreme() {
        let p = get_preset(PresetName::Paranoid);
        assert!(!p.robot_mode.enabled);
        assert!((p.robot_mode.min_posterior - 0.999).abs() < 1e-9);
        assert_eq!(p.robot_mode.max_kills, 1);
    }

    #[test]
    fn paranoid_fdr_0_1pct() {
        let p = get_preset(PresetName::Paranoid);
        assert_eq!(p.fdr_control.method, FdrMethod::By);
        assert!((p.fdr_control.alpha - 0.001).abs() < 1e-9);
        assert_eq!(p.fdr_control.min_candidates, Some(5));
    }

    #[test]
    fn paranoid_data_loss_maximum_blocking() {
        let p = get_preset(PresetName::Paranoid);
        assert!(p.data_loss_gates.block_if_open_write_fds);
        assert!(p.data_loss_gates.block_if_locked_files);
        assert!(p.data_loss_gates.block_if_active_tty);
        assert_eq!(p.data_loss_gates.block_if_recent_io_seconds, Some(3600));
    }

    #[test]
    fn paranoid_load_aware_sensitive() {
        let p = get_preset(PresetName::Paranoid);
        assert!(p.load_aware.enabled);
        assert!(p.load_aware.load_per_core_high <= 0.5);
    }

    #[test]
    fn paranoid_decision_time_long() {
        let p = get_preset(PresetName::Paranoid);
        assert!(p.decision_time_bound.min_seconds >= 300);
        assert!(p.decision_time_bound.max_seconds >= 1800);
    }

    // ── Cross-preset comparisons ──────────────────────────────────────

    #[test]
    fn presets_min_age_ordering() {
        let dev = get_preset(PresetName::Developer);
        let ci = get_preset(PresetName::Ci);
        let srv = get_preset(PresetName::Server);
        let par = get_preset(PresetName::Paranoid);
        assert!(dev.guardrails.min_process_age_seconds < ci.guardrails.min_process_age_seconds);
        assert!(ci.guardrails.min_process_age_seconds < srv.guardrails.min_process_age_seconds);
        assert!(srv.guardrails.min_process_age_seconds < par.guardrails.min_process_age_seconds);
    }

    #[test]
    fn presets_fdr_alpha_ordering() {
        let dev = get_preset(PresetName::Developer);
        let ci = get_preset(PresetName::Ci);
        let srv = get_preset(PresetName::Server);
        let par = get_preset(PresetName::Paranoid);
        assert!(dev.fdr_control.alpha > ci.fdr_control.alpha);
        assert!(ci.fdr_control.alpha > srv.fdr_control.alpha);
        assert!(srv.fdr_control.alpha > par.fdr_control.alpha);
    }

    #[test]
    fn presets_useful_kill_cost_ordering() {
        let dev = get_preset(PresetName::Developer);
        let ci = get_preset(PresetName::Ci);
        let srv = get_preset(PresetName::Server);
        let par = get_preset(PresetName::Paranoid);
        assert!(dev.loss_matrix.useful.kill < ci.loss_matrix.useful.kill);
        assert!(ci.loss_matrix.useful.kill < srv.loss_matrix.useful.kill);
        assert!(srv.loss_matrix.useful.kill < par.loss_matrix.useful.kill);
    }

    #[test]
    fn presets_max_kills_ordering() {
        let dev = get_preset(PresetName::Developer);
        let ci = get_preset(PresetName::Ci);
        let srv = get_preset(PresetName::Server);
        let par = get_preset(PresetName::Paranoid);
        assert!(par.guardrails.max_kills_per_run <= srv.guardrails.max_kills_per_run);
        assert!(srv.guardrails.max_kills_per_run <= ci.guardrails.max_kills_per_run);
        assert!(ci.guardrails.max_kills_per_run <= dev.guardrails.max_kills_per_run);
    }

    // ── PresetInfo ────────────────────────────────────────────────────

    #[test]
    fn preset_info_fields_from_policy() {
        let info = PresetInfo::from_preset(PresetName::Developer);
        assert_eq!(info.name, "developer");
        assert_eq!(info.min_process_age_seconds, 1800);
        assert_eq!(info.max_kills_per_run, 20);
        assert!(!info.robot_mode_enabled);
    }

    #[test]
    fn preset_info_serde_roundtrip() {
        let info = PresetInfo::from_preset(PresetName::Server);
        let json = serde_json::to_string(&info).unwrap();
        let back: PresetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, info.name);
        assert!((back.fdr_alpha - info.fdr_alpha).abs() < 1e-9);
    }

    #[test]
    fn list_presets_covers_all_names() {
        let list = list_presets();
        let names: Vec<&str> = list.iter().map(|p| p.name.as_str()).collect();
        for &p in PresetName::ALL {
            assert!(names.contains(&p.as_str()));
        }
    }

    // ── All presets serde roundtrip ───────────────────────────────────

    #[test]
    fn all_presets_policy_roundtrip() {
        for &p in PresetName::ALL {
            let policy = get_preset(p);
            let json = serde_json::to_string(&policy).unwrap();
            let back: Policy = serde_json::from_str(&json).unwrap();
            assert_eq!(back.policy_id, policy.policy_id);
            assert_eq!(back.schema_version, "1.0.0");
        }
    }
}
