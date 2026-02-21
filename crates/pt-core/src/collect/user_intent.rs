//! User-intent/context feature computation for process triage.
//!
//! This module implements user-intent features per Plan §3.2 and §8 "context priors":
//! - Active controlling TTY / recent TTY activity
//! - tmux/screen session attribution
//! - Recent shell activity heuristics
//! - Repo activity windows (git status timestamps, file modification recency)
//! - Editor focus signals (optional, privacy-safe, opt-in)
//!
//! These features help avoid false kills by detecting when a process is likely
//! part of an *active workflow*.
//!
//! # Privacy
//!
//! All features respect redaction/hashing policy. Default behavior does not require
//! invasive telemetry. Missing context is always explicit (not silently assumed).
//!
//! # Example
//!
//! ```no_run
//! use pt_core::collect::user_intent::{collect_user_intent, UserIntentConfig};
//!
//! let config = UserIntentConfig::default();
//! if let Some(features) = collect_user_intent(1234, &config) {
//!     println!("User intent score: {:.2}", features.user_intent_score);
//!     for evidence in &features.evidence {
//!         println!("  - {}: {:.2}", evidence.signal_type.name(), evidence.weight);
//!     }
//! }
//! ```

#[cfg(target_os = "linux")]
use crate::collect::parse_proc_stat as read_proc_stat;
use crate::supervision::session::{
    detect_screen_session, detect_ssh_connection, detect_tmux_session,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};

/// Schema version for user intent features.
pub const USER_INTENT_SCHEMA_VERSION: &str = "1.0.0";

/// Maximum age for "recent" TTY activity (seconds).
const RECENT_TTY_ACTIVITY_SECS: u64 = 300; // 5 minutes

/// Maximum age for "recent" repo activity (seconds).
const RECENT_REPO_ACTIVITY_SECS: u64 = 600; // 10 minutes

/// Maximum age for "recent" shell activity (seconds).
const RECENT_SHELL_ACTIVITY_SECS: u64 = 300; // 5 minutes

/// Signal types for user intent detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentSignalType {
    /// Process has an active controlling TTY.
    ActiveTty,
    /// Process shows recent TTY activity (input/output).
    RecentTtyActivity,
    /// Process is in a tmux session.
    TmuxSession,
    /// Process is in a screen session.
    ScreenSession,
    /// Process is in an SSH session chain.
    SshSession,
    /// Process has a recent shell parent.
    RecentShellActivity,
    /// Process CWD is in an active repo.
    ActiveRepoContext,
    /// Process is associated with an active editor (opt-in).
    EditorFocus,
    /// Process is the foreground job in its terminal.
    ForegroundJob,
    /// Process session has multiple active processes.
    ActiveSessionContext,
}

impl IntentSignalType {
    /// Get human-readable name for this signal type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ActiveTty => "active_tty",
            Self::RecentTtyActivity => "recent_tty_activity",
            Self::TmuxSession => "tmux_session",
            Self::ScreenSession => "screen_session",
            Self::SshSession => "ssh_session",
            Self::RecentShellActivity => "recent_shell_activity",
            Self::ActiveRepoContext => "active_repo_context",
            Self::EditorFocus => "editor_focus",
            Self::ForegroundJob => "foreground_job",
            Self::ActiveSessionContext => "active_session_context",
        }
    }

    /// Get the default weight for this signal type.
    pub fn default_weight(&self) -> f64 {
        match self {
            Self::ActiveTty => 0.7,
            Self::RecentTtyActivity => 0.8,
            Self::TmuxSession => 0.85,
            Self::ScreenSession => 0.85,
            Self::SshSession => 0.6,
            Self::RecentShellActivity => 0.65,
            Self::ActiveRepoContext => 0.75,
            Self::EditorFocus => 0.9,
            Self::ForegroundJob => 0.95,
            Self::ActiveSessionContext => 0.5,
        }
    }
}

/// Evidence for user intent detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentEvidence {
    /// Type of signal detected.
    pub signal_type: IntentSignalType,
    /// Weight/confidence of this signal (0.0 to 1.0).
    pub weight: f64,
    /// Human-readable description.
    pub description: String,
    /// Additional structured data (privacy-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IntentMetadata>,
}

/// Structured metadata for intent evidence (privacy-safe).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntentMetadata {
    /// TTY device info.
    Tty { device: String },
    /// Tmux session info (sanitized).
    Tmux {
        server_pid: Option<u32>,
        socket_hash: String,
    },
    /// Screen session info (sanitized).
    Screen {
        session_pid: Option<u32>,
        session_hash: String,
    },
    /// SSH connection info (sanitized, no IPs).
    Ssh { connection_hash: String },
    /// Repo activity info.
    Repo {
        last_modified_secs_ago: u64,
        has_uncommitted_changes: Option<bool>,
    },
    /// Shell activity info.
    Shell { shell_type: String, shell_pid: u32 },
    /// Foreground job info.
    Foreground { pgid: u32, tpgid: i32 },
}

/// User intent features for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIntentFeatures {
    /// Process ID.
    pub pid: u32,

    /// Normalized user intent score (0.0 to 1.0).
    /// Higher values indicate stronger evidence of active user engagement.
    pub user_intent_score: f64,

    /// Individual evidence items contributing to the score.
    pub evidence: Vec<IntentEvidence>,

    /// Privacy mode metadata.
    pub privacy_mode: PrivacyMode,

    /// Provenance tracking.
    pub provenance: UserIntentProvenance,

    /// Schema version for reproducibility.
    pub schema_version: String,
}

impl UserIntentFeatures {
    /// Create features indicating no user intent detected.
    pub fn none(pid: u32, privacy_mode: PrivacyMode) -> Self {
        Self {
            pid,
            user_intent_score: 0.0,
            evidence: vec![],
            privacy_mode,
            provenance: UserIntentProvenance::default(),
            schema_version: USER_INTENT_SCHEMA_VERSION.to_string(),
        }
    }

    /// Check if any intent signals were detected.
    pub fn has_intent(&self) -> bool {
        self.user_intent_score > 0.0
    }

    /// Get the strongest signal type (if any).
    pub fn strongest_signal(&self) -> Option<IntentSignalType> {
        self.evidence
            .iter()
            .max_by(|a, b| {
                a.weight
                    .partial_cmp(&b.weight)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| e.signal_type)
    }
}

/// Privacy mode metadata tracking what was collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyMode {
    /// Whether TTY detection was enabled.
    pub tty_enabled: bool,
    /// Whether TTY detection succeeded.
    pub tty_collected: bool,

    /// Whether session multiplexer detection was enabled.
    pub session_mux_enabled: bool,
    /// Whether session multiplexer detection succeeded.
    pub session_mux_collected: bool,

    /// Whether SSH detection was enabled.
    pub ssh_enabled: bool,
    /// Whether SSH detection succeeded.
    pub ssh_collected: bool,

    /// Whether shell activity detection was enabled.
    pub shell_activity_enabled: bool,
    /// Whether shell activity detection succeeded.
    pub shell_activity_collected: bool,

    /// Whether repo activity detection was enabled.
    pub repo_activity_enabled: bool,
    /// Whether repo activity detection succeeded.
    pub repo_activity_collected: bool,

    /// Whether editor focus detection was enabled (opt-in).
    pub editor_focus_enabled: bool,
    /// Whether editor focus detection succeeded.
    pub editor_focus_collected: bool,

    /// Signals that were skipped due to privacy settings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_signals: Vec<String>,
}

impl Default for PrivacyMode {
    fn default() -> Self {
        Self {
            tty_enabled: true,
            tty_collected: false,
            session_mux_enabled: true,
            session_mux_collected: false,
            ssh_enabled: true,
            ssh_collected: false,
            shell_activity_enabled: true,
            shell_activity_collected: false,
            repo_activity_enabled: true,
            repo_activity_collected: false,
            editor_focus_enabled: false, // Opt-in by default
            editor_focus_collected: false,
            skipped_signals: vec![],
        }
    }
}

/// Provenance tracking for user intent computation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserIntentProvenance {
    /// Timestamp when collection was performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_at_unix_us: Option<u64>,

    /// Number of signals checked.
    pub signals_checked: u32,

    /// Number of signals detected.
    pub signals_detected: u32,

    /// Scoring method used.
    pub scoring_method: ScoringMethod,

    /// Data sources consulted.
    pub data_sources: Vec<String>,

    /// Warnings during collection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Method used to compute the final intent score.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoringMethod {
    /// Maximum of all signal weights.
    #[default]
    MaxWeight,
    /// Weighted average of signal weights.
    WeightedAverage,
    /// Probabilistic combination (1 - product of (1 - weights)).
    Probabilistic,
}

/// Configuration for user intent collection.
#[derive(Debug, Clone)]
pub struct UserIntentConfig {
    /// Enable TTY detection.
    pub enable_tty: bool,
    /// Enable session multiplexer detection (tmux/screen).
    pub enable_session_mux: bool,
    /// Enable SSH session detection.
    pub enable_ssh: bool,
    /// Enable shell activity detection.
    pub enable_shell_activity: bool,
    /// Enable repo activity detection.
    pub enable_repo_activity: bool,
    /// Enable editor focus detection (opt-in feature).
    pub enable_editor_focus: bool,
    /// Scoring method for combining signals.
    pub scoring_method: ScoringMethod,
    /// Custom signal weights (overrides defaults).
    pub custom_weights: HashMap<IntentSignalType, f64>,
    /// Maximum age for recent TTY activity (seconds).
    pub recent_tty_secs: u64,
    /// Maximum age for recent repo activity (seconds).
    pub recent_repo_secs: u64,
    /// Maximum age for recent shell activity (seconds).
    pub recent_shell_secs: u64,
}

impl Default for UserIntentConfig {
    fn default() -> Self {
        Self {
            enable_tty: true,
            enable_session_mux: true,
            enable_ssh: true,
            enable_shell_activity: true,
            enable_repo_activity: true,
            enable_editor_focus: false, // Opt-in
            scoring_method: ScoringMethod::MaxWeight,
            custom_weights: HashMap::new(),
            recent_tty_secs: RECENT_TTY_ACTIVITY_SECS,
            recent_repo_secs: RECENT_REPO_ACTIVITY_SECS,
            recent_shell_secs: RECENT_SHELL_ACTIVITY_SECS,
        }
    }
}

impl UserIntentConfig {
    /// Get the weight for a signal type (custom or default).
    pub fn weight_for(&self, signal: IntentSignalType) -> f64 {
        self.custom_weights
            .get(&signal)
            .copied()
            .unwrap_or_else(|| signal.default_weight())
    }
}

/// Collect user intent features for a process.
///
/// # Arguments
/// * `pid` - Process ID to analyze
/// * `config` - Configuration for collection
///
/// # Returns
/// * `Option<UserIntentFeatures>` - Features or None if process not found
#[cfg(target_os = "linux")]
pub fn collect_user_intent(pid: u32, config: &UserIntentConfig) -> Option<UserIntentFeatures> {
    trace!(pid, "collecting user intent features");

    let mut evidence = Vec::new();
    let mut privacy_mode = PrivacyMode::default();
    let mut provenance = UserIntentProvenance::default();
    let mut data_sources = Vec::new();

    let now = SystemTime::now();
    provenance.collected_at_unix_us = now
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_micros() as u64);

    // Read process stat
    // parse_proc_stat returns Option, so we don't need .ok()
    let proc_stat = read_proc_stat(pid)?;
    data_sources.push("proc_stat".to_string());

    let mut signals_checked = 0u32;

    // 1. TTY detection
    privacy_mode.tty_enabled = config.enable_tty;
    if config.enable_tty {
        signals_checked += 1;
        if let Some(tty_evidence) = detect_tty_signals(pid, &proc_stat, config) {
            privacy_mode.tty_collected = true;
            data_sources.push("proc_fd".to_string());
            evidence.extend(tty_evidence);
        }
    } else {
        privacy_mode.skipped_signals.push("tty".to_string());
    }

    // 2. Session multiplexer detection (tmux/screen)
    privacy_mode.session_mux_enabled = config.enable_session_mux;
    if config.enable_session_mux {
        signals_checked += 1;
        if let Some(mux_evidence) = detect_session_mux_signals(pid, config) {
            privacy_mode.session_mux_collected = true;
            data_sources.push("proc_environ".to_string());
            evidence.extend(mux_evidence);
        }
    } else {
        privacy_mode.skipped_signals.push("session_mux".to_string());
    }

    // 3. SSH detection
    privacy_mode.ssh_enabled = config.enable_ssh;
    if config.enable_ssh {
        signals_checked += 1;
        if let Some(ssh_evidence) = detect_ssh_signals(pid, config) {
            privacy_mode.ssh_collected = true;
            evidence.extend(ssh_evidence);
        }
    } else {
        privacy_mode.skipped_signals.push("ssh".to_string());
    }

    // 4. Shell activity detection
    privacy_mode.shell_activity_enabled = config.enable_shell_activity;
    if config.enable_shell_activity {
        signals_checked += 1;
        if let Some(shell_evidence) = detect_shell_activity_signals(pid, config) {
            privacy_mode.shell_activity_collected = true;
            evidence.extend(shell_evidence);
        }
    } else {
        privacy_mode
            .skipped_signals
            .push("shell_activity".to_string());
    }

    // 5. Repo activity detection
    privacy_mode.repo_activity_enabled = config.enable_repo_activity;
    if config.enable_repo_activity {
        signals_checked += 1;
        if let Some(repo_evidence) = detect_repo_activity_signals(pid, config) {
            privacy_mode.repo_activity_collected = true;
            data_sources.push("cwd_stat".to_string());
            evidence.extend(repo_evidence);
        }
    } else {
        privacy_mode
            .skipped_signals
            .push("repo_activity".to_string());
    }

    // 6. Editor focus detection (opt-in)
    privacy_mode.editor_focus_enabled = config.enable_editor_focus;
    if config.enable_editor_focus {
        signals_checked += 1;
        if let Some(editor_evidence) = detect_editor_focus_signals(pid, config) {
            privacy_mode.editor_focus_collected = true;
            evidence.extend(editor_evidence);
        }
    } else {
        privacy_mode
            .skipped_signals
            .push("editor_focus".to_string());
    }

    // Compute final score
    let user_intent_score = compute_intent_score(&evidence, config);

    provenance.signals_checked = signals_checked;
    provenance.signals_detected = evidence.len() as u32;
    provenance.scoring_method = config.scoring_method;
    provenance.data_sources = data_sources;

    debug!(
        pid,
        score = user_intent_score,
        signals = evidence.len(),
        "user intent features collected"
    );

    Some(UserIntentFeatures {
        pid,
        user_intent_score,
        evidence,
        privacy_mode,
        provenance,
        schema_version: USER_INTENT_SCHEMA_VERSION.to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn collect_user_intent(pid: u32, _config: &UserIntentConfig) -> Option<UserIntentFeatures> {
    // Non-Linux platforms: return empty features
    let privacy_mode = PrivacyMode::default();
    Some(UserIntentFeatures::none(pid, privacy_mode))
}

#[cfg(target_os = "linux")]
use crate::collect::ProcessStat;

/// Detect TTY-related intent signals.
#[cfg(target_os = "linux")]
fn detect_tty_signals(
    pid: u32,
    proc_stat: &ProcessStat,
    config: &UserIntentConfig,
) -> Option<Vec<IntentEvidence>> {
    let mut evidence = Vec::new();

    // Check if process has a controlling TTY
    if proc_stat.tty_nr != 0 {
        let tty_device = format!("tty:{}", proc_stat.tty_nr);
        evidence.push(IntentEvidence {
            signal_type: IntentSignalType::ActiveTty,
            weight: config.weight_for(IntentSignalType::ActiveTty),
            description: format!("Process has controlling TTY ({})", proc_stat.tty_nr),
            metadata: Some(IntentMetadata::Tty { device: tty_device }),
        });

        // Check if process is foreground job
        if proc_stat.tpgid > 0 && proc_stat.pgrp == proc_stat.tpgid {
            evidence.push(IntentEvidence {
                signal_type: IntentSignalType::ForegroundJob,
                weight: config.weight_for(IntentSignalType::ForegroundJob),
                description: format!(
                    "Process is in foreground process group (PGID={}, TPGID={})",
                    proc_stat.pgrp, proc_stat.tpgid
                ),
                metadata: Some(IntentMetadata::Foreground {
                    pgid: proc_stat.pgrp as u32,
                    tpgid: proc_stat.tpgid,
                }),
            });
        }
    }

    // Check for recent TTY activity by examining fd timestamps
    if let Some(activity_evidence) = detect_recent_tty_activity(pid, config) {
        evidence.push(activity_evidence);
    }

    if evidence.is_empty() {
        None
    } else {
        Some(evidence)
    }
}

/// Detect recent TTY activity by examining file descriptor timestamps.
#[cfg(target_os = "linux")]
fn detect_recent_tty_activity(pid: u32, config: &UserIntentConfig) -> Option<IntentEvidence> {
    let fd_path = format!("/proc/{}/fd", pid);

    // Check stdin (fd 0), stdout (fd 1), stderr (fd 2)
    for fd in [0, 1, 2] {
        let link_path = format!("{}/{}", fd_path, fd);
        if let Ok(target) = fs::read_link(&link_path) {
            let target_str = target.to_string_lossy();
            // Check if it's a tty/pts device
            if target_str.contains("/dev/pts/") || target_str.contains("/dev/tty") {
                // Check modification and access time of the target file (not the symlink)
                if let Ok(metadata) = fs::metadata(&link_path) {
                    let mut min_age_secs = u64::MAX;
                    if let Ok(accessed) = metadata.accessed() {
                        if let Ok(age) = SystemTime::now().duration_since(accessed) {
                            min_age_secs = min_age_secs.min(age.as_secs());
                        }
                    }
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = SystemTime::now().duration_since(modified) {
                            min_age_secs = min_age_secs.min(age.as_secs());
                        }
                    }
                    
                    if min_age_secs < config.recent_tty_secs {
                        return Some(IntentEvidence {
                            signal_type: IntentSignalType::RecentTtyActivity,
                            weight: config.weight_for(IntentSignalType::RecentTtyActivity),
                            description: format!(
                                "Recent TTY activity on fd {} ({} secs ago)",
                                fd,
                                min_age_secs
                            ),
                            metadata: Some(IntentMetadata::Tty {
                                device: target_str.to_string(),
                            }),
                        });
                    }
                }
            }
        }
    }

    None
}

/// Detect session multiplexer signals (tmux/screen).
#[cfg(target_os = "linux")]
fn detect_session_mux_signals(pid: u32, config: &UserIntentConfig) -> Option<Vec<IntentEvidence>> {
    let mut evidence = Vec::new();

    // Check for tmux session
    if let Some(tmux_info) = detect_tmux_session(pid) {
        let socket_hash = hash_string(&tmux_info.socket_path);
        evidence.push(IntentEvidence {
            signal_type: IntentSignalType::TmuxSession,
            weight: config.weight_for(IntentSignalType::TmuxSession),
            description: format!(
                "Process is in tmux session (server PID: {:?})",
                tmux_info.server_pid
            ),
            metadata: Some(IntentMetadata::Tmux {
                server_pid: tmux_info.server_pid,
                socket_hash,
            }),
        });
    }

    // Check for screen session
    if let Some(screen_info) = detect_screen_session(pid) {
        let session_hash = hash_string(&screen_info.session_id);
        evidence.push(IntentEvidence {
            signal_type: IntentSignalType::ScreenSession,
            weight: config.weight_for(IntentSignalType::ScreenSession),
            description: format!("Process is in screen session (PID: {:?})", screen_info.pid),
            metadata: Some(IntentMetadata::Screen {
                session_pid: screen_info.pid,
                session_hash,
            }),
        });
    }

    if evidence.is_empty() {
        None
    } else {
        Some(evidence)
    }
}

/// Detect SSH session signals.
#[cfg(target_os = "linux")]
fn detect_ssh_signals(pid: u32, config: &UserIntentConfig) -> Option<Vec<IntentEvidence>> {
    let ssh_info = detect_ssh_connection(pid)?;

    // Hash the connection info for privacy
    let connection_str = format!(
        "{}:{}->{}:{}",
        ssh_info.client_ip, ssh_info.client_port, ssh_info.server_ip, ssh_info.server_port
    );
    let connection_hash = hash_string(&connection_str);

    Some(vec![IntentEvidence {
        signal_type: IntentSignalType::SshSession,
        weight: config.weight_for(IntentSignalType::SshSession),
        description: "Process is in an SSH session".to_string(),
        metadata: Some(IntentMetadata::Ssh { connection_hash }),
    }])
}

/// Shell process names for detection.
const SHELL_NAMES: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "tcsh", "csh", "ksh", "ash",
];

/// Detect shell activity signals.
#[cfg(target_os = "linux")]
fn detect_shell_activity_signals(
    pid: u32,
    config: &UserIntentConfig,
) -> Option<Vec<IntentEvidence>> {
    // Walk up the process tree looking for recent shell activity
    let mut current_pid = pid;
    let mut depth = 0;
    const MAX_DEPTH: u32 = 10;

    while depth < MAX_DEPTH {
        let proc_stat = read_proc_stat(current_pid)?;

        // Check if this is a shell
        let comm_lower = proc_stat.comm.to_lowercase();
        if SHELL_NAMES.iter().any(|&s| comm_lower == s) {
            // Check if shell has recent activity by checking its stdin TTY
            let fd0_path = format!("/proc/{}/fd/0", current_pid);
            if let Ok(target) = fs::read_link(&fd0_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("/dev/pts/") || target_str.contains("/dev/tty") {
                    if let Ok(metadata) = fs::metadata(&fd0_path) {
                        if let Ok(accessed) = metadata.accessed() {
                            if let Ok(age) = SystemTime::now().duration_since(accessed) {
                                if age.as_secs() < config.recent_shell_secs {
                                    return Some(vec![IntentEvidence {
                                        signal_type: IntentSignalType::RecentShellActivity,
                                        weight: config.weight_for(IntentSignalType::RecentShellActivity),
                                        description: format!(
                                            "Parent shell {} (PID {}) has recent activity ({} secs ago)",
                                            proc_stat.comm,
                                            current_pid,
                                            age.as_secs()
                                        ),
                                        metadata: Some(IntentMetadata::Shell {
                                            shell_type: proc_stat.comm.clone(),
                                            shell_pid: current_pid,
                                        }),
                                    }]);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Move to parent
        if proc_stat.ppid == 0 || proc_stat.ppid == current_pid {
            break;
        }
        current_pid = proc_stat.ppid;
        depth += 1;
    }

    None
}

/// Detect repo activity signals.
#[cfg(target_os = "linux")]
fn detect_repo_activity_signals(
    pid: u32,
    config: &UserIntentConfig,
) -> Option<Vec<IntentEvidence>> {
    // Get process CWD
    let cwd_path = format!("/proc/{}/cwd", pid);
    let cwd = fs::read_link(&cwd_path).ok()?;

    // Look for .git directory in CWD or parents
    let mut search_path = cwd.as_path();
    let mut git_dir: Option<std::path::PathBuf> = None;

    for _ in 0..10 {
        let potential_git = search_path.join(".git");
        if potential_git.exists() {
            git_dir = Some(potential_git);
            break;
        }
        match search_path.parent() {
            Some(parent) => search_path = parent,
            None => break,
        }
    }

    let git_dir = git_dir?;

    // Check git index or HEAD for recent modification
    let index_path = git_dir.join("index");
    let head_path = git_dir.join("HEAD");

    let mut most_recent_secs: Option<u64> = None;

    for path in [&index_path, &head_path] {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = SystemTime::now().duration_since(modified) {
                    let age_secs = age.as_secs();
                    if age_secs < config.recent_repo_secs {
                        most_recent_secs = Some(
                            most_recent_secs
                                .map(|prev| prev.min(age_secs))
                                .unwrap_or(age_secs),
                        );
                    }
                }
            }
        }
    }

    let last_modified_secs = most_recent_secs?;

    Some(vec![IntentEvidence {
        signal_type: IntentSignalType::ActiveRepoContext,
        weight: config.weight_for(IntentSignalType::ActiveRepoContext),
        description: format!(
            "Process CWD is in git repo with recent activity ({} secs ago)",
            last_modified_secs
        ),
        metadata: Some(IntentMetadata::Repo {
            last_modified_secs_ago: last_modified_secs,
            has_uncommitted_changes: None, // Could check git status but privacy concern
        }),
    }])
}

/// Detect editor focus signals (opt-in feature).
#[cfg(target_os = "linux")]
fn detect_editor_focus_signals(
    _pid: u32,
    _config: &UserIntentConfig,
) -> Option<Vec<IntentEvidence>> {
    // Editor focus detection is complex and platform-specific.
    // This is a placeholder for future implementation.
    // Possible approaches:
    // - Check X11/Wayland focused window
    // - Check for editor socket connections
    // - Check for editor-specific environment variables
    //
    // For now, this feature is opt-in and not implemented.
    None
}

/// Compute the final intent score from evidence.
fn compute_intent_score(evidence: &[IntentEvidence], config: &UserIntentConfig) -> f64 {
    if evidence.is_empty() {
        return 0.0;
    }

    match config.scoring_method {
        ScoringMethod::MaxWeight => evidence
            .iter()
            .map(|e| e.weight)
            .fold(0.0f64, |a, b| a.max(b)),
        ScoringMethod::WeightedAverage => {
            let sum: f64 = evidence.iter().map(|e| e.weight).sum();
            sum / evidence.len() as f64
        }
        ScoringMethod::Probabilistic => {
            // P(at least one intent) = 1 - P(no intent)
            // P(no intent) = product of (1 - weight) for each signal
            let no_intent_prob: f64 = evidence.iter().map(|e| 1.0 - e.weight).product();
            1.0 - no_intent_prob
        }
    }
}

/// Hash a string for privacy-safe logging (truncated SHA-256).
fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8]) // First 8 bytes = 16 hex chars
}

/// Batch collect user intent features for multiple processes.
pub fn collect_user_intent_batch(
    pids: &[u32],
    config: &UserIntentConfig,
) -> Vec<(u32, Option<UserIntentFeatures>)> {
    pids.iter()
        .map(|&pid| (pid, collect_user_intent(pid, config)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_signal_default_weights() {
        assert!(IntentSignalType::ForegroundJob.default_weight() > 0.9);
        assert!(IntentSignalType::TmuxSession.default_weight() > 0.8);
        assert!(IntentSignalType::ActiveTty.default_weight() > 0.5);
    }

    #[test]
    fn test_intent_signal_names() {
        assert_eq!(IntentSignalType::ActiveTty.name(), "active_tty");
        assert_eq!(IntentSignalType::TmuxSession.name(), "tmux_session");
        assert_eq!(IntentSignalType::ForegroundJob.name(), "foreground_job");
    }

    #[test]
    fn test_scoring_methods() {
        let evidence = vec![
            IntentEvidence {
                signal_type: IntentSignalType::ActiveTty,
                weight: 0.7,
                description: "test".to_string(),
                metadata: None,
            },
            IntentEvidence {
                signal_type: IntentSignalType::TmuxSession,
                weight: 0.85,
                description: "test".to_string(),
                metadata: None,
            },
        ];

        // MaxWeight
        let config_max = UserIntentConfig {
            scoring_method: ScoringMethod::MaxWeight,
            ..Default::default()
        };
        let score_max = compute_intent_score(&evidence, &config_max);
        assert!((score_max - 0.85).abs() < 0.001);

        // WeightedAverage
        let config_avg = UserIntentConfig {
            scoring_method: ScoringMethod::WeightedAverage,
            ..Default::default()
        };
        let score_avg = compute_intent_score(&evidence, &config_avg);
        assert!((score_avg - 0.775).abs() < 0.001);

        // Probabilistic
        let config_prob = UserIntentConfig {
            scoring_method: ScoringMethod::Probabilistic,
            ..Default::default()
        };
        let score_prob = compute_intent_score(&evidence, &config_prob);
        // 1 - (1-0.7) * (1-0.85) = 1 - 0.3 * 0.15 = 1 - 0.045 = 0.955
        assert!((score_prob - 0.955).abs() < 0.001);
    }

    #[test]
    fn test_empty_evidence_score() {
        let evidence: Vec<IntentEvidence> = vec![];
        let config = UserIntentConfig::default();
        assert_eq!(compute_intent_score(&evidence, &config), 0.0);
    }

    #[test]
    fn test_privacy_mode_default() {
        let privacy = PrivacyMode::default();
        assert!(privacy.tty_enabled);
        assert!(privacy.session_mux_enabled);
        assert!(!privacy.editor_focus_enabled); // Opt-in
    }

    #[test]
    fn test_user_intent_features_none() {
        let features = UserIntentFeatures::none(1234, PrivacyMode::default());
        assert_eq!(features.pid, 1234);
        assert_eq!(features.user_intent_score, 0.0);
        assert!(features.evidence.is_empty());
        assert!(!features.has_intent());
        assert!(features.strongest_signal().is_none());
    }

    #[test]
    fn test_config_custom_weights() {
        let mut config = UserIntentConfig::default();
        config
            .custom_weights
            .insert(IntentSignalType::ActiveTty, 0.99);

        assert_eq!(config.weight_for(IntentSignalType::ActiveTty), 0.99);
        assert_eq!(
            config.weight_for(IntentSignalType::TmuxSession),
            IntentSignalType::TmuxSession.default_weight()
        );
    }

    #[test]
    fn test_hash_string() {
        let hash1 = hash_string("test");
        let hash2 = hash_string("test");
        let hash3 = hash_string("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_user_intent_features_strongest_signal() {
        let mut features = UserIntentFeatures::none(1234, PrivacyMode::default());
        features.evidence.push(IntentEvidence {
            signal_type: IntentSignalType::ActiveTty,
            weight: 0.7,
            description: "test".to_string(),
            metadata: None,
        });
        features.evidence.push(IntentEvidence {
            signal_type: IntentSignalType::ForegroundJob,
            weight: 0.95,
            description: "test".to_string(),
            metadata: None,
        });
        features.user_intent_score = 0.95;

        assert!(features.has_intent());
        assert_eq!(
            features.strongest_signal(),
            Some(IntentSignalType::ForegroundJob)
        );
    }

    #[test]
    fn test_intent_metadata_serialization() {
        let metadata = IntentMetadata::Tty {
            device: "/dev/pts/0".to_string(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("tty"));
        assert!(json.contains("/dev/pts/0"));

        let metadata = IntentMetadata::Tmux {
            server_pid: Some(1234),
            socket_hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("tmux"));
        assert!(json.contains("1234"));
    }

    #[test]
    fn test_provenance_default() {
        let prov = UserIntentProvenance::default();
        assert_eq!(prov.signals_checked, 0);
        assert_eq!(prov.signals_detected, 0);
        assert_eq!(prov.scoring_method, ScoringMethod::MaxWeight);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_collect_user_intent_current_process() {
        let pid = std::process::id();
        let config = UserIntentConfig::default();
        let features = collect_user_intent(pid, &config);

        assert!(features.is_some());
        let features = features.unwrap();
        assert_eq!(features.pid, pid);
        assert!(!features.schema_version.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_collect_user_intent_batch() {
        let pid = std::process::id();
        let config = UserIntentConfig::default();
        let results = collect_user_intent_batch(&[pid], &config);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, pid);
        assert!(results[0].1.is_some());
    }

    // === Deterministic fixture tests for session attribution ===

    #[test]
    fn test_tmux_metadata_hashing_is_deterministic() {
        // Same socket path should produce same hash
        let socket1 = "/tmp/tmux-1000/default";
        let socket2 = "/tmp/tmux-1000/default";
        let socket_different = "/tmp/tmux-2000/other";

        let hash1 = hash_string(socket1);
        let hash2 = hash_string(socket2);
        let hash3 = hash_string(socket_different);

        assert_eq!(hash1, hash2, "Same socket path should produce same hash");
        assert_ne!(
            hash1, hash3,
            "Different paths should produce different hashes"
        );
    }

    #[test]
    fn test_screen_metadata_hashing_is_deterministic() {
        // Same session ID should produce same hash
        let session1 = "12345.pts-0.hostname";
        let session2 = "12345.pts-0.hostname";
        let session_different = "67890.pts-1.otherhost";

        let hash1 = hash_string(session1);
        let hash2 = hash_string(session2);
        let hash3 = hash_string(session_different);

        assert_eq!(hash1, hash2, "Same session ID should produce same hash");
        assert_ne!(
            hash1, hash3,
            "Different sessions should produce different hashes"
        );
    }

    #[test]
    fn test_ssh_connection_hashing_is_deterministic() {
        // Same connection info should produce same hash
        let conn1 = "192.168.1.100:54321->192.168.1.1:22";
        let conn2 = "192.168.1.100:54321->192.168.1.1:22";
        let conn_different = "10.0.0.5:12345->10.0.0.1:22";

        let hash1 = hash_string(conn1);
        let hash2 = hash_string(conn2);
        let hash3 = hash_string(conn_different);

        assert_eq!(hash1, hash2, "Same connection should produce same hash");
        assert_ne!(
            hash1, hash3,
            "Different connections should produce different hashes"
        );
    }

    // === Privacy tests ===

    #[test]
    fn test_privacy_mode_tracks_all_signals() {
        let privacy = PrivacyMode::default();

        // Verify default privacy toggles match the intended defaults.
        assert!(privacy.tty_enabled);
        assert!(privacy.session_mux_enabled);
        assert!(privacy.ssh_enabled);
        assert!(privacy.shell_activity_enabled);
        assert!(privacy.repo_activity_enabled);
        assert!(!privacy.editor_focus_enabled); // Opt-in only
    }

    #[test]
    fn test_privacy_mode_default_disables_invasive_signals() {
        let privacy = PrivacyMode::default();

        // Editor focus should be disabled by default (opt-in only)
        assert!(!privacy.editor_focus_enabled);
    }

    #[test]
    fn test_privacy_mode_skipped_signals_tracking() {
        let mut privacy = PrivacyMode {
            tty_enabled: false,
            ..Default::default()
        };

        // Simulate disabled signals
        privacy.skipped_signals.push("tty".to_string());

        assert!(privacy.skipped_signals.contains(&"tty".to_string()));
    }

    #[test]
    fn test_metadata_does_not_leak_raw_paths() {
        // Tmux metadata should hash the socket path
        let metadata = IntentMetadata::Tmux {
            server_pid: Some(1234),
            socket_hash: hash_string("/tmp/tmux-1000/default"),
        };
        let json = serde_json::to_string(&metadata).unwrap();

        // Should not contain raw path
        assert!(!json.contains("/tmp/tmux"), "Should not contain raw path");
        // Should contain only the hash
        assert!(json.contains("socket_hash"));
    }

    #[test]
    fn test_metadata_does_not_leak_ip_addresses() {
        // SSH metadata should hash connection info
        let metadata = IntentMetadata::Ssh {
            connection_hash: hash_string("192.168.1.100:54321->192.168.1.1:22"),
        };
        let json = serde_json::to_string(&metadata).unwrap();

        // Should not contain raw IP
        assert!(!json.contains("192.168"), "Should not contain raw IP");
        assert!(!json.contains(":22"), "Should not contain port info");
    }

    #[test]
    fn test_repo_metadata_does_not_leak_file_contents() {
        // Repo metadata should only contain timing info, not file contents
        let metadata = IntentMetadata::Repo {
            last_modified_secs_ago: 300,
            has_uncommitted_changes: None, // Explicitly not tracked for privacy
        };
        let json = serde_json::to_string(&metadata).unwrap();

        // Should only contain timing info
        assert!(json.contains("last_modified_secs_ago"));
        assert!(!json.contains("file_content"));
        assert!(!json.contains("diff"));
    }

    // === Signal weight boundary tests ===

    #[test]
    fn test_all_signal_weights_are_valid() {
        // All signal types should have weights in [0, 1]
        let signals = [
            IntentSignalType::ActiveTty,
            IntentSignalType::RecentTtyActivity,
            IntentSignalType::TmuxSession,
            IntentSignalType::ScreenSession,
            IntentSignalType::SshSession,
            IntentSignalType::RecentShellActivity,
            IntentSignalType::ActiveRepoContext,
            IntentSignalType::EditorFocus,
            IntentSignalType::ForegroundJob,
            IntentSignalType::ActiveSessionContext,
        ];

        for signal in signals {
            let weight = signal.default_weight();
            assert!(
                (0.0..=1.0).contains(&weight),
                "Signal {:?} weight {} is out of bounds",
                signal,
                weight
            );
        }
    }

    #[test]
    fn test_scoring_methods_produce_valid_scores() {
        // Test that all scoring methods produce scores in [0, 1]
        let evidence = vec![
            IntentEvidence {
                signal_type: IntentSignalType::ActiveTty,
                weight: 0.7,
                description: "test".to_string(),
                metadata: None,
            },
            IntentEvidence {
                signal_type: IntentSignalType::TmuxSession,
                weight: 0.85,
                description: "test".to_string(),
                metadata: None,
            },
            IntentEvidence {
                signal_type: IntentSignalType::ForegroundJob,
                weight: 0.95,
                description: "test".to_string(),
                metadata: None,
            },
        ];

        for method in [
            ScoringMethod::MaxWeight,
            ScoringMethod::WeightedAverage,
            ScoringMethod::Probabilistic,
        ] {
            let config = UserIntentConfig {
                scoring_method: method,
                ..Default::default()
            };
            let score = compute_intent_score(&evidence, &config);
            assert!(
                (0.0..=1.0).contains(&score),
                "Scoring method {:?} produced invalid score {}",
                method,
                score
            );
        }
    }

    // === Serialization round-trip tests ===

    #[test]
    fn test_user_intent_features_serialization_roundtrip() {
        let mut features = UserIntentFeatures::none(1234, PrivacyMode::default());
        features.evidence.push(IntentEvidence {
            signal_type: IntentSignalType::TmuxSession,
            weight: 0.85,
            description: "In tmux session".to_string(),
            metadata: Some(IntentMetadata::Tmux {
                server_pid: Some(5678),
                socket_hash: "abc123def456".to_string(),
            }),
        });
        features.user_intent_score = 0.85;
        features.provenance.signals_checked = 5;
        features.provenance.signals_detected = 1;

        // Serialize and deserialize
        let json = serde_json::to_string_pretty(&features).unwrap();
        let parsed: UserIntentFeatures = serde_json::from_str(&json).unwrap();

        assert_eq!(features.pid, parsed.pid);
        assert!((features.user_intent_score - parsed.user_intent_score).abs() < 0.001);
        assert_eq!(features.evidence.len(), parsed.evidence.len());
        assert_eq!(features.schema_version, parsed.schema_version);
    }

    #[test]
    fn test_privacy_mode_serialization_roundtrip() {
        let mut privacy = PrivacyMode {
            tty_collected: true,
            ..Default::default()
        };
        privacy.skipped_signals.push("editor_focus".to_string());

        let json = serde_json::to_string(&privacy).unwrap();
        let parsed: PrivacyMode = serde_json::from_str(&json).unwrap();

        assert_eq!(privacy.tty_enabled, parsed.tty_enabled);
        assert_eq!(privacy.tty_collected, parsed.tty_collected);
        assert_eq!(privacy.skipped_signals, parsed.skipped_signals);
    }

    // === Config validation tests ===

    #[test]
    fn test_config_with_all_disabled() {
        let config = UserIntentConfig {
            enable_tty: false,
            enable_session_mux: false,
            enable_ssh: false,
            enable_shell_activity: false,
            enable_repo_activity: false,
            enable_editor_focus: false,
            ..Default::default()
        };

        // With all disabled, we should track what was skipped
        let evidence: Vec<IntentEvidence> = vec![];
        let score = compute_intent_score(&evidence, &config);
        assert_eq!(score, 0.0, "No evidence should produce zero score");
    }

    #[test]
    fn test_config_time_thresholds() {
        let config = UserIntentConfig::default();

        // Verify reasonable defaults
        assert!(config.recent_tty_secs > 0);
        assert!(config.recent_repo_secs > 0);
        assert!(config.recent_shell_secs > 0);

        // Verify tty threshold is less than repo threshold (tty is more recent)
        assert!(
            config.recent_tty_secs <= config.recent_repo_secs,
            "TTY recency should be at most as long as repo recency"
        );
    }

    #[test]
    fn test_schema_version_is_valid_semver() {
        let version = USER_INTENT_SCHEMA_VERSION;
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3, "Schema version should be semver format");
        for part in parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "Each semver part should be numeric"
            );
        }
    }
}
