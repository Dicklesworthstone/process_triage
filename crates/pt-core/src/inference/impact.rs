//! Dependency impact score features for process classification.
//!
//! This module computes dependency impact scores used to scale kill-cost in the
//! loss matrix. A higher impact score indicates more external dependencies and
//! higher risk of collateral damage if the process is killed.
//!
//! # Design Philosophy - Conservative by Default
//!
//! **Critical**: Missing data increases uncertainty and defaults to HIGHER impact,
//! not lower. When we can't determine if a process has dependencies, we assume
//! it does. This prevents false negatives (missing critical dependencies) at
//! the cost of some false positives (over-estimating impact).
//!
//! # Impact Components
//!
//! - **Network exposure**: Listen ports, active connections
//! - **Data dependencies**: Open file descriptors, critical write handles
//! - **Supervision status**: Whether managed by orchestrator/agent
//! - **Process tree**: Child processes that would be orphaned
//!
//! # Usage
//!
//! ```no_run
//! use pt_core::inference::impact::{ImpactScorer, compute_impact_score};
//!
//! // Quick single-process scoring
//! let result = compute_impact_score(1234);
//! println!("Impact: {:.2} ({})", result.score, result.severity);
//!
//! // Batch scoring with shared cache
//! let mut scorer = ImpactScorer::new();
//! scorer.populate_caches().ok();
//! for pid in &[1234, 5678] {
//!     let result = scorer.score(*pid);
//!     println!("PID {}: impact={:.2}", pid, result.score);
//! }
//! ```

use crate::collect::{
    collect_network_info, parse_fd, CriticalFileCategory, FdInfo, NetworkInfo, NetworkSnapshot,
};
use crate::supervision::{detect_supervision, CombinedResult, SupervisorCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Configuration for impact score computation.
#[derive(Debug, Clone)]
pub struct ImpactConfig {
    /// Weight for listen port count (default: 0.15).
    pub listen_port_weight: f64,

    /// Weight for established connection count (default: 0.10).
    pub established_conn_weight: f64,

    /// Weight for total open FD count (default: 0.05).
    pub open_fd_weight: f64,

    /// Weight for write FD count (default: 0.10).
    pub write_fd_weight: f64,

    /// Weight for critical write handles (default: 0.25).
    pub critical_write_weight: f64,

    /// Weight for child process count (default: 0.10).
    pub child_count_weight: f64,

    /// Weight for supervision status (default: 0.25).
    pub supervision_weight: f64,

    /// Maximum listen ports to consider (for normalization).
    pub max_listen_ports: usize,

    /// Maximum connections to consider (for normalization).
    pub max_connections: usize,

    /// Maximum FDs to consider (for normalization).
    pub max_fds: usize,

    /// Maximum children to consider (for normalization).
    pub max_children: usize,

    /// Default score when data is unavailable (conservative: high).
    pub missing_data_penalty: f64,
}

impl Default for ImpactConfig {
    fn default() -> Self {
        Self {
            listen_port_weight: 0.15,
            established_conn_weight: 0.10,
            open_fd_weight: 0.05,
            write_fd_weight: 0.10,
            critical_write_weight: 0.25,
            child_count_weight: 0.10,
            supervision_weight: 0.25,
            max_listen_ports: 10,
            max_connections: 50,
            max_fds: 1000,
            max_children: 20,
            missing_data_penalty: 0.5,
        }
    }
}

/// Individual components contributing to the impact score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpactComponents {
    /// Number of listening ports (TCP + UDP).
    pub listen_ports_count: usize,

    /// Number of established/active connections.
    pub established_conns_count: usize,

    /// Total open file descriptors.
    pub open_fds_count: usize,

    /// File descriptors open for writing.
    pub open_write_fds_count: usize,

    /// Critical write handles (databases, locks, etc.).
    pub critical_writes_count: usize,

    /// Critical write categories detected.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub critical_write_categories: Vec<CriticalWriteCategory>,

    /// Number of direct child processes.
    pub child_count: usize,

    /// Supervisor level (none, terminal, orchestrator, agent, etc.).
    pub supervisor_level: SupervisorLevel,

    /// Name of detected supervisor (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_name: Option<String>,

    /// Data sources that were unavailable (for transparency).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_data: Vec<MissingDataSource>,
}

/// Simplified critical write category for output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalWriteCategory {
    /// SQLite WAL/journal files.
    Database,
    /// Git locks and objects.
    Git,
    /// Package manager locks.
    PackageManager,
    /// Application lock files.
    AppLock,
    /// Other open writes.
    Other,
}

impl From<CriticalFileCategory> for CriticalWriteCategory {
    fn from(cat: CriticalFileCategory) -> Self {
        match cat {
            CriticalFileCategory::SqliteWal | CriticalFileCategory::DatabaseWrite => {
                CriticalWriteCategory::Database
            }
            CriticalFileCategory::GitLock | CriticalFileCategory::GitRebase => {
                CriticalWriteCategory::Git
            }
            CriticalFileCategory::SystemPackageLock
            | CriticalFileCategory::NodePackageLock
            | CriticalFileCategory::CargoLock => CriticalWriteCategory::PackageManager,
            CriticalFileCategory::AppLock => CriticalWriteCategory::AppLock,
            CriticalFileCategory::OpenWrite => CriticalWriteCategory::Other,
        }
    }
}

/// Supervisor level for impact scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorLevel {
    /// No supervisor detected.
    #[default]
    None,
    /// Terminal multiplexer (tmux, screen).
    Terminal,
    /// IDE (VS Code, JetBrains).
    Ide,
    /// CI/CD system (GitHub Actions, Jenkins).
    Ci,
    /// System orchestrator (systemd, launchd).
    Orchestrator,
    /// AI agent (Claude, Codex, etc.) - highest protection.
    Agent,
    /// Unknown supervisor (detected but unclassified).
    Unknown,
}

impl SupervisorLevel {
    /// Get the protection weight for this supervisor level.
    ///
    /// Higher values indicate stronger protection against killing.
    pub fn protection_weight(&self) -> f64 {
        match self {
            SupervisorLevel::None => 0.0,
            SupervisorLevel::Terminal => 0.3,
            SupervisorLevel::Ide => 0.5,
            SupervisorLevel::Ci => 0.8,
            SupervisorLevel::Orchestrator => 0.9,
            SupervisorLevel::Agent => 1.0,
            SupervisorLevel::Unknown => 0.6,
        }
    }
}

impl From<Option<SupervisorCategory>> for SupervisorLevel {
    fn from(cat: Option<SupervisorCategory>) -> Self {
        match cat {
            None => SupervisorLevel::None,
            Some(SupervisorCategory::Agent) => SupervisorLevel::Agent,
            Some(SupervisorCategory::Ide) => SupervisorLevel::Ide,
            Some(SupervisorCategory::Ci) => SupervisorLevel::Ci,
            Some(SupervisorCategory::Orchestrator) => SupervisorLevel::Orchestrator,
            Some(SupervisorCategory::Terminal) => SupervisorLevel::Terminal,
            Some(SupervisorCategory::Other) => SupervisorLevel::Unknown,
        }
    }
}

/// Data sources that were unavailable during scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingDataSource {
    /// Network information unavailable.
    Network,
    /// File descriptor information unavailable.
    FileDescriptors,
    /// File descriptor inspection truncated (too many FDs).
    TruncatedFileDescriptors,
    /// Supervision detection failed.
    Supervision,
    /// Process tree information unavailable.
    ProcessTree,
}

/// Severity classification of impact score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactSeverity {
    /// Low impact (0.0-0.25) - safe to kill with normal caution.
    Low,
    /// Medium impact (0.25-0.5) - review before killing.
    Medium,
    /// High impact (0.5-0.75) - significant dependencies, careful review required.
    High,
    /// Critical impact (0.75-1.0) - should not be auto-killed.
    Critical,
}

impl ImpactSeverity {
    /// Classify a score into a severity level.
    pub fn from_score(score: f64) -> Self {
        if score < 0.25 {
            ImpactSeverity::Low
        } else if score < 0.5 {
            ImpactSeverity::Medium
        } else if score < 0.75 {
            ImpactSeverity::High
        } else {
            ImpactSeverity::Critical
        }
    }
}

impl std::fmt::Display for ImpactSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ImpactSeverity::Low => "low",
            ImpactSeverity::Medium => "medium",
            ImpactSeverity::High => "high",
            ImpactSeverity::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

/// Result of impact score computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactResult {
    /// Normalized impact score (0.0-1.0).
    pub score: f64,

    /// Severity classification.
    pub severity: ImpactSeverity,

    /// Individual component values.
    pub components: ImpactComponents,

    /// Human-readable explanation of key factors.
    pub explanation: String,

    /// Whether score is elevated due to missing data (conservative default).
    pub elevated_due_to_missing_data: bool,
}

impl ImpactResult {
    /// Create a result for a process that couldn't be analyzed.
    pub fn unavailable(pid: u32) -> Self {
        Self {
            score: 0.75, // Conservative: assume high impact
            severity: ImpactSeverity::High,
            components: ImpactComponents {
                missing_data: vec![
                    MissingDataSource::Network,
                    MissingDataSource::FileDescriptors,
                    MissingDataSource::Supervision,
                    MissingDataSource::ProcessTree,
                ],
                ..Default::default()
            },
            explanation: format!(
                "Process {} could not be analyzed; assuming high impact for safety",
                pid
            ),
            elevated_due_to_missing_data: true,
        }
    }
}

/// Errors from impact score computation.
#[derive(Debug, Error)]
pub enum ImpactError {
    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Permission denied for process {0}")]
    PermissionDenied(u32),
}

/// Evidence for impact score (for ledger integration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactEvidence {
    /// The computed impact score.
    pub score: f64,

    /// Individual components.
    pub components: ImpactComponents,

    /// Severity level.
    pub severity: ImpactSeverity,

    /// Whether elevated due to missing data.
    pub elevated: bool,
}

impl From<&ImpactResult> for ImpactEvidence {
    fn from(result: &ImpactResult) -> Self {
        Self {
            score: result.score,
            components: result.components.clone(),
            severity: result.severity,
            elevated: result.elevated_due_to_missing_data,
        }
    }
}

/// Impact scorer with caching for batch operations.
pub struct ImpactScorer {
    config: ImpactConfig,
    child_count_cache: HashMap<u32, usize>,
    #[cfg(target_os = "linux")]
    network_snapshot: Option<NetworkSnapshot>,
}

impl ImpactScorer {
    /// Create a new scorer with default configuration.
    pub fn new() -> Self {
        Self::with_config(ImpactConfig::default())
    }

    /// Create a scorer with custom configuration.
    pub fn with_config(config: ImpactConfig) -> Self {
        Self {
            config,
            child_count_cache: HashMap::new(),
            #[cfg(target_os = "linux")]
            network_snapshot: None,
        }
    }

    /// Populate caches for efficient batch scoring.
    ///
    /// This pre-computes child counts for all processes.
    #[cfg(target_os = "linux")]
    pub fn populate_caches(&mut self) -> Result<(), ImpactError> {
        self.child_count_cache.clear();
        self.network_snapshot = Some(NetworkSnapshot::collect());

        // Read all PIDs and their PPIDs to build child count map
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                if let Ok(pid) = name_str.parse::<u32>() {
                    if let Some(ppid) = self.read_ppid(pid) {
                        *self.child_count_cache.entry(ppid).or_insert(0) += 1;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn populate_caches(&mut self) -> Result<(), ImpactError> {
        Ok(())
    }

    /// Read PPID for a process.
    #[cfg(target_os = "linux")]
    fn read_ppid(&self, pid: u32) -> Option<u32> {
        let stat_path = format!("/proc/{}/stat", pid);
        let content = std::fs::read_to_string(&stat_path).ok()?;

        // Find end of comm field (after closing paren)
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;

        // PPID is the second field after comm
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        fields.get(1)?.parse().ok()
    }

    #[cfg(not(target_os = "linux"))]
    fn read_ppid(&self, _pid: u32) -> Option<u32> {
        None
    }

    /// Get child count for a process.
    fn get_child_count(&self, pid: u32) -> Option<usize> {
        // First check cache
        if let Some(&count) = self.child_count_cache.get(&pid) {
            return Some(count);
        }

        // If cache not populated, scan /proc
        #[cfg(target_os = "linux")]
        {
            let mut count = 0;
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(child_pid) = name_str.parse::<u32>() {
                        if let Some(ppid) = self.read_ppid(child_pid) {
                            if ppid == pid {
                                count += 1;
                            }
                        }
                    }
                }
            }
            Some(count)
        }

        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Score a single process.
    pub fn score(&self, pid: u32) -> ImpactResult {
        let mut components = ImpactComponents::default();
        let mut missing_data = Vec::new();

        // Collect network information
        #[cfg(target_os = "linux")]
        let network_info_opt = if let Some(snapshot) = &self.network_snapshot {
            snapshot.get_process_info(pid)
        } else {
            collect_network_info(pid)
        };

        #[cfg(not(target_os = "linux"))]
        let network_info_opt: Option<NetworkInfo> = None;

        let network_score = match network_info_opt {
            Some(net_info) => {
                let (score, listen, established) = self.score_network(&net_info);
                components.listen_ports_count = listen;
                components.established_conns_count = established;
                score
            }
            None => {
                missing_data.push(MissingDataSource::Network);
                self.config.missing_data_penalty
            }
        };

        // Collect file descriptor information
        let fd_score = match parse_fd(pid) {
            Some(fd_info) => {
                if fd_info.truncated {
                    missing_data.push(MissingDataSource::TruncatedFileDescriptors);
                }
                let (score, total, write, critical, categories) = self.score_fds(&fd_info);
                components.open_fds_count = total;
                components.open_write_fds_count = write;
                components.critical_writes_count = critical;
                components.critical_write_categories = categories;
                
                // If truncated, ensure score is at least high enough to trigger caution
                if fd_info.truncated {
                    score.max(0.75) // Treat as Critical/High impact
                } else {
                    score
                }
            }
            None => {
                missing_data.push(MissingDataSource::FileDescriptors);
                self.config.missing_data_penalty
            }
        };

        // Detect supervision
        let supervision_score = match detect_supervision(pid) {
            Ok(result) => {
                let (score, level, name) = self.score_supervision(&result);
                components.supervisor_level = level;
                components.supervisor_name = name;
                score
            }
            Err(_) => {
                missing_data.push(MissingDataSource::Supervision);
                // Conservative: assume some supervision
                self.config.missing_data_penalty * 0.5
            }
        };

        // Get child count
        let child_score = match self.get_child_count(pid) {
            Some(count) => {
                components.child_count = count;
                self.score_children(count)
            }
            None => {
                missing_data.push(MissingDataSource::ProcessTree);
                self.config.missing_data_penalty * 0.3
            }
        };

        components.missing_data = missing_data.clone();

        // Compute weighted total
        let raw_score = network_score
            * (self.config.listen_port_weight + self.config.established_conn_weight)
            + fd_score
                * (self.config.open_fd_weight
                    + self.config.write_fd_weight
                    + self.config.critical_write_weight)
            + supervision_score * self.config.supervision_weight
            + child_score * self.config.child_count_weight;

        // Clamp to [0, 1]
        let score = raw_score.clamp(0.0, 1.0);
        let severity = ImpactSeverity::from_score(score);
        let elevated = !missing_data.is_empty();

        // Generate explanation
        let explanation = self.generate_explanation(pid, &components, score, elevated);

        ImpactResult {
            score,
            severity,
            components,
            explanation,
            elevated_due_to_missing_data: elevated,
        }
    }

    /// Score network-related impact.
    fn score_network(&self, info: &NetworkInfo) -> (f64, usize, usize) {
        let listen_count = info.listen_ports.len();
        let established_count = info
            .tcp_connections
            .iter()
            .filter(|c| c.state.is_active())
            .count();

        // Normalize counts
        let listen_normalized =
            (listen_count as f64 / self.config.max_listen_ports as f64).min(1.0);
        let conn_normalized =
            (established_count as f64 / self.config.max_connections as f64).min(1.0);

        // Combine with higher weight on listen ports (server capability)
        let score = listen_normalized * 0.6 + conn_normalized * 0.4;

        (score, listen_count, established_count)
    }

    /// Score file descriptor-related impact.
    fn score_fds(&self, info: &FdInfo) -> (f64, usize, usize, usize, Vec<CriticalWriteCategory>) {
        let total_fds = info.count;
        let write_fds = info.open_files.iter().filter(|f| f.mode.write).count();
        let critical_count = info.critical_writes.len();

        // Collect unique critical categories
        let mut categories: Vec<CriticalWriteCategory> = info
            .critical_writes
            .iter()
            .map(|c| CriticalWriteCategory::from(c.category))
            .collect();
        categories.sort_by_key(|c| *c as u8);
        categories.dedup();

        // Normalize
        let fd_normalized = (total_fds as f64 / self.config.max_fds as f64).min(1.0);
        let write_normalized = (write_fds as f64 / 100.0).min(1.0); // Normalize to ~100 write FDs

        // Critical writes are heavily weighted
        let critical_normalized = if critical_count > 0 {
            // Any critical write is significant
            (0.5 + 0.5 * (critical_count as f64 / 5.0)).min(1.0)
        } else {
            0.0
        };

        // Combine scores
        let score = fd_normalized * 0.2 + write_normalized * 0.3 + critical_normalized * 0.5;

        (score, total_fds, write_fds, critical_count, categories)
    }

    /// Score supervision-related impact.
    fn score_supervision(&self, result: &CombinedResult) -> (f64, SupervisorLevel, Option<String>) {
        let level: SupervisorLevel = result.supervisor_type.into();
        let name = result.supervisor_name.clone();

        // Supervised processes get protection score based on supervisor type
        let score = if result.is_supervised {
            level.protection_weight() * result.confidence
        } else {
            0.0
        };

        (score, level, name)
    }

    /// Score child process impact.
    fn score_children(&self, count: usize) -> f64 {
        (count as f64 / self.config.max_children as f64).min(1.0)
    }

    /// Generate human-readable explanation.
    fn generate_explanation(
        &self,
        pid: u32,
        components: &ImpactComponents,
        score: f64,
        elevated: bool,
    ) -> String {
        let mut factors = Vec::new();

        if components.listen_ports_count > 0 {
            factors.push(format!(
                "{} listening port{}",
                components.listen_ports_count,
                if components.listen_ports_count == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }

        if components.established_conns_count > 0 {
            factors.push(format!(
                "{} active connection{}",
                components.established_conns_count,
                if components.established_conns_count == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }

        if components.critical_writes_count > 0 {
            factors.push(format!(
                "{} critical write handle{}",
                components.critical_writes_count,
                if components.critical_writes_count == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }

        if components.child_count > 0 {
            factors.push(format!(
                "{} child process{}",
                components.child_count,
                if components.child_count == 1 {
                    ""
                } else {
                    "es"
                }
            ));
        }

        if components.supervisor_level != SupervisorLevel::None {
            let supervisor_str = components
                .supervisor_name
                .as_ref()
                .map(|n| format!(" ({})", n))
                .unwrap_or_default();
            factors.push(format!(
                "supervised by {:?}{}",
                components.supervisor_level, supervisor_str
            ));
        }

        let factors_str = if factors.is_empty() {
            "no significant dependencies detected".to_string()
        } else {
            factors.join(", ")
        };

        let elevated_str = if elevated {
            " (elevated due to missing data)"
        } else {
            ""
        };

        format!(
            "PID {}: impact={:.2} ({}){}; {}",
            pid,
            score,
            ImpactSeverity::from_score(score),
            elevated_str,
            factors_str
        )
    }
}

impl Default for ImpactScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for single-process impact scoring.
pub fn compute_impact_score(pid: u32) -> ImpactResult {
    let scorer = ImpactScorer::new();
    scorer.score(pid)
}

/// Batch compute impact scores efficiently.
pub fn compute_impact_scores_batch(pids: &[u32]) -> Vec<(u32, ImpactResult)> {
    let mut scorer = ImpactScorer::new();
    let _ = scorer.populate_caches();

    pids.iter().map(|&pid| (pid, scorer.score(pid))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impact_config_default() {
        let config = ImpactConfig::default();
        // Weights should sum to approximately 1.0
        let total = config.listen_port_weight
            + config.established_conn_weight
            + config.open_fd_weight
            + config.write_fd_weight
            + config.critical_write_weight
            + config.child_count_weight
            + config.supervision_weight;
        assert!((total - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_impact_severity_from_score() {
        assert_eq!(ImpactSeverity::from_score(0.0), ImpactSeverity::Low);
        assert_eq!(ImpactSeverity::from_score(0.24), ImpactSeverity::Low);
        assert_eq!(ImpactSeverity::from_score(0.25), ImpactSeverity::Medium);
        assert_eq!(ImpactSeverity::from_score(0.49), ImpactSeverity::Medium);
        assert_eq!(ImpactSeverity::from_score(0.5), ImpactSeverity::High);
        assert_eq!(ImpactSeverity::from_score(0.74), ImpactSeverity::High);
        assert_eq!(ImpactSeverity::from_score(0.75), ImpactSeverity::Critical);
        assert_eq!(ImpactSeverity::from_score(1.0), ImpactSeverity::Critical);
    }

    #[test]
    fn test_supervisor_level_protection_weight() {
        assert_eq!(SupervisorLevel::None.protection_weight(), 0.0);
        assert!(
            SupervisorLevel::Terminal.protection_weight()
                < SupervisorLevel::Agent.protection_weight()
        );
        assert!(
            SupervisorLevel::Ide.protection_weight()
                < SupervisorLevel::Orchestrator.protection_weight()
        );
        assert_eq!(SupervisorLevel::Agent.protection_weight(), 1.0);
    }

    #[test]
    fn test_supervisor_level_from_category() {
        assert_eq!(
            SupervisorLevel::from(Some(SupervisorCategory::Agent)),
            SupervisorLevel::Agent
        );
        assert_eq!(
            SupervisorLevel::from(Some(SupervisorCategory::Orchestrator)),
            SupervisorLevel::Orchestrator
        );
        assert_eq!(SupervisorLevel::from(None), SupervisorLevel::None);
    }

    #[test]
    fn test_critical_write_category_from() {
        assert_eq!(
            CriticalWriteCategory::from(CriticalFileCategory::SqliteWal),
            CriticalWriteCategory::Database
        );
        assert_eq!(
            CriticalWriteCategory::from(CriticalFileCategory::GitLock),
            CriticalWriteCategory::Git
        );
        assert_eq!(
            CriticalWriteCategory::from(CriticalFileCategory::SystemPackageLock),
            CriticalWriteCategory::PackageManager
        );
    }

    #[test]
    fn test_impact_result_unavailable() {
        let result = ImpactResult::unavailable(1234);
        assert!(result.score >= 0.75);
        assert!(result.elevated_due_to_missing_data);
        assert!(!result.components.missing_data.is_empty());
    }

    #[test]
    fn test_impact_scorer_new() {
        let scorer = ImpactScorer::new();
        // Should create without panic
        let _ = scorer;
    }

    #[test]
    fn test_impact_components_default() {
        let components = ImpactComponents::default();
        assert_eq!(components.listen_ports_count, 0);
        assert_eq!(components.supervisor_level, SupervisorLevel::None);
        assert!(components.critical_write_categories.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_compute_impact_score_self() {
        let pid = std::process::id();
        let result = compute_impact_score(pid);

        // Should successfully score our own process
        assert!(result.score >= 0.0);
        assert!(result.score <= 1.0);
        assert!(!result.explanation.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_impact_scorer_with_cache() {
        let mut scorer = ImpactScorer::new();
        let _ = scorer.populate_caches();

        let pid = std::process::id();
        let result = scorer.score(pid);

        assert!(result.score >= 0.0);
        assert!(result.score <= 1.0);
    }

    #[test]
    fn test_impact_evidence_from_result() {
        let result = ImpactResult {
            score: 0.6,
            severity: ImpactSeverity::High,
            components: ImpactComponents {
                listen_ports_count: 2,
                ..Default::default()
            },
            explanation: "test".to_string(),
            elevated_due_to_missing_data: false,
        };

        let evidence: ImpactEvidence = (&result).into();
        assert_eq!(evidence.score, 0.6);
        assert_eq!(evidence.severity, ImpactSeverity::High);
        assert_eq!(evidence.components.listen_ports_count, 2);
    }

    #[test]
    fn test_network_scoring() {
        let scorer = ImpactScorer::new();

        // Empty network info should score low
        let empty_net = NetworkInfo::default();
        let (score, listen, established) = scorer.score_network(&empty_net);
        assert_eq!(score, 0.0);
        assert_eq!(listen, 0);
        assert_eq!(established, 0);
    }

    #[test]
    fn test_fd_scoring_empty() {
        let scorer = ImpactScorer::new();

        let empty_fd = FdInfo::default();
        let (score, total, write, critical, categories) = scorer.score_fds(&empty_fd);
        assert_eq!(score, 0.0);
        assert_eq!(total, 0);
        assert_eq!(write, 0);
        assert_eq!(critical, 0);
        assert!(categories.is_empty());
    }

    #[test]
    fn test_child_scoring() {
        let scorer = ImpactScorer::new();

        assert_eq!(scorer.score_children(0), 0.0);
        assert!(scorer.score_children(10) > 0.0);
        assert!(scorer.score_children(10) < scorer.score_children(20));
        // Max capped at 1.0
        assert!(scorer.score_children(100) <= 1.0);
    }

    #[test]
    fn test_explanation_generation() {
        let scorer = ImpactScorer::new();

        let components = ImpactComponents {
            listen_ports_count: 2,
            established_conns_count: 5,
            critical_writes_count: 1,
            supervisor_level: SupervisorLevel::Agent,
            supervisor_name: Some("claude".to_string()),
            ..Default::default()
        };

        let explanation = scorer.generate_explanation(1234, &components, 0.8, false);

        assert!(explanation.contains("1234"));
        assert!(explanation.contains("2 listening ports"));
        assert!(explanation.contains("5 active connections"));
        assert!(explanation.contains("1 critical write handle"));
        assert!(explanation.contains("Agent"));
        assert!(explanation.contains("claude"));
    }

    #[test]
    fn test_explanation_with_missing_data() {
        let scorer = ImpactScorer::new();

        let components = ImpactComponents::default();
        let explanation = scorer.generate_explanation(1234, &components, 0.5, true);

        assert!(explanation.contains("elevated due to missing data"));
    }
}
