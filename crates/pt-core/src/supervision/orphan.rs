//! Unexpected reparenting (orphan) feature detection.
//!
//! This module provides the `unexpected_reparenting` feature that indicates whether
//! a process with PPID=1 is truly orphaned (unexpected) or expected (managed by a supervisor).
//!
//! Key insight from the plan: **PPID=1 is not universally orphan**:
//! - macOS launchd manages services as direct children
//! - Containers have their own PID 1
//! - Supervisor daemons (systemd, pm2) intentionally parent to init
//! - nohup/disown processes intentionally orphan themselves
//!
//! This feature conditions on supervision context to produce meaningful evidence.

use super::nohup::{detect_nohup, BackgroundIntent, NohupError, NohupResult};
use super::{detect_supervision, CombinedResult, DetectionError, SupervisorCategory};
use serde::{Deserialize, Serialize};
use std::fs;
use thiserror::Error;

/// Errors from orphan detection.
#[derive(Debug, Error)]
pub enum OrphanError {
    #[error("Detection error: {0}")]
    Detection(#[from] DetectionError),

    #[error("Nohup detection error: {0}")]
    Nohup(#[from] NohupError),

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Reason why reparenting was classified as expected or unexpected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReparentingReason {
    /// PPID is not 1, not orphaned.
    NotOrphaned,
    /// Reparented to init without any detected supervision.
    ReparentedToInitWithoutSupervision,
    /// PID 1 is a known supervisor (systemd, launchd, etc.).
    Pid1IsSupervisorExpected,
    /// Running in a container where PID 1 is expected.
    ContainerPid1Expected,
    /// Process was intentionally backgrounded (nohup/disown).
    IntentionallyBackgrounded,
    /// Process is supervised by an agent/IDE/CI (not orphaned).
    SupervisedByAutomation,
    /// macOS launchd manages the process.
    LaunchdManaged,
    /// Systemd manages the process.
    SystemdManaged,
    /// tmux/screen session parent.
    TerminalMultiplexerManaged,
    /// Unable to determine reason.
    Unknown,
}

impl std::fmt::Display for ReparentingReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ReparentingReason::NotOrphaned => "not_orphaned",
            ReparentingReason::ReparentedToInitWithoutSupervision => {
                "reparented_to_init_without_supervision"
            }
            ReparentingReason::Pid1IsSupervisorExpected => "pid1_is_supervisor_expected",
            ReparentingReason::ContainerPid1Expected => "container_pid1_expected",
            ReparentingReason::IntentionallyBackgrounded => "intentionally_backgrounded",
            ReparentingReason::SupervisedByAutomation => "supervised_by_automation",
            ReparentingReason::LaunchdManaged => "launchd_managed",
            ReparentingReason::SystemdManaged => "systemd_managed",
            ReparentingReason::TerminalMultiplexerManaged => "terminal_multiplexer_managed",
            ReparentingReason::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

/// Result of unexpected reparenting detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanResult {
    /// The process ID analyzed.
    pub pid: u32,
    /// The process's parent PID.
    pub ppid: u32,
    /// Whether the reparenting is unexpected (true = evidence of abandonment).
    pub unexpected_reparenting: bool,
    /// Reason for the classification.
    pub reason: ReparentingReason,
    /// Confidence in the classification (0.0-1.0).
    pub confidence: f64,
    /// Whether the process is supervised.
    pub is_supervised: bool,
    /// Supervision detection result (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervision: Option<SupervisionSummary>,
    /// Nohup detection result (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nohup: Option<NohupSummary>,
    /// Whether running in a container.
    pub in_container: bool,
    /// Explanation of the classification for telemetry/debugging.
    pub explanation: String,
}

/// Summary of supervision detection for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisionSummary {
    /// Whether supervision was detected.
    pub is_supervised: bool,
    /// Supervisor category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_type: Option<SupervisorCategory>,
    /// Supervisor name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_name: Option<String>,
    /// Confidence score.
    pub confidence: f64,
}

impl From<&CombinedResult> for SupervisionSummary {
    fn from(r: &CombinedResult) -> Self {
        Self {
            is_supervised: r.is_supervised,
            supervisor_type: r.supervisor_type,
            supervisor_name: r.supervisor_name.clone(),
            confidence: r.confidence,
        }
    }
}

/// Summary of nohup detection for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NohupSummary {
    /// Whether process appears backgrounded.
    pub is_background: bool,
    /// Inferred intent.
    pub intent: String,
    /// Whether SIGHUP is ignored.
    pub ignores_sighup: bool,
}

impl From<&NohupResult> for NohupSummary {
    fn from(r: &NohupResult) -> Self {
        Self {
            is_background: r.is_background,
            intent: match r.inferred_intent {
                BackgroundIntent::Intentional => "intentional".to_string(),
                BackgroundIntent::Forgotten => "forgotten".to_string(),
                BackgroundIntent::Unknown => "unknown".to_string(),
            },
            ignores_sighup: r.ignores_sighup,
        }
    }
}

/// Check if we're running inside a container.
#[cfg(target_os = "linux")]
pub fn detect_container() -> bool {
    // Check common container indicators

    // 1. Check for /.dockerenv
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }

    // 2. Check cgroup for container patterns
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("/docker/")
            || cgroup.contains("/kubepods/")
            || cgroup.contains("/lxc/")
            || cgroup.contains("/containerd/")
        {
            return true;
        }
    }

    // 3. Check /proc/1/environ for container hints
    if let Ok(environ) = fs::read("/proc/1/environ") {
        let environ_str = String::from_utf8_lossy(&environ);
        if environ_str.contains("KUBERNETES_") || environ_str.contains("container=") {
            return true;
        }
    }

    // 4. Check if PID 1 is not init/systemd
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let comm = comm.trim();
        // If PID 1 is not a typical init system, we're likely in a container
        if ![
            "init",
            "systemd",
            "launchd",
            "upstart",
            "runit",
            "s6-svscan",
        ]
        .contains(&comm)
        {
            // Could be a container entrypoint
            return true;
        }
    }

    false
}

#[cfg(target_os = "macos")]
pub fn detect_container() -> bool {
    // macOS doesn't typically run in containers in the same way
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn detect_container() -> bool {
    false
}

/// Read PPID from /proc/<pid>/stat.
#[cfg(target_os = "linux")]
fn read_ppid(pid: u32) -> Result<u32, OrphanError> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OrphanError::ProcessNotFound(pid)
        } else {
            OrphanError::IoError(e)
        }
    })?;

    // Format: pid (comm) state ppid ...
    let close_paren = content
        .rfind(')')
        .ok_or(OrphanError::ProcessNotFound(pid))?;
    let rest = &content[close_paren + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    if fields.len() < 2 {
        return Err(OrphanError::ProcessNotFound(pid));
    }

    fields[1]
        .parse()
        .map_err(|_| OrphanError::ProcessNotFound(pid))
}

#[cfg(not(target_os = "linux"))]
fn read_ppid(_pid: u32) -> Result<u32, OrphanError> {
    Ok(0)
}

/// Analyzer for unexpected reparenting detection.
pub struct OrphanAnalyzer {
    /// Cached container detection result.
    in_container: bool,
}

impl OrphanAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            in_container: detect_container(),
        }
    }

    /// Analyze a process for unexpected reparenting.
    pub fn analyze(&self, pid: u32) -> Result<OrphanResult, OrphanError> {
        let ppid = read_ppid(pid)?;

        // If PPID is not 1, not orphaned at all
        if ppid != 1 {
            return Ok(OrphanResult {
                pid,
                ppid,
                unexpected_reparenting: false,
                reason: ReparentingReason::NotOrphaned,
                confidence: 1.0,
                is_supervised: false, // Will check later if needed
                supervision: None,
                nohup: None,
                in_container: self.in_container,
                explanation: format!("Process has parent PID {}, not orphaned", ppid),
            });
        }

        // PPID is 1, need to determine if this is expected or unexpected
        self.analyze_orphaned(pid, ppid)
    }

    /// Analyze a process that has PPID=1.
    fn analyze_orphaned(&self, pid: u32, ppid: u32) -> Result<OrphanResult, OrphanError> {
        let mut result = OrphanResult {
            pid,
            ppid,
            unexpected_reparenting: true, // Default to unexpected, will update
            reason: ReparentingReason::Unknown,
            confidence: 0.5,
            is_supervised: false,
            supervision: None,
            nohup: None,
            in_container: self.in_container,
            explanation: String::new(),
        };

        // Check for container context first
        if self.in_container {
            result.unexpected_reparenting = false;
            result.reason = ReparentingReason::ContainerPid1Expected;
            result.confidence = 0.9;
            result.explanation = "Running in container, PPID=1 is expected".to_string();
            return Ok(result);
        }

        // Check supervision detection
        if let Ok(supervision) = detect_supervision(pid) {
            result.supervision = Some(SupervisionSummary::from(&supervision));
            result.is_supervised = supervision.is_supervised;

            if supervision.is_supervised {
                result.unexpected_reparenting = false;
                result.confidence = supervision.confidence;

                // Determine specific reason based on supervisor type
                match supervision.supervisor_type {
                    Some(SupervisorCategory::Orchestrator) => {
                        // Check if it's systemd or launchd
                        let name = supervision.supervisor_name.as_deref().unwrap_or("");
                        if name.contains("systemd") {
                            result.reason = ReparentingReason::SystemdManaged;
                            result.explanation = format!(
                                "Process is managed by systemd ({})",
                                supervision.supervisor_name.as_deref().unwrap_or("unknown")
                            );
                        } else if name.contains("launchd") {
                            result.reason = ReparentingReason::LaunchdManaged;
                            result.explanation = format!(
                                "Process is managed by launchd ({})",
                                supervision.supervisor_name.as_deref().unwrap_or("unknown")
                            );
                        } else {
                            result.reason = ReparentingReason::Pid1IsSupervisorExpected;
                            result.explanation = format!(
                                "Process is managed by orchestrator: {}",
                                supervision.supervisor_name.as_deref().unwrap_or("unknown")
                            );
                        }
                    }
                    Some(SupervisorCategory::Terminal) => {
                        result.reason = ReparentingReason::TerminalMultiplexerManaged;
                        result.explanation = format!(
                            "Process is in terminal multiplexer session: {}",
                            supervision.supervisor_name.as_deref().unwrap_or("unknown")
                        );
                    }
                    Some(SupervisorCategory::Agent)
                    | Some(SupervisorCategory::Ide)
                    | Some(SupervisorCategory::Ci) => {
                        result.reason = ReparentingReason::SupervisedByAutomation;
                        result.explanation = format!(
                            "Process is supervised by automation: {:?} ({})",
                            supervision.supervisor_type,
                            supervision.supervisor_name.as_deref().unwrap_or("unknown")
                        );
                    }
                    _ => {
                        result.reason = ReparentingReason::SupervisedByAutomation;
                        result.explanation = format!(
                            "Process is supervised: {}",
                            supervision.supervisor_name.as_deref().unwrap_or("unknown")
                        );
                    }
                }

                return Ok(result);
            }
        }

        // Check for nohup/disown
        if let Ok(nohup_result) = detect_nohup(pid) {
            result.nohup = Some(NohupSummary::from(&nohup_result));

            if nohup_result.is_background {
                match nohup_result.inferred_intent {
                    BackgroundIntent::Intentional => {
                        result.unexpected_reparenting = false;
                        result.reason = ReparentingReason::IntentionallyBackgrounded;
                        result.confidence = nohup_result.confidence;
                        result.explanation =
                            "Process was intentionally backgrounded (nohup/disown)".to_string();
                        return Ok(result);
                    }
                    BackgroundIntent::Forgotten => {
                        // Forgotten nohup is still unexpected - likely abandoned
                        result.unexpected_reparenting = true;
                        result.reason = ReparentingReason::ReparentedToInitWithoutSupervision;
                        result.confidence = nohup_result.confidence;
                        result.explanation =
                            "Process appears to be forgotten nohup/disown (stale output)"
                                .to_string();
                        return Ok(result);
                    }
                    BackgroundIntent::Unknown => {
                        // Check SIGHUP ignored as weak signal
                        if nohup_result.ignores_sighup {
                            result.unexpected_reparenting = false;
                            result.reason = ReparentingReason::IntentionallyBackgrounded;
                            result.confidence = 0.6;
                            result.explanation =
                                "Process ignores SIGHUP, likely intentionally backgrounded"
                                    .to_string();
                            return Ok(result);
                        }
                    }
                }
            }
        }

        // macOS special case: check if PID 1 is launchd
        #[cfg(target_os = "macos")]
        {
            // On macOS, PPID=1 means launchd which is often expected
            result.unexpected_reparenting = false;
            result.reason = ReparentingReason::LaunchdManaged;
            result.confidence = 0.7;
            result.explanation =
                "On macOS, PPID=1 (launchd) is often expected for daemons".to_string();
            return Ok(result);
        }

        // No supervision or intentional backgrounding detected
        // This is unexpected reparenting - evidence of abandonment
        result.unexpected_reparenting = true;
        result.reason = ReparentingReason::ReparentedToInitWithoutSupervision;
        result.confidence = 0.8;
        result.explanation =
            "Process orphaned to init with no detected supervision or intentional backgrounding"
                .to_string();

        Ok(result)
    }
}

impl Default for OrphanAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to check for unexpected reparenting.
pub fn detect_unexpected_reparenting(pid: u32) -> Result<OrphanResult, OrphanError> {
    let analyzer = OrphanAnalyzer::new();
    analyzer.analyze(pid)
}

/// Check if a process is orphaned (PPID=1) regardless of whether it's expected.
pub fn is_orphaned(pid: u32) -> Result<bool, OrphanError> {
    let ppid = read_ppid(pid)?;
    Ok(ppid == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reparenting_reason_display() {
        assert_eq!(ReparentingReason::NotOrphaned.to_string(), "not_orphaned");
        assert_eq!(
            ReparentingReason::ReparentedToInitWithoutSupervision.to_string(),
            "reparented_to_init_without_supervision"
        );
        assert_eq!(
            ReparentingReason::ContainerPid1Expected.to_string(),
            "container_pid1_expected"
        );
    }

    #[test]
    fn test_orphan_analyzer_new() {
        let analyzer = OrphanAnalyzer::new();
        // Just ensure it creates without panic
        let _ = analyzer;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_unexpected_reparenting_current_process() {
        let pid = std::process::id();
        let result = detect_unexpected_reparenting(pid);

        // Should succeed for current process
        assert!(result.is_ok());

        let result = result.unwrap();
        // Current process is probably not orphaned (has a parent shell)
        // But if it is, we should still get a valid result
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_orphaned_current_process() {
        let pid = std::process::id();
        let result = is_orphaned(pid);

        assert!(result.is_ok());
        // Test process is probably not orphaned
        // But the function should return without error
    }

    #[test]
    fn test_supervision_summary_from() {
        let combined = CombinedResult::not_supervised();
        let summary = SupervisionSummary::from(&combined);

        assert!(!summary.is_supervised);
        assert!(summary.supervisor_name.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container() {
        // This test just verifies the function runs without panic
        // The result depends on the test environment
        let _ = detect_container();
    }
}
