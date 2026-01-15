//! Pre-check providers for action execution safety gates.
//!
//! This module provides implementations for the various pre-checks defined in
//! `PreCheck` enum that must pass before an action can be executed:
//!
//! - `CheckNotProtected`: Verify process is not in protected list
//! - `CheckDataLossGate`: Check for open write file descriptors
//! - `CheckSupervisor`: Check for supervisor/systemd management
//! - `CheckSessionSafety`: Verify session safety (not session leader, etc.)

use crate::collect::protected::ProtectedFilter;
use crate::config::policy::{DataLossGates, Guardrails};
use crate::plan::PreCheck;
use serde::Serialize;
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, trace};

/// Errors during pre-check validation.
#[derive(Debug, Error)]
pub enum PreCheckError {
    #[error("protected process: {reason}")]
    Protected { reason: String },
    #[error("data loss risk: {reason}")]
    DataLossRisk { reason: String },
    #[error("supervisor conflict: {reason}")]
    SupervisorConflict { reason: String },
    #[error("session safety: {reason}")]
    SessionSafety { reason: String },
    #[error("check failed: {0}")]
    Failed(String),
}

/// Result of a pre-check.
#[derive(Debug, Clone, Serialize)]
pub enum PreCheckResult {
    /// Check passed.
    Passed,
    /// Check failed - action should be blocked.
    Blocked { check: PreCheck, reason: String },
}

impl PreCheckResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, PreCheckResult::Passed)
    }
}

/// Trait for providing pre-check validations.
///
/// All checks read current process state from /proc for TOCTOU safety.
/// This ensures we validate the process as it exists now, not when the decision was made.
pub trait PreCheckProvider {
    /// Check if a process is protected (should never be killed).
    ///
    /// Reads comm, cmd, user from /proc to validate current state.
    fn check_not_protected(&self, pid: u32) -> PreCheckResult;

    /// Check for data loss risk (open write handles, etc.).
    fn check_data_loss(&self, pid: u32) -> PreCheckResult;

    /// Check if process is under supervisor management.
    fn check_supervisor(&self, pid: u32) -> PreCheckResult;

    /// Check session safety (not killing session leader, etc.).
    fn check_session_safety(&self, pid: u32, sid: Option<u32>) -> PreCheckResult;

    /// Run all applicable pre-checks for an action.
    fn run_checks(&self, checks: &[PreCheck], pid: u32, sid: Option<u32>) -> Vec<PreCheckResult> {
        checks
            .iter()
            .filter_map(|check| match check {
                PreCheck::VerifyIdentity => None, // Handled separately by IdentityProvider
                PreCheck::CheckNotProtected => Some(self.check_not_protected(pid)),
                PreCheck::CheckDataLossGate => Some(self.check_data_loss(pid)),
                PreCheck::CheckSupervisor => Some(self.check_supervisor(pid)),
                PreCheck::CheckSessionSafety => Some(self.check_session_safety(pid, sid)),
            })
            .collect()
    }
}

/// Configuration for live pre-check provider.
#[derive(Debug, Clone)]
pub struct LivePreCheckConfig {
    /// Maximum open write file descriptors before blocking.
    pub max_open_write_fds: u32,
    /// Block if process has locked files.
    pub block_if_locked_files: bool,
    /// Block if process has active TTY.
    pub block_if_active_tty: bool,
    /// Block if process CWD is deleted.
    pub block_if_deleted_cwd: bool,
    /// Block if recent I/O within this many seconds.
    pub block_if_recent_io_seconds: u64,
}

impl Default for LivePreCheckConfig {
    fn default() -> Self {
        Self {
            max_open_write_fds: 0,
            block_if_locked_files: true,
            block_if_active_tty: true,
            block_if_deleted_cwd: true,
            block_if_recent_io_seconds: 60,
        }
    }
}

impl From<&DataLossGates> for LivePreCheckConfig {
    fn from(gates: &DataLossGates) -> Self {
        Self {
            max_open_write_fds: gates.max_open_write_fds.unwrap_or(0),
            block_if_locked_files: gates.block_if_locked_files,
            block_if_active_tty: gates.block_if_active_tty,
            block_if_deleted_cwd: gates.block_if_deleted_cwd.unwrap_or(true),
            block_if_recent_io_seconds: gates.block_if_recent_io_seconds.unwrap_or(60),
        }
    }
}

/// Live pre-check provider that reads from /proc.
#[cfg(target_os = "linux")]
pub struct LivePreCheckProvider {
    protected_filter: Option<ProtectedFilter>,
    config: LivePreCheckConfig,
    /// Known supervisor comm names.
    known_supervisors: HashSet<String>,
}

#[cfg(target_os = "linux")]
impl LivePreCheckProvider {
    /// Create a new provider with the given guardrails and config.
    pub fn new(
        guardrails: Option<&Guardrails>,
        config: LivePreCheckConfig,
    ) -> Result<Self, crate::collect::protected::ProtectedFilterError> {
        let protected_filter = guardrails
            .map(ProtectedFilter::from_guardrails)
            .transpose()?;

        let known_supervisors: HashSet<String> = [
            "systemd",
            "init",
            "upstart",
            "supervisord",
            "runit",
            "s6-supervise",
            "runsv",
            "containerd-shim",
            "docker-containerd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Ok(Self {
            protected_filter,
            config,
            known_supervisors,
        })
    }

    /// Create with default config.
    pub fn with_defaults() -> Self {
        Self {
            protected_filter: None,
            config: LivePreCheckConfig::default(),
            known_supervisors: HashSet::new(),
        }
    }

    /// Check if process has open write file descriptors.
    fn has_open_write_fds(&self, pid: u32) -> (bool, u32) {
        let fd_dir = format!("/proc/{pid}/fd");
        let fdinfo_dir = format!("/proc/{pid}/fdinfo");

        let Ok(entries) = std::fs::read_dir(&fd_dir) else {
            return (false, 0);
        };

        let mut write_count = 0;

        for entry in entries.flatten() {
            let fd_name = entry.file_name();
            let fdinfo_path = format!("{fdinfo_dir}/{}", fd_name.to_string_lossy());

            if let Ok(content) = std::fs::read_to_string(&fdinfo_path) {
                // Check flags field for write mode
                for line in content.lines() {
                    if line.starts_with("flags:") {
                        if let Some(flags_str) = line.split_whitespace().nth(1) {
                            if let Ok(flags) = u32::from_str_radix(flags_str.trim_start_matches("0"), 8) {
                                // O_WRONLY = 1, O_RDWR = 2
                                let access_mode = flags & 0o3;
                                if access_mode == 1 || access_mode == 2 {
                                    write_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        (write_count > self.config.max_open_write_fds, write_count)
    }

    /// Check if process has any locked files.
    fn has_locked_files(&self, pid: u32) -> bool {
        let locks_path = "/proc/locks";
        let Ok(content) = std::fs::read_to_string(locks_path) else {
            return false;
        };

        let pid_str = pid.to_string();
        for line in content.lines() {
            // Format: 1: POSIX  ADVISORY  WRITE 12345 ...
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 4 && parts[4] == pid_str {
                return true;
            }
        }

        false
    }

    /// Check if process has active TTY.
    fn has_active_tty(&self, pid: u32) -> bool {
        let stat_path = format!("/proc/{pid}/stat");
        let Ok(content) = std::fs::read_to_string(&stat_path) else {
            return false;
        };

        // Parse tty_nr from stat (field 7 after comm)
        if let Some(comm_end) = content.rfind(')') {
            if let Some(after_comm) = content.get(comm_end + 2..) {
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                if let Some(tty_nr_str) = fields.get(4) {
                    if let Ok(tty_nr) = tty_nr_str.parse::<i32>() {
                        return tty_nr != 0;
                    }
                }
            }
        }

        false
    }

    /// Check if process CWD is deleted.
    fn has_deleted_cwd(&self, pid: u32) -> bool {
        let cwd_link = format!("/proc/{pid}/cwd");
        if let Ok(target) = std::fs::read_link(&cwd_link) {
            let target_str = target.to_string_lossy();
            return target_str.ends_with(" (deleted)");
        }
        false
    }

    /// Read process comm (basename) from /proc.
    fn read_comm(&self, pid: u32) -> Option<String> {
        let comm_path = format!("/proc/{pid}/comm");
        std::fs::read_to_string(&comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Read process cmdline from /proc.
    fn read_cmdline(&self, pid: u32) -> Option<String> {
        let cmdline_path = format!("/proc/{pid}/cmdline");
        std::fs::read_to_string(&cmdline_path)
            .ok()
            .map(|s| s.replace('\0', " ").trim().to_string())
    }

    /// Read process owner username from /proc.
    fn read_user(&self, pid: u32) -> Option<String> {
        let status_path = format!("/proc/{pid}/status");
        let content = std::fs::read_to_string(&status_path).ok()?;

        // Find Uid line: "Uid:\t1000\t1000\t1000\t1000"
        for line in content.lines() {
            if line.starts_with("Uid:") {
                if let Some(uid_str) = line.split_whitespace().nth(1) {
                    if let Ok(uid) = uid_str.parse::<u32>() {
                        // Try to resolve UID to username
                        #[cfg(unix)]
                        {
                            use std::ffi::CStr;
                            unsafe {
                                let pwd = libc::getpwuid(uid);
                                if !pwd.is_null() {
                                    let name = CStr::from_ptr((*pwd).pw_name);
                                    if let Ok(s) = name.to_str() {
                                        return Some(s.to_string());
                                    }
                                }
                            }
                        }
                        // Fallback to UID string
                        return Some(uid.to_string());
                    }
                }
            }
        }

        None
    }

    /// Get parent process comm name.
    fn get_ppid_comm(&self, pid: u32) -> Option<String> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(&stat_path).ok()?;

        // Get PPID (field 4 after comm)
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let ppid: u32 = fields.first()?.parse().ok()?;

        // Get parent's comm
        let parent_comm_path = format!("/proc/{ppid}/comm");
        std::fs::read_to_string(&parent_comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Check if process is managed by a known supervisor.
    fn is_supervisor_managed(&self, pid: u32) -> Option<String> {
        if let Some(ppid_comm) = self.get_ppid_comm(pid) {
            if self.known_supervisors.contains(&ppid_comm) {
                return Some(ppid_comm);
            }
        }

        // Also check if systemd is tracking this as a service
        let cgroup_path = format!("/proc/{pid}/cgroup");
        if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
            for line in content.lines() {
                if line.contains(".service") || line.contains(".scope") {
                    // Extract service name
                    if let Some(start) = line.rfind('/') {
                        let unit = &line[start + 1..];
                        if unit.ends_with(".service") || unit.ends_with(".scope") {
                            return Some(format!("systemd:{unit}"));
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(target_os = "linux")]
impl PreCheckProvider for LivePreCheckProvider {
    fn check_not_protected(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking protection status");

        // Read current process state from /proc for TOCTOU safety
        let comm = self.read_comm(pid).unwrap_or_default();
        let cmd = self.read_cmdline(pid).unwrap_or_default();
        let user = self.read_user(pid).unwrap_or_default();

        trace!(pid, %comm, "read process identity for protection check");

        if let Some(ref filter) = self.protected_filter {
            // Check protected PIDs first (fast lookup)
            if filter.protected_pids().contains(&pid) {
                debug!(pid, "process has protected PID");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckNotProtected,
                    reason: format!("protected PID: {pid}"),
                };
            }

            // Check protected users
            if filter.protected_users().contains(&user.to_lowercase()) {
                debug!(pid, %user, "process owned by protected user");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckNotProtected,
                    reason: format!("owned by protected user: {user}"),
                };
            }

            // Check patterns against comm (basename)
            if let Some(pattern) = filter.matches_any_pattern(&comm) {
                debug!(pid, %comm, pattern, "process comm matches protected pattern");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckNotProtected,
                    reason: format!("matches protected pattern: {pattern}"),
                };
            }

            // Check patterns against full command line
            if let Some(pattern) = filter.matches_any_pattern(&cmd) {
                debug!(pid, pattern, "process cmd matches protected pattern");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckNotProtected,
                    reason: format!("matches protected pattern: {pattern}"),
                };
            }
        }

        PreCheckResult::Passed
    }

    fn check_data_loss(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking data loss risk");

        // Check open write file descriptors
        let (exceeds_max, write_count) = self.has_open_write_fds(pid);
        if exceeds_max {
            debug!(pid, write_count, "process has open write fds");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckDataLossGate,
                reason: format!(
                    "{write_count} open write fds (max: {})",
                    self.config.max_open_write_fds
                ),
            };
        }

        // Check locked files
        if self.config.block_if_locked_files && self.has_locked_files(pid) {
            debug!(pid, "process has locked files");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckDataLossGate,
                reason: "process has locked files".to_string(),
            };
        }

        // Check deleted CWD
        if self.config.block_if_deleted_cwd && self.has_deleted_cwd(pid) {
            debug!(pid, "process has deleted cwd");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckDataLossGate,
                reason: "process CWD is deleted".to_string(),
            };
        }

        PreCheckResult::Passed
    }

    fn check_supervisor(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking supervisor status");

        if let Some(supervisor) = self.is_supervisor_managed(pid) {
            debug!(pid, supervisor = %supervisor, "process is supervisor-managed");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckSupervisor,
                reason: format!("managed by {supervisor} - may respawn"),
            };
        }

        PreCheckResult::Passed
    }

    fn check_session_safety(&self, pid: u32, sid: Option<u32>) -> PreCheckResult {
        trace!(pid, ?sid, "checking session safety");

        // Don't kill session leaders (would orphan entire session)
        if let Some(session_id) = sid {
            if session_id == pid {
                debug!(pid, "process is session leader");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckSessionSafety,
                    reason: "process is session leader".to_string(),
                };
            }
        }

        // Check if process has active TTY
        if self.config.block_if_active_tty && self.has_active_tty(pid) {
            debug!(pid, "process has active TTY");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckSessionSafety,
                reason: "process has active TTY".to_string(),
            };
        }

        PreCheckResult::Passed
    }
}

/// No-op pre-check provider (all checks pass).
#[derive(Debug, Default)]
pub struct NoopPreCheckProvider;

impl PreCheckProvider for NoopPreCheckProvider {
    fn check_not_protected(&self, _pid: u32) -> PreCheckResult {
        PreCheckResult::Passed
    }

    fn check_data_loss(&self, _pid: u32) -> PreCheckResult {
        PreCheckResult::Passed
    }

    fn check_supervisor(&self, _pid: u32) -> PreCheckResult {
        PreCheckResult::Passed
    }

    fn check_session_safety(&self, _pid: u32, _sid: Option<u32>) -> PreCheckResult {
        PreCheckResult::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_provider_passes_all() {
        let provider = NoopPreCheckProvider;
        assert!(provider.check_not_protected(123).is_passed());
        assert!(provider.check_data_loss(123).is_passed());
        assert!(provider.check_supervisor(123).is_passed());
        assert!(provider.check_session_safety(123, None).is_passed());
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn live_provider_defaults() {
            let provider = LivePreCheckProvider::with_defaults();
            // Self should pass basic checks (we're not protected)
            let pid = std::process::id();
            // Now reads from /proc automatically
            assert!(provider.check_not_protected(pid).is_passed());
        }

        #[test]
        fn live_provider_detects_tty() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();

            // Check TTY detection (may or may not have TTY depending on test environment)
            let has_tty = provider.has_active_tty(pid);
            // Just verify the function doesn't panic
            let _ = has_tty;
        }

        #[test]
        fn live_provider_detects_write_fds() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();

            // We should have some file descriptors open
            let (exceeds, count) = provider.has_open_write_fds(pid);
            // With max_open_write_fds = 0, any write fd would exceed
            // The test binary likely has stdout/stderr which may or may not count
            let _ = (exceeds, count);
        }
    }
}
