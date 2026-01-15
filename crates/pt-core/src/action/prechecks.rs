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
#[cfg(target_os = "linux")]
use crate::collect::parse_io;
use crate::collect::systemd::{collect_systemd_unit, SystemdUnit, SystemdUnitType};
use crate::collect::ProcessState;
use crate::config::policy::{DataLossGates, Guardrails};
use crate::supervision::session::{SessionAnalyzer, SessionConfig, SessionProtectionType};
use std::fmt;
use crate::plan::PreCheck;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;
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

/// Recommended supervisor action for a managed process.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorAction {
    /// Restart the unit (for services that should continue running).
    RestartUnit { command: String },
    /// Stop the unit (for services that should be terminated).
    StopUnit { command: String },
    /// Kill the process directly (not recommended for supervised processes).
    KillProcess,
}

impl fmt::Display for SupervisorAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupervisorAction::RestartUnit { command } => write!(f, "restart: `{command}`"),
            SupervisorAction::StopUnit { command } => write!(f, "stop: `{command}`"),
            SupervisorAction::KillProcess => write!(f, "kill process directly"),
        }
    }
}

/// Information about supervisor management of a process.
#[derive(Debug, Clone, Serialize)]
pub struct SupervisorInfo {
    /// Name of the supervisor (e.g., "systemd", "supervisord").
    pub supervisor: String,
    /// Full unit name if known (e.g., "nginx.service").
    pub unit_name: Option<String>,
    /// Unit type for systemd units.
    pub unit_type: Option<SystemdUnitType>,
    /// Whether this process is the main process of the unit.
    pub is_main_process: bool,
    /// Recommended action to manage this process.
    pub recommended_action: SupervisorAction,
    /// Optional systemd unit info for detailed metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<SystemdUnit>,
}

impl SupervisorInfo {
    /// Create supervisor info for a systemd-managed process.
    fn from_systemd_unit(unit: SystemdUnit, pid: u32) -> Self {
        let is_main = unit.is_main_process || unit.main_pid == Some(pid);
        let unit_name = unit.name.clone();
        let unit_type = unit.unit_type;

        let recommended_action = match unit_type {
            SystemdUnitType::Service => {
                SupervisorAction::RestartUnit {
                    command: format!("systemctl restart {}", unit_name),
                }
            }
            SystemdUnitType::Scope => {
                // Scopes are usually user sessions - stop is appropriate
                SupervisorAction::StopUnit {
                    command: format!("systemctl stop {}", unit_name),
                }
            }
            _ => SupervisorAction::KillProcess,
        };

        Self {
            supervisor: "systemd".to_string(),
            unit_name: Some(unit_name),
            unit_type: Some(unit_type),
            is_main_process: is_main,
            recommended_action,
            systemd_unit: Some(unit),
        }
    }

    /// Create supervisor info for a non-systemd supervisor (e.g., supervisord).
    fn from_parent_supervisor(supervisor_name: &str) -> Self {
        Self {
            supervisor: supervisor_name.to_string(),
            unit_name: None,
            unit_type: None,
            is_main_process: false,
            recommended_action: SupervisorAction::KillProcess,
            systemd_unit: None,
        }
    }

    /// Format reason string for blocking with actionable recommendations.
    pub fn to_block_reason(&self) -> String {
        match &self.recommended_action {
            SupervisorAction::RestartUnit { command } => {
                format!(
                    "managed by {} ({}) - process may respawn. Use `{}` instead of killing",
                    self.supervisor,
                    self.unit_name.as_deref().unwrap_or("unknown"),
                    command
                )
            }
            SupervisorAction::StopUnit { command } => {
                format!(
                    "managed by {} ({}) - use `{}` to stop cleanly",
                    self.supervisor,
                    self.unit_name.as_deref().unwrap_or("unknown"),
                    command
                )
            }
            SupervisorAction::KillProcess => {
                format!(
                    "managed by {} - may respawn after kill",
                    self.supervisor
                )
            }
        }
    }
}

impl fmt::Display for SupervisorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.unit_name.as_deref() {
            Some(unit) if !unit.is_empty() => write!(f, "{} ({})", self.supervisor, unit),
            _ => write!(f, "{}", self.supervisor),
        }
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

    /// Get detailed supervisor info for a process.
    ///
    /// Returns `None` if the process is not supervised.
    /// This is useful for callers that want to display recommended actions.
    fn get_supervisor_info(&self, _pid: u32) -> Option<SupervisorInfo> {
        None
    }

    /// Check if process state is valid for the planned action.
    ///
    /// Verifies that the process is not in an unkillable state (zombie/D-state)
    /// if we're planning a kill action.
    fn check_process_state(&self, _pid: u32) -> PreCheckResult {
        // Default implementation - can be overridden by live implementations
        PreCheckResult::Passed
    }

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
                PreCheck::VerifyProcessState => Some(self.check_process_state(pid)),
            })
            .collect()
    }
}

/// Configuration for live pre-check provider.
#[derive(Debug, Clone)]
pub struct LivePreCheckConfig {
    /// Block if process has open write file descriptors.
    pub block_if_open_write_fds: bool,
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
    /// Use enhanced session chain detection (SSH, tmux/screen, parent shells).
    pub enhanced_session_safety: bool,
    /// Protect processes in the same session as pt.
    pub protect_same_session: bool,
    /// Protect SSH connection chains.
    pub protect_ssh_chains: bool,
    /// Protect tmux/screen chains.
    pub protect_multiplexers: bool,
    /// Protect parent shells of pt.
    pub protect_parent_shells: bool,
}

impl Default for LivePreCheckConfig {
    fn default() -> Self {
        Self {
            block_if_open_write_fds: true,
            max_open_write_fds: 0,
            block_if_locked_files: true,
            block_if_active_tty: true,
            block_if_deleted_cwd: true,
            block_if_recent_io_seconds: 60,
            enhanced_session_safety: true,
            protect_same_session: true,
            protect_ssh_chains: true,
            protect_multiplexers: true,
            protect_parent_shells: true,
        }
    }
}

impl From<&DataLossGates> for LivePreCheckConfig {
    fn from(gates: &DataLossGates) -> Self {
        Self {
            block_if_open_write_fds: gates.block_if_open_write_fds,
            max_open_write_fds: gates.max_open_write_fds.unwrap_or(0),
            block_if_locked_files: gates.block_if_locked_files,
            block_if_active_tty: gates.block_if_active_tty,
            block_if_deleted_cwd: gates.block_if_deleted_cwd.unwrap_or(true),
            block_if_recent_io_seconds: gates.block_if_recent_io_seconds.unwrap_or(60),
            // Default to enabled for session safety features
            enhanced_session_safety: true,
            protect_same_session: true,
            protect_ssh_chains: true,
            protect_multiplexers: true,
            protect_parent_shells: true,
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
                            if let Ok(flags) = u32::from_str_radix(flags_str, 8) {
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

    /// Best-effort check for recent I/O activity (write-heavy).
    ///
    /// Uses a short probe window to detect increases in /proc/<pid>/io counters.
    fn has_recent_io(&self, pid: u32, window: Duration) -> bool {
        let before = parse_io(pid);
        let Some(before) = before else {
            return false;
        };

        let probe_ms = window.as_millis().min(200).max(10) as u64;
        std::thread::sleep(Duration::from_millis(probe_ms));

        let after = parse_io(pid);
        let Some(after) = after else {
            return false;
        };

        let write_bytes_delta = after.write_bytes.saturating_sub(before.write_bytes);
        let wchar_delta = after.wchar.saturating_sub(before.wchar);

        write_bytes_delta > 0 || wchar_delta > 0
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

    /// Read process state from /proc/[pid]/stat.
    ///
    /// Parses the state field (field 3 in stat) and returns the ProcessState.
    fn read_process_state(&self, pid: u32) -> Option<ProcessState> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(&stat_path).ok()?;

        // Parse state from stat: pid (comm) state ...
        // State is the first character after the closing paren
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let state_char = after_comm.chars().next()?;

        Some(ProcessState::from_char(state_char))
    }

    /// Read kernel wait channel from /proc/[pid]/wchan.
    ///
    /// Returns the kernel function name where the process is blocked (if in sleep state).
    fn read_wchan(&self, pid: u32) -> Option<String> {
        let wchan_path = format!("/proc/{pid}/wchan");
        let wchan = std::fs::read_to_string(&wchan_path).ok()?.trim().to_string();

        // "0" means not blocked, return None in that case
        if wchan == "0" || wchan.is_empty() {
            None
        } else {
            Some(wchan)
        }
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
    ///
    /// Returns detailed supervisor info including unit metadata and recommended actions.
    fn is_supervisor_managed(&self, pid: u32) -> Option<SupervisorInfo> {
        // First check for non-systemd supervisors via parent comm
        if let Some(ppid_comm) = self.get_ppid_comm(pid) {
            if self.known_supervisors.contains(&ppid_comm) && ppid_comm != "systemd" {
                return Some(SupervisorInfo::from_parent_supervisor(&ppid_comm));
            }
        }

        // Try to get systemd unit info with full metadata
        let cgroup_unit = self.extract_cgroup_unit(pid);
        if let Some(unit) = collect_systemd_unit(pid, cgroup_unit.as_deref()) {
            // Filter out slice-only units (e.g., user.slice) - these aren't real supervision
            if unit.unit_type == SystemdUnitType::Slice {
                trace!(pid, unit_name = %unit.name, "ignoring slice-only unit");
                return None;
            }

            debug!(
                pid,
                unit_name = %unit.name,
                unit_type = ?unit.unit_type,
                is_main = unit.is_main_process,
                "detected systemd unit"
            );

            return Some(SupervisorInfo::from_systemd_unit(unit, pid));
        }

        None
    }

    /// Extract the cgroup unit name from /proc/PID/cgroup.
    fn extract_cgroup_unit(&self, pid: u32) -> Option<String> {
        let cgroup_path = format!("/proc/{pid}/cgroup");
        let content = std::fs::read_to_string(&cgroup_path).ok()?;

        for line in content.lines() {
            // Look for lines with .service or .scope (not .slice - those aren't real supervision)
            if line.contains(".service") || line.contains(".scope") {
                // Extract unit name from path like "0::/system.slice/nginx.service"
                if let Some(start) = line.rfind('/') {
                    let unit = &line[start + 1..];
                    if !unit.is_empty() {
                        return Some(unit.to_string());
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
        if self.config.block_if_open_write_fds {
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

        // Check for recent I/O activity (best-effort).
        if self.config.block_if_recent_io_seconds > 0 {
            let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
            if self.has_recent_io(pid, window) {
                debug!(pid, window_s = self.config.block_if_recent_io_seconds, "process has recent I/O activity");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckDataLossGate,
                    reason: format!(
                        "recent I/O activity within {}s window",
                        self.config.block_if_recent_io_seconds
                    ),
                };
            }
        }

        PreCheckResult::Passed
    }

    fn check_supervisor(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking supervisor status");

        if let Some(supervisor_info) = self.is_supervisor_managed(pid) {
            let supervisor_name = supervisor_info.supervisor.as_str();
            debug!(
                pid,
                supervisor = supervisor_name,
                unit = ?supervisor_info.unit_name,
                action = %supervisor_info.recommended_action,
                "process is supervisor-managed"
            );
            return PreCheckResult::Blocked {
                check: PreCheck::CheckSupervisor,
                reason: supervisor_info.to_block_reason(),
            };
        }

        PreCheckResult::Passed
    }

    fn get_supervisor_info(&self, pid: u32) -> Option<SupervisorInfo> {
        self.is_supervisor_managed(pid)
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

        // Check if process has active TTY (basic check, always enabled if configured)
        if self.config.block_if_active_tty && self.has_active_tty(pid) {
            debug!(pid, "process has active TTY");
            return PreCheckResult::Blocked {
                check: PreCheck::CheckSessionSafety,
                reason: "process has active TTY".to_string(),
            };
        }

        // Enhanced session safety checks using SessionAnalyzer
        if self.config.enhanced_session_safety {
            let session_config = SessionConfig {
                max_ancestry_depth: 20,
                protect_same_session: self.config.protect_same_session,
                protect_parent_shells: self.config.protect_parent_shells,
                protect_multiplexers: self.config.protect_multiplexers,
                protect_ssh_chains: self.config.protect_ssh_chains,
                protect_foreground_groups: true,
            };

            let mut analyzer = SessionAnalyzer::with_config(session_config);
            let pt_pid = std::process::id();
            match analyzer.analyze(pid, pt_pid) {
                Ok(result) => {
                    if result.is_protected {
                        // Build a descriptive reason based on protection types
                        let protection_desc: Vec<&str> = result.protection_types.iter().map(|p| {
                            match p {
                                SessionProtectionType::SessionLeader => "session leader",
                                SessionProtectionType::SameSession => "same session as pt",
                                SessionProtectionType::ParentShell => "parent shell of pt",
                                SessionProtectionType::TmuxServer => "tmux server",
                                SessionProtectionType::TmuxClient => "tmux client",
                                SessionProtectionType::ScreenServer => "screen server",
                                SessionProtectionType::ScreenClient => "screen client",
                                SessionProtectionType::SshChain => "SSH connection chain",
                                SessionProtectionType::ForegroundGroup => "foreground process group",
                                SessionProtectionType::TtyController => "TTY controller",
                            }
                        }).collect();

                        let reason = if let Some(r) = result.reason {
                            r
                        } else {
                            format!("protected session chain: {}", protection_desc.join(", "))
                        };

                        debug!(pid, protections = ?result.protection_types, "process is session-protected");
                        return PreCheckResult::Blocked {
                            check: PreCheck::CheckSessionSafety,
                            reason,
                        };
                    }
                }
                Err(e) => {
                    // Log but don't fail on analyzer errors - fall through to pass
                    trace!(pid, error = %e, "session analyzer error, skipping enhanced checks");
                }
            }
        }

        PreCheckResult::Passed
    }

    fn check_process_state(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking process state for kill viability");

        // Read current process state from /proc
        let state = match self.read_process_state(pid) {
            Some(s) => s,
            None => {
                // Process may have exited - treat as passed (nothing to check)
                trace!(pid, "could not read process state, assuming gone");
                return PreCheckResult::Passed;
            }
        };

        // Check for zombie state - cannot be killed
        if state.is_zombie() {
            debug!(pid, "process is a zombie (Z state)");
            return PreCheckResult::Blocked {
                check: PreCheck::VerifyProcessState,
                reason: format!(
                    "process is a zombie (Z state): already dead, cannot be killed. \
                     The parent process must reap it."
                ),
            };
        }

        // Check for D-state (uninterruptible sleep) - kill may not work
        if state.is_disksleep() {
            let wchan = self.read_wchan(pid);
            let wchan_info = wchan
                .as_ref()
                .map(|w| format!(" (blocked in: {})", w))
                .unwrap_or_default();

            debug!(pid, ?wchan, "process is in D-state (uninterruptible sleep)");
            return PreCheckResult::Blocked {
                check: PreCheck::VerifyProcessState,
                reason: format!(
                    "process is in uninterruptible sleep (D state){}: \
                     kill action may not succeed. Consider investigating the \
                     underlying I/O issue instead.",
                    wchan_info
                ),
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

    #[test]
    fn supervisor_action_display() {
        let restart = SupervisorAction::RestartUnit {
            command: "systemctl restart nginx.service".to_string(),
        };
        assert!(restart.to_string().contains("restart"));
        assert!(restart.to_string().contains("nginx.service"));

        let stop = SupervisorAction::StopUnit {
            command: "systemctl stop test.scope".to_string(),
        };
        assert!(stop.to_string().contains("stop"));

        let kill = SupervisorAction::KillProcess;
        assert!(kill.to_string().contains("kill"));
    }

    #[test]
    fn supervisor_info_from_parent() {
        let info = SupervisorInfo::from_parent_supervisor("supervisord");
        assert_eq!(info.supervisor, "supervisord");
        assert!(info.unit_name.is_none());
        assert!(!info.is_main_process);
        assert!(matches!(info.recommended_action, SupervisorAction::KillProcess));
    }

    #[test]
    fn supervisor_info_block_reason_restart() {
        let info = SupervisorInfo {
            supervisor: "systemd".to_string(),
            unit_name: Some("nginx.service".to_string()),
            unit_type: Some(SystemdUnitType::Service),
            is_main_process: true,
            recommended_action: SupervisorAction::RestartUnit {
                command: "systemctl restart nginx.service".to_string(),
            },
            systemd_unit: None,
        };

        let reason = info.to_block_reason();
        assert!(reason.contains("systemd"));
        assert!(reason.contains("nginx.service"));
        assert!(reason.contains("systemctl restart"));
    }

    #[test]
    fn supervisor_info_block_reason_stop() {
        let info = SupervisorInfo {
            supervisor: "systemd".to_string(),
            unit_name: Some("session-1.scope".to_string()),
            unit_type: Some(SystemdUnitType::Scope),
            is_main_process: false,
            recommended_action: SupervisorAction::StopUnit {
                command: "systemctl stop session-1.scope".to_string(),
            },
            systemd_unit: None,
        };

        let reason = info.to_block_reason();
        assert!(reason.contains("systemctl stop"));
        assert!(reason.contains("session-1.scope"));
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

        #[test]
        fn live_provider_extract_cgroup_unit() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();

            // Try to extract cgroup unit for self - may or may not have one
            let unit = provider.extract_cgroup_unit(pid);
            // Just verify the function doesn't panic
            let _ = unit;
        }

        #[test]
        fn live_provider_get_supervisor_info() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();

            // Get supervisor info for self - should handle gracefully
            let info = provider.get_supervisor_info(pid);
            // Just verify the function returns without panicking
            let _ = info;
        }
    }
}
