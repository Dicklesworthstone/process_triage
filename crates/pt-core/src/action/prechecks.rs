//! Pre-check providers for action execution safety gates.
//!
//! This module provides implementations for the various pre-checks defined in
//! `PreCheck` enum that must pass before an action can be executed:
//!
//! - `CheckNotProtected`: Verify process is not in protected list
//! - `CheckDataLossGate`: Check for open write file descriptors
//! - `CheckSupervisor`: Check for supervisor/systemd management
//! - `CheckSessionSafety`: Verify session safety (not session leader, etc.)

#[cfg(target_os = "linux")]
use crate::collect::parse_io;
use crate::collect::protected::ProtectedFilter;
use crate::collect::systemd::{collect_systemd_unit, SystemdUnit, SystemdUnitType};
use crate::collect::ProcessState;
use crate::config::policy::{DataLossGates, Guardrails};
use crate::plan::PreCheck;
use crate::supervision::session::{SessionAnalyzer, SessionConfig, SessionProtectionType};
#[cfg(target_os = "linux")]
use crate::supervision::{detect_supervision, is_human_supervised};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, trace};

fn recent_io_probe_window(window: Duration) -> Duration {
    if window.is_zero() {
        Duration::from_millis(10)
    } else {
        window
    }
}

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
            SystemdUnitType::Service => SupervisorAction::RestartUnit {
                command: format!("systemctl restart {}", unit_name),
            },
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
                format!("managed by {} - may respawn after kill", self.supervisor)
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

    /// Check if process is supervised by an AI agent and if action should be blocked.
    fn check_agent_supervision(&self, _pid: u32) -> PreCheckResult {
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
                PreCheck::CheckAgentSupervision => Some(self.check_agent_supervision(pid)),
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
        let protected_filter = ProtectedFilter::from_guardrails(&Guardrails::default()).ok();
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
        Self {
            protected_filter,
            config: LivePreCheckConfig::default(),
            known_supervisors,
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

        std::thread::sleep(recent_io_probe_window(window));

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
        let wchan = std::fs::read_to_string(&wchan_path)
            .ok()?
            .trim()
            .to_string();

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
                debug!(
                    pid,
                    window_s = self.config.block_if_recent_io_seconds,
                    "process has recent I/O activity"
                );
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

    fn check_agent_supervision(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking AI/IDE/CI supervision status");

        match detect_supervision(pid) {
            Ok(result) => {
                if is_human_supervised(&result) {
                    let supervisor = result
                        .supervisor_name
                        .clone()
                        .unwrap_or_else(|| "unknown supervisor".to_string());
                    let category = result
                        .supervisor_type
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    debug!(
                        pid,
                        %supervisor,
                        %category,
                        confidence = result.confidence,
                        "process is human-supervised"
                    );

                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckAgentSupervision,
                        reason: format!(
                            "supervised by {} ({}, confidence: {:.0}%): requires human confirmation",
                            supervisor,
                            category,
                            result.confidence * 100.0
                        ),
                    };
                }
            }
            Err(e) => {
                trace!(pid, error = %e, "agent supervision detection error, allowing action");
            }
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
                        let protection_desc: Vec<&str> = result
                            .protection_types
                            .iter()
                            .map(|p| match p {
                                SessionProtectionType::SessionLeader => "session leader",
                                SessionProtectionType::SameSession => "same session as pt",
                                SessionProtectionType::ParentShell => "parent shell of pt",
                                SessionProtectionType::TmuxServer => "tmux server",
                                SessionProtectionType::TmuxClient => "tmux client",
                                SessionProtectionType::ScreenServer => "screen server",
                                SessionProtectionType::ScreenClient => "screen client",
                                SessionProtectionType::SshChain => "SSH connection chain",
                                SessionProtectionType::ForegroundGroup => {
                                    "foreground process group"
                                }
                                SessionProtectionType::TtyController => "TTY controller",
                            })
                            .collect();

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
                reason: "process is a zombie (Z state): already dead, cannot be killed. \
                     The parent process must reap it."
                    .to_string(),
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

    fn check_agent_supervision(&self, _pid: u32) -> PreCheckResult {
        PreCheckResult::Passed
    }

    fn check_session_safety(&self, _pid: u32, _sid: Option<u32>) -> PreCheckResult {
        PreCheckResult::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PreCheckResult ──────────────────────────────────────────────

    #[test]
    fn precheck_result_passed_is_passed() {
        assert!(PreCheckResult::Passed.is_passed());
    }

    #[test]
    fn precheck_result_blocked_is_not_passed() {
        let blocked = PreCheckResult::Blocked {
            check: PreCheck::CheckNotProtected,
            reason: "test".to_string(),
        };
        assert!(!blocked.is_passed());
    }

    #[test]
    fn precheck_result_blocked_preserves_check_and_reason() {
        let blocked = PreCheckResult::Blocked {
            check: PreCheck::CheckDataLossGate,
            reason: "open write fds".to_string(),
        };
        let (check, reason) = match blocked {
            PreCheckResult::Blocked { check, reason } => (check, reason),
            _ => {
                assert!(false, "expected Blocked");
                return;
            }
        };
        assert!(matches!(check, PreCheck::CheckDataLossGate));
        assert_eq!(reason, "open write fds");
    }

    // ── NoopPreCheckProvider ────────────────────────────────────────

    #[test]
    fn noop_provider_passes_all() {
        let provider = NoopPreCheckProvider;
        assert!(provider.check_not_protected(123).is_passed());
        assert!(provider.check_data_loss(123).is_passed());
        assert!(provider.check_supervisor(123).is_passed());
        assert!(provider.check_session_safety(123, None).is_passed());
    }

    #[test]
    fn noop_provider_passes_agent_supervision() {
        let provider = NoopPreCheckProvider;
        assert!(provider.check_agent_supervision(123).is_passed());
    }

    #[test]
    fn noop_provider_session_safety_with_sid() {
        let provider = NoopPreCheckProvider;
        assert!(provider.check_session_safety(123, Some(100)).is_passed());
        // Even when pid == sid (session leader), noop still passes
        assert!(provider.check_session_safety(123, Some(123)).is_passed());
    }

    #[test]
    fn noop_provider_default_trait_methods() {
        let provider = NoopPreCheckProvider;
        // Default implementations from the trait
        assert!(provider.get_supervisor_info(123).is_none());
        assert!(provider.check_process_state(123).is_passed());
    }

    // ── NoopPreCheckProvider::run_checks ─────────────────────────────

    #[test]
    fn noop_run_checks_empty() {
        let provider = NoopPreCheckProvider;
        let results = provider.run_checks(&[], 123, None);
        assert!(results.is_empty());
    }

    #[test]
    fn noop_run_checks_verify_identity_skipped() {
        let provider = NoopPreCheckProvider;
        let results = provider.run_checks(&[PreCheck::VerifyIdentity], 123, None);
        // VerifyIdentity is handled separately, should be filtered out
        assert!(results.is_empty());
    }

    #[test]
    fn noop_run_checks_all_types() {
        let provider = NoopPreCheckProvider;
        let checks = vec![
            PreCheck::CheckNotProtected,
            PreCheck::CheckDataLossGate,
            PreCheck::CheckSupervisor,
            PreCheck::CheckAgentSupervision,
            PreCheck::CheckSessionSafety,
            PreCheck::VerifyProcessState,
        ];
        let results = provider.run_checks(&checks, 123, None);
        assert_eq!(results.len(), 6);
        assert!(results.iter().all(|r| r.is_passed()));
    }

    #[test]
    fn noop_run_checks_mixed_with_identity() {
        let provider = NoopPreCheckProvider;
        let checks = vec![
            PreCheck::VerifyIdentity,
            PreCheck::CheckNotProtected,
            PreCheck::VerifyIdentity,
            PreCheck::CheckSupervisor,
        ];
        let results = provider.run_checks(&checks, 123, None);
        // VerifyIdentity entries are filtered, only 2 results
        assert_eq!(results.len(), 2);
    }

    // ── SupervisorAction Display ────────────────────────────────────

    #[test]
    fn supervisor_action_display_restart() {
        let restart = SupervisorAction::RestartUnit {
            command: "systemctl restart nginx.service".to_string(),
        };
        let s = restart.to_string();
        assert!(s.contains("restart"));
        assert!(s.contains("nginx.service"));
    }

    #[test]
    fn supervisor_action_display_stop() {
        let stop = SupervisorAction::StopUnit {
            command: "systemctl stop test.scope".to_string(),
        };
        let s = stop.to_string();
        assert!(s.contains("stop"));
        assert!(s.contains("test.scope"));
    }

    #[test]
    fn supervisor_action_display_kill() {
        let kill = SupervisorAction::KillProcess;
        assert!(kill.to_string().contains("kill"));
    }

    // ── SupervisorInfo construction ─────────────────────────────────

    #[test]
    fn supervisor_info_from_parent() {
        let info = SupervisorInfo::from_parent_supervisor("supervisord");
        assert_eq!(info.supervisor, "supervisord");
        assert!(info.unit_name.is_none());
        assert!(info.unit_type.is_none());
        assert!(!info.is_main_process);
        assert!(info.systemd_unit.is_none());
        assert!(matches!(
            info.recommended_action,
            SupervisorAction::KillProcess
        ));
    }

    #[test]
    fn supervisor_info_from_systemd_unit_service() {
        let unit = SystemdUnit {
            name: "nginx.service".to_string(),
            unit_type: SystemdUnitType::Service,
            active_state: crate::collect::systemd::SystemdActiveState::Active,
            sub_state: None,
            main_pid: Some(1234),
            control_pid: None,
            fragment_path: None,
            description: None,
            is_main_process: true,
            provenance: crate::collect::systemd::SystemdProvenance {
                source: crate::collect::systemd::SystemdDataSource::default(),
                warnings: vec![],
            },
        };

        let info = SupervisorInfo::from_systemd_unit(unit, 1234);
        assert_eq!(info.supervisor, "systemd");
        assert_eq!(info.unit_name.as_deref(), Some("nginx.service"));
        assert_eq!(info.unit_type, Some(SystemdUnitType::Service));
        assert!(info.is_main_process);
        assert!(matches!(
            info.recommended_action,
            SupervisorAction::RestartUnit { .. }
        ));
    }

    #[test]
    fn supervisor_info_from_systemd_unit_scope() {
        let unit = SystemdUnit {
            name: "session-1.scope".to_string(),
            unit_type: SystemdUnitType::Scope,
            active_state: crate::collect::systemd::SystemdActiveState::Active,
            sub_state: None,
            main_pid: None,
            control_pid: None,
            fragment_path: None,
            description: None,
            is_main_process: false,
            provenance: crate::collect::systemd::SystemdProvenance {
                source: crate::collect::systemd::SystemdDataSource::default(),
                warnings: vec![],
            },
        };

        let info = SupervisorInfo::from_systemd_unit(unit, 5678);
        assert_eq!(info.unit_type, Some(SystemdUnitType::Scope));
        assert!(!info.is_main_process);
        // Scopes get StopUnit instead of RestartUnit
        assert!(matches!(
            info.recommended_action,
            SupervisorAction::StopUnit { .. }
        ));
    }

    #[test]
    fn supervisor_info_from_systemd_unit_timer_gets_kill() {
        let unit = SystemdUnit {
            name: "cleanup.timer".to_string(),
            unit_type: SystemdUnitType::Timer,
            active_state: crate::collect::systemd::SystemdActiveState::Active,
            sub_state: None,
            main_pid: None,
            control_pid: None,
            fragment_path: None,
            description: None,
            is_main_process: false,
            provenance: crate::collect::systemd::SystemdProvenance {
                source: crate::collect::systemd::SystemdDataSource::default(),
                warnings: vec![],
            },
        };

        let info = SupervisorInfo::from_systemd_unit(unit, 9999);
        // Non-service, non-scope types fall through to KillProcess
        assert!(matches!(
            info.recommended_action,
            SupervisorAction::KillProcess
        ));
    }

    #[test]
    fn supervisor_info_is_main_process_from_main_pid() {
        // When is_main_process is false but main_pid matches pid
        let unit = SystemdUnit {
            name: "test.service".to_string(),
            unit_type: SystemdUnitType::Service,
            active_state: crate::collect::systemd::SystemdActiveState::Active,
            sub_state: None,
            main_pid: Some(42),
            control_pid: None,
            fragment_path: None,
            description: None,
            is_main_process: false,
            provenance: crate::collect::systemd::SystemdProvenance {
                source: crate::collect::systemd::SystemdDataSource::default(),
                warnings: vec![],
            },
        };

        let info = SupervisorInfo::from_systemd_unit(unit, 42);
        // is_main = unit.is_main_process || unit.main_pid == Some(pid)
        assert!(info.is_main_process);
    }

    // ── SupervisorInfo block reasons ────────────────────────────────

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
        assert!(reason.contains("respawn"));
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

    #[test]
    fn supervisor_info_block_reason_kill_process() {
        let info = SupervisorInfo::from_parent_supervisor("runit");
        let reason = info.to_block_reason();
        assert!(reason.contains("runit"));
        assert!(reason.contains("respawn"));
    }

    #[test]
    fn supervisor_info_block_reason_missing_unit_name() {
        let info = SupervisorInfo {
            supervisor: "systemd".to_string(),
            unit_name: None,
            unit_type: None,
            is_main_process: false,
            recommended_action: SupervisorAction::RestartUnit {
                command: "systemctl restart unknown".to_string(),
            },
            systemd_unit: None,
        };

        let reason = info.to_block_reason();
        assert!(reason.contains("unknown"));
    }

    // ── SupervisorInfo Display ──────────────────────────────────────

    #[test]
    fn supervisor_info_display_with_unit() {
        let info = SupervisorInfo {
            supervisor: "systemd".to_string(),
            unit_name: Some("nginx.service".to_string()),
            unit_type: Some(SystemdUnitType::Service),
            is_main_process: true,
            recommended_action: SupervisorAction::KillProcess,
            systemd_unit: None,
        };
        let s = format!("{info}");
        assert!(s.contains("systemd"));
        assert!(s.contains("nginx.service"));
    }

    #[test]
    fn supervisor_info_display_without_unit() {
        let info = SupervisorInfo::from_parent_supervisor("supervisord");
        let s = format!("{info}");
        assert_eq!(s, "supervisord");
    }

    #[test]
    fn supervisor_info_display_with_empty_unit() {
        let info = SupervisorInfo {
            supervisor: "systemd".to_string(),
            unit_name: Some(String::new()),
            unit_type: None,
            is_main_process: false,
            recommended_action: SupervisorAction::KillProcess,
            systemd_unit: None,
        };
        let s = format!("{info}");
        // Empty unit name: falls through to just supervisor name
        assert_eq!(s, "systemd");
    }

    // ── LivePreCheckConfig defaults ─────────────────────────────────

    #[test]
    fn live_config_defaults() {
        let config = LivePreCheckConfig::default();
        assert!(config.block_if_open_write_fds);
        assert_eq!(config.max_open_write_fds, 0);
        assert!(config.block_if_locked_files);
        assert!(config.block_if_active_tty);
        assert!(config.block_if_deleted_cwd);
        assert_eq!(config.block_if_recent_io_seconds, 60);
        assert!(config.enhanced_session_safety);
        assert!(config.protect_same_session);
        assert!(config.protect_ssh_chains);
        assert!(config.protect_multiplexers);
        assert!(config.protect_parent_shells);
    }

    #[test]
    fn recent_io_probe_window_respects_nonzero_input() {
        assert_eq!(
            recent_io_probe_window(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        assert_eq!(
            recent_io_probe_window(Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn recent_io_probe_window_fallback_for_zero() {
        assert_eq!(
            recent_io_probe_window(Duration::ZERO),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn live_config_from_data_loss_gates_defaults() {
        let gates = DataLossGates {
            block_if_open_write_fds: true,
            max_open_write_fds: None,
            block_if_locked_files: false,
            block_if_deleted_cwd: None,
            block_if_active_tty: false,
            block_if_recent_io_seconds: None,
        };
        let config = LivePreCheckConfig::from(&gates);
        assert!(config.block_if_open_write_fds);
        assert_eq!(config.max_open_write_fds, 0); // None → 0
        assert!(!config.block_if_locked_files);
        assert!(config.block_if_deleted_cwd); // None → true
        assert!(!config.block_if_active_tty);
        assert_eq!(config.block_if_recent_io_seconds, 60); // None → 60
                                                           // Session safety defaults are always enabled
        assert!(config.enhanced_session_safety);
    }

    #[test]
    fn live_config_from_data_loss_gates_with_values() {
        let gates = DataLossGates {
            block_if_open_write_fds: false,
            max_open_write_fds: Some(5),
            block_if_locked_files: true,
            block_if_deleted_cwd: Some(false),
            block_if_active_tty: true,
            block_if_recent_io_seconds: Some(120),
        };
        let config = LivePreCheckConfig::from(&gates);
        assert!(!config.block_if_open_write_fds);
        assert_eq!(config.max_open_write_fds, 5);
        assert!(config.block_if_locked_files);
        assert!(!config.block_if_deleted_cwd);
        assert!(config.block_if_active_tty);
        assert_eq!(config.block_if_recent_io_seconds, 120);
    }

    // ── PreCheckError Display ───────────────────────────────────────

    #[test]
    fn precheck_error_display() {
        let err = PreCheckError::Protected {
            reason: "systemd".to_string(),
        };
        assert!(err.to_string().contains("protected"));
        assert!(err.to_string().contains("systemd"));

        let err = PreCheckError::DataLossRisk {
            reason: "write fds".to_string(),
        };
        assert!(err.to_string().contains("data loss"));

        let err = PreCheckError::SupervisorConflict {
            reason: "nginx".to_string(),
        };
        assert!(err.to_string().contains("supervisor"));

        let err = PreCheckError::SessionSafety {
            reason: "leader".to_string(),
        };
        assert!(err.to_string().contains("session"));

        let err = PreCheckError::Failed("unknown".to_string());
        assert!(err.to_string().contains("check failed"));
    }

    // ── Serialization ───────────────────────────────────────────────

    #[test]
    fn precheck_result_serializes_passed() {
        let result = PreCheckResult::Passed;
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Passed"));
    }

    #[test]
    fn precheck_result_serializes_blocked() {
        let result = PreCheckResult::Blocked {
            check: PreCheck::CheckNotProtected,
            reason: "test reason".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Blocked"));
        assert!(json.contains("test reason"));
    }

    #[test]
    fn supervisor_action_serializes() {
        let restart = SupervisorAction::RestartUnit {
            command: "systemctl restart nginx".to_string(),
        };
        let json = serde_json::to_string(&restart).unwrap();
        assert!(json.contains("restart_unit"));

        let stop = SupervisorAction::StopUnit {
            command: "systemctl stop foo".to_string(),
        };
        let json = serde_json::to_string(&stop).unwrap();
        assert!(json.contains("stop_unit"));

        let kill = SupervisorAction::KillProcess;
        let json = serde_json::to_string(&kill).unwrap();
        assert!(json.contains("kill_process"));
    }

    #[test]
    fn supervisor_info_serializes() {
        let info = SupervisorInfo::from_parent_supervisor("runit");
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("runit"));
        assert!(json.contains("supervisor"));
        // unit_name is None → should be present as null
        assert!(json.contains("unit_name"));
        // systemd_unit skipped when None
        assert!(!json.contains("systemd_unit"));
    }

    // ── Linux-specific tests ────────────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn live_provider_defaults() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            assert!(provider.check_not_protected(pid).is_passed());
        }

        #[test]
        fn live_provider_new_with_guardrails() {
            let guardrails = Guardrails::default();
            let config = LivePreCheckConfig::default();
            let provider = LivePreCheckProvider::new(Some(&guardrails), config);
            assert!(provider.is_ok());
            let provider = provider.unwrap();
            assert!(provider.protected_filter.is_some());
        }

        #[test]
        fn live_provider_new_without_guardrails() {
            let config = LivePreCheckConfig::default();
            let provider = LivePreCheckProvider::new(None, config);
            assert!(provider.is_ok());
            let provider = provider.unwrap();
            assert!(provider.protected_filter.is_none());
        }

        #[test]
        fn live_provider_known_supervisors() {
            let provider = LivePreCheckProvider::with_defaults();
            assert!(provider.known_supervisors.contains("systemd"));
            assert!(provider.known_supervisors.contains("supervisord"));
            assert!(provider.known_supervisors.contains("runit"));
            assert!(provider.known_supervisors.contains("containerd-shim"));
            assert!(!provider.known_supervisors.contains("bash"));
        }

        #[test]
        fn live_provider_read_comm_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let comm = provider.read_comm(pid);
            assert!(comm.is_some());
            // The comm should not be empty
            assert!(!comm.unwrap().is_empty());
        }

        #[test]
        fn live_provider_read_comm_nonexistent() {
            let provider = LivePreCheckProvider::with_defaults();
            let comm = provider.read_comm(u32::MAX);
            assert!(comm.is_none());
        }

        #[test]
        fn live_provider_read_cmdline_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let cmdline = provider.read_cmdline(pid);
            assert!(cmdline.is_some());
        }

        #[test]
        fn live_provider_read_user_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let user = provider.read_user(pid);
            assert!(user.is_some());
        }

        #[test]
        fn live_provider_read_process_state_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let state = provider.read_process_state(pid);
            assert!(state.is_some());
            // Test process should be running or sleeping, not zombie
            let state = state.unwrap();
            assert!(!state.is_zombie());
        }

        #[test]
        fn live_provider_read_process_state_nonexistent() {
            let provider = LivePreCheckProvider::with_defaults();
            let state = provider.read_process_state(u32::MAX);
            assert!(state.is_none());
        }

        #[test]
        fn live_provider_check_process_state_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Our own process should pass state checks
            assert!(provider.check_process_state(pid).is_passed());
        }

        #[test]
        fn live_provider_check_process_state_nonexistent() {
            let provider = LivePreCheckProvider::with_defaults();
            // Nonexistent process should pass (treat as gone)
            assert!(provider.check_process_state(u32::MAX).is_passed());
        }

        #[test]
        fn live_provider_detects_tty() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Just verify the function doesn't panic
            let _ = provider.has_active_tty(pid);
        }

        #[test]
        fn live_provider_detects_write_fds() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let (_, count) = provider.has_open_write_fds(pid);
            // Should return a count without panicking
            let _ = count;
        }

        #[test]
        fn live_provider_has_deleted_cwd_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Our CWD should not be deleted
            assert!(!provider.has_deleted_cwd(pid));
        }

        #[test]
        fn live_provider_has_locked_files_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Just verify the function doesn't panic
            let _ = provider.has_locked_files(pid);
        }

        #[test]
        fn live_provider_extract_cgroup_unit() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Just verify the function doesn't panic
            let _ = provider.extract_cgroup_unit(pid);
        }

        #[test]
        fn live_provider_get_supervisor_info_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Just verify the function doesn't panic
            let _ = provider.get_supervisor_info(pid);
        }

        #[test]
        fn live_provider_read_wchan_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Just verify the function doesn't panic
            let _ = provider.read_wchan(pid);
        }

        #[test]
        fn live_provider_run_all_checks_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let checks = vec![PreCheck::CheckNotProtected, PreCheck::VerifyProcessState];
            let results = provider.run_checks(&checks, pid, None);
            assert_eq!(results.len(), 2);
            // Self should not be protected
            assert!(results[0].is_passed());
            // Self should have valid process state
            assert!(results[1].is_passed());
        }

        #[test]
        fn live_provider_check_session_safety_self_as_leader() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // If we pass our own PID as the session ID, it means we're the session leader
            let result = provider.check_session_safety(pid, Some(pid));
            // Should be blocked as session leader
            assert!(!result.is_passed());
            if let PreCheckResult::Blocked { reason, .. } = result {
                assert!(reason.contains("session leader"));
            }
        }

        #[test]
        fn live_provider_data_loss_disabled_config() {
            let config = LivePreCheckConfig {
                block_if_open_write_fds: false,
                max_open_write_fds: 0,
                block_if_locked_files: false,
                block_if_active_tty: false,
                block_if_deleted_cwd: false,
                block_if_recent_io_seconds: 0,
                enhanced_session_safety: false,
                protect_same_session: false,
                protect_ssh_chains: false,
                protect_multiplexers: false,
                protect_parent_shells: false,
            };
            let provider = LivePreCheckProvider::new(None, config).unwrap();
            let pid = std::process::id();
            // All data loss gates disabled → should pass
            assert!(provider.check_data_loss(pid).is_passed());
        }
    }
}
