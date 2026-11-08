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
use crate::collect::proc_parsers::{read_io, read_required_proc_stat};
use crate::collect::protected::ProtectedFilter;
#[cfg(target_os = "linux")]
use crate::collect::systemd::collect_systemd_unit;
use crate::collect::systemd::{SystemdUnit, SystemdUnitType};
use crate::collect::ProcessState;
use crate::config::policy::{DataLossGates, Guardrails};
use crate::decision::Action;
use crate::plan::{PlanAction, PreCheck};
use crate::supervision::session::{SessionAnalyzer, SessionConfig, SessionProtectionType};
use crate::supervision::{detect_supervision, is_human_supervised, SupervisorCategory};
#[cfg(target_os = "linux")]
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, trace};

/// User name for a uid via the system resolver (getpwuid_r; Directory Services on macOS).
#[cfg(target_os = "macos")]
fn user_name_for_uid(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: passwd is plain old data; getpwuid_r writes into `pwd` and `buf` only,
    // and sets `result` to &pwd on success or null when there is no such user.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: pw_name points into `buf`, NUL-terminated by getpwuid_r.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(any(target_os = "linux", test))]
fn recent_io_probe_window(window: Duration) -> Duration {
    if window.is_zero() {
        Duration::from_millis(10)
    } else {
        window
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_supervision_cgroup_path(pid: u32, content: &str) -> Result<Option<String>, String> {
    let invalid =
        |reason: &str| format!("invalid /proc/{pid}/cgroup supervision evidence: {reason}");
    let mut unified = None;
    let mut systemd = None;
    let mut hierarchies = HashSet::new();
    for line in content.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(invalid("truncated row"));
        };
        let hierarchy: u32 = hierarchy
            .parse()
            .map_err(|_| invalid("invalid hierarchy"))?;
        if !hierarchies.insert(hierarchy) {
            return Err(invalid("duplicate hierarchy"));
        }
        if !path.starts_with('/') || (hierarchy == 0) != controllers.is_empty() {
            return Err(invalid("invalid path or controllers"));
        }
        if hierarchy == 0 {
            unified = Some(path.to_string());
        } else if controllers
            .split(',')
            .any(|controller| controller == "name=systemd")
            && systemd.replace(path.to_string()).is_some()
        {
            return Err(invalid("duplicate systemd hierarchy"));
        }
    }
    if hierarchies.is_empty() {
        return Err(invalid("empty table"));
    }
    Ok(unified.or(systemd))
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
    #[cfg(any(target_os = "linux", test))]
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

    /// Action-aware protection, so restorative actions can release a FUSE
    /// server that was stopped before it was recognized as infrastructure.
    fn check_not_protected_for_action(&self, pid: u32, _action: Action) -> PreCheckResult {
        self.check_not_protected(pid)
    }

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

    /// Run protection first with the intended action, then the remaining gates
    /// in their listed order. Stop at the first refusal: later probes may follow
    /// paths on a mount whose server the infrastructure gate identifies as unsafe.
    /// Identity verification remains the caller's responsibility.
    fn run_checks_for_action(
        &self,
        checks: &[PreCheck],
        pid: u32,
        sid: Option<u32>,
        action: Action,
    ) -> Vec<PreCheckResult> {
        let mut results = Vec::new();
        // A stale or edited plan can list data-loss probes ahead of protection.
        // Do not touch their filesystem targets until infrastructure is checked.
        if checks.contains(&PreCheck::CheckNotProtected) {
            let result = self.check_not_protected_for_action(pid, action);
            let blocked = !result.is_passed();
            results.push(result);
            if blocked {
                return results;
            }
        }
        for check in checks {
            let result = match check {
                // Identity is handled by IdentityProvider; protection ran above.
                PreCheck::VerifyIdentity | PreCheck::CheckNotProtected => continue,
                PreCheck::CheckDataLossGate => self.check_data_loss(pid),
                PreCheck::CheckSupervisor => self.check_supervisor(pid),
                PreCheck::CheckAgentSupervision => self.check_agent_supervision(pid),
                PreCheck::CheckSessionSafety => self.check_session_safety(pid, sid),
                PreCheck::VerifyProcessState => self.check_process_state(pid),
            };
            let blocked = !result.is_passed();
            results.push(result);
            if blocked {
                break;
            }
        }
        results
    }

    /// Preserve the recorded action route when running live gates. Implementors
    /// without a supervisor adapter retain the ordinary refusal behavior.
    fn run_checks_for_plan(&self, action: &PlanAction) -> Vec<PreCheckResult> {
        if action.routing == crate::plan::ActionRouting::Supervisor
            || action.supervisor_restart.is_some()
        {
            return vec![PreCheckResult::Blocked {
                check: PreCheck::CheckSupervisor,
                reason: "precheck provider does not implement supervisor-aware safety checks"
                    .to_string(),
            }];
        }
        self.run_checks_for_action(
            &crate::plan::effective_pre_checks(action),
            action.target.pid.0,
            action.target.sid,
            action.action,
        )
    }
}

/// Refuse disruptive actions when a Linux FUSE server is present or its device
/// descriptors cannot be inspected. Recovery actions remain available so an
/// already stopped or restricted server can resume serving its mounts.
#[cfg(target_os = "linux")]
pub fn fuse_action_precheck(evidence: Option<bool>, action: Action) -> PreCheckResult {
    if matches!(
        action,
        Action::Keep | Action::Resume | Action::Unfreeze | Action::Unquarantine
    ) {
        return PreCheckResult::Passed;
    }
    match evidence {
        Some(false) => PreCheckResult::Passed,
        Some(true) => PreCheckResult::Blocked {
            check: PreCheck::CheckNotProtected,
            reason: format!(
                "{}: {}",
                crate::collect::protected::FUSE_SERVER_RULE,
                crate::collect::protected::FUSE_SERVER_NOTES
            ),
        },
        None => PreCheckResult::Blocked {
            check: PreCheck::CheckNotProtected,
            reason: "cannot inspect FUSE device descriptors; refusing without complete infrastructure evidence"
                .to_string(),
        },
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

/// Whether `/proc/locks` content lists `pid` as a lock holder or blocked waiter.
///
/// Holder lines: `1: POSIX  ADVISORY  WRITE 12345 08:02:1234 0 EOF`.
/// Waiter lines insert `->`: `1: -> POSIX  ADVISORY  WRITE 12346 08:02:1234 0 EOF`,
/// shifting every field by one; the old fixed-index parse missed all waiters.
#[cfg(any(target_os = "linux", test))]
fn proc_locks_mentions_pid(content: &str, pid: u32) -> Result<bool, String> {
    if !content.is_empty() && !content.ends_with('\n') {
        return Err("incomplete lock table".to_string());
    }
    let mut found = false;
    for (index, line) in content.lines().enumerate() {
        let owner = parse_proc_lock_owner(line)
            .map_err(|error| format!("invalid lock row {}: {error}", index + 1))?;
        found |= owner == i64::from(pid);
    }
    Ok(found)
}

/// Validate the complete kernel lock record before interpreting its owner.
/// OFD locks use owner -1; fdinfo, rather than that value, attributes them.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_lock_owner(line: &str) -> Result<i64, String> {
    let mut parts = line.split_whitespace().peekable();
    parts
        .next()
        .and_then(|index| index.strip_suffix(':'))
        .and_then(|index| index.parse::<u64>().ok())
        .ok_or_else(|| "missing or invalid lock index".to_string())?;
    if parts.peek() == Some(&"->") {
        parts.next();
    }
    let fields: Vec<_> = parts.collect();
    if fields.len() != 7 {
        return Err("incomplete or extra lock fields".to_string());
    }
    if !matches!(
        fields[0],
        "POSIX" | "FLOCK" | "OFDLCK" | "LEASE" | "DELEG" | "ACCESS"
    ) || !matches!(
        fields[1],
        "ADVISORY" | "MANDATORY" | "ACTIVE" | "BREAKING" | "BREAKER" | "*NOINODE*"
    ) || !matches!(fields[2], "READ" | "WRITE" | "UNLCK")
    {
        return Err("unknown lock class, mode or type".to_string());
    }
    let owner = fields[3]
        .parse::<i64>()
        .ok()
        .filter(|owner| (-1..=i64::from(u32::MAX)).contains(owner))
        .ok_or_else(|| "invalid lock owner".to_string())?;
    if fields[4] != "<none>:0" {
        let device: Vec<_> = fields[4].split(':').collect();
        if device.len() != 3
            || u32::from_str_radix(device[0], 16).is_err()
            || u32::from_str_radix(device[1], 16).is_err()
            || device[2].parse::<u64>().is_err()
        {
            return Err("invalid lock device or inode".to_string());
        }
    }
    let start = fields[5]
        .parse::<u64>()
        .map_err(|_| "invalid lock start offset".to_string())?;
    if fields[6] != "EOF" && fields[6].parse::<u64>().ok().is_none_or(|end| end < start) {
        return Err("invalid lock end offset".to_string());
    }
    Ok(owner)
}

#[cfg(target_os = "linux")]
fn fdinfo_has_lock(content: &str) -> Result<bool, String> {
    if !content.ends_with('\n') {
        return Err("incomplete descriptor information".to_string());
    }
    let mut position = None;
    let mut flags = None;
    let mut found = false;
    for line in content.lines() {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| "invalid descriptor information row".to_string())?;
        match key {
            "pos" => {
                let value = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| "invalid descriptor position".to_string())?;
                if position.replace(value).is_some() {
                    return Err("duplicate descriptor position".to_string());
                }
            }
            "flags" => {
                let value = u32::from_str_radix(value.trim(), 8)
                    .map_err(|_| "invalid descriptor flags".to_string())?;
                if flags.replace(value).is_some() {
                    return Err("duplicate descriptor flags".to_string());
                }
            }
            "lock" => {
                parse_proc_lock_owner(value)?;
                found = true;
            }
            _ => {}
        }
    }
    if position.is_none() || flags.is_none() {
        return Err("missing descriptor position or flags".to_string());
    }
    Ok(found)
}

#[cfg(target_os = "linux")]
fn read_locked_files_from_proc(pid: u32, proc_root: &std::path::Path) -> Result<bool, String> {
    let locks_path = proc_root.join("locks");
    let content = std::fs::read_to_string(&locks_path)
        .map_err(|error| format!("cannot read {}: {error}", locks_path.display()))?;
    if proc_locks_mentions_pid(&content, pid)
        .map_err(|error| format!("{}: {error}", locks_path.display()))?
    {
        return Ok(true);
    }

    // The global table cannot attribute OFD locks (owner -1), or inherited
    // flock locks whose original owner has exited. fdinfo lists locks attached
    // to this target's actual open descriptions, including either case.
    let fdinfo_dir = proc_root.join(pid.to_string()).join("fdinfo");
    let entries = std::fs::read_dir(&fdinfo_dir)
        .map_err(|error| format!("cannot inspect {}: {error}", fdinfo_dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", fdinfo_dir.display()))?;
        let path = entry.path();
        let content = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if fdinfo_has_lock(&content).map_err(|error| format!("{}: {error}", path.display()))? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(target_os = "macos", test))]
fn lsof_lock_evidence(
    pid: u32,
    output: Result<crate::collect::tool_runner::ToolOutput, crate::collect::tool_runner::ToolError>,
) -> Result<bool, String> {
    let output = output.map_err(|error| format!("lsof for pid {pid}: {error}"))?;
    if !output.success() || output.timed_out || output.truncated || !output.stderr.is_empty() {
        return Err(format!(
            "incomplete lsof evidence for pid {pid} (exit {:?}, timeout {}, truncated {}): {}",
            output.exit_code,
            output.timed_out,
            output.truncated,
            output.stderr_str().trim()
        ));
    }
    let content = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("invalid lsof evidence for pid {pid}: {error}"))?;
    if !content.ends_with('\n') {
        return Err(format!("incomplete lsof fields for pid {pid}"));
    }
    let mut seen_process = false;
    let mut seen_file = false;
    let mut seen_file_type = false;
    let mut found = false;
    for line in content.lines() {
        if let Some(owner) = line.strip_prefix('p') {
            if seen_process || owner.parse::<u32>().ok() != Some(pid) {
                return Err(format!("mismatched lsof process evidence for pid {pid}"));
            }
            seen_process = true;
        } else if let Some(fd) = line.strip_prefix('f') {
            if !seen_process
                || fd.is_empty()
                || fd.eq_ignore_ascii_case("NOFD")
                || fd.eq_ignore_ascii_case("err")
            {
                return Err(format!("unreadable lsof descriptor evidence for pid {pid}"));
            }
            if seen_file && !seen_file_type {
                return Err(format!("missing lsof descriptor type for pid {pid}"));
            }
            seen_file = true;
            seen_file_type = false;
        } else if let Some(file_type) = line.strip_prefix('t') {
            let file_type = file_type.trim().to_ascii_uppercase();
            if !seen_file
                || seen_file_type
                || file_type.is_empty()
                || file_type.starts_with("UNKN")
                || file_type.contains('?')
            {
                return Err(format!("unreadable lsof descriptor type for pid {pid}"));
            }
            seen_file_type = true;
        } else if let Some(lock) = line.strip_prefix('l') {
            if !seen_file {
                return Err(format!("lsof lock without descriptor for pid {pid}"));
            }
            match lock {
                "" | " " => {}
                // Lower-case fields denote partial-file or read/write locks.
                "r" | "R" | "w" | "W" | "u" | "U" | "N" | "x" | "X" => found = true,
                _ => return Err(format!("unknown lsof lock state for pid {pid}: {lock}")),
            }
        } else {
            return Err(format!("invalid lsof field for pid {pid}"));
        }
    }
    if !seen_process || !seen_file || !seen_file_type {
        return Err(format!(
            "missing lsof process, descriptor, or type evidence for pid {pid}"
        ));
    }
    Ok(found)
}

/// Keep the safety query separate from the best-effort inventory collector.
/// `+w` enables warnings, and `0` keeps field contents separate from records.
#[cfg(any(target_os = "macos", test))]
fn lsof_write_fd_args(pid: &str) -> [&str; 7] {
    ["+w", "-n", "-P", "-p", pid, "-F", "0pftna"]
}

/// Read one complete lsof field set: NUL-terminated fields followed by a newline.
/// A newline within a name remains part of that field, never a second descriptor.
#[cfg(any(target_os = "macos", test))]
fn take_lsof_field_set<'a>(remaining: &mut &'a str) -> Result<Vec<&'a str>, String> {
    let mut fields = Vec::new();
    loop {
        let rest = *remaining;
        let end = rest
            .find('\0')
            .ok_or_else(|| "unterminated lsof field".to_string())?;
        let field = &rest[..end];
        if field.is_empty() {
            return Err("empty lsof field".to_string());
        }
        fields.push(field);
        *remaining = &rest[end + 1..];
        if let Some(rest) = remaining.strip_prefix('\n') {
            *remaining = rest;
            return Ok(fields);
        }
    }
}

/// Count writable regular descriptors only from complete, scoped lsof evidence.
/// The inventory collector can return an empty list on errors, omit unknown
/// fields and keep partial output; none of those outcomes proves a safe zero.
#[cfg(any(target_os = "macos", test))]
fn lsof_write_fd_evidence(
    pid: u32,
    output: Result<crate::collect::tool_runner::ToolOutput, crate::collect::tool_runner::ToolError>,
) -> Result<u32, String> {
    let output = output.map_err(|error| format!("lsof for pid {pid}: {error}"))?;
    if !output.success() || output.timed_out || output.truncated || !output.stderr.is_empty() {
        return Err(format!(
            "incomplete lsof writable-descriptor evidence for pid {pid} (exit {:?}, timeout {}, truncated {}): {}",
            output.exit_code,
            output.timed_out,
            output.truncated,
            output.stderr_str().trim()
        ));
    }
    let mut remaining = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("invalid lsof evidence for pid {pid}: {error}"))?;
    let process = take_lsof_field_set(&mut remaining)?;
    let owner = process
        .first()
        .and_then(|field| field.strip_prefix('p'))
        .filter(|owner| !owner.is_empty() && owner.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|owner| owner.parse::<u32>().ok());
    if pid == 0 || process.len() != 1 || owner != Some(pid) || remaining.is_empty() {
        return Err(format!(
            "missing or mismatched lsof process/descriptor evidence for pid {pid}"
        ));
    }

    let mut descriptors = HashSet::new();
    let mut write_count = 0_u32;
    while !remaining.is_empty() {
        let fields = take_lsof_field_set(&mut remaining)?;
        let fd = fields[0]
            .strip_prefix('f')
            .filter(|fd| !fd.is_empty())
            .ok_or_else(|| format!("missing lsof descriptor for pid {pid}"))?;
        let numeric = fd.bytes().all(|byte| byte.is_ascii_digit());
        if numeric {
            let fd = fd
                .parse::<i32>()
                .map_err(|_| format!("invalid lsof descriptor number for pid {pid}"))?;
            if !descriptors.insert(fd) {
                return Err(format!("duplicate lsof descriptor for pid {pid}"));
            }
        } else if !matches!(fd, "cwd" | "rtd" | "txt" | "mem" | "ltx" | "mmap" | "ctty") {
            // NOFD/err mean the descriptor table could not be inspected. Unknown
            // pseudo descriptors (including fileports with unknown access) must
            // not be silently treated as read-only references.
            return Err(format!(
                "unreadable or unknown lsof descriptor for pid {pid}"
            ));
        }

        let mut file_type = None;
        let mut access = None;
        let mut name = None;
        for field in &fields[1..] {
            if let Some(value) = field.strip_prefix('t') {
                if file_type.replace(value).is_some() || value.is_empty() {
                    return Err(format!(
                        "duplicate or empty lsof descriptor type for pid {pid}"
                    ));
                }
            } else if let Some(value) = field.strip_prefix('a') {
                if access.replace(value).is_some() || !matches!(value, "r" | "w" | "u" | " " | "-")
                {
                    return Err(format!(
                        "duplicate or invalid lsof access mode for pid {pid}"
                    ));
                }
            } else if let Some(value) = field.strip_prefix('n') {
                if name.replace(value).is_some() {
                    return Err(format!("duplicate lsof descriptor name for pid {pid}"));
                }
            } else {
                return Err(format!("unexpected lsof descriptor field for pid {pid}"));
            }
        }
        let file_type =
            file_type.ok_or_else(|| format!("missing lsof descriptor type for pid {pid}"))?;
        match file_type {
            "REG" | "VREG" => {
                if name.is_none_or(str::is_empty) {
                    return Err(format!("missing lsof regular-file name for pid {pid}"));
                }
                if numeric {
                    match access {
                        Some("r") => {}
                        Some("w" | "u") => {
                            // A path ending in " (deleted)" does not prove that
                            // every link/reference is gone. Unlike Linux's
                            // metadata probe, this query has no link-count proof.
                            write_count = write_count.checked_add(1).ok_or_else(|| {
                                "lsof writable-descriptor count overflow".to_string()
                            })?;
                        }
                        _ => {
                            return Err(format!(
                                "missing or unknown regular-file access mode for pid {pid}"
                            ));
                        }
                    }
                } else if matches!(access, Some("w" | "u")) {
                    return Err(format!(
                        "writable lsof reference has no numeric descriptor for pid {pid}"
                    ));
                }
            }
            "DIR" | "VDIR" | "CHR" | "VCHR" | "BLK" | "VBLK" | "FIFO" | "VFIFO" | "PIPE"
            | "SOCK" | "unix" | "IPv4" | "IPv6" | "KQUEUE" | "PSXSEM" | "PSXSHM" | "FSEVENT"
            | "NPOLICY" | "systm" => {}
            _ => return Err(format!("unknown lsof descriptor type for pid {pid}")),
        }
    }
    Ok(write_count)
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_proc_tty(pid: u32, content: &str) -> Result<bool, String> {
    let invalid = |reason: &str| format!("invalid /proc/{pid}/stat TTY evidence: {reason}");
    let open = content.find('(').ok_or_else(|| invalid("missing comm"))?;
    let close = content
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| invalid("missing comm terminator"))?;
    if content[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err(invalid("PID differs from requested process"));
    }
    let fields: Vec<_> = content[close + 1..].split_whitespace().collect();
    if !content.ends_with('\n')
        || fields
            .get(19)
            .and_then(|birth| birth.parse::<u64>().ok())
            .is_none()
    {
        return Err(invalid("incomplete process identity"));
    }
    fields
        .get(4)
        .and_then(|tty| tty.parse::<i32>().ok())
        .map(|tty| tty != 0)
        .ok_or_else(|| invalid("missing or invalid tty_nr"))
}

/// Whether an open-file target (a `/proc/<pid>/fd` link) is a file
/// whose pending writes could be lost by killing the process.
///
/// memfds and unlinked files that had a name are excluded: nothing in them can
/// outlive the process, and counting them refused every leaked Chromium or
/// Electron process (they hold unlinked `/dev/shm` or `/tmp` segments and memfds
/// open read-write). An `O_TMPFILE` file (`#<inode>`) is still being built and
/// may be linked into place, so it stays protected, as do named `/dev/shm` files.
/// `still_linked` is the file's own link count being nonzero: a " (deleted)" link
/// only says the name it was opened by is gone, not that the file is.
#[cfg(any(target_os = "linux", test))]
fn is_persistent_file_target(target: &str, still_linked: bool) -> bool {
    if !target.starts_with('/') || target.starts_with("/memfd:") {
        return false;
    }
    let path = match target.strip_suffix(" (deleted)") {
        Some(path) if !still_linked && !is_unnamed_tmpfile(path) => return false,
        Some(path) => path,
        None => target,
    };
    (path.starts_with("/dev/shm/") || !path.starts_with("/dev/"))
        && !["/proc/", "/sys/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// Linux names an `O_TMPFILE` descriptor `<dir>/#<inode>`.
#[cfg(any(target_os = "linux", test))]
fn is_unnamed_tmpfile(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .and_then(|name| name.strip_prefix('#'))
        .is_some_and(|inode| !inode.is_empty() && inode.bytes().all(|b| b.is_ascii_digit()))
}

/// Number of persistent regular files `pid` holds open for writing: the data-loss
/// gate's definition, shared by `agent plan` and the apply-time pre-check. `None`
/// when the process's open files cannot be read.
pub fn open_write_fd_count(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let fd_dir = format!("/proc/{pid}/fd");
        let fdinfo_dir = format!("/proc/{pid}/fdinfo");
        let entries = std::fs::read_dir(&fd_dir).ok()?;
        let mut write_count = 0;

        for entry in entries {
            let entry = entry.ok()?;
            let fd_name = entry.file_name();
            // Only writes to real, persistent files can lose data. stdout/stderr
            // to a pty/pipe, sockets, /dev/null, anon inodes, memfds and unlinked
            // named files do not (see is_persistent_file_target).
            let target = match std::fs::read_link(entry.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            let target = target.to_string_lossy();
            let still_linked = if target.ends_with(" (deleted)") {
                use std::os::unix::fs::MetadataExt;
                match std::fs::metadata(entry.path()) {
                    Ok(metadata) => metadata.nlink() > 0,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return None,
                }
            } else {
                false
            };
            if !is_persistent_file_target(&target, still_linked) {
                continue;
            }
            let metadata = match std::fs::metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            if !metadata.is_file() {
                continue;
            }
            let fdinfo_path = format!("{fdinfo_dir}/{}", fd_name.to_string_lossy());
            let content_bytes = match std::fs::read(&fdinfo_path) {
                Ok(content) => content,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            let content = String::from_utf8_lossy(&content_bytes);
            let flags = content
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())?;
            // O_WRONLY = 1, O_RDWR = 2
            if matches!(flags & 0o3, 1 | 2) {
                write_count += 1;
            }
        }
        Some(write_count)
    }
    #[cfg(target_os = "macos")]
    {
        lsof_write_fd_evidence(
            pid,
            crate::collect::tool_runner::run_tool(
                crate::collect::macos::lsof_path(),
                &lsof_write_fd_args(&pid.to_string()),
                Some(Duration::from_secs(5)),
                None,
            ),
        )
        .ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecentIoEvidence {
    #[cfg(target_os = "linux")]
    Active,
    #[cfg(target_os = "linux")]
    Idle,
    /// The platform has no per-process I/O counters (macOS). Not activity: as in
    /// v2.2.1 the gate passes, since refusing here blocked every macOS action.
    #[cfg(not(target_os = "linux"))]
    Unsupported,
    Unknown(String),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct IoSample {
    birth_ticks: u64,
    wchar: u64,
    write_bytes: u64,
    started_at: Instant,
    finished_at: Instant,
}

/// A read-only observation retained by the planner. It is only a starting point
/// for a new live read, never permission to act on a saved "idle" verdict.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentIoBaseline {
    target: pt_common::ProcessIdentity,
    scope: RecentIoScope,
    started_boot_ns: u64,
    finished_boot_ns: u64,
    birth_ticks: u64,
    wchar: u64,
    write_bytes: u64,
}

/// Boot and namespace identities keep persisted clock/counter observations
/// comparable across separate planner and executor processes.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecentIoScope {
    boot_id: String,
    pid_namespace: String,
    time_namespace: String,
}

#[cfg(target_os = "linux")]
impl RecentIoScope {
    fn read() -> Result<Self, String> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| format!("cannot read I/O observation boot identity: {error}"))?
            .trim()
            .to_string();
        if boot_id.is_empty() || boot_id == "unknown" {
            return Err("I/O observation boot identity is unavailable".to_string());
        }
        let namespace = |name| {
            std::fs::read_link(format!("/proc/self/ns/{name}"))
                .map_err(|error| format!("cannot read I/O {name} namespace: {error}"))?
                .into_os_string()
                .into_string()
                .map_err(|_| format!("invalid I/O {name} namespace"))
        };
        Ok(Self {
            boot_id,
            pid_namespace: namespace("pid")?,
            time_namespace: namespace("time")?,
        })
    }
}

#[cfg(target_os = "linux")]
fn io_boot_clock_ns() -> Result<u64, String> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into the valid stack-allocated timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } != 0 {
        return Err(format!(
            "cannot read I/O observation clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    let seconds = u64::try_from(clock.tv_sec).map_err(|_| "negative I/O boot clock")?;
    let nanos = u64::try_from(clock.tv_nsec).map_err(|_| "negative I/O clock nanoseconds")?;
    if nanos >= 1_000_000_000 {
        return Err("invalid I/O clock nanoseconds".to_string());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| "I/O boot clock overflow".to_string())
}

#[cfg(target_os = "linux")]
impl RecentIoBaseline {
    /// Observe a verified process without sleeping. Unavailable observations are
    /// omitted; apply will use its ordinary full-window probe for those targets.
    pub fn capture(target: &pt_common::ProcessIdentity) -> Option<Self> {
        Self::capture_with_sample(target)
            .ok()
            .map(|(baseline, _)| baseline)
    }

    fn capture_with_sample(
        target: &pt_common::ProcessIdentity,
    ) -> Result<(Self, IoSample), String> {
        use super::executor::IdentityProvider;
        if target.quality != pt_common::IdentityQuality::Full || target.pid.0 <= 1 {
            return Err("I/O observation requires a full target identity".to_string());
        }
        let identity = super::signal::LiveIdentityProvider::new();
        let validate = || match identity.revalidate(target) {
            Ok(true) => Ok(()),
            Ok(false) => Err("I/O observation target identity changed".to_string()),
            Err(error) => Err(format!("cannot verify I/O observation identity: {error}")),
        };
        validate()?;
        let scope = RecentIoScope::read()?;
        let started_boot_ns = io_boot_clock_ns()?;
        let sample = read_io_sample(target.pid.0)?;
        let finished_boot_ns = io_boot_clock_ns()?;
        validate()?;
        if scope != RecentIoScope::read()?
            || finished_boot_ns < started_boot_ns
            || target.start_id
                != pt_common::StartId::from_linux(&scope.boot_id, sample.birth_ticks, target.pid.0)
        {
            return Err("I/O observation scope, clock or identity changed".to_string());
        }
        Ok((
            Self {
                target: target.clone(),
                scope,
                started_boot_ns,
                finished_boot_ns,
                birth_ticks: sample.birth_ticks,
                wchar: sample.wchar,
                write_bytes: sample.write_bytes,
            },
            sample,
        ))
    }

    /// Translate a valid saved observation into the current process's monotonic
    /// clock only after a fresh, equally scoped read. The interval excludes both
    /// reads, so serialization or slow procfs reads cannot inflate coverage.
    fn observation(
        &self,
        current: &Self,
        after: IoSample,
        window: Duration,
    ) -> Option<RecentIoObservation> {
        if self.target.quality != pt_common::IdentityQuality::Full
            || current.target.quality != pt_common::IdentityQuality::Full
            || !self.target.matches(&current.target)
            || self.scope != current.scope
            || self.started_boot_ns > self.finished_boot_ns
            || current.started_boot_ns > current.finished_boot_ns
            || self.birth_ticks != current.birth_ticks
            || self.target.start_id
                != pt_common::StartId::from_linux(
                    &self.scope.boot_id,
                    self.birth_ticks,
                    self.target.pid.0,
                )
            || self.wchar > current.wchar
            || self.write_bytes > current.write_bytes
        {
            return None;
        }
        let elapsed =
            Duration::from_nanos(current.started_boot_ns.checked_sub(self.finished_boot_ns)?);
        if elapsed < window {
            return None;
        }
        let before_at = after.started_at.checked_sub(elapsed)?;
        Some(RecentIoObservation {
            before: Ok(IoSample {
                birth_ticks: self.birth_ticks,
                wchar: self.wchar,
                write_bytes: self.write_bytes,
                started_at: before_at,
                finished_at: before_at,
            }),
            after: Ok(after),
            window,
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct RecentIoObservation {
    before: Result<IoSample, String>,
    after: Result<IoSample, String>,
    window: Duration,
}

#[cfg(target_os = "linux")]
impl RecentIoObservation {
    fn evidence(&self) -> RecentIoEvidence {
        let (before, after) = match (&self.before, &self.after) {
            (Ok(before), Ok(after)) => (before, after),
            (Err(before), Err(after)) => {
                return RecentIoEvidence::Unknown(format!(
                    "before sample: {before}; after sample: {after}"
                ));
            }
            (Err(reason), _) => {
                return RecentIoEvidence::Unknown(format!("before sample: {reason}"));
            }
            (_, Err(reason)) => {
                return RecentIoEvidence::Unknown(format!("after sample: {reason}"));
            }
        };
        if before.birth_ticks != after.birth_ticks {
            return RecentIoEvidence::Unknown(
                "process birth changed during I/O window".to_string(),
            );
        }
        if !after
            .started_at
            .checked_duration_since(before.finished_at)
            .is_some_and(|elapsed| elapsed >= self.window)
        {
            return RecentIoEvidence::Unknown(
                "I/O samples do not cover the required window".to_string(),
            );
        }
        if after.wchar < before.wchar || after.write_bytes < before.write_bytes {
            return RecentIoEvidence::Unknown(
                "I/O counters decreased during observation".to_string(),
            );
        }
        if after.wchar > before.wchar || after.write_bytes > before.write_bytes {
            RecentIoEvidence::Active
        } else {
            RecentIoEvidence::Idle
        }
    }

    fn revalidate(&self, current: Result<IoSample, String>) -> RecentIoEvidence {
        let evidence = self.evidence();
        if matches!(evidence, RecentIoEvidence::Unknown(_)) {
            return evidence;
        }
        let (after, current) = match (&self.after, current) {
            (Ok(after), Ok(current)) => (after, current),
            (_, Err(reason)) => {
                return RecentIoEvidence::Unknown(format!("cache revalidation: {reason}"));
            }
            (Err(reason), _) => return RecentIoEvidence::Unknown(reason.clone()),
        };
        if after.birth_ticks != current.birth_ticks {
            return RecentIoEvidence::Unknown(
                "process birth changed since cached I/O sample".to_string(),
            );
        }
        let Some(age) = current.started_at.checked_duration_since(after.finished_at) else {
            return RecentIoEvidence::Unknown(
                "cached I/O sample is newer than revalidation".to_string(),
            );
        };
        if current.wchar < after.wchar || current.write_bytes < after.write_bytes {
            return RecentIoEvidence::Unknown(
                "I/O counters decreased since cached sample".to_string(),
            );
        }
        let increased = current.wchar > after.wchar || current.write_bytes > after.write_bytes;
        // Equal cumulative counters for the same birth extend a complete idle
        // window through this fresh read, even when earlier actions were slow.
        if evidence == RecentIoEvidence::Idle && !increased {
            return RecentIoEvidence::Idle;
        }
        if age > self.window {
            return RecentIoEvidence::Unknown(
                "cached activity is stale; a complete new I/O window is required".to_string(),
            );
        }
        RecentIoEvidence::Active
    }
}

#[cfg(target_os = "linux")]
fn read_io_birth(pid: u32) -> Result<u64, String> {
    let bytes = std::fs::read(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("cannot read /proc/{pid}/stat for I/O identity: {error}"))?;
    parse_io_birth(pid, &String::from_utf8_lossy(&bytes))
}

#[cfg(target_os = "linux")]
fn parse_io_birth(pid: u32, content: &str) -> Result<u64, String> {
    let open = content
        .find('(')
        .ok_or_else(|| format!("invalid /proc/{pid}/stat process identity"))?;
    let close = content
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| format!("invalid /proc/{pid}/stat process identity"))?;
    if content[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err(format!("mismatched /proc/{pid}/stat PID"));
    }
    content[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| format!("missing or invalid /proc/{pid}/stat birth ticks"))
}

#[cfg(target_os = "linux")]
fn read_io_sample(pid: u32) -> Result<IoSample, String> {
    let started_at = Instant::now();
    let birth_ticks = read_io_birth(pid)?;
    let io = read_io(pid).map_err(|error| error.to_string())?;
    if read_io_birth(pid)? != birth_ticks {
        return Err(format!(
            "process birth changed while reading /proc/{pid}/io"
        ));
    }
    Ok(IoSample {
        birth_ticks,
        wchar: io.wchar,
        write_bytes: io.write_bytes,
        started_at,
        finished_at: Instant::now(),
    })
}

/// Live pre-check provider that reads from /proc (Linux) or sysctl/lsof (macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct LivePreCheckProvider {
    protected_filter: Option<ProtectedFilter>,
    config: LivePreCheckConfig,
    /// Known supervisor comm names.
    known_supervisors: HashSet<String>,
    /// Recent-I/O results sampled up front for many pids (see `prime_recent_io`).
    #[cfg(target_os = "linux")]
    recent_io: std::sync::Mutex<std::collections::HashMap<u32, RecentIoObservation>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl LivePreCheckProvider {
    /// Reuse plan-time counters only when a fresh read already covers the full
    /// configured window for the same process, boot and namespaces. Missing,
    /// ambiguous, young or invalid baselines use the unchanged shared live probe.
    /// Counter growth over a longer saved interval conservatively blocks action.
    #[cfg(target_os = "linux")]
    pub fn prime_recent_io_from_baselines(
        &self,
        targets: &[pt_common::ProcessIdentity],
        baselines: &[RecentIoBaseline],
    ) {
        if self.config.block_if_recent_io_seconds == 0 {
            return;
        }
        let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
        let mut unobserved = Vec::new();
        let mut seen = HashSet::new();
        let mut observations = Vec::new();
        for target in targets {
            if !seen.insert(target.pid.0) {
                continue;
            }
            let mut matching = baselines
                .iter()
                .filter(|baseline| baseline.target.pid == target.pid);
            let baseline = matching.next().filter(|_| matching.next().is_none());
            let observation = baseline
                .filter(|baseline| baseline.target.matches(target))
                .and_then(|baseline| {
                    let (current, sample) = RecentIoBaseline::capture_with_sample(target).ok()?;
                    baseline.observation(&current, sample, window)
                });
            match observation {
                Some(observation) => observations.push((target.pid.0, observation)),
                None => unobserved.push(target.pid.0),
            }
        }
        trace!(
            reused = observations.len(),
            fresh = unobserved.len(),
            "priming identity-bound recent I/O evidence"
        );
        self.recent_io
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(observations);
        self.prime_recent_io(&unobserved);
    }

    /// Sample recent I/O for all `pids` in ONE probe window and cache the results,
    /// so applying N destructive actions costs one window instead of N (it slept
    /// the full window, 60 s by default, per target). Pids not primed are probed
    /// individually as before.
    pub fn prime_recent_io(&self, pids: &[u32]) {
        // Unsupported probes become Unknown when the enabled gate is evaluated.
        #[cfg(not(target_os = "linux"))]
        let _ = pids;
        #[cfg(target_os = "linux")]
        if self.config.block_if_recent_io_seconds > 0 && !pids.is_empty() {
            let before: Vec<_> = pids.iter().map(|&pid| (pid, read_io_sample(pid))).collect();
            let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
            std::thread::sleep(recent_io_probe_window(window));
            let observations: Vec<_> = before
                .into_iter()
                .map(|(pid, before)| {
                    (
                        pid,
                        RecentIoObservation {
                            before,
                            after: read_io_sample(pid),
                            window,
                        },
                    )
                })
                .collect();
            let mut cache = self.recent_io.lock().unwrap_or_else(|e| e.into_inner());
            for (pid, observation) in observations {
                cache.insert(pid, observation);
            }
        }
    }

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
            "launchd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Ok(Self {
            protected_filter,
            config,
            known_supervisors,
            #[cfg(target_os = "linux")]
            recent_io: Default::default(),
        })
    }

    /// Read process comm (basename) from the OS.
    fn read_comm(&self, pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let comm_path = format!("/proc/{pid}/comm");
            let comm_bytes = std::fs::read(&comm_path).ok()?;
            Some(String::from_utf8_lossy(&comm_bytes).trim().to_string())
        }
        #[cfg(target_os = "macos")]
        {
            crate::collect::read_process_snapshot(pid).map(|info| info.comm)
        }
    }

    /// Read process cmdline from the OS.
    fn read_cmdline(&self, pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let cmdline_path = format!("/proc/{pid}/cmdline");
            let cmdline_bytes = std::fs::read(&cmdline_path).ok()?;
            let s = String::from_utf8_lossy(&cmdline_bytes);
            Some(s.replace('\0', " ").trim().to_string())
        }
        #[cfg(target_os = "macos")]
        {
            // Full argv via ps (the command-line protection rules need the arguments,
            // e.g. `ssh -M`, `-zsh`, `ssh host nc -U .../sock`); comm as a fallback.
            let pid_arg = pid.to_string();
            crate::collect::tool_runner::run_tool(
                "ps",
                &["-p", &pid_arg, "-o", "args="],
                Some(std::time::Duration::from_secs(5)),
                None,
            )
            .ok()
            .filter(|out| out.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|args| !args.is_empty())
            .or_else(|| self.read_comm(pid))
        }
    }

    /// Read process owner username.
    fn read_user(&self, pid: u32) -> Option<String> {
        let uid = self.read_uid(pid)?;
        // macOS keeps real users in Directory Services, not /etc/passwd: ask the
        // system resolver so operator-listed protected users match by name.
        #[cfg(target_os = "macos")]
        if let Some(name) = user_name_for_uid(uid) {
            return Some(name);
        }
        // Try to resolve UID to username safely
        #[cfg(unix)]
        {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                let uid_str_target = uid.to_string();
                for pwd_line in passwd.lines() {
                    let mut fields = pwd_line.split(':');
                    let username = fields.next();
                    let _passwd = fields.next();
                    let uid_field = fields.next();
                    if let (Some(u), Some(f)) = (username, uid_field) {
                        if f == uid_str_target {
                            return Some(u.to_string());
                        }
                    }
                }
            }
        }
        Some(uid.to_string())
    }

    /// Read process UID.
    fn read_uid(&self, pid: u32) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            let status_path = format!("/proc/{pid}/status");
            let content_bytes = std::fs::read(&status_path).ok()?;
            let content = String::from_utf8_lossy(&content_bytes);
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    return line.split_whitespace().nth(1)?.parse().ok();
                }
            }
            None
        }
        #[cfg(target_os = "macos")]
        {
            crate::collect::read_process_snapshot(pid).map(|info| info.uid)
        }
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
            #[cfg(target_os = "linux")]
            recent_io: Default::default(),
        }
    }

    /// Check if process has open write file descriptors.
    fn has_open_write_fds(&self, pid: u32) -> Option<(bool, u32)> {
        let write_count = open_write_fd_count(pid)?;
        Some((write_count > self.config.max_open_write_fds, write_count))
    }

    /// Observe a full I/O window, retaining unreadable and invalid evidence.
    fn has_recent_io(&self, pid: u32, window: Duration) -> RecentIoEvidence {
        #[cfg(target_os = "linux")]
        {
            let cached = self
                .recent_io
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&pid)
                .cloned();
            if let Some(cached) = cached {
                if cached.window != window {
                    return RecentIoEvidence::Unknown(
                        "cached I/O window differs from the required window".to_string(),
                    );
                }
                return cached.revalidate(read_io_sample(pid));
            }
            let before = read_io_sample(pid);
            std::thread::sleep(recent_io_probe_window(window));
            let observation = RecentIoObservation {
                before,
                after: read_io_sample(pid),
                window,
            };
            let evidence = observation.evidence();
            self.recent_io
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(pid, observation);
            evidence
        }
        #[cfg(target_os = "macos")]
        {
            let _ = pid;
            let _ = window;
            RecentIoEvidence::Unsupported
        }
    }

    /// Check locks without treating unavailable evidence as an unlocked process.
    fn has_locked_files(&self, pid: u32) -> Result<bool, String> {
        #[cfg(target_os = "linux")]
        {
            read_locked_files_from_proc(pid, std::path::Path::new("/proc"))
        }
        #[cfg(target_os = "macos")]
        {
            lsof_lock_evidence(
                pid,
                crate::collect::tool_runner::run_tool(
                    "lsof",
                    &["+w", "-n", "-P", "-p", &pid.to_string(), "-F", "pflt"],
                    Some(std::time::Duration::from_secs(5)),
                    None,
                ),
            )
        }
    }

    /// Check terminal attachment while preserving missing or malformed evidence.
    fn has_active_tty(&self, pid: u32) -> Result<bool, String> {
        #[cfg(target_os = "linux")]
        {
            let stat_path = format!("/proc/{pid}/stat");
            let content = std::fs::read_to_string(&stat_path)
                .map_err(|error| format!("cannot read {stat_path}: {error}"))?;
            parse_proc_tty(pid, &content)
        }
        #[cfg(target_os = "macos")]
        {
            crate::collect::macos::read_session_stat(pid)
                .map(|info| info.tty_nr != 0)
                .ok_or_else(|| format!("cannot read native terminal information for pid {pid}"))
        }
    }

    /// Check Linux CWD evidence without treating an unreadable link as healthy.
    #[cfg(target_os = "linux")]
    fn has_deleted_cwd(&self, pid: u32) -> Result<bool, String> {
        let cwd_link = format!("/proc/{pid}/cwd");
        let target = std::fs::read_link(&cwd_link)
            .map_err(|error| format!("cannot read {cwd_link}: {error}"))?;
        Ok(target.to_string_lossy().ends_with(" (deleted)"))
    }

    /// Read process state.
    fn read_process_state(&self, pid: u32) -> Option<ProcessState> {
        #[cfg(target_os = "linux")]
        {
            let stat_path = format!("/proc/{pid}/stat");
            let content_bytes = std::fs::read(&stat_path).ok()?;
            let content = String::from_utf8_lossy(&content_bytes);

            // Parse state from stat: pid (comm) state ...
            // State is the first character after the closing paren
            let comm_end = content.rfind(')')?;
            let after_comm = content.get(comm_end + 2..)?;
            let state_char = after_comm.chars().next()?;

            Some(ProcessState::from_char(state_char))
        }
        #[cfg(target_os = "macos")]
        {
            crate::collect::read_process_snapshot(pid)
                .map(|info| ProcessState::from_char(info.state))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            None
        }
    }

    /// Read kernel wait channel.
    #[cfg(target_os = "linux")]
    fn read_wchan(&self, pid: u32) -> Option<String> {
        let wchan_path = format!("/proc/{pid}/wchan");
        let wchan_bytes = std::fs::read(&wchan_path).ok()?;
        let wchan = String::from_utf8_lossy(&wchan_bytes).trim().to_string();

        // "0" means not blocked, return None in that case
        if wchan == "0" || wchan.is_empty() {
            None
        } else {
            Some(wchan)
        }
    }

    /// Get parent process comm name.
    fn get_ppid_comm(&self, pid: u32) -> Result<Option<String>, String> {
        #[cfg(target_os = "linux")]
        {
            let before = read_required_proc_stat(pid).map_err(|error| error.to_string())?;
            if before.ppid == 0 {
                return Ok(None);
            }
            if before.ppid == pid {
                return Err(format!(
                    "parent supervision evidence for PID {pid} has a self-parent loop"
                ));
            }
            let parent = read_required_proc_stat(before.ppid).map_err(|error| error.to_string())?;
            let parent_after =
                read_required_proc_stat(before.ppid).map_err(|error| error.to_string())?;
            let after = read_required_proc_stat(pid).map_err(|error| error.to_string())?;
            if after.starttime != before.starttime
                || after.ppid != before.ppid
                || parent_after.starttime != parent.starttime
                || parent_after.comm != parent.comm
            {
                return Err(format!("parent supervision evidence changed for PID {pid}"));
            }
            Ok(Some(parent.comm))
        }
        // No /proc here: take the parent from `ps`, as v2.2.1 did, so the launchd
        // check below still runs. Refusing instead blocked every macOS action.
        #[cfg(target_os = "macos")]
        {
            Ok(crate::collect::read_process_snapshot(pid)
                .and_then(|info| self.read_comm(info.ppid)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            Ok(None)
        }
    }

    /// Check if process is managed by a known supervisor.
    fn is_supervisor_managed(&self, pid: u32) -> Result<Option<SupervisorInfo>, String> {
        // First check for non-systemd supervisors via parent comm
        if let Some(ppid_comm) = self.get_ppid_comm(pid)? {
            if self.known_supervisors.contains(&ppid_comm) && ppid_comm != "systemd" {
                return Ok(Some(SupervisorInfo::from_parent_supervisor(&ppid_comm)));
            }
        }

        // Try to get systemd unit info with full metadata (Linux only)
        #[cfg(target_os = "linux")]
        {
            // A login session (session-N.scope) or transient scope holds whatever a user
            // started; systemd does not supervise or restart it. Treating it as a unit
            // blocked every action on processes started over SSH ("use systemctl stop
            // session-N.scope", which would end the whole login).
            let cgroup_path = self.read_supervision_cgroup_path(pid)?;
            if cgroup_path.as_deref().is_some_and(|path| {
                crate::collect::classify_live_cgroup_path(pid, path).is_user_workload()
            }) {
                trace!(
                    pid,
                    "login-session / terminal-pane / transient-scope workload: not supervised"
                );
                return Ok(None);
            }
            let cgroup_unit = cgroup_path
                .as_deref()
                .and_then(|path| {
                    path.rsplit('/')
                        .find(|unit| unit.ends_with(".service") || unit.ends_with(".scope"))
                })
                .map(str::to_string);
            if let Some(unit) = collect_systemd_unit(pid, cgroup_unit.as_deref()) {
                // Filter out slice-only units (e.g., user.slice) - these aren't real supervision
                if unit.unit_type == SystemdUnitType::Slice {
                    trace!(pid, unit_name = %unit.name, "ignoring slice-only unit");
                    return Ok(None);
                }

                debug!(
                    pid,
                    unit_name = %unit.name,
                    unit_type = ?unit.unit_type,
                    is_main = unit.is_main_process,
                    "detected systemd unit"
                );

                return Ok(Some(SupervisorInfo::from_systemd_unit(unit, pid)));
            }
        }

        // Check for launchd (macOS only)
        #[cfg(target_os = "macos")]
        {
            if let Some(launchd_service) = crate::collect::macos::detect_launchd_service(pid) {
                let label = launchd_service.label;
                let service_target = format!("system/{}", label);
                return Ok(Some(SupervisorInfo {
                    supervisor: "launchd".to_string(),
                    unit_name: Some(label.clone()),
                    unit_type: None,
                    is_main_process: true, // If detect_launchd_service returns it, it's the main process
                    recommended_action: SupervisorAction::StopUnit {
                        command: format!("launchctl bootout {}", service_target),
                    },
                    systemd_unit: None,
                }));
            }
        }

        Ok(None)
    }

    /// Read validated current cgroup placement without converting errors to absence.
    #[cfg(target_os = "linux")]
    fn read_supervision_cgroup_path(&self, pid: u32) -> Result<Option<String>, String> {
        let before = read_required_proc_stat(pid).map_err(|error| error.to_string())?;
        let cgroup_path = format!("/proc/{pid}/cgroup");
        let content_bytes = std::fs::read(&cgroup_path)
            .map_err(|error| format!("cannot read {cgroup_path}: {error}"))?;
        let content = std::str::from_utf8(&content_bytes)
            .map_err(|_| format!("invalid UTF-8 at {cgroup_path}"))?;
        let path = parse_supervision_cgroup_path(pid, content)?;
        let after = read_required_proc_stat(pid).map_err(|error| error.to_string())?;
        if after.starttime != before.starttime {
            return Err(format!("cgroup supervision evidence changed for PID {pid}"));
        }
        Ok(path)
    }
}

impl LivePreCheckProvider {
    fn check_not_protected_with_service(
        &self,
        pid: u32,
        _action: Action,
        bound_user_service: bool,
    ) -> PreCheckResult {
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

            // Built-in live-infrastructure protection (same rules as the scan filter)
            let mut session_workload = false;
            if filter.builtin_enabled() {
                if crate::collect::protected::live_invoker_chain_pids().contains(&pid) {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckNotProtected,
                        reason: "pt itself or one of its invoking processes".to_string(),
                    };
                }
                if let Some((rule, notes)) =
                    crate::collect::protected::builtin_protection_match(&comm, &cmd)
                {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckNotProtected,
                        reason: format!("{rule}: {notes}"),
                    };
                }
                // Prefer direct descriptor evidence to ancestry heuristics so
                // a FUSE server always gets mount-specific remediation.
                #[cfg(target_os = "linux")]
                {
                    let result = fuse_action_precheck(
                        crate::collect::protected::holds_fuse_device(pid),
                        _action,
                    );
                    if !result.is_passed() {
                        return result;
                    }
                }
                if let Some((daemon_pid, daemon)) =
                    crate::collect::protected::live_service_ancestor(pid)
                {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckNotProtected,
                        reason: format!(
                            "builtin.service_child: worker/plugin of service {daemon} (pid {daemon_pid})"
                        ),
                    };
                }
                let role = crate::collect::read_cgroup_role(pid);
                if role.is_supervised_service()
                    && !(bound_user_service && role == crate::collect::CgroupRole::UserService)
                {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckNotProtected,
                        reason: format!(
                            "supervised service (cgroup {role:?}); stop the unit instead"
                        ),
                    };
                }
                session_workload = role.is_user_workload();
                // macOS has no cgroups: same owner/executable placement as the scan.
                if cfg!(target_os = "macos") {
                    use crate::collect::protected::{macos_placement, MacPlacement};
                    match macos_placement(&user, &comm, &cmd) {
                        MacPlacement::System(notes) => {
                            return PreCheckResult::Blocked {
                                check: PreCheck::CheckNotProtected,
                                reason: format!("builtin.macos_system: {notes}"),
                            };
                        }
                        MacPlacement::UserWorkload => session_workload = true,
                    }
                }
            }

            // Check protected users (login-session workloads are exempt, see
            // ProtectedFilter::is_protected_with_role)
            if !(session_workload && crate::collect::protected::is_root_user(&user))
                && filter.protected_users().contains(&user.to_lowercase())
            {
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

    /// A verified single-process service may own a detached session. Its own
    /// no-TTY session-leader status is not an interactive session to preserve;
    /// every other protection from the shared session analyzer still applies.
    #[cfg(target_os = "linux")]
    fn check_bound_restart_session(&self, pid: u32) -> PreCheckResult {
        let blocked = |reason| PreCheckResult::Blocked {
            check: PreCheck::CheckSessionSafety,
            reason,
        };
        match self.has_active_tty(pid) {
            Ok(false) => {}
            Ok(true) => return blocked("interactive service has an active TTY".to_string()),
            Err(error) => return blocked(format!("TTY evidence unavailable: {error}")),
        }
        if self.config.enhanced_session_safety {
            let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                max_ancestry_depth: 20,
                protect_same_session: self.config.protect_same_session,
                protect_parent_shells: self.config.protect_parent_shells,
                protect_multiplexers: self.config.protect_multiplexers,
                protect_ssh_chains: self.config.protect_ssh_chains,
                protect_foreground_groups: true,
            });
            let result = match analyzer.analyze(pid, std::process::id()) {
                Ok(result) => result,
                Err(error) => {
                    return blocked(format!("session safety evidence unavailable: {error}"));
                }
            };
            if !detached_service_session_is_safe(&result) {
                return blocked(format!(
                    "protected session chain: {}",
                    result
                        .protection_types
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        PreCheckResult::Passed
    }

    #[cfg(target_os = "linux")]
    fn run_bound_restart_checks(&self, action: &PlanAction) -> Vec<PreCheckResult> {
        let blocked = |check, reason| PreCheckResult::Blocked { check, reason };
        let binding = match super::supervisor::restart_binding_for_action(action) {
            Ok(binding) => binding,
            Err(error) => {
                return vec![blocked(PreCheck::CheckSupervisor, error.to_string())];
            }
        };
        let started = Instant::now();
        let budget = Duration::from_millis(action.timeouts.preflight_ms.min(30_000));
        let remaining = || {
            budget
                .checked_sub(started.elapsed())
                .filter(|left| !left.is_zero())
        };
        if remaining().is_none() {
            return vec![blocked(
                PreCheck::CheckSupervisor,
                "supervisor preflight budget exhausted".to_string(),
            )];
        }
        // Infrastructure protection precedes descriptor and filesystem probes.
        let protection =
            self.check_not_protected_with_service(action.target.pid.0, action.action, true);
        let refused = !protection.is_passed();
        let mut results = vec![protection];
        if refused {
            return results;
        }
        let validation = super::supervisor::validate_systemd_user_restart(
            &action.target,
            binding,
            remaining().unwrap_or_default(),
        );
        if let Err(error) = validation {
            results.push(blocked(PreCheck::CheckSupervisor, error.to_string()));
            return results;
        }
        results.push(PreCheckResult::Passed);
        for check in crate::plan::effective_pre_checks(action) {
            let Some(left) = remaining() else {
                results.push(blocked(
                    check,
                    "supervisor preflight budget exhausted".to_string(),
                ));
                break;
            };
            let result = match check {
                PreCheck::VerifyIdentity
                | PreCheck::CheckNotProtected
                | PreCheck::CheckSupervisor => continue,
                PreCheck::CheckSessionSafety => {
                    self.check_bound_restart_session(action.target.pid.0)
                }
                PreCheck::CheckDataLossGate => {
                    let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
                    let cached = self
                        .recent_io
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .contains_key(&action.target.pid.0);
                    if !window.is_zero() && !cached && window >= left {
                        blocked(
                            PreCheck::CheckDataLossGate,
                            "complete recent-I/O evidence must be primed before the bounded \
                             supervisor preflight; the required window is not shortened"
                                .to_string(),
                        )
                    } else {
                        self.check_data_loss(action.target.pid.0)
                    }
                }
                PreCheck::CheckAgentSupervision => {
                    self.check_agent_supervision(action.target.pid.0)
                }
                PreCheck::VerifyProcessState => self.check_process_state(action.target.pid.0),
            };
            let refused = !result.is_passed();
            results.push(result);
            if refused {
                break;
            }
        }
        if results.iter().all(PreCheckResult::is_passed) && remaining().is_none() {
            results.push(blocked(
                PreCheck::CheckSupervisor,
                "supervisor preflight budget exhausted".to_string(),
            ));
        }
        results
    }
}

#[cfg(any(target_os = "linux", test))]
fn detached_service_session_is_safe(result: &crate::supervision::session::SessionResult) -> bool {
    result.tty_nr.is_none()
        && (!result.is_protected || !result.protection_types.is_empty())
        && result
            .protection_types
            .iter()
            .all(|protection| *protection == SessionProtectionType::SessionLeader)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PreCheckProvider for LivePreCheckProvider {
    fn check_not_protected(&self, pid: u32) -> PreCheckResult {
        self.check_not_protected_for_action(pid, Action::Kill)
    }

    fn check_not_protected_for_action(&self, pid: u32, action: Action) -> PreCheckResult {
        self.check_not_protected_with_service(pid, action, false)
    }

    fn run_checks_for_plan(&self, action: &PlanAction) -> Vec<PreCheckResult> {
        if action.routing == crate::plan::ActionRouting::Supervisor
            || action.supervisor_restart.is_some()
        {
            #[cfg(target_os = "linux")]
            {
                return self.run_bound_restart_checks(action);
            }
            #[cfg(not(target_os = "linux"))]
            {
                return vec![PreCheckResult::Blocked {
                    check: PreCheck::CheckSupervisor,
                    reason: "systemd user-service restart requires Linux".to_string(),
                }];
            }
        }
        self.run_checks_for_action(
            &crate::plan::effective_pre_checks(action),
            action.target.pid.0,
            action.target.sid,
            action.action,
        )
    }

    fn check_data_loss(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking data loss risk");

        // Check open write file descriptors
        if self.config.block_if_open_write_fds {
            let Some((exceeds_max, write_count)) = self.has_open_write_fds(pid) else {
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckDataLossGate,
                    reason:
                        "cannot inspect open files; refusing without complete data-loss evidence"
                            .to_string(),
                };
            };
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
        if self.config.block_if_locked_files {
            match self.has_locked_files(pid) {
                Ok(false) => {}
                Ok(true) => {
                    debug!(pid, "process has locked files");
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckDataLossGate,
                        reason: "process has locked files".to_string(),
                    };
                }
                Err(error) => {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckDataLossGate,
                        reason: format!("locked-file evidence unavailable: {error}"),
                    };
                }
            }
        }

        // This gate is supported on Linux, where procfs exposes deleted CWDs.
        #[cfg(target_os = "linux")]
        if self.config.block_if_deleted_cwd {
            match self.has_deleted_cwd(pid) {
                Ok(false) => {}
                Ok(true) => {
                    debug!(pid, "process has deleted cwd");
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckDataLossGate,
                        reason: "process CWD is deleted".to_string(),
                    };
                }
                Err(error) => {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckDataLossGate,
                        reason: format!("CWD evidence unavailable: {error}"),
                    };
                }
            }
        }

        // Enabled I/O gates require a complete observation, including identity.
        if self.config.block_if_recent_io_seconds > 0 {
            let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
            match self.has_recent_io(pid, window) {
                #[cfg(target_os = "linux")]
                RecentIoEvidence::Idle => {}
                #[cfg(not(target_os = "linux"))]
                RecentIoEvidence::Unsupported => {}
                RecentIoEvidence::Unknown(reason) => {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckDataLossGate,
                        reason: format!("recent I/O evidence unavailable: {reason}"),
                    };
                }
                #[cfg(target_os = "linux")]
                RecentIoEvidence::Active => {
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
        }

        PreCheckResult::Passed
    }

    fn check_supervisor(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking supervisor status");

        let supervisor_info = match self.is_supervisor_managed(pid) {
            Ok(info) => info,
            Err(error) => {
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckSupervisor,
                    reason: format!("supervisor evidence unavailable: {error}"),
                }
            }
        };
        if let Some(supervisor_info) = supervisor_info {
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
                        .map(|t: SupervisorCategory| t.to_string())
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
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckAgentSupervision,
                    reason: format!("agent supervision evidence unavailable: {e}"),
                };
            }
        }

        PreCheckResult::Passed
    }

    fn get_supervisor_info(&self, pid: u32) -> Option<SupervisorInfo> {
        self.is_supervisor_managed(pid).ok().flatten()
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
        if self.config.block_if_active_tty {
            match self.has_active_tty(pid) {
                Ok(false) => {}
                Ok(true) => {
                    debug!(pid, "process has active TTY");
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckSessionSafety,
                        reason: "process has active TTY".to_string(),
                    };
                }
                Err(error) => {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckSessionSafety,
                        reason: format!("TTY evidence unavailable: {error}"),
                    };
                }
            }
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
                Err(error) => {
                    return PreCheckResult::Blocked {
                        check: PreCheck::CheckSessionSafety,
                        reason: format!("session safety evidence unavailable: {error}"),
                    };
                }
            }
        }

        PreCheckResult::Passed
    }

    fn check_process_state(&self, pid: u32) -> PreCheckResult {
        trace!(pid, "checking process state for kill viability");

        // Read current process state
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
        #[cfg(target_os = "linux")]
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

    fn check_process_state(&self, _pid: u32) -> PreCheckResult {
        PreCheckResult::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_service_session_exception_preserves_every_other_session_protection() {
        use crate::supervision::session::SessionResult;
        let leader = SessionResult::protected(
            vec![SessionProtectionType::SessionLeader],
            "detached service session".to_string(),
            vec![],
        );
        assert!(detached_service_session_is_safe(&leader));
        for extra in [
            SessionProtectionType::SameSession,
            SessionProtectionType::ParentShell,
            SessionProtectionType::TmuxServer,
            SessionProtectionType::TmuxClient,
            SessionProtectionType::ScreenServer,
            SessionProtectionType::ScreenClient,
            SessionProtectionType::SshChain,
            SessionProtectionType::ForegroundGroup,
            SessionProtectionType::TtyController,
        ] {
            let mut changed = leader.clone();
            changed.protection_types.push(extra);
            assert!(!detached_service_session_is_safe(&changed), "{extra:?}");
        }
        let mut attached = leader.clone();
        attached.tty_nr = Some(34816);
        assert!(!detached_service_session_is_safe(&attached));
        let mut unknown = leader;
        unknown.protection_types.clear();
        assert!(!detached_service_session_is_safe(&unknown));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_preflight_refuses_zero_budget_and_forged_routing_before_probes() {
        // SAFETY: geteuid only reads the test process's credentials.
        let uid = unsafe { libc::geteuid() };
        let identity = pt_common::ProcessIdentity::full(
            u32::MAX,
            pt_common::StartId::from_linux("preflight-test", 1, u32::MAX),
            uid,
            None,
            None,
            pt_common::IdentityQuality::Full,
        );
        let binding = crate::action::SystemdUserServiceBinding {
            target: identity.clone(),
            unit: "worker-proof.service".into(),
            control_group: format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/worker-proof.service"
            ),
            invocation_id: "1234567890abcdef1234567890abcdef".into(),
        };
        let mut action: PlanAction = serde_json::from_value(serde_json::json!({
            "action_id": "preflight-test", "target": identity, "action": "restart",
            "order": 0, "stage": 0, "pre_checks": [], "rationale": {},
            "on_success": [], "on_failure": [], "blocked": false,
            "timeouts": {"preflight_ms": 0, "execute_ms": 1, "verify_ms": 1},
            "routing": "supervisor", "supervisor_restart": binding,
        }))
        .unwrap();
        let provider = LivePreCheckProvider::with_defaults();
        let results = provider.run_checks_for_plan(&action);
        assert!(matches!(&results[0], PreCheckResult::Blocked {
            check: PreCheck::CheckSupervisor, reason
        } if reason.contains("budget exhausted")));
        action.timeouts.preflight_ms = 5000;
        action.routing = crate::plan::ActionRouting::ZombieToParent;
        let results = provider.run_checks_for_plan(&action);
        assert!(matches!(&results[0], PreCheckResult::Blocked {
            check: PreCheck::CheckSupervisor, reason
        } if reason.contains("invalid supervisor restart route")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_prechecks_block_disruption_and_unknown_descriptors() {
        for action in [
            Action::Pause,
            Action::Freeze,
            Action::Throttle,
            Action::Quarantine,
            Action::Renice,
            Action::Restart,
            Action::Kill,
        ] {
            assert!(matches!(
                fuse_action_precheck(Some(true), action),
                PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                    if reason.contains("builtin.fuse_server") && reason.contains("fusermount -u")
            ));
            assert!(matches!(
                fuse_action_precheck(None, action),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("complete infrastructure evidence")
            ));
            assert!(fuse_action_precheck(Some(false), action).is_passed());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_prechecks_allow_actions_that_restore_mount_access() {
        for action in [
            Action::Keep,
            Action::Resume,
            Action::Unfreeze,
            Action::Unquarantine,
        ] {
            for evidence in [Some(true), Some(false), None] {
                assert!(fuse_action_precheck(evidence, action).is_passed());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn action_prechecks_stop_after_refusal_and_preserve_recovery() {
        // This provider makes unsafe probe ordering observable without ever
        // hanging a real mount. It uses the production FUSE refusal logic.
        #[derive(Default)]
        struct FuseHolderProvider {
            calls: std::cell::RefCell<Vec<&'static str>>,
            refused: std::cell::Cell<bool>,
        }

        impl PreCheckProvider for FuseHolderProvider {
            fn check_not_protected(&self, _pid: u32) -> PreCheckResult {
                panic!("action-aware dispatch must supply the intended action");
            }

            fn check_not_protected_for_action(&self, _pid: u32, action: Action) -> PreCheckResult {
                self.calls.borrow_mut().push("protection");
                let result = fuse_action_precheck(Some(true), action);
                self.refused.set(!result.is_passed());
                result
            }

            fn check_data_loss(&self, _pid: u32) -> PreCheckResult {
                assert!(!self.refused.get(), "must not probe a refused FUSE server");
                self.calls.borrow_mut().push("data_loss");
                PreCheckResult::Passed
            }

            fn check_supervisor(&self, _pid: u32) -> PreCheckResult {
                self.calls.borrow_mut().push("supervisor");
                PreCheckResult::Passed
            }

            fn check_session_safety(&self, _pid: u32, _sid: Option<u32>) -> PreCheckResult {
                self.calls.borrow_mut().push("session");
                PreCheckResult::Passed
            }
        }

        let checks = [
            PreCheck::VerifyIdentity,
            // Even an edited plan with data-loss first must refuse before any
            // path-following probe; duplicate protection is evaluated once.
            PreCheck::CheckDataLossGate,
            PreCheck::CheckSessionSafety,
            PreCheck::CheckNotProtected,
            PreCheck::CheckSupervisor,
            PreCheck::CheckNotProtected,
        ];
        for action in [Action::Pause, Action::Freeze, Action::Kill] {
            let provider = FuseHolderProvider::default();
            let results = provider.run_checks_for_action(&checks, 123, None, action);
            assert!(matches!(
                results.as_slice(),
                [PreCheckResult::Blocked { .. }]
            ));
            assert_eq!(*provider.calls.borrow(), vec!["protection"]);
        }
        for action in [Action::Resume, Action::Unfreeze, Action::Unquarantine] {
            let provider = FuseHolderProvider::default();
            let results = provider.run_checks_for_action(&checks, 123, None, action);
            assert_eq!(results.len(), 4);
            assert!(results.iter().all(PreCheckResult::is_passed));
            assert_eq!(
                *provider.calls.borrow(),
                vec!["protection", "data_loss", "session", "supervisor"]
            );
        }
    }

    #[test]
    fn proc_locks_parses_holders_and_waiters() {
        let content = "1: POSIX  ADVISORY  WRITE 12345 08:02:1234 0 EOF\n\
                       1: -> POSIX  ADVISORY  WRITE 12346 08:02:1234 0 EOF\n\
                       2: FLOCK  ADVISORY  WRITE 777 00:1a:99 0 EOF\n\
                       3: OFDLCK ADVISORY  READ  -1 00:1a:5 0 EOF\n";
        assert!(proc_locks_mentions_pid(content, 12345).unwrap(), "holder");
        assert!(
            proc_locks_mentions_pid(content, 12346).unwrap(),
            "blocked waiter"
        );
        assert!(
            proc_locks_mentions_pid(content, 777).unwrap(),
            "flock holder"
        );
        assert!(
            !proc_locks_mentions_pid(content, 1).unwrap(),
            "lock index is not a pid"
        );
        assert!(
            !proc_locks_mentions_pid(content, 99).unwrap(),
            "inode is not a pid"
        );
        assert!(!proc_locks_mentions_pid("", 12345).unwrap());
    }

    #[test]
    fn proc_locks_requires_complete_valid_records() {
        for content in [
            "1: POSIX ADVISORY WRITE 42 08:02:1234 0 EOF",
            "1: POSIX ADVISORY WRITE\n",
            "1: POSIX ADVISORY WRITE invalid 08:02:1234 0 EOF\n",
            "1: POSIX ADVISORY WRITE 42 invalid 0 EOF\n",
            "1: POSIX ADVISORY WRITE 42 08:02:1234 10 5\n",
            "1: POSIX ADVISORY WRITE 42 08:02:1234 0 EOF extra\n",
            "1: POSIX ADVISORY WRITE 42 08:02:1234 0 EOF\n2: truncated\n",
        ] {
            assert!(proc_locks_mentions_pid(content, 42).is_err(), "{content}");
        }
        let leases = "1: LEASE ACTIVE READ 42 08:02:1234 0 EOF\n\
                      2: LEASE BREAKING UNLCK 43 08:02:1235 0 EOF\n\
                      3: DELEG BREAKER READ 44 <none>:0 0 EOF\n";
        for pid in [42, 43, 44] {
            assert_eq!(proc_locks_mentions_pid(leases, pid), Ok(true));
        }
        assert_eq!(proc_locks_mentions_pid(leases, 45), Ok(false));
    }

    fn lsof_output(stdout: &str) -> crate::collect::tool_runner::ToolOutput {
        crate::collect::tool_runner::ToolOutput {
            command: "lsof".to_string(),
            args: Vec::new(),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_code: Some(0),
            truncated: false,
            duration: Duration::ZERO,
            timed_out: false,
        }
    }

    #[test]
    fn lsof_locks_include_partial_locks_and_complete_unlocked_output() {
        assert_eq!(
            lsof_lock_evidence(
                42,
                Ok(lsof_output(
                    "p42\nfcwd\ntDIR\nf0\ntCHR\nf1\ntREG\nf4\ntIPv4\n"
                ))
            ),
            Ok(false)
        );
        for lock in ["r", "R", "w", "W", "u", "U", "N", "x", "X"] {
            let content = format!("p42\nfcwd\ntDIR\nf3\nl{lock}\ntREG\n");
            assert_eq!(lsof_lock_evidence(42, Ok(lsof_output(&content))), Ok(true));
        }
        assert_eq!(
            lsof_lock_evidence(42, Ok(lsof_output("p42\nf0\ntCHR\nl \n"))),
            Ok(false)
        );
    }

    #[test]
    fn lsof_locks_reject_failed_or_incomplete_observations() {
        for content in [
            "",
            "p42\n",
            "p43\nf0\ntCHR\n",
            "p42\nf0",
            "p42\nlW\n",
            "p42\nfNOFD\n",
            "p42\nferr\ntREG\n",
            "p42\nf0\ntREG\nl?\n",
            "p42\ntREG\n",
            "p42\nf0\n",
            "p42\nf0\nt\n",
            "p42\nf0\ntunknown\n",
            "p42\nf0\ntUNKN123\n",
            "p42\nf0\nt?\n",
            "p42\nf0\ntREG\ntREG\n",
            "p42\nf0\nf1\ntREG\n",
            "p42\nf0\ntREG\nf1\n",
            "p42\nf0\ntREG\nf1\ntunknown\n",
        ] {
            assert!(
                lsof_lock_evidence(42, Ok(lsof_output(content))).is_err(),
                "{content}"
            );
        }
        for failure in ["exit", "timeout", "truncated", "stderr"] {
            let mut output = lsof_output("p42\nf0\ntCHR\n");
            match failure {
                "exit" => output.exit_code = Some(1),
                "timeout" => output.timed_out = true,
                "truncated" => output.truncated = true,
                "stderr" => output.stderr = b"cannot examine file descriptors".to_vec(),
                _ => unreachable!(),
            }
            let error = lsof_lock_evidence(42, Ok(output)).unwrap_err();
            assert!(error.contains("incomplete lsof evidence"), "{error}");
        }
        let error = lsof_lock_evidence(
            42,
            Err(crate::collect::tool_runner::ToolError::CommandNotFound(
                "lsof".to_string(),
            )),
        )
        .unwrap_err();
        assert!(error.contains("lsof for pid 42"));
    }

    #[test]
    fn lsof_writable_descriptors_require_observed_regular_write_access() {
        let content = concat!(
            "p42\0\n",
            "fcwd\0a \0tDIR\0n/work\0\n",
            "ftxt\0a \0tREG\0n/bin/worker\0\n",
            "fmem\0a \0tREG\0n/lib/one\0\n",
            "fmem\0a \0tREG\0n/lib/two\0\n",
            "f0\0ar\0tCHR\0n/dev/null\0\n",
            "f1\0aw\0tFIFO\0npipe\0\n",
            "f2\0aw\0tPIPE\0npipe\0\n",
            "f3\0ar\0tREG\0n/work/input\0\n",
            "f4\0au\0tunix\0n/tmp/ipc.sock\0\n",
            "f5\0au\0tIPv4\0n127.0.0.1:8000\0\n",
            "f6\0au\0tKQUEUE\0\n",
        );
        assert_eq!(lsof_write_fd_evidence(42, Ok(lsof_output(content))), Ok(0));
        let writers = format!(
            "{content}f7\0aw\0tREG\0n/work/output\0\n\
             f8\0au\0tVREG\0n/private/tmp/pending (deleted)\0\n"
        );
        assert_eq!(lsof_write_fd_evidence(42, Ok(lsof_output(&writers))), Ok(2));
    }

    #[test]
    fn lsof_writable_descriptors_refuse_failed_or_partial_tool_results() {
        let complete = "p42\0\nf3\0ar\0tREG\0n/work/input\0\n";
        for failure in [
            "nonzero",
            "signal",
            "timeout",
            "truncated",
            "stderr",
            "utf8",
        ] {
            let mut output = lsof_output(complete);
            match failure {
                "nonzero" => output.exit_code = Some(1),
                "signal" => output.exit_code = None,
                "timeout" => output.timed_out = true,
                "truncated" => output.truncated = true,
                "stderr" => output.stderr = b"WARNING: cannot inspect descriptor".to_vec(),
                "utf8" => output.stdout.push(0xff),
                _ => unreachable!(),
            }
            assert!(lsof_write_fd_evidence(42, Ok(output)).is_err(), "{failure}");
        }
        for error in [
            crate::collect::tool_runner::ToolError::CommandNotFound("lsof".into()),
            crate::collect::tool_runner::ToolError::Timeout(Duration::from_secs(5)),
            crate::collect::tool_runner::ToolError::OutputTruncated {
                limit: 32,
                actual: 32,
            },
        ] {
            assert!(lsof_write_fd_evidence(42, Err(error)).is_err());
        }
    }

    #[test]
    fn lsof_writable_descriptors_reject_missing_or_foreign_process_scope() {
        for content in [
            "",
            "p42\0\n",
            "p0\0\nf3\0ar\0tREG\0n/work/input\0\n",
            "p43\0\nf3\0ar\0tREG\0n/work/input\0\n",
            "p+42\0\nf3\0ar\0tREG\0n/work/input\0\n",
            "p42 \0\nf3\0ar\0tREG\0n/work/input\0\n",
            "f3\0ar\0tREG\0n/work/input\0\n",
            "p42\0p42\0\nf3\0ar\0tREG\0n/work/input\0\n",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0\np43\0\n",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0\np42\0\n",
        ] {
            assert!(
                lsof_write_fd_evidence(42, Ok(lsof_output(content))).is_err(),
                "{content:?}"
            );
        }
    }

    #[test]
    fn lsof_writable_descriptors_reject_incomplete_or_ambiguous_records() {
        for record in [
            "fNOFD\0\n",
            "ferr\0tREG\0ar\0nPermission denied\0\n",
            "funknown\0tREG\0ar\0n/work/input\0\n",
            "ffp.3\0tREG\0a \0n/work/input\0\n",
            "f2147483648\0tREG\0ar\0n/work/input\0\n",
            "f3\0\n",
            "f3\0ar\0n/work/input\0\n",
            "f3\0tREG\0n/work/input\0\n",
            "f3\0tREG\0ar\0\n",
            "f3\0tREG\0ar\0n\0\n",
            "f3\0tREG\0a \0n/work/input\0\n",
            "f3\0tREG\0a-\0n/work/input\0\n",
            "f3\0tREG\0ax\0n/work/input\0\n",
            "f3\0tunknown\0ar\0n/work/input\0\n",
            "f3\0tUNKNv\0ar\0n/work/input\0\n",
            "f3\0tREG\0tREG\0ar\0n/work/input\0\n",
            "f3\0tREG\0tCHR\0ar\0n/work/input\0\n",
            "f3\0tREG\0ar\0ar\0n/work/input\0\n",
            "f3\0tREG\0ar\0aw\0n/work/input\0\n",
            "f3\0tREG\0ar\0n/work/input\0n/work/other\0\n",
            "f3\0tREG\0ar\0n/work/input\0f4\0\n",
            "f3\0tREG\0ar\0n/work/input\0zunexpected\0\n",
            "f3\0tREG\0ar\0n/work/input\0\nf3\0tREG\0ar\0n/work/input\0\n",
            "f3\0tREG\0ar\0n/work/input\0\nf03\0tREG\0ar\0n/work/input\0\n",
            "ftxt\0tREG\0aw\0n/work/output\0\n",
        ] {
            let content = format!("p42\0\n{record}");
            assert!(
                lsof_write_fd_evidence(42, Ok(lsof_output(&content))).is_err(),
                "{record:?}"
            );
        }
    }

    #[test]
    fn lsof_writable_descriptors_require_terminated_sets_and_keep_names_opaque() {
        for content in [
            "p42\nf3\nar\ntREG\nn/work/input\n",
            "p42\0f3\0ar\0tREG\0n/work/input\0\n",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0",
            "p42\0\nf3\0ar\0tREG\0n/work/input",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0\n\n",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0\0\n",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0\nf4",
            "p42\0\nf3\0ar\0tREG\0n/work/input\0aw\0\n",
        ] {
            assert!(
                lsof_write_fd_evidence(42, Ok(lsof_output(content))).is_err(),
                "{content:?}"
            );
        }
        // A name can contain newline/field-like text, including "(deleted)".
        // None can manufacture another descriptor or remove its write mode.
        let content = "p42\0\nf3\0aw\0tREG\0n/work/output\nf4\nar\ntCHR (deleted)\0\n";
        assert_eq!(lsof_write_fd_evidence(42, Ok(lsof_output(content))), Ok(1));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn lsof_writable_descriptors_observe_owned_regular_and_ipc_handles() {
        use std::io::{BufRead, Write};
        use std::process::{Child, Command, Stdio};

        struct Holder(Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                // EOF releases only this test's read-blocked child. No process
                // found by scanning is signalled, and fixture files are kept.
                drop(self.0.stdin.take());
                let _ = self.0.wait();
            }
        }

        let dir = tempfile::tempdir().unwrap().keep();
        let regular = dir.join("pending\nwork (deleted)");
        std::fs::write(&regular, b"existing data").unwrap();
        let fifo = dir.join("ipc.fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is NUL-terminated and valid for this call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        for (path, open, expected) in [
            (&regular, "exec 3>>\"$1\"", 1),
            (&regular, "exec 3<\"$1\"", 0),
            (&fifo, "exec 3<>\"$1\"", 0),
        ] {
            let script = format!("{open}; printf 'ready\\n'; read -r done");
            let mut holder = Holder(
                Command::new("sh")
                    .args(["-c", &script, "pt-lsof-test"])
                    .arg(path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn owned descriptor holder"),
            );
            let mut ready = String::new();
            std::io::BufReader::new(holder.0.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            assert_eq!(ready.trim(), "ready");
            let pid = holder.0.id();
            #[cfg(target_os = "macos")]
            let command = crate::collect::macos::lsof_path();
            #[cfg(target_os = "linux")]
            let command = "lsof";
            let output = crate::collect::tool_runner::run_tool(
                command,
                &lsof_write_fd_args(&pid.to_string()),
                Some(Duration::from_secs(5)),
                None,
            );
            #[cfg(target_os = "linux")]
            if matches!(
                output,
                Err(crate::collect::tool_runner::ToolError::CommandNotFound(_))
            ) {
                eprintln!("SKIP real lsof descriptor test: optional Linux lsof is not installed");
                return;
            }
            assert_eq!(lsof_write_fd_evidence(pid, output), Ok(expected), "{open}");
            assert!(holder.0.try_wait().unwrap().is_none());
            writeln!(holder.0.stdin.as_mut().unwrap(), "done").unwrap();
            assert!(holder.0.wait().unwrap().success());
        }
    }

    #[test]
    fn tty_parser_rejects_unknown_fields_and_keeps_real_device_numbers() {
        let suffix = "-1 0 0 0 0 0 0 0 0 0 0 0 1 0 123\n";
        for (tty, expected) in [("0", false), ("34816", true), ("-2147483648", true)] {
            let content = format!("42 (name ) with parentheses) S 1 2 3 {tty} {suffix}");
            assert_eq!(parse_proc_tty(42, &content), Ok(expected));
        }
        for content in [
            "42 (name) S 1".to_string(),
            format!("42 (name) S 1 2 3 invalid {suffix}"),
            format!("42 (name) S 1 2 3 2147483648 {suffix}"),
            format!("43 (name) S 1 2 3 0 {suffix}"),
            "42 (name) S 1 2 3 0\n".to_string(),
        ] {
            assert!(parse_proc_tty(42, &content).is_err(), "{content}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn required_lock_and_tty_gates_refuse_missing_target_evidence() {
        let config = LivePreCheckConfig {
            block_if_open_write_fds: false,
            block_if_locked_files: true,
            block_if_deleted_cwd: false,
            block_if_recent_io_seconds: 0,
            block_if_active_tty: true,
            enhanced_session_safety: false,
            ..LivePreCheckConfig::default()
        };
        let provider = LivePreCheckProvider::new(None, config.clone()).unwrap();
        assert!(
            matches!(provider.check_data_loss(u32::MAX), PreCheckResult::Blocked { check, reason }
            if check == PreCheck::CheckDataLossGate && reason.contains("locked-file evidence unavailable"))
        );
        assert!(
            matches!(provider.check_session_safety(u32::MAX, None), PreCheckResult::Blocked { check, reason }
            if check == PreCheck::CheckSessionSafety && reason.contains("TTY evidence unavailable"))
        );
        let disabled = LivePreCheckProvider::new(
            None,
            LivePreCheckConfig {
                block_if_locked_files: false,
                block_if_active_tty: false,
                ..config
            },
        )
        .unwrap();
        assert!(disabled.check_data_loss(u32::MAX).is_passed());
        assert!(disabled.check_session_safety(u32::MAX, None).is_passed());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn enhanced_session_gate_refuses_missing_evidence_without_basic_tty_gate() {
        let config = LivePreCheckConfig {
            block_if_active_tty: false,
            enhanced_session_safety: true,
            ..LivePreCheckConfig::default()
        };
        let provider = LivePreCheckProvider::new(None, config.clone()).unwrap();
        assert!(matches!(
            provider.check_session_safety(u32::MAX, None),
            PreCheckResult::Blocked { check, reason }
                if check == PreCheck::CheckSessionSafety
                    && reason.contains("session safety evidence unavailable")
                    && reason.contains(&u32::MAX.to_string())
        ));

        let disabled = LivePreCheckProvider::new(
            None,
            LivePreCheckConfig {
                enhanced_session_safety: false,
                ..config
            },
        )
        .unwrap();
        assert!(disabled.check_session_safety(u32::MAX, None).is_passed());
        // Disabling enhanced analysis does not remove the explicit leader guard.
        assert!(matches!(
            disabled.check_session_safety(42, Some(42)),
            PreCheckResult::Blocked { check, reason }
                if check == PreCheck::CheckSessionSafety && reason == "process is session leader"
        ));
    }

    #[test]
    fn persistent_file_targets_only() {
        for t in [
            "/data/projects/app/db.sqlite",
            "/home/ubuntu/.cache/x.log",
            "/tmp/build.out",
            "/run/user/1000/work-in-progress.log",
            "/dev/shm/pending.data",
            "/tmp/#5242881 (deleted)",
        ] {
            assert!(is_persistent_file_target(t, false), "{t}");
        }
        // The opened name is gone but another hard link keeps the file (or the real
        // name ends in " (deleted)"): its writes still land on disk.
        assert!(is_persistent_file_target("/data/app/a.log (deleted)", true));
        // Chromium/Electron hold these read-write; none of it outlives the process.
        for t in [
            "/tmp/old.log (deleted)",
            "/dev/shm/.org.chromium.Chromium.XyZ123 (deleted)",
            "/tmp/.org.chromium.Chromium.AbC456 (deleted)",
            "/memfd:wayland-cursor (deleted)",
            "/memfd:pulseaudio",
            "/tmp/#notinode (deleted)",
            "/dev/pts/3",
            "/dev/null",
            "pipe:[123]",
            "socket:[456]",
            "anon_inode:[eventfd]",
            "/proc/1/status",
        ] {
            assert!(!is_persistent_file_target(t, false), "{t}");
        }
    }

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
                panic!("expected Blocked");
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
    fn supervisor_info_block_reason_launchd_stop_includes_service_target() {
        let info = SupervisorInfo {
            supervisor: "launchd".to_string(),
            unit_name: Some("com.example.agent".to_string()),
            unit_type: None,
            is_main_process: true,
            recommended_action: SupervisorAction::StopUnit {
                command: "launchctl bootout system/com.example.agent".to_string(),
            },
            systemd_unit: None,
        };

        let reason = info.to_block_reason();
        assert!(reason.contains("launchctl bootout system/com.example.agent"));
        assert!(reason.contains("com.example.agent"));
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
    fn supervisor_cgroup_observation_preserves_session_exemptions() {
        for path in [
            "/user.slice/user-1000.slice/session-42.scope",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/owned.scope",
        ] {
            let observed = parse_supervision_cgroup_path(42, &format!("0::{path}\n"))
                .unwrap()
                .unwrap();
            assert!(crate::collect::classify_cgroup_path(&observed).is_user_workload());
        }
        assert_eq!(
            parse_supervision_cgroup_path(42, "0::/\n").unwrap(),
            Some("/".to_string())
        );
        assert_eq!(
            parse_supervision_cgroup_path(42, "5:cpu,cpuacct:/owned\n").unwrap(),
            None
        );
        for content in [
            "",
            "0::",
            "invalid",
            "0::/\n0::/other\n",
            "1::/\n",
            "invalid:name=systemd:/owned\n",
        ] {
            let error = parse_supervision_cgroup_path(42, content).unwrap_err();
            assert!(error.contains("/proc/42/cgroup"), "{error}");
        }
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

    // ── macOS-specific tests ────────────────────────────────────────

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;

        /// macOS has no per-process I/O counters; as in v2.2.1, an enabled
        /// recent-I/O gate does not refuse on that alone.
        #[test]
        fn recent_io_gate_passes_without_io_counters_on_macos() {
            let config = LivePreCheckConfig {
                block_if_open_write_fds: false,
                block_if_locked_files: false,
                block_if_active_tty: false,
                block_if_deleted_cwd: false,
                block_if_recent_io_seconds: 1,
                enhanced_session_safety: false,
                ..LivePreCheckConfig::default()
            };
            let provider = LivePreCheckProvider::new(None, config).expect("provider");
            let result = provider.check_data_loss(std::process::id());
            assert!(result.is_passed(), "{result:?}");
        }

        /// The parent lookup and launchd check run on macOS, and missing Linux-only
        /// ancestry evidence does not refuse an unsupervised process.
        #[test]
        fn supervisor_checks_pass_unsupervised_process_on_macos() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn child");
            std::thread::sleep(Duration::from_millis(300));
            let provider =
                LivePreCheckProvider::new(None, LivePreCheckConfig::default()).expect("provider");
            let supervisor = provider.check_supervisor(child.id());
            let agent = provider.check_agent_supervision(child.id());
            let _ = child.kill();
            let _ = child.wait();
            assert!(supervisor.is_passed(), "{supervisor:?}");
            assert!(agent.is_passed(), "{agent:?}");
        }

        /// The data-loss gate sees a regular file held open for writing (via lsof).
        #[test]
        fn data_loss_gate_blocks_open_write_handle_on_macos() {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("target.log");
            let writer = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .expect("open writer");
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .stdout(writer)
                .spawn()
                .expect("spawn writer");
            std::thread::sleep(Duration::from_millis(300));
            let provider =
                LivePreCheckProvider::new(None, LivePreCheckConfig::default()).expect("provider");
            let result = provider.check_data_loss(child.id());
            let _ = child.kill();
            let _ = child.wait();
            match result {
                PreCheckResult::Blocked { reason, .. } => {
                    assert!(reason.contains("open write fds"), "{reason}")
                }
                other => panic!("open write handle must block, got {other:?}"),
            }
        }
    }

    // ── Linux-specific tests ────────────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::live_test_harness::run_owned_unprivileged_case;

        fn lock_only_provider() -> LivePreCheckProvider {
            LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_open_write_fds: false,
                    block_if_locked_files: true,
                    block_if_deleted_cwd: false,
                    block_if_recent_io_seconds: 0,
                    ..LivePreCheckConfig::default()
                },
            )
            .unwrap()
        }

        fn cwd_only_provider() -> LivePreCheckProvider {
            LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_open_write_fds: false,
                    block_if_locked_files: false,
                    block_if_deleted_cwd: true,
                    block_if_recent_io_seconds: 0,
                    ..LivePreCheckConfig::default()
                },
            )
            .unwrap()
        }

        #[test]
        fn deleted_cwd_gate_preserves_unavailable_evidence_and_disabled_policy() {
            let provider = cwd_only_provider();
            assert!(matches!(
                provider.check_data_loss(u32::MAX),
                PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::CheckDataLossGate
                        && reason.contains("CWD evidence unavailable")
                        && reason.contains(&format!("/proc/{}/cwd", u32::MAX))
            ));

            let disabled = LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_deleted_cwd: false,
                    ..provider.config.clone()
                },
            )
            .unwrap();
            assert!(disabled.check_data_loss(u32::MAX).is_passed());
        }

        #[test]
        fn locked_file_observation_preserves_proc_read_and_parse_failures() {
            let root = tempfile::tempdir().unwrap().keep();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("cannot read"));
            std::fs::write(root.join("locks"), "1: truncated\n").unwrap();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("invalid lock row"));
            std::fs::write(root.join("locks"), "").unwrap();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("fdinfo"));
            let fdinfo = root.join("42/fdinfo");
            std::fs::create_dir_all(&fdinfo).unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(false));
            std::fs::write(fdinfo.join("3"), "pos:\t0\n").unwrap();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("missing descriptor"));
            let complete = "pos:\t0\nflags:\t0100002\nmnt_id:\t1\nino:\t5\n";
            std::fs::write(fdinfo.join("3"), complete).unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(false));
            std::fs::write(
                fdinfo.join("3"),
                format!("{complete}lock:\t1: OFDLCK ADVISORY WRITE -1 00:01:5 0 EOF\n"),
            )
            .unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(true));
            std::fs::write(fdinfo.join("3"), format!("{complete}lock:\t1: OFDLCK\n")).unwrap();
            assert!(read_locked_files_from_proc(42, &root).is_err());
            // A directory is a real read error even for root; it must not be
            // silently skipped as if the descriptor had no lock.
            let unreadable = tempfile::tempdir().unwrap().keep();
            std::fs::write(unreadable.join("locks"), "").unwrap();
            std::fs::create_dir_all(unreadable.join("42/fdinfo/3")).unwrap();
            assert!(read_locked_files_from_proc(42, &unreadable)
                .unwrap_err()
                .contains("cannot read"));
        }

        struct DescriptorChild {
            child: std::process::Child,
            reader: Option<std::thread::JoinHandle<()>>,
        }

        impl Drop for DescriptorChild {
            fn drop(&mut self) {
                // This child is owned and unreaped, so its PID cannot be reused.
                let _ = self.child.kill();
                let _ = self.child.wait();
                if let Some(reader) = self.reader.take() {
                    let _ = reader.join();
                }
            }
        }

        fn descriptor_child(file: std::fs::File, attach_tty: bool) -> DescriptorChild {
            use std::io::BufRead;
            use std::os::unix::process::CommandExt;
            use std::process::{Command, Stdio};

            let mut command = Command::new("sh");
            command
                .args(["-c", "printf 'ready\\n'; read -r finish"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(file));
            // SAFETY: the child hook uses only async-signal-safe syscalls. The
            // inherited stderr is our owned descriptor, or the owned pty slave.
            unsafe {
                command.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if attach_tty && libc::ioctl(libc::STDERR_FILENO, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut fixture = DescriptorChild {
                child: command.spawn().unwrap(),
                reader: None,
            };
            let stdout = fixture.child.stdout.take().unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            fixture.reader = Some(std::thread::spawn(move || {
                let mut ready = String::new();
                let result = std::io::BufReader::new(stdout)
                    .read_line(&mut ready)
                    .map(|_| ready);
                let _ = ready_tx.send(result);
            }));
            let ready = ready_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            assert_eq!(ready, "ready\n");
            fixture
        }

        #[test]
        fn locked_file_gate_detects_inherited_locks_without_blocking_unrelated_files() {
            use std::os::fd::AsRawFd;

            let provider = lock_only_provider();
            for ofd in [false, true] {
                let root = tempfile::tempdir().unwrap().keep();
                let path = root.join("held.lock");
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                let rc = if ofd {
                    // SAFETY: flock is plain data, fully initialized before
                    // fcntl reads it; the fd belongs to our retained file.
                    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
                    lock.l_type = libc::F_WRLCK as i16;
                    lock.l_whence = libc::SEEK_SET as i16;
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) }
                } else {
                    // SAFETY: flock operates on only our owned descriptor.
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                };
                assert_eq!(
                    rc,
                    0,
                    "acquire owned lock: {}",
                    std::io::Error::last_os_error()
                );

                // This child opens the same inode through a different open
                // description. Another process's OFD/flock lock is not its own.
                let unrelated = descriptor_child(std::fs::File::open(&path).unwrap(), false);
                assert_eq!(provider.has_locked_files(unrelated.child.id()), Ok(false));
                assert!(provider.check_data_loss(unrelated.child.id()).is_passed());

                let holder = descriptor_child(file, false);
                let pid = holder.child.id();
                let global = std::fs::read_to_string("/proc/locks").unwrap();
                assert_eq!(proc_locks_mentions_pid(&global, pid), Ok(false));
                let descriptor = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/2")).unwrap();
                assert!(descriptor.contains(if ofd { "OFDLCK" } else { "FLOCK" }));
                assert_eq!(provider.has_locked_files(pid), Ok(true));
                assert!(
                    matches!(provider.check_data_loss(pid), PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::CheckDataLossGate && reason == "process has locked files")
                );
            }
        }

        #[test]
        fn tty_gate_tracks_real_controlling_terminal() {
            use std::os::fd::FromRawFd;

            let provider = LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_active_tty: true,
                    enhanced_session_safety: false,
                    ..LivePreCheckConfig::default()
                },
            )
            .unwrap();
            let detached = descriptor_child(std::fs::File::open("/dev/null").unwrap(), false);
            assert_eq!(provider.has_active_tty(detached.child.id()), Ok(false));
            assert!(provider
                .check_session_safety(detached.child.id(), None)
                .is_passed());

            let (mut master, mut slave) = (-1, -1);
            // SAFETY: openpty writes two valid descriptors into these integers;
            // null optional arguments request the default terminal settings.
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(rc, 0, "open owned pty: {}", std::io::Error::last_os_error());
            // SAFETY: successful openpty transferred both descriptors to us.
            let _master = unsafe { std::fs::File::from_raw_fd(master) };
            let slave = unsafe { std::fs::File::from_raw_fd(slave) };
            let attached = descriptor_child(slave, true);
            assert_eq!(provider.has_active_tty(attached.child.id()), Ok(true));
            assert!(
                matches!(provider.check_session_safety(attached.child.id(), None), PreCheckResult::Blocked { check, reason }
                if check == PreCheck::CheckSessionSafety && reason == "process has active TTY")
            );
        }

        fn io_only_provider(seconds: u64) -> LivePreCheckProvider {
            LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_open_write_fds: false,
                    block_if_locked_files: false,
                    block_if_active_tty: false,
                    block_if_deleted_cwd: false,
                    block_if_recent_io_seconds: seconds,
                    enhanced_session_safety: false,
                    ..LivePreCheckConfig::default()
                },
            )
            .expect("I/O-only provider")
        }

        fn io_sample_at(at: Instant, birth_ticks: u64, wchar: u64, write_bytes: u64) -> IoSample {
            IoSample {
                birth_ticks,
                wchar,
                write_bytes,
                started_at: at,
                finished_at: at,
            }
        }

        fn saved_io_baseline(started_boot_ns: u64, finished_boot_ns: u64) -> RecentIoBaseline {
            RecentIoBaseline {
                target: pt_common::ProcessIdentity::new(
                    42,
                    pt_common::StartId::from_linux("test-boot", 10, 42),
                    1000,
                ),
                scope: RecentIoScope {
                    boot_id: "test-boot".to_string(),
                    pid_namespace: "pid:[123]".to_string(),
                    time_namespace: "time:[456]".to_string(),
                },
                started_boot_ns,
                finished_boot_ns,
                birth_ticks: 10,
                wchar: 20,
                write_bytes: 30,
            }
        }

        #[test]
        fn saved_io_window_uses_read_boundaries_and_preserves_active_evidence() {
            let window = Duration::from_secs(60);
            let before = saved_io_baseline(1_000_000_000, 2_000_000_000);
            let after = saved_io_baseline(62_000_000_000, 63_000_000_000);
            let sample = io_sample_at(Instant::now() + window, 10, 20, 30);
            let restored: RecentIoBaseline =
                serde_json::from_slice(&serde_json::to_vec(&before).unwrap()).unwrap();
            let observation = restored
                .observation(&after, sample.clone(), window)
                .expect("complete persisted observation window");
            assert_eq!(observation.evidence(), RecentIoEvidence::Idle);
            let short = RecentIoBaseline {
                started_boot_ns: after.started_boot_ns - 1,
                ..after.clone()
            };
            assert!(restored
                .observation(&short, sample.clone(), window)
                .is_none());
            // Long read latency is not observation coverage: neither wall-clock
            // timestamps nor the end of the new read may extend the interval.
            let slow = RecentIoBaseline {
                started_boot_ns: 61_000_000_000,
                finished_boot_ns: 120_000_000_000,
                ..after.clone()
            };
            assert!(restored
                .observation(&slow, sample.clone(), window)
                .is_none());
            for (wchar, write_bytes) in [(21, 30), (20, 31)] {
                let current = RecentIoBaseline {
                    wchar,
                    write_bytes,
                    ..after.clone()
                };
                let sample = io_sample_at(sample.started_at, 10, wchar, write_bytes);
                assert_eq!(
                    restored
                        .observation(&current, sample, window)
                        .unwrap()
                        .evidence(),
                    RecentIoEvidence::Active
                );
            }
        }

        #[test]
        fn saved_io_window_refuses_identity_scope_clock_and_counter_changes() {
            let before = saved_io_baseline(1_000_000_000, 2_000_000_000);
            let after = saved_io_baseline(62_000_000_000, 63_000_000_000);
            let window = Duration::from_secs(60);
            let sample = io_sample_at(Instant::now() + window, 10, 20, 30);
            let changes: [fn(&mut RecentIoBaseline); 12] = [
                |value| value.target.uid += 1,
                |value| value.target.pid.0 += 1,
                |value| value.target.start_id.0 = "test-boot:11:42".to_string(),
                |value| value.target.quality = pt_common::IdentityQuality::PidOnly,
                |value| value.scope.boot_id = "different-boot".to_string(),
                |value| value.scope.pid_namespace = "pid:[789]".to_string(),
                |value| value.scope.time_namespace = "time:[789]".to_string(),
                |value| value.birth_ticks += 1,
                |value| value.started_boot_ns = 1,
                |value| value.finished_boot_ns = 0,
                |value| value.wchar -= 1,
                |value| value.write_bytes -= 1,
            ];
            for (index, change) in changes.iter().enumerate() {
                let mut current = after.clone();
                change(&mut current);
                assert!(
                    before
                        .observation(&current, sample.clone(), window)
                        .is_none(),
                    "invalid current observation {index} was reused"
                );
            }
            let mut invalid = before.clone();
            invalid.finished_boot_ns = invalid.started_boot_ns - 1;
            assert!(invalid
                .observation(&after, sample.clone(), window)
                .is_none());
            invalid = before.clone();
            invalid.target.quality = pt_common::IdentityQuality::NoBootId;
            assert!(invalid.observation(&after, sample, window).is_none());
        }

        #[test]
        fn saved_io_observations_reuse_live_idle_window_and_fallback_on_ambiguity() {
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = OwnedChild(
                std::process::Command::new("sleep")
                    .arg("30")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("owned idle child"),
            );
            let pid = child.0.id();
            let scope = RecentIoScope::read().expect("live boot and namespace identities");
            let target = pt_common::ProcessIdentity::new(
                pid,
                pt_common::StartId::from_linux(&scope.boot_id, read_io_birth(pid).unwrap(), pid),
                // SAFETY: getuid reads this process's real UID, inherited by the child.
                unsafe { libc::getuid() },
            );
            let baseline = RecentIoBaseline::capture(&target).expect("capture live baseline");
            let serialized = serde_json::to_vec(&baseline).unwrap();
            let restored: RecentIoBaseline = serde_json::from_slice(&serialized).unwrap();
            std::thread::sleep(Duration::from_secs(2));
            let provider = io_only_provider(2);
            let began = Instant::now();
            provider.prime_recent_io_from_baselines(
                std::slice::from_ref(&target),
                std::slice::from_ref(&restored),
            );
            assert!(
                began.elapsed() < Duration::from_secs(2),
                "saved window was not reused"
            );
            assert!(provider.check_data_loss(pid).is_passed());
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "owned process must survive"
            );

            // Ambiguous evidence cannot choose whichever baseline grants action.
            let provider = io_only_provider(1);
            let began = Instant::now();
            provider.prime_recent_io_from_baselines(
                std::slice::from_ref(&target),
                &[restored.clone(), restored],
            );
            assert!(began.elapsed() >= Duration::from_secs(1));
            assert!(provider.check_data_loss(pid).is_passed());
        }

        #[test]
        fn saved_io_observations_still_block_a_live_periodic_writer() {
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            // Python writes and closes /dev/null repeatedly without spawning
            // descendants or holding a persistent regular-file descriptor.
            let mut child = OwnedChild(
                std::process::Command::new("python3")
                    .args([
                        "-c",
                        "import time\nwhile True:\n with open('/dev/null', 'w') as f: f.write('heartbeat')\n time.sleep(0.1)",
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("owned periodic writer"),
            );
            let pid = child.0.id();
            let scope = RecentIoScope::read().unwrap();
            let target = pt_common::ProcessIdentity::new(
                pid,
                pt_common::StartId::from_linux(&scope.boot_id, read_io_birth(pid).unwrap(), pid),
                // SAFETY: getuid only reads the real UID inherited by the child.
                unsafe { libc::getuid() },
            );
            let baseline = RecentIoBaseline::capture(&target).expect("writer observation");
            std::thread::sleep(Duration::from_secs(2));
            let provider = io_only_provider(2);
            let began = Instant::now();
            provider.prime_recent_io_from_baselines(&[target], &[baseline]);
            assert!(began.elapsed() < Duration::from_secs(2));
            assert!(matches!(
                provider.check_data_loss(pid),
                PreCheckResult::Blocked { reason, .. } if reason.contains("recent I/O")
            ));
            assert!(child.0.try_wait().unwrap().is_none(), "writer must survive");
        }

        #[test]
        fn recent_io_requires_valid_full_window_and_same_birth() {
            let start = Instant::now();
            let window = Duration::from_secs(1);
            let before = io_sample_at(start, 42, 0, 0);
            let after = io_sample_at(start + window, 42, 0, 0);
            let idle = RecentIoObservation {
                before: Ok(before.clone()),
                after: Ok(after.clone()),
                window,
            };
            assert_eq!(idle.evidence(), RecentIoEvidence::Idle);
            for (sample, reason) in [
                (io_sample_at(start + window, 43, 0, 0), "birth changed"),
                (io_sample_at(start, 42, 0, 0), "required window"),
            ] {
                let observation = RecentIoObservation {
                    after: Ok(sample),
                    ..idle.clone()
                };
                assert!(
                    matches!(observation.evidence(), RecentIoEvidence::Unknown(error)
                    if error.contains(reason))
                );
            }
            let active = RecentIoObservation {
                after: Ok(io_sample_at(start + window, 42, 1, 0)),
                ..idle.clone()
            };
            assert_eq!(active.evidence(), RecentIoEvidence::Active);
            let storage_active = RecentIoObservation {
                after: Ok(io_sample_at(start + window, 42, 0, 1)),
                ..idle
            };
            assert_eq!(storage_active.evidence(), RecentIoEvidence::Active);
        }

        #[test]
        fn recent_io_birth_parser_does_not_default_missing_or_invalid_ticks() {
            let fields = "S 1 2 3 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0";
            assert_eq!(
                parse_io_birth(42, &format!("42 (a ) name) {fields} 123")),
                Ok(123)
            );
            assert_eq!(parse_io_birth(42, &format!("42 (a) {fields} 0")), Ok(0));
            for content in [
                "42 (a) S 1".to_string(),
                format!("42 (a) {fields} invalid"),
                format!("43 (a) {fields} 123"),
                "42 a S 1".to_string(),
            ] {
                assert!(parse_io_birth(42, &content).is_err(), "{content}");
            }
        }

        #[test]
        fn recent_io_preserves_both_failures_and_refuses_decreasing_counters() {
            let start = Instant::now();
            let window = Duration::from_secs(1);
            let observation = RecentIoObservation {
                before: Err("permission denied reading I/O".to_string()),
                after: Err("missing wchar counter".to_string()),
                window,
            };
            assert!(
                matches!(observation.evidence(), RecentIoEvidence::Unknown(reason)
                if reason.contains("before sample: permission denied")
                    && reason.contains("after sample: missing wchar"))
            );
            for after in [
                io_sample_at(start + window, 42, 9, 10),
                io_sample_at(start + window, 42, 10, 9),
            ] {
                let observation = RecentIoObservation {
                    before: Ok(io_sample_at(start, 42, 10, 10)),
                    after: Ok(after),
                    window,
                };
                assert!(
                    matches!(observation.evidence(), RecentIoEvidence::Unknown(reason)
                    if reason.contains("decreased"))
                );
            }
        }

        #[test]
        fn recent_io_cache_requires_fresh_identity_and_counter_evidence() {
            let start = Instant::now();
            let window = Duration::from_secs(1);
            let idle = RecentIoObservation {
                before: Ok(io_sample_at(start, 42, 10, 10)),
                after: Ok(io_sample_at(start + window, 42, 10, 10)),
                window,
            };
            // The unchanged cumulative counters cover the intervening delay,
            // so a slow earlier action does not force another per-target sleep.
            assert_eq!(
                idle.revalidate(Ok(io_sample_at(start + window * 10, 42, 10, 10))),
                RecentIoEvidence::Idle
            );
            assert_eq!(
                idle.revalidate(Ok(io_sample_at(start + window * 2, 42, 11, 10))),
                RecentIoEvidence::Active
            );
            for (sample, reason) in [
                (
                    io_sample_at(start + window * 2, 43, 10, 10),
                    "birth changed",
                ),
                (io_sample_at(start + window * 2, 42, 9, 10), "decreased"),
                (io_sample_at(start + window * 2, 42, 10, 9), "decreased"),
                (io_sample_at(start + window * 10, 42, 11, 10), "stale"),
            ] {
                assert!(
                    matches!(idle.revalidate(Ok(sample)), RecentIoEvidence::Unknown(error)
                    if error.contains(reason))
                );
            }
            assert!(
                matches!(idle.revalidate(Err("permission denied".to_string())),
                RecentIoEvidence::Unknown(reason) if reason.contains("cache revalidation"))
            );
            let active = RecentIoObservation {
                before: Ok(io_sample_at(start, 42, 9, 10)),
                ..idle
            };
            assert!(matches!(
                active.revalidate(Ok(io_sample_at(start + window * 10, 42, 10, 10))),
                RecentIoEvidence::Unknown(reason) if reason.contains("stale")
            ));
        }

        #[test]
        fn recent_io_records_missing_targets_and_only_zero_disables_the_gate() {
            let provider = io_only_provider(1);
            let began = Instant::now();
            provider.prime_recent_io(&[u32::MAX]);
            assert!(began.elapsed() >= Duration::from_secs(1));
            assert!(provider.recent_io.lock().unwrap().contains_key(&u32::MAX));
            let result = provider.check_data_loss(u32::MAX);
            assert!(matches!(result, PreCheckResult::Blocked { check, reason }
                if check == PreCheck::CheckDataLossGate
                    && reason.contains("recent I/O evidence unavailable")
                    && reason.contains("before sample")
                    && reason.contains("after sample")));
            assert!(io_only_provider(0).check_data_loss(u32::MAX).is_passed());
        }

        #[test]
        fn recent_io_owned_child_readability() {
            use crate::collect::proc_parsers::IoReadError;
            use std::io::{Read, Write};
            use std::process::{Child, Command, Stdio};

            const MODE: &str = "PT_TEST_RECENT_IO_CHILD";
            if let Ok(mode) = std::env::var(MODE) {
                assert!(matches!(mode.as_str(), "idle" | "writer" | "unreadable"));
                let dumpable = if mode == "unreadable" { 0 } else { 1 };
                // SAFETY: PR_SET_DUMPABLE takes an integer flag and no pointers.
                // This runs after exec inside only this owned fixture process.
                let result = unsafe {
                    libc::prctl(
                        libc::PR_SET_DUMPABLE,
                        dumpable as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                assert_eq!(
                    result,
                    0,
                    "set fixture dumpability: {}",
                    std::io::Error::last_os_error()
                );
                println!("PT_RECENT_IO_READY");
                loop {
                    if mode == "writer" {
                        writeln!(std::io::stdout(), "owned writer").expect("write fixture pipe");
                        std::thread::sleep(Duration::from_millis(100));
                    } else {
                        std::thread::park();
                    }
                }
            }

            if run_owned_unprivileged_case(
                "action::prechecks::tests::linux_tests::recent_io_owned_child_readability",
            ) {
                return;
            }
            struct OwnedChild {
                child: Child,
                reader: Option<std::thread::JoinHandle<std::io::Result<()>>>,
            }
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    // This unreaped child remains owned by this test, so its
                    // PID cannot be recycled before kill/wait complete.
                    let pid = self.child.id();
                    if let Err(error) = self.child.kill() {
                        eprintln!("owned I/O fixture pid={pid} cleanup kill: {error}");
                    }
                    if let Err(error) = self.child.wait() {
                        eprintln!("owned I/O fixture pid={pid} cleanup wait: {error}");
                    }
                    // Killing/reaping the only pipe writer closes stdout
                    // before this join, including readiness timeout or panic.
                    if let Some(reader) = self.reader.take() {
                        match reader.join() {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                eprintln!("owned I/O fixture pid={pid} stdout drain: {error}");
                            }
                            Err(_) => {
                                eprintln!("owned I/O fixture pid={pid} stdout reader panicked");
                            }
                        }
                    }
                }
            }
            // Privileged callers may bypass procfs access restrictions. Such a
            // runner must not silently turn this permission-negative into PASS.
            // SAFETY: geteuid has no arguments or memory effects.
            assert_ne!(
                unsafe { libc::geteuid() },
                0,
                "requires an unprivileged fixture caller"
            );
            for mode in ["idle", "writer", "unreadable"] {
                let mut child = OwnedChild {
                    child: Command::new(std::env::current_exe().expect("test executable"))
                        .args([
                            "--exact",
                            "action::prechecks::tests::linux_tests::recent_io_owned_child_readability",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env(MODE, mode)
                        .stdout(Stdio::piped())
                        .spawn()
                        .expect("spawn owned I/O fixture"),
                    reader: None,
                };
                let pid = child.child.id();
                let birth = read_io_birth(pid).expect("owned child birth");
                let mut output = child.child.stdout.take().expect("fixture stdout");
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                child.reader = Some(std::thread::spawn(move || {
                    const READY: &[u8] = b"PT_RECENT_IO_READY\n";
                    let mut buffer = [0u8; 4096];
                    let mut pending = Vec::with_capacity(buffer.len() + READY.len());
                    let mut announced = false;
                    loop {
                        let count = match output.read(&mut buffer) {
                            Ok(0) => {
                                if !announced {
                                    let _ = ready_tx
                                        .send(Err("stdout reached EOF before fixture readiness"
                                            .to_string()));
                                }
                                return Ok(());
                            }
                            Ok(count) => count,
                            Err(error) => {
                                if !announced {
                                    let _ = ready_tx.send(Err(format!(
                                        "stdout read before fixture readiness: {error}"
                                    )));
                                }
                                return Err(error);
                            }
                        };
                        if !announced {
                            pending.extend_from_slice(&buffer[..count]);
                            if pending.windows(READY.len()).any(|bytes| bytes == READY) {
                                let _ = ready_tx.send(Ok(()));
                                announced = true;
                                pending.clear();
                            } else {
                                let consumed = pending.len().saturating_sub(READY.len() - 1);
                                drop(pending.drain(..consumed));
                            }
                        }
                        // Continue draining to EOF after READY without storing
                        // output, so a scheduled writer cannot fill its pipe.
                    }
                }));
                let readiness = ready_rx.recv_timeout(Duration::from_secs(10));
                assert!(
                    matches!(readiness, Ok(Ok(()))),
                    "owned fixture readiness: mode={mode} pid={pid} birth={birth} result={readiness:?}"
                );
                if mode == "unreadable" {
                    let error = read_io(pid).expect_err("actual procfs permission refusal");
                    assert!(
                        matches!(&error, IoReadError::Read { source, .. }
                        if source.kind() == std::io::ErrorKind::PermissionDenied),
                        "{error}"
                    );
                    eprintln!(
                        "owned I/O fixture pid={pid} birth={birth} mode={mode} read_error={error}"
                    );
                    // The same real non-dumpable child denies fdinfo access.
                    // An enabled lock gate must retain that refusal as well.
                    let lock_provider = lock_only_provider();
                    let error = lock_provider.has_locked_files(pid).unwrap_err();
                    assert!(error.contains("fdinfo"), "{error}");
                    let result = lock_provider.check_data_loss(pid);
                    assert!(matches!(result, PreCheckResult::Blocked { check, reason }
                        if check == PreCheck::CheckDataLossGate
                            && reason.contains("locked-file evidence unavailable")
                            && reason.contains("fdinfo")));

                    // The same owned, live child also hides its CWD. A failed
                    // lookup must not become a negative deleted-directory result.
                    let cwd_path = format!("/proc/{pid}/cwd");
                    let error =
                        std::fs::read_link(&cwd_path).expect_err("actual CWD permission refusal");
                    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                    let result = cwd_only_provider().check_data_loss(pid);
                    assert!(matches!(result, PreCheckResult::Blocked { check, reason }
                        if check == PreCheck::CheckDataLossGate
                            && reason.contains("CWD evidence unavailable")
                            && reason.contains(&cwd_path)));

                    // An unreadable caller environment cannot establish that
                    // its multiplexer or SSH session is absent, either.
                    let session_error = SessionAnalyzer::new()
                        .analyze(pid, pid)
                        .expect_err("required session environment is unreadable");
                    assert!(matches!(
                        session_error,
                        crate::supervision::session::SessionError::Environment(
                            crate::supervision::environ::EnvironError::IoError { source, .. }
                        ) if source.kind() == std::io::ErrorKind::PermissionDenied
                    ));
                } else {
                    read_io(pid).expect("readable owned I/O fixture");
                    assert!(cwd_only_provider().check_data_loss(pid).is_passed());
                }
                let provider = io_only_provider(1);
                provider.prime_recent_io(&[pid]);
                let result = provider.check_data_loss(pid);
                eprintln!(
                    "owned I/O fixture pid={pid} birth={birth} mode={mode} result={result:?}"
                );
                match mode {
                    "idle" => assert!(result.is_passed(), "readable idle child: {result:?}"),
                    "writer" => assert!(matches!(result, PreCheckResult::Blocked { reason, .. }
                        if reason.contains("recent I/O activity"))),
                    "unreadable" => {
                        assert!(matches!(result, PreCheckResult::Blocked { reason, .. }
                        if reason.contains("recent I/O evidence unavailable")
                            && reason.contains("before sample") && reason.contains("after sample")
                            && reason.contains(&format!("/proc/{pid}/io"))))
                    }
                    _ => unreachable!("fixture modes are fixed"),
                }
                assert!(child.child.try_wait().expect("owned child state").is_none());
                assert_eq!(read_io_birth(pid).expect("surviving child birth"), birth);
            }
        }

        #[test]
        fn supervision_owned_process_evidence() {
            use std::io::Read;
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::process::{Child, Command, Stdio};

            if run_owned_unprivileged_case(
                "action::prechecks::tests::linux_tests::supervision_owned_process_evidence",
            ) {
                return;
            }
            // A privileged caller can bypass the permission-negative oracle.
            // SAFETY: geteuid only observes this test's credentials.
            assert_ne!(
                unsafe { libc::geteuid() },
                0,
                "requires an unprivileged caller"
            );
            const SCRIPT: &str = r#"
import ctypes, os, signal, socket, sys, time
libc = ctypes.CDLL(None, use_errno=True)
mode = sys.argv[1]
if mode == 'supervisord':
    assert libc.prctl(15, ctypes.c_char_p(b'supervisord'), 0, 0, 0) == 0
    child = os.fork()
    if child:
        print('PT_SUPERVISION_OWNED', child, flush=True)
        try:
            sys.stdin.buffer.read()
        finally:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            waited, status = os.waitpid(child, 0)
            assert waited == child
            print('PT_SUPERVISION_REAPED', child, flush=True)
        sys.exit(0)
    mode = 'clean'
assert libc.prctl(15, ctypes.c_char_p(b'pt-owned'), 0, 0, 0) == 0
assert libc.prctl(4, 0 if mode == 'unreadable' else 1, 0, 0, 0) == 0
if mode == 'tcp':
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
print('PT_SUPERVISION_READY', os.getpid(), flush=True)
while True:
    time.sleep(60)
"#;
            struct Fixture {
                child: Child,
                target: Option<OwnedFd>,
                reader: Option<std::thread::JoinHandle<std::io::Result<()>>>,
            }
            impl Drop for Fixture {
                fn drop(&mut self) {
                    if let Some(target) = &self.target {
                        // SAFETY: this pidfd was bound to our fixture target.
                        let rc = unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                target.as_raw_fd(),
                                libc::SIGKILL,
                                std::ptr::null::<libc::siginfo_t>(),
                                0,
                            )
                        };
                        if rc != 0 {
                            eprintln!(
                                "owned supervision target cleanup: {}",
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                    // Before READY, our supervisor may already own its fork.
                    // Enumerate only this unreaped, test-owned parent's children.
                    if let Ok(children) = std::fs::read_to_string(format!(
                        "/proc/{0}/task/{0}/children",
                        self.child.id()
                    )) {
                        for pid in children
                            .split_whitespace()
                            .filter_map(|pid| pid.parse::<u32>().ok())
                        {
                            // SAFETY: the child relationship was observed while
                            // the owned fixture parent is still unreaped.
                            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                            if fd >= 0 {
                                let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
                                let rc = unsafe {
                                    libc::syscall(
                                        libc::SYS_pidfd_send_signal,
                                        fd.as_raw_fd(),
                                        libc::SIGKILL,
                                        std::ptr::null::<libc::siginfo_t>(),
                                        0,
                                    )
                                };
                                if rc != 0 {
                                    eprintln!(
                                        "owned supervisor child pid={pid} cleanup: {}",
                                        std::io::Error::last_os_error()
                                    );
                                }
                            }
                        }
                    }
                    drop(self.child.stdin.take());
                    let deadline = Instant::now() + Duration::from_secs(10);
                    loop {
                        match self.child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) if Instant::now() < deadline => {
                                std::thread::sleep(Duration::from_millis(10))
                            }
                            other => {
                                eprintln!("owned supervision parent cleanup state: {other:?}");
                                if let Err(error) = self.child.kill() {
                                    eprintln!("owned fixture kill: {error}");
                                }
                                if let Err(error) = self.child.wait() {
                                    eprintln!("owned fixture wait: {error}");
                                }
                                break;
                            }
                        }
                    }
                    // The target is killed and the parent waited before joining
                    // the continuously drained stdout pipe, including panic paths.
                    if let Some(reader) = self.reader.take() {
                        match reader.join() {
                            Ok(Ok(())) => {}
                            other => eprintln!("owned supervision reader cleanup: {other:?}"),
                        }
                    }
                }
            }
            for mode in ["clean", "tcp", "unreadable", "supervisord"] {
                let mut fixture = Fixture {
                    child: Command::new("python3")
                        .args(["-u", "-c", SCRIPT, mode])
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .expect("spawn owned supervision fixture"),
                    target: None,
                    reader: None,
                };
                let mut output = fixture.child.stdout.take().unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                fixture.reader = Some(std::thread::spawn(move || {
                    let mut buffer = [0u8; 4096];
                    let mut pending = Vec::new();
                    loop {
                        let count = output.read(&mut buffer)?;
                        if count == 0 {
                            return Ok(());
                        }
                        pending.extend_from_slice(&buffer[..count]);
                        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                            let line: Vec<_> = pending.drain(..=end).collect();
                            let line = std::str::from_utf8(&line).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                            })?;
                            if let Some(pid) = line
                                .strip_prefix("PT_SUPERVISION_READY ")
                                .and_then(|pid| pid.trim().parse::<u32>().ok())
                            {
                                let _ = tx.send(("ready", pid));
                            } else if let Some(pid) = line
                                .strip_prefix("PT_SUPERVISION_REAPED ")
                                .and_then(|pid| pid.trim().parse::<u32>().ok())
                            {
                                let _ = tx.send(("reaped", pid));
                            }
                        }
                        if pending.len() > 4096 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "oversized fixture output",
                            ));
                        }
                    }
                }));
                let (event, pid) = rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("bounded owned fixture readiness");
                assert_eq!(event, "ready");
                // SAFETY: READY identifies this parent's own fixture target.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                assert!(
                    fd >= 0,
                    "bind owned target: {}",
                    std::io::Error::last_os_error()
                );
                fixture.target = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
                let before = read_required_proc_stat(pid).unwrap();
                let credentials = crate::collect::proc_parsers::parse_proc_status(pid)
                    .expect("owned fixture credentials");
                // SAFETY: getuid/geteuid only observe this test's credentials.
                assert_eq!(credentials.ruid, unsafe { libc::getuid() });
                assert_eq!(credentials.euid, unsafe { libc::geteuid() });
                let provider = LivePreCheckProvider::with_defaults();
                if mode == "unreadable" {
                    let error = crate::supervision::read_environ(pid).unwrap_err();
                    assert!(
                        matches!(&error, crate::supervision::EnvironError::IoError { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied),
                        "{error}"
                    );
                    let error = crate::supervision::IpcAnalyzer::new()
                        .analyze(pid)
                        .unwrap_err();
                    assert!(
                        matches!(&error, crate::supervision::IpcError::IoError { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied),
                        "{error}"
                    );
                    let result = provider.check_agent_supervision(pid);
                    assert!(
                        matches!(&result, PreCheckResult::Blocked { check: PreCheck::CheckAgentSupervision, reason } if reason.contains("evidence unavailable") && reason.contains(&pid.to_string())),
                        "{result:?}"
                    );
                    eprintln!(
                        "owned supervision pid={pid} birth={} mode={mode} result={result:?}",
                        before.starttime
                    );
                } else if mode == "supervisord" {
                    assert_eq!(before.ppid, fixture.child.id());
                    assert_eq!(
                        read_required_proc_stat(before.ppid).unwrap().comm,
                        "supervisord"
                    );
                    let result = provider.check_supervisor(pid);
                    assert!(
                        matches!(&result, PreCheckResult::Blocked { check: PreCheck::CheckSupervisor, reason } if reason.contains("supervisord")),
                        "{result:?}"
                    );
                    eprintln!(
                        "owned supervision pid={pid} parent={} mode={mode} result={result:?}",
                        before.ppid
                    );
                } else {
                    if mode == "tcp" {
                        let inodes: Vec<u64> = std::fs::read_dir(format!("/proc/{pid}/fd"))
                            .unwrap()
                            .map(|entry| std::fs::read_link(entry.unwrap().path()).unwrap())
                            .filter_map(|link| {
                                link.to_str()
                                    .and_then(|link| link.strip_prefix("socket:["))
                                    .and_then(|link| link.strip_suffix(']'))
                                    .and_then(|inode| inode.parse().ok())
                            })
                            .collect();
                        assert_eq!(inodes.len(), 1);
                        assert!(
                            crate::collect::network::has_inet_socket_inode(pid, inodes[0]).unwrap()
                        );
                    }
                    let result =
                        detect_supervision(pid).expect("complete readable supervision evidence");
                    assert!(
                        result.ancestry.is_some()
                            && result.environ.is_some()
                            && result.ipc.is_some()
                    );
                    assert!(!result.ipc.as_ref().unwrap().is_supervised);
                    assert!(
                        !is_human_supervised(&result),
                        "actual clean fixture is supervised: {result:?}"
                    );
                    assert!(provider.check_agent_supervision(pid).is_passed());
                }
                assert_eq!(
                    read_required_proc_stat(pid).unwrap().starttime,
                    before.starttime
                );
                assert!(fixture.child.try_wait().unwrap().is_none());
                if mode == "supervisord" {
                    // EOF asks the actual owner to kill and reap its child.
                    drop(fixture.child.stdin.take());
                    assert_eq!(
                        rx.recv_timeout(Duration::from_secs(10))
                            .expect("bounded owned child reaping"),
                        ("reaped", pid)
                    );
                }
            }
        }

        fn inspect_child_descriptor(
            script: &str,
            path: &std::path::Path,
            stderr_file: Option<std::fs::File>,
        ) -> (Option<u32>, PreCheckResult) {
            use std::io::{BufRead, Write};
            use std::process::{Command, Stdio};

            let mut child = Command::new("sh")
                .args(["-c", script, "pt-fd-test"])
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(stderr_file.map(Stdio::from).unwrap_or_else(Stdio::null))
                .spawn()
                .expect("spawn descriptor holder");
            let mut ready = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            assert_eq!(ready.trim(), "ready");
            let provider = LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_locked_files: false,
                    block_if_deleted_cwd: false,
                    block_if_recent_io_seconds: 0,
                    ..LivePreCheckConfig::default()
                },
            )
            .unwrap();
            let count = open_write_fd_count(child.id());
            let result = provider.check_data_loss(child.id());
            writeln!(child.stdin.take().unwrap(), "done").unwrap();
            assert!(child.wait().unwrap().success());
            (count, result)
        }

        #[test]
        fn data_loss_blocks_regular_writer_but_allows_read_only_file() {
            let dir = tempfile::tempdir().unwrap().keep();
            let path = dir.join("pending-data.log");
            std::fs::write(&path, b"existing data").unwrap();
            let (count, result) = inspect_child_descriptor(
                "exec 3>>\"$1\"; printf 'ready\\n'; read -r done",
                &path,
                None,
            );
            assert_eq!(count, Some(1));
            assert!(
                matches!(result, PreCheckResult::Blocked { reason, .. } if reason.contains("open write fds"))
            );
            let (count, result) = inspect_child_descriptor(
                "exec 3<\"$1\"; printf 'ready\\n'; read -r done",
                &path,
                None,
            );
            assert_eq!(count, Some(0));
            assert!(result.is_passed());
        }

        #[test]
        fn data_loss_blocks_regular_writer_in_dev_shm() {
            let dir = tempfile::tempdir_in("/dev/shm").unwrap().keep();
            let path = dir.join("pending-data.log");
            let (count, result) = inspect_child_descriptor(
                "exec 3>>\"$1\"; printf 'ready\\n'; read -r done",
                &path,
                None,
            );
            assert_eq!(count, Some(1));
            assert!(
                matches!(result, PreCheckResult::Blocked { reason, .. } if reason.contains("open write fds"))
            );
        }

        #[test]
        fn data_loss_allows_named_pipe_writer() {
            let dir = tempfile::tempdir().unwrap().keep();
            let path = dir.join("ipc.fifo");
            let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: the path is NUL-terminated and remains valid during mkfifo.
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            let (count, result) = inspect_child_descriptor(
                "exec 3<>\"$1\"; printf 'ready\\n'; read -r done",
                &path,
                None,
            );
            assert_eq!(count, Some(0));
            assert!(result.is_passed());
        }

        #[test]
        fn data_loss_blocks_unlinked_regular_writer() {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;

            let dir = tempfile::tempdir().unwrap().keep();
            // O_TMPFILE creates an unnamed regular file without deleting a path.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_TMPFILE)
                .open(&dir)
                .unwrap();
            assert!(file.metadata().unwrap().is_file());
            let target = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
            assert!(target.to_string_lossy().ends_with(" (deleted)"));
            let (count, result) =
                inspect_child_descriptor("printf 'ready\\n'; read -r done", &dir, Some(file));
            assert_eq!(count, Some(1));
            assert!(
                matches!(result, PreCheckResult::Blocked { reason, .. } if reason.contains("open write fds"))
            );
        }

        #[test]
        fn data_loss_refuses_without_descriptor_evidence() {
            let provider = LivePreCheckProvider::with_defaults();
            assert_eq!(open_write_fd_count(u32::MAX), None);
            assert!(
                matches!(provider.check_data_loss(u32::MAX), PreCheckResult::Blocked { reason, .. }
                if reason.contains("complete data-loss evidence"))
            );
        }

        #[test]
        fn infrastructure_gate_refuses_unreadable_fuse_descriptors() {
            let provider = LivePreCheckProvider::with_defaults();
            assert!(matches!(
                provider.check_not_protected(u32::MAX),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("cannot inspect FUSE device descriptors")
            ));
        }

        #[test]
        fn live_provider_refuses_inherited_fuse_device() {
            use std::process::{Command, Stdio};

            let device = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")
            {
                Ok(device) => device,
                Err(error) => {
                    eprintln!("SKIP live FUSE descriptor test: /dev/fuse unavailable: {error}");
                    return;
                }
            };
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let child = OwnedChild(
                Command::new("sleep")
                    .arg("300")
                    .stdin(Stdio::from(device))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn disposable FUSE holder"),
            );
            let provider = LivePreCheckProvider::with_defaults();
            assert_eq!(
                crate::collect::protected::holds_fuse_device(child.0.id()),
                Some(true)
            );
            for action in [Action::Pause, Action::Freeze, Action::Kill] {
                let results = provider.run_checks_for_action(
                    &[PreCheck::CheckNotProtected],
                    child.0.id(),
                    None,
                    action,
                );
                assert!(matches!(
                    results.as_slice(),
                    [PreCheckResult::Blocked { reason, .. }]
                        if reason.contains("builtin.fuse_server") && reason.contains("fusermount -u")
                ));
            }
        }

        #[test]
        fn live_provider_defaults_block_own_invoker_chain() {
            // pt must never act on itself or its callers. This also makes the check
            // independent of the user running the tests (the old "self is not
            // protected" assertion failed whenever tests ran as root).
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            match provider.check_not_protected(pid) {
                PreCheckResult::Blocked { reason, .. } => {
                    assert!(reason.contains("invoking"), "unexpected reason: {reason}")
                }
                other => panic!("own process must be protected, got {other:?}"),
            }
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
            // Our own process should pass state checks. Retry a few times because
            // the process can transiently enter D-state (uninterruptible sleep)
            // while performing the /proc read itself under heavy I/O load.
            let mut passed = false;
            for _ in 0..5 {
                if provider.check_process_state(pid).is_passed() {
                    passed = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(passed, "process state check did not pass after retries");
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
            let (_, count) = provider.has_open_write_fds(pid).expect("inspect own files");
            // Should return a count without panicking
            let _ = count;
        }

        #[test]
        fn live_provider_has_deleted_cwd_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Our CWD should not be deleted
            assert_eq!(provider.has_deleted_cwd(pid), Ok(false));
            assert!(cwd_only_provider().check_data_loss(pid).is_passed());
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
            provider
                .read_supervision_cgroup_path(pid)
                .expect("observed cgroup placement");
        }

        #[test]
        fn missing_supervision_evidence_blocks_both_required_checks() {
            let provider = LivePreCheckProvider::with_defaults();
            for (result, expected) in [
                (
                    provider.check_supervisor(u32::MAX),
                    PreCheck::CheckSupervisor,
                ),
                (
                    provider.check_agent_supervision(u32::MAX),
                    PreCheck::CheckAgentSupervision,
                ),
            ] {
                assert!(matches!(result, PreCheckResult::Blocked { check, reason }
                    if check == expected && reason.contains("evidence unavailable")
                        && reason.contains(&u32::MAX.to_string())));
            }
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
            // Self is always protected (invoker chain)
            assert!(!results[0].is_passed());
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
