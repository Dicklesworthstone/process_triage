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
use std::time::{Duration, Instant};
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

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn recent_io_probe_window(window: Duration) -> Duration {
    if window.is_zero() {
        Duration::from_millis(10)
    } else {
        window
    }
}

/// Both platforms expose native parent, birth and state facts. An unavailable
/// read is not evidence that a process has no supervisor or has exited.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_precheck_stat(pid: u32) -> Result<crate::collect::proc_parsers::ProcessStat, String> {
    #[cfg(target_os = "linux")]
    {
        read_required_proc_stat(pid).map_err(|error| error.to_string())
    }
    #[cfg(target_os = "macos")]
    {
        crate::collect::macos::read_session_stat(pid)
            .ok_or_else(|| format!("cannot read native process identity and state for PID {pid}"))
    }
}

/// Bind a parent name to the same child and parent incarnations on both sides
/// of the observation. This also validates a parentless namespace boundary.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn parent_comm_from_observations(
    pid: u32,
    mut read: impl FnMut(u32) -> Result<crate::collect::proc_parsers::ProcessStat, String>,
) -> Result<Option<String>, String> {
    let mut observed = |expected_pid| {
        let stat = read(expected_pid)?;
        if stat.pid != expected_pid || stat.comm.trim().is_empty() {
            return Err(format!(
                "invalid parent supervision identity for PID {expected_pid}"
            ));
        }
        Ok(stat)
    };
    let before = observed(pid)?;
    if before.ppid == pid {
        return Err(format!(
            "parent supervision evidence for PID {pid} has a self-parent loop"
        ));
    }
    let parent = if before.ppid == 0 {
        None
    } else {
        let parent = observed(before.ppid)?;
        let after = observed(before.ppid)?;
        if after.starttime != parent.starttime || after.comm != parent.comm {
            return Err(format!("parent supervision evidence changed for PID {pid}"));
        }
        Some(parent.comm)
    };
    let after = observed(pid)?;
    if after.starttime != before.starttime || after.ppid != before.ppid || after.comm != before.comm
    {
        return Err(format!("parent supervision evidence changed for PID {pid}"));
    }
    Ok(parent)
}

/// A failed observation is not proof of exit. In particular, procfs may hide a
/// live process and native process APIs may refuse a process owned by someone
/// else. Signal zero only tests existence; EPERM still proves the PID is live.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_is_absent(pid: u32) -> Result<bool, String> {
    let Ok(native_pid) = libc::pid_t::try_from(pid) else {
        // Do not cast an out-of-range ID into a negative process-group request.
        return Ok(true);
    };
    if native_pid <= 0 {
        return Err("invalid process PID; refusing a process-group probe".to_string());
    }
    super::signal::ensure_action_pid_namespace().map_err(|error| error.to_string())?;
    // SAFETY: the positive PID names one process and signal zero sends no signal.
    if unsafe { libc::kill(native_pid, 0) } == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        Some(libc::EPERM) => Ok(false),
        _ => Err(format!(
            "cannot establish whether PID {pid} exited: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn read_process_state_from_proc(
    pid: u32,
    proc_root: &std::path::Path,
) -> Result<Option<ProcessState>, String> {
    let path = proc_root.join(pid.to_string()).join("stat");
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if process_is_absent(pid)? {
                Ok(None)
            } else {
                Err(format!(
                    "cannot read {} for a still-present process: {error}",
                    path.display()
                ))
            };
        }
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    let stat = crate::collect::proc_parsers::parse_required_proc_stat_content(pid, &content)
        .map_err(|error| error.to_string())?;
    Ok(Some(ProcessState::from_char(stat.state)))
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn process_state_precheck(
    observation: Result<Option<ProcessState>, String>,
    wchan: Option<&str>,
) -> PreCheckResult {
    let state = match observation {
        Ok(Some(state)) => state,
        // Identity validation and signal delivery independently reject a gone
        // process. This gate must not turn a confirmed exit into an I/O failure.
        Ok(None) => return PreCheckResult::Passed,
        Err(error) => {
            return PreCheckResult::Blocked {
                check: PreCheck::VerifyProcessState,
                reason: format!("process state evidence unavailable: {error}"),
            };
        }
    };
    let reason = match state {
        ProcessState::Unknown => {
            "process state evidence unavailable: unknown process state".to_string()
        }
        ProcessState::Zombie => "process is a zombie (Z state): already dead, cannot be killed. \
             The parent process must reap it."
            .to_string(),
        ProcessState::Dead => "process is already dead (X state): cannot be killed".to_string(),
        ProcessState::DiskSleep => {
            let wchan_info = wchan
                .map(|wchan| format!(" (blocked in: {wchan})"))
                .unwrap_or_default();
            format!(
                "process is in uninterruptible sleep (D state){wchan_info}: \
                 kill action may not succeed. Consider investigating the \
                 underlying I/O issue instead."
            )
        }
        _ => return PreCheckResult::Passed,
    };
    PreCheckResult::Blocked {
        check: PreCheck::VerifyProcessState,
        reason,
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

/// Numeric ownership and name resolution are separate observations. A readable
/// UID remains useful when account lookup fails, but is never a resolved name.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[derive(Debug, Clone)]
struct ProtectionOwner {
    uid: u32,
    name: Option<String>,
}

/// Command and owner rules need observed values. An unreadable or empty field
/// cannot prove that a target does not match a configured protection rule.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn required_protection_metadata(
    pid: u32,
    comm: Option<String>,
    cmdline: Option<String>,
    owner: Option<ProtectionOwner>,
    protected_users: &HashSet<String>,
    require_owner_name: bool,
) -> Result<(String, String, String), PreCheckResult> {
    let unavailable = |field: &str| {
        PreCheckResult::Blocked {
        check: PreCheck::CheckNotProtected,
        reason: format!(
            "protection evidence unavailable for PID {pid}: cannot read complete {field}; refusing to bypass configured protection rules"
        ),
    }
    };
    let required = |value: Option<String>, field: &str| {
        value
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| unavailable(field))
    };
    let comm = required(comm, "process name")?;
    let cmdline = required(cmdline, "command line")?;
    let owner = owner.ok_or_else(|| unavailable("process owner"))?;

    // An explicit numeric rule protects the observed UID even when a name was
    // resolved. Unlike the named root rule, it has no session-workload exception.
    if protected_users
        .iter()
        .any(|user| user.parse::<u32>().ok() == Some(owner.uid))
    {
        return Err(PreCheckResult::Blocked {
            check: PreCheck::CheckNotProtected,
            reason: format!("owned by protected user UID: {}", owner.uid),
        });
    }

    let name = owner.name.filter(|name| !name.trim().is_empty());
    let name_required = require_owner_name
        || protected_users
            .iter()
            .any(|user| user.parse::<u32>().is_err());
    let user = match name {
        Some(name) => name,
        None if name_required => return Err(unavailable("process owner name")),
        // No name-based rule or placement decision relies on this label. The
        // numeric policy check above used the observed UID, not this string.
        None => owner.uid.to_string(),
    };
    Ok((comm, cmdline, user))
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
    /// Optional operation deadline for live safety observations. An expired
    /// budget refuses the action; it never shortens a required evidence window.
    fn operation_deadline(&self) -> Option<Instant> {
        None
    }

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
            let result = precheck_with_deadline(
                self.operation_deadline(),
                PreCheck::CheckNotProtected,
                || self.check_not_protected_for_action(pid, action),
            );
            let blocked = !result.is_passed();
            results.push(result);
            if blocked {
                return results;
            }
        }
        for check in checks {
            // Identity is handled by IdentityProvider; protection ran above.
            if matches!(
                check,
                PreCheck::VerifyIdentity | PreCheck::CheckNotProtected
            ) {
                continue;
            }
            let result =
                precheck_with_deadline(self.operation_deadline(), check.clone(), || match check {
                    PreCheck::CheckDataLossGate => self.check_data_loss(pid),
                    PreCheck::CheckSupervisor => self.check_supervisor(pid),
                    PreCheck::CheckAgentSupervision => self.check_agent_supervision(pid),
                    PreCheck::CheckSessionSafety => self.check_session_safety(pid, sid),
                    PreCheck::VerifyProcessState => self.check_process_state(pid),
                    PreCheck::VerifyIdentity | PreCheck::CheckNotProtected => unreachable!(),
                });
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

/// The exact child and immediate agent parent shown during an interactive scan.
/// This is deliberately not serializable: a saved plan cannot grant consent.
#[derive(Debug, Clone)]
pub struct AgentChildReview {
    child: crate::collect::ProcessRecord,
    parent: crate::collect::ProcessRecord,
    child_identity: pt_common::ProcessIdentity,
}

impl AgentChildReview {
    /// Capture only a same-user, non-agent direct child of a recognized agent.
    /// Linux supplies the full birth and ancestry observations this route needs.
    pub fn from_records(
        child: &crate::collect::ProcessRecord,
        parent: &crate::collect::ProcessRecord,
    ) -> Option<Self> {
        if !cfg!(target_os = "linux")
            || child.ppid != parent.pid
            || child.pid == parent.pid
            || parent.ppid == child.pid
            || parent.ppid == parent.pid
            || child.uid != parent.uid
            || crate::collect::protected::agent_kind(&child.cmd).is_some()
            || crate::collect::protected::agent_kind(&parent.cmd).is_none()
            || !reviewed_process_is_live(child)
            || !reviewed_process_is_live(parent)
        {
            return None;
        }
        let (child_boot, child_start) = reviewed_process_birth(child)?;
        let (parent_boot, parent_start) = reviewed_process_birth(parent)?;
        if child_boot != parent_boot || parent_start > child_start {
            return None;
        }
        Some(Self {
            child: child.clone(),
            parent: parent.clone(),
            child_identity: pt_common::ProcessIdentity::full(
                child.pid.0,
                child.start_id.clone(),
                child.uid,
                child.pgid,
                child.sid,
                pt_common::IdentityQuality::Full,
            ),
        })
    }

    /// Called only after an individual row selection and interactive confirmation.
    /// It authorizes reconsidering supervision for this exact direct kill, never
    /// a parent route, a control operation, an agent root or another child.
    pub fn confirm_kill(&self, action: &PlanAction) -> Option<ConfirmedAgentChildAction> {
        if !direct_child_kill(action) || action.target != self.child_identity {
            return None;
        }
        Some(ConfirmedAgentChildAction {
            review: self.clone(),
            action: action.clone(),
        })
    }
}

/// Ephemeral consent for one explicitly reviewed child action. Its private fields
/// cannot be supplied by an executable plan, policy setting or PID whitelist.
#[derive(Debug, Clone)]
pub struct ConfirmedAgentChildAction {
    review: AgentChildReview,
    action: PlanAction,
}

impl ConfirmedAgentChildAction {
    /// All reviewed action fields remain binding, including timeouts and routing.
    pub fn matches_action(&self, action: &PlanAction) -> bool {
        direct_child_kill(action)
            && action.target == self.review.child_identity
            && action.action_id == self.action.action_id
            && serde_json::to_value(action)
                .ok()
                .zip(serde_json::to_value(&self.action).ok())
                .is_some_and(|(current, confirmed)| current == confirmed)
    }

    /// Require both original incarnations and their relationship in the same
    /// fresh census. PID reuse, reparenting, exec or job-control changes expire
    /// consent. Ordinary scheduler changes do not imply a different process.
    pub fn validate_population(
        &self,
        action: &PlanAction,
        population: &[crate::collect::ProcessRecord],
    ) -> Result<(), String> {
        if !self.matches_action(action) {
            return Err("interactive agent-child consent does not match this action".to_string());
        }
        for original in [&self.review.child, &self.review.parent] {
            let mut matches = population
                .iter()
                .filter(|record| record.pid == original.pid);
            let current = matches.next().ok_or_else(|| {
                format!(
                    "reviewed agent-child process {} is unavailable",
                    original.pid.0
                )
            })?;
            if matches.next().is_some()
                || !same_reviewed_process(original, current)
                || !reviewed_process_is_live(current)
            {
                return Err(format!(
                    "reviewed agent-child process {} changed or is ambiguous",
                    original.pid.0
                ));
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn validate_live(&self, action: &PlanAction) -> Result<(), String> {
        if !cfg!(target_os = "linux") {
            return Err("interactive agent-child consent requires Linux ancestry evidence".into());
        }
        let scan = crate::collect::quick_scan(&crate::collect::QuickScanOptions {
            pids: vec![self.review.child.pid.0, self.review.parent.pid.0],
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        })
        .map_err(|error| format!("cannot revalidate reviewed agent child: {error}"))?;
        if !scan.metadata.warnings.is_empty() {
            return Err("reviewed agent-child census is incomplete".to_string());
        }
        self.validate_population(action, &scan.processes)
    }
}

fn direct_child_kill(action: &PlanAction) -> bool {
    action.action == Action::Kill
        && action.routing == crate::plan::ActionRouting::Direct
        && !action.blocked
        && action.supervisor_restart.is_none()
        && action.original_zombie_target.is_none()
        && action.memory_cap.is_none()
        && action.d_state_diagnostics.is_none()
        && !action.action_id.is_empty()
        && action.target.quality == pt_common::IdentityQuality::Full
}

fn reviewed_process_birth(process: &crate::collect::ProcessRecord) -> Option<(&str, u64)> {
    let mut parts = process.start_id.0.split(':');
    let boot = parts.next()?;
    uuid::Uuid::parse_str(boot).ok()?;
    let start = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none() && pid == process.pid.0 && pid > 1 && pid <= i32::MAX as u32)
        .then_some((boot, start))
}

fn reviewed_process_is_live(process: &crate::collect::ProcessRecord) -> bool {
    matches!(
        process.state,
        ProcessState::Running | ProcessState::Sleeping | ProcessState::Stopped | ProcessState::Idle
    ) && !process.comm.trim().is_empty()
        && !process.cmd.trim().is_empty()
        && process.pgid.is_some_and(|id| id > 0)
        && process.sid.is_some_and(|id| id > 0)
}

fn same_reviewed_process(
    original: &crate::collect::ProcessRecord,
    current: &crate::collect::ProcessRecord,
) -> bool {
    original.pid == current.pid
        && original.ppid == current.ppid
        && original.start_id == current.start_id
        && original.uid == current.uid
        && original.pgid == current.pgid
        && original.sid == current.sid
        && original.comm == current.comm
        && original.cmd == current.cmd
        && original.tty == current.tty
}

/// Preserve a real refusal observed by a probe, even when it finished late.
/// Only a passing result can be replaced by an exhausted operation budget.
fn precheck_with_deadline(
    deadline: Option<Instant>,
    check: PreCheck,
    observe: impl FnOnce() -> PreCheckResult,
) -> PreCheckResult {
    let expired = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let refusal = || PreCheckResult::Blocked {
        check: check.clone(),
        reason: "operation deadline expired during safety prechecks; no action admitted"
            .to_string(),
    };
    if expired() {
        return refusal();
    }
    let result = observe();
    if result.is_passed() && expired() {
        refusal()
    } else {
        result
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

/// Whether `/proc/locks` lists a matching task as a lock holder or blocked waiter.
///
/// Holder lines: `1: POSIX  ADVISORY  WRITE 12345 08:02:1234 0 EOF`.
/// Waiter lines insert `->`: `1: -> POSIX  ADVISORY  WRITE 12346 08:02:1234 0 EOF`,
/// shifting every field by one; the old fixed-index parse missed all waiters.
#[cfg(any(target_os = "linux", test))]
fn proc_locks_mentions_target(
    content: &str,
    matches_pid: impl Fn(u32) -> bool,
) -> Result<bool, String> {
    if !content.is_empty() && !content.ends_with('\n') {
        return Err("incomplete lock table".to_string());
    }
    let mut found = false;
    for (index, line) in content.lines().enumerate() {
        let owner = parse_proc_lock_owner(line)
            .map_err(|error| format!("invalid lock row {}: {error}", index + 1))?;
        found |= u32::try_from(owner).is_ok_and(&matches_pid);
    }
    Ok(found)
}

/// Validate the complete kernel lock record before interpreting its owner.
/// OFD locks use owner -1; fdinfo, rather than that value, attributes them.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_lock_owner(line: &str) -> Result<i64, String> {
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
    let deadline = Instant::now()
        .checked_add(WRITE_FD_INSPECTION_TIMEOUT)
        .ok_or_else(|| "locked-file inspection deadline is unavailable".to_string())?;
    let locks_path = proc_root.join("locks");
    let content = read_bounded_lock_table(&locks_path, deadline, MAX_LOCK_TABLE_BYTES)?;
    let process_dir = proc_root.join(pid.to_string());
    locked_file_evidence(&content, deadline, || {
        write_fd_snapshot_from(
            &process_dir,
            pid,
            deadline,
            MAX_WRITE_FD_TASKS,
            MAX_WRITE_FD_INSPECTION,
        )
    })
    .map_err(|error| format!("{}: {error}", process_dir.display()))
}

#[cfg(target_os = "linux")]
const MAX_LOCK_TABLE_BYTES: u64 = 8 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn read_bounded_lock_table(
    path: &std::path::Path,
    deadline: Instant,
    max_bytes: u64,
) -> Result<String, String> {
    use std::io::Read;

    if Instant::now() >= deadline {
        return Err("locked-file inspection deadline expired".to_string());
    }
    let mut content = String::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(max_bytes.saturating_add(1))
                .read_to_string(&mut content)
        })
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if content.len() as u64 > max_bytes {
        return Err(format!(
            "{} exceeds the {max_bytes}-byte locked-file inspection limit",
            path.display()
        ));
    }
    if Instant::now() >= deadline {
        return Err("locked-file inspection deadline expired".to_string());
    }
    Ok(content)
}

/// The global table cannot attribute OFD locks (owner -1), or inherited flock
/// locks whose original owner has exited. Inspect every task's actual descriptor
/// table, including read-only handles and private tables after CLONE_FILES is
/// unshared. Only complete, stable observations can prove the absence of locks.
#[cfg(target_os = "linux")]
fn locked_file_evidence(
    global_locks: &str,
    deadline: Instant,
    mut snapshot: impl FnMut() -> Option<WriteFdSnapshot>,
) -> Result<bool, String> {
    if Instant::now() >= deadline {
        return Err("locked-file inspection deadline expired".to_string());
    }
    let unavailable = || {
        "cannot inspect complete task identity and fdinfo evidence within locked-file limits"
            .to_string()
    };
    let before = snapshot().ok_or_else(unavailable)?;
    let globally_locked =
        proc_locks_mentions_target(global_locks, |owner| before.tasks.contains_key(&owner))?;
    if globally_locked || before.descriptors.values().any(|fd| fd.has_lock) {
        return Ok(true);
    }
    let after = snapshot().ok_or_else(unavailable)?;
    if after.descriptors.values().any(|fd| fd.has_lock) {
        return Ok(true);
    }
    if before != after {
        return Err(
            "task identities or descriptor tables changed during lock inspection".to_string(),
        );
    }
    if Instant::now() >= deadline {
        return Err("locked-file inspection deadline expired".to_string());
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

/// Data-loss facts from a complete descriptor observation. The writable count
/// is conservative across task tables; critical-file rules are shared with the
/// inventory collector but never inferred from an incomplete inventory.
#[derive(Debug, Clone, Default)]
pub struct DescriptorSafetyEvidence {
    pub open_write_fds: u32,
    pub critical_writes: Vec<crate::collect::CriticalFile>,
}

/// Collect writable regular descriptors only from complete, scoped lsof evidence.
/// The inventory collector can return an empty list on errors, omit unknown
/// fields and keep partial output; none of those outcomes proves a safe zero.
#[cfg(any(target_os = "macos", test))]
fn lsof_descriptor_safety_evidence(
    pid: u32,
    output: Result<crate::collect::tool_runner::ToolOutput, crate::collect::tool_runner::ToolError>,
) -> Result<DescriptorSafetyEvidence, String> {
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
    let mut evidence = DescriptorSafetyEvidence::default();
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
                            evidence.open_write_fds =
                                evidence.open_write_fds.checked_add(1).ok_or_else(|| {
                                    "lsof writable-descriptor count overflow".to_string()
                                })?;
                            let number = fd.parse::<u32>().map_err(|_| {
                                format!("invalid writable lsof descriptor for pid {pid}")
                            })?;
                            if let Some(critical) =
                                crate::collect::proc_parsers::detect_critical_file(
                                    number,
                                    name.expect("regular-file name validated"),
                                )
                            {
                                evidence.critical_writes.push(critical);
                            }
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
    Ok(evidence)
}

#[cfg(test)]
fn lsof_write_fd_evidence(
    pid: u32,
    output: Result<crate::collect::tool_runner::ToolOutput, crate::collect::tool_runner::ToolError>,
) -> Result<u32, String> {
    lsof_descriptor_safety_evidence(pid, output).map(|evidence| evidence.open_write_fds)
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

// Descriptor links and fdinfo are procfs observations. Following a descriptor
// with metadata(), however, calls into its backing filesystem and can hang on a
// stalled FUSE/NFS mount. Keep every such lookup in the bounded tool runner.
#[cfg(target_os = "linux")]
const WRITE_FD_INSPECTION_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(target_os = "linux")]
const MAX_WRITE_FD_INSPECTION: usize = 50_000;
#[cfg(target_os = "linux")]
const MAX_WRITE_FD_TASKS: usize = 1024;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WriteFdObservation {
    target: std::path::PathBuf,
    flags: u32,
    inode: u64,
    mount_id: u64,
    has_lock: bool,
}

#[cfg(target_os = "linux")]
impl WriteFdObservation {
    fn writable(&self) -> bool {
        matches!(self.flags & libc::O_ACCMODE as u32, 1 | 2)
    }
}

/// Every thread can own a different descriptor table after unshare(CLONE_FILES).
/// Keep its identity and the complete table, including read-only descriptors,
/// so a new task or reopened descriptor invalidates a negative observation.
/// Writable-file and locked-file gates share this bounded kernel evidence.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct WriteFdSnapshot {
    tasks: std::collections::BTreeMap<u32, WriteFdTaskIdentity>,
    descriptors: std::collections::BTreeMap<String, WriteFdObservation>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct WriteFdTaskIdentity {
    device: u64,
    inode: u64,
    birth_ticks: u64,
    uid: u32,
}

#[cfg(target_os = "linux")]
fn write_fd_task_identity(task_dir: &std::path::Path, tid: u32) -> Option<WriteFdTaskIdentity> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(task_dir).ok()?;
    let mut content = String::new();
    const MAX_STAT_BYTES: u64 = 16 * 1024;
    std::fs::File::open(task_dir.join("stat"))
        .ok()?
        .take(MAX_STAT_BYTES + 1)
        .read_to_string(&mut content)
        .ok()?;
    if content.len() as u64 > MAX_STAT_BYTES {
        return None;
    }
    let stat =
        crate::collect::proc_parsers::parse_required_proc_stat_content(tid, &content).ok()?;
    Some(WriteFdTaskIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        birth_ticks: stat.starttime,
        uid: metadata.uid(),
    })
}

#[cfg(target_os = "linux")]
fn write_fd_task_ids(
    process_dir: &std::path::Path,
    pid: u32,
    deadline: Instant,
    max_tasks: usize,
) -> Option<std::collections::BTreeSet<u32>> {
    let mut tids = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(process_dir.join("task")).ok()? {
        if Instant::now() >= deadline || tids.len() >= max_tasks {
            return None;
        }
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_str()?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let tid = name.parse::<u32>().ok()?;
        if tid == 0 || name != tid.to_string() || !tids.insert(tid) {
            return None;
        }
    }
    (tids.contains(&pid) && Instant::now() < deadline).then_some(tids)
}

/// Read all required kernel fields, preserving unknown/duplicate/truncated
/// evidence instead of making an unreadable access mode look read-only.
#[cfg(target_os = "linux")]
fn write_fd_flags_and_identity(content: &str) -> Option<(u32, u64, u64)> {
    if !content.ends_with('\n') {
        return None;
    }
    let (mut flags, mut inode, mut mount_id) = (None, None, None);
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("flags:") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
                return None;
            }
            if flags.replace(u32::from_str_radix(value, 8).ok()?).is_some() {
                return None;
            }
        } else if let Some(value) = line.strip_prefix("ino:") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            if inode.replace(value.parse::<u64>().ok()?).is_some() {
                return None;
            }
        } else if let Some(value) = line.strip_prefix("mnt_id:") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            if mount_id.replace(value.parse::<u64>().ok()?).is_some() {
                return None;
            }
        }
    }
    let flags = flags?;
    // Mode 3 is a Linux-specific ioctl-only access mode. Do not guess that an
    // unfamiliar mode proves there can be no pending writes.
    if flags & libc::O_ACCMODE as u32 == 3 {
        return None;
    }
    Some((flags, inode?, mount_id?))
}

#[cfg(target_os = "linux")]
fn write_fd_snapshot(pid: u32, deadline: Instant) -> Option<WriteFdSnapshot> {
    write_fd_snapshot_from(
        &std::path::PathBuf::from(format!("/proc/{pid}")),
        pid,
        deadline,
        MAX_WRITE_FD_TASKS,
        MAX_WRITE_FD_INSPECTION,
    )
}

#[cfg(target_os = "linux")]
fn write_fd_snapshot_from(
    process_dir: &std::path::Path,
    pid: u32,
    deadline: Instant,
    max_tasks: usize,
    max_descriptors: usize,
) -> Option<WriteFdSnapshot> {
    use std::io::Read;

    let tids = write_fd_task_ids(process_dir, pid, deadline, max_tasks)?;
    let mut observed = WriteFdSnapshot {
        tasks: std::collections::BTreeMap::new(),
        descriptors: std::collections::BTreeMap::new(),
    };
    for &tid in &tids {
        let task_dir = process_dir.join("task").join(tid.to_string());
        let identity = write_fd_task_identity(&task_dir, tid)?;
        let entries = std::fs::read_dir(task_dir.join("fd")).ok()?;
        for entry in entries {
            if Instant::now() >= deadline || observed.descriptors.len() >= max_descriptors {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let fd = name.parse::<u32>().ok()?;
            if name != fd.to_string() {
                return None;
            }
            let target = std::fs::read_link(entry.path()).ok()?;
            // Large lock/event tables can make fdinfo arbitrarily long. Its
            // required header must fit within a fixed per-descriptor bound.
            const MAX_FDINFO_BYTES: u64 = 64 * 1024;
            let mut content = String::new();
            std::fs::File::open(task_dir.join("fdinfo").join(name))
                .ok()?
                .take(MAX_FDINFO_BYTES + 1)
                .read_to_string(&mut content)
                .ok()?;
            if content.len() as u64 > MAX_FDINFO_BYTES {
                return None;
            }
            let (flags, inode, mount_id) = write_fd_flags_and_identity(&content)?;
            let has_lock = fdinfo_has_lock(&content).ok()?;
            let path = task_dir.join("fd").join(name).to_str()?.to_string();
            if observed
                .descriptors
                .insert(
                    path,
                    WriteFdObservation {
                        target,
                        flags,
                        inode,
                        mount_id,
                        has_lock,
                    },
                )
                .is_some()
            {
                return None;
            }
        }
        if write_fd_task_identity(&task_dir, tid)? != identity {
            return None;
        }
        observed.tasks.insert(tid, identity);
    }
    if write_fd_task_ids(process_dir, pid, deadline, max_tasks)? != tids {
        return None;
    }
    (Instant::now() < deadline).then_some(observed)
}

/// Count only a complete, successful metadata response for the exact requested
/// writable descriptors. Paths in this protocol are generated /proc paths, not
/// displayed filenames; a filename containing whitespace cannot inject a row.
#[cfg(target_os = "linux")]
fn descriptor_safety_from_metadata(
    requested: &std::collections::BTreeMap<String, &WriteFdObservation>,
    output: &crate::collect::tool_runner::ToolOutput,
) -> Option<DescriptorSafetyEvidence> {
    if !output.success() || !output.stderr.is_empty() {
        return None;
    }
    let content = std::str::from_utf8(&output.stdout).ok()?;
    if !content.ends_with('\n') {
        return None;
    }
    let mut seen = HashSet::new();
    let mut evidence = DescriptorSafetyEvidence::default();
    for line in content.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 4 || !seen.insert(fields[0]) {
            return None;
        }
        let observation = requested.get(fields[0])?;
        if fields[1].is_empty()
            || !fields[1].bytes().all(|byte| byte.is_ascii_hexdigit())
            || fields[2..]
                .iter()
                .any(|field| field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return None;
        }
        let mode = u32::from_str_radix(fields[1], 16).ok()?;
        let links = fields[2].parse::<u64>().ok()?;
        let inode = fields[3].parse::<u64>().ok()?;
        if inode != observation.inode
            || mode & !0xffff != 0
            || !matches!(
                mode & libc::S_IFMT,
                0 | libc::S_IFREG
                    | libc::S_IFDIR
                    | libc::S_IFCHR
                    | libc::S_IFBLK
                    | libc::S_IFIFO
                    | libc::S_IFSOCK
            )
        {
            return None;
        }
        // Linux anonymous-inode descriptors (eventfd/epoll/etc.) have no file
        // type bits. That kernel link label is distinct from any absolute file
        // path. A zero type elsewhere, or a symlink despite -L, is not proof of
        // a harmless descriptor and must not turn into a successful zero.
        if mode & libc::S_IFMT == 0
            && !observation
                .target
                .as_os_str()
                .as_encoded_bytes()
                .starts_with(b"anon_inode:")
        {
            return None;
        }
        // File type and link count, not a pathname prefix, establish persistence.
        // A regular file under /dev or a name ending in " (deleted)" can still
        // have live links. Conversely memfds and unlinked named scratch files
        // have no links. O_TMPFILE remains protected because it can be linked
        // into place later; its kernel flag is stronger evidence than "#123".
        if mode & libc::S_IFMT == libc::S_IFREG {
            if links > 0 || observation.flags & libc::O_TMPFILE as u32 == libc::O_TMPFILE as u32 {
                evidence.open_write_fds = evidence.open_write_fds.checked_add(1)?;
            }
            let fd = std::path::Path::new(fields[0])
                .file_name()?
                .to_str()?
                .parse::<u32>()
                .ok()?;
            // A malformed/unrepresentable path is not evidence that no named
            // transaction is in progress. Never classify device/FIFO paths as
            // lock files merely because their names resemble a critical file.
            if let Some(critical) =
                crate::collect::proc_parsers::detect_critical_file(fd, observation.target.to_str()?)
            {
                evidence.critical_writes.push(critical);
            }
        }
    }
    (seen.len() == requested.len()).then_some(evidence)
}

#[cfg(target_os = "linux")]
fn descriptor_safety_with_probe<F>(pid: u32, probe: F) -> Option<DescriptorSafetyEvidence>
where
    F: FnOnce(&[String], Duration) -> Option<crate::collect::tool_runner::ToolOutput>,
{
    let deadline = Instant::now().checked_add(WRITE_FD_INSPECTION_TIMEOUT)?;
    let birth = read_io_birth(pid).ok()?;
    let before = write_fd_snapshot(pid, deadline)?;
    let requested: std::collections::BTreeMap<_, _> = before
        .descriptors
        .iter()
        .filter(|(_, observation)| observation.writable())
        .map(|(path, observation)| (path.clone(), observation))
        .collect();
    let evidence = if requested.is_empty() {
        DescriptorSafetyEvidence::default()
    } else {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let paths: Vec<_> = requested.keys().cloned().collect();
        descriptor_safety_from_metadata(&requested, &probe(&paths, remaining)?)?
    };
    // The command inspected live numeric descriptors. Reject a close/reopen,
    // changed access mode, mount, pathname, task census or process incarnation
    // instead of mixing one file's metadata with another file's access flags.
    if before != write_fd_snapshot(pid, deadline)? || read_io_birth(pid).ok()? != birth {
        return None;
    }
    (Instant::now() < deadline).then_some(evidence)
}

#[cfg(all(target_os = "linux", test))]
fn count_write_fd_metadata(
    requested: &std::collections::BTreeMap<String, &WriteFdObservation>,
    output: &crate::collect::tool_runner::ToolOutput,
) -> Option<u32> {
    descriptor_safety_from_metadata(requested, output).map(|evidence| evidence.open_write_fds)
}

#[cfg(all(target_os = "linux", test))]
fn open_write_fd_count_with_probe<F>(pid: u32, probe: F) -> Option<u32>
where
    F: FnOnce(&[String], Duration) -> Option<crate::collect::tool_runner::ToolOutput>,
{
    descriptor_safety_with_probe(pid, probe).map(|evidence| evidence.open_write_fds)
}

#[cfg(target_os = "linux")]
fn write_fd_probe_runner(remaining: Duration) -> crate::collect::tool_runner::ToolRunner {
    use crate::collect::tool_runner::{ToolConfig, ToolRunner};
    ToolRunner::new(ToolConfig {
        default_timeout: remaining,
        budget_ms: WRITE_FD_INSPECTION_TIMEOUT.as_millis() as u64,
        max_output_bytes: MAX_WRITE_FD_INSPECTION * 128,
        use_nice: false,
        ..ToolConfig::default()
    })
}

/// Conservative count of persistent writable descriptor references across every
/// thread: the data-loss gate's definition, shared by plan and apply. Shared
/// tables can contribute repeatedly because equality of descriptor metadata does
/// not prove shared ownership. `None` means incomplete, changing or over-budget
/// evidence; only a complete zero proves there are no persistent writers.
pub fn open_write_fd_count(pid: u32) -> Option<u32> {
    collect_descriptor_safety_evidence(pid)
        .ok()
        .map(|evidence| evidence.open_write_fds)
}

/// Observe mandatory critical-file and configurable writable-file evidence for
/// one complete, current process identity. Both checks use the same bounded task
/// walk and metadata probe; an unavailable or changing observation is an error,
/// never an empty set of critical files.
pub fn descriptor_safety_evidence(
    target: &pt_common::ProcessIdentity,
) -> Result<DescriptorSafetyEvidence, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use super::executor::IdentityProvider;

        let provider = super::signal::LiveIdentityProvider::new();
        descriptor_safety_for_identity(
            target,
            || {
                provider
                    .revalidate(target)
                    .map_err(|error| error.to_string())
            },
            || collect_descriptor_safety_evidence(target.pid.0),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = target;
        Err("complete descriptor safety evidence is unsupported on this platform".to_string())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn descriptor_safety_for_identity(
    target: &pt_common::ProcessIdentity,
    mut revalidate: impl FnMut() -> Result<bool, String>,
    collect: impl FnOnce() -> Result<DescriptorSafetyEvidence, String>,
) -> Result<DescriptorSafetyEvidence, String> {
    if target.quality != pt_common::IdentityQuality::Full || !target.can_safely_revalidate() {
        return Err("descriptor safety requires a complete process identity".to_string());
    }
    if !revalidate()? {
        return Err("process identity changed before descriptor safety inspection".to_string());
    }
    let evidence = collect()?;
    if !revalidate()? {
        return Err("process identity changed during descriptor safety inspection".to_string());
    }
    Ok(evidence)
}

fn collect_descriptor_safety_evidence(pid: u32) -> Result<DescriptorSafetyEvidence, String> {
    #[cfg(target_os = "linux")]
    {
        use crate::collect::tool_runner::ToolSpec;
        descriptor_safety_with_probe(pid, |paths, remaining| {
            let mut args = vec![
                "-L".to_string(),
                "-c".to_string(),
                "%n %f %h %i".to_string(),
                "--".to_string(),
            ];
            args.extend_from_slice(paths);
            write_fd_probe_runner(remaining)
                .run(&ToolSpec::new("stat", args))
                .ok()
        })
        .ok_or_else(|| {
            format!(
                "cannot establish complete data-loss evidence for pid {pid}: descriptor tables, access modes, file metadata or process identity are unavailable, changed or over budget"
            )
        })
    }
    #[cfg(target_os = "macos")]
    {
        let before = crate::collect::macos::read_bsd_info(pid)
            .ok_or_else(|| format!("cannot read descriptor owner identity for pid {pid}"))?;
        let evidence = lsof_descriptor_safety_evidence(
            pid,
            crate::collect::tool_runner::run_tool(
                crate::collect::macos::lsof_path(),
                &lsof_write_fd_args(&pid.to_string()),
                Some(Duration::from_secs(5)),
                None,
            ),
        )?;
        let after = crate::collect::macos::read_bsd_info(pid)
            .ok_or_else(|| format!("cannot recheck descriptor owner identity for pid {pid}"))?;
        if before != after {
            return Err(format!("descriptor owner identity changed for pid {pid}"));
        }
        Ok(evidence)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err("complete descriptor safety evidence is unsupported on this platform".to_string())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecentIoEvidence {
    Active,
    Idle,
    Unknown(String),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn recent_io_precheck(evidence: RecentIoEvidence, window: Duration) -> PreCheckResult {
    let reason = match evidence {
        RecentIoEvidence::Idle => return PreCheckResult::Passed,
        RecentIoEvidence::Active => {
            format!("recent I/O activity within {}s window", window.as_secs())
        }
        RecentIoEvidence::Unknown(reason) => {
            format!("recent I/O evidence unavailable: {reason}")
        }
    };
    PreCheckResult::Blocked {
        check: PreCheck::CheckDataLossGate,
        reason,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct IoSample {
    /// Linux start ticks or macOS process-start absolute time. Only observations
    /// from one native reader are compared; persisted baselines are Linux-only.
    birth_ticks: u64,
    /// Linux wchar or macOS logical writes. Physical disk writes are observed
    /// separately so delayed writeback also blocks an apparently idle target.
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

    /// The interval excludes both reads. An invalid boundary cannot contribute
    /// even partial coverage towards the required window.
    fn elapsed_until(&self, current: &Self) -> Option<Duration> {
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
        Some(Duration::from_nanos(
            current.started_boot_ns.checked_sub(self.finished_boot_ns)?,
        ))
    }

    fn observation(
        &self,
        current: &Self,
        after: IoSample,
        window: Duration,
    ) -> Option<RecentIoObservation> {
        let elapsed = self.elapsed_until(current)?;
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct RecentIoObservation {
    before: Result<IoSample, String>,
    after: Result<IoSample, String>,
    window: Duration,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RecentIoObservation {
    fn unavailable(window: Duration, reason: String) -> Self {
        Self {
            before: Err(reason.clone()),
            after: Err(reason),
            window,
        }
    }

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

/// Darwin exposes both logical and physical file-write counters through
/// RUSAGE_INFO_V4. Do not substitute zero counters when this API is unavailable.
/// API/field definitions: Apple's xnu/libsyscall/wrappers/libproc/libproc.h and
/// xnu/bsd/kern/kern_resource.c (gather_rusage_info, RUSAGE_INFO_V4).
#[cfg(target_os = "macos")]
fn read_io_sample(pid: u32) -> Result<IoSample, String> {
    let started_at = Instant::now();
    let native_pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| format!("invalid I/O observation PID {pid}"))?;
    let identity = || {
        crate::collect::macos::read_bsd_info(pid)
            .ok_or_else(|| format!("cannot read native I/O identity for PID {pid}"))
    };
    let before = identity()?;
    // SAFETY: rusage_info_v4 contains only integers/arrays; the documented V4
    // flavor writes exactly this structure into our valid, aligned buffer.
    let mut usage: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::proc_pid_rusage(
            native_pid,
            libc::RUSAGE_INFO_V4,
            (&mut usage as *mut libc::rusage_info_v4).cast(),
        )
    };
    if result != 0 {
        return Err(format!(
            "cannot read native logical and physical write counters for PID {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if before != identity()? || usage.ri_proc_start_abstime == 0 || usage.ri_proc_exit_abstime != 0
    {
        return Err(format!(
            "process changed or exited during native I/O observation for PID {pid}"
        ));
    }
    Ok(IoSample {
        birth_ticks: usage.ri_proc_start_abstime,
        wchar: usage.ri_logical_writes,
        write_bytes: usage.ri_diskio_byteswritten,
        started_at,
        finished_at: Instant::now(),
    })
}

/// Live pre-check provider that reads from /proc (Linux) or sysctl/lsof (macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct LivePreCheckProvider {
    protected_filter: Option<ProtectedFilter>,
    config: LivePreCheckConfig,
    /// Shared absolute operation budget; absent for callers without a timeout.
    deadline: Option<Instant>,
    /// Known supervisor comm names.
    known_supervisors: HashSet<String>,
    /// Recent-I/O results sampled up front for many pids (see `prime_recent_io`).
    recent_io: std::sync::Mutex<std::collections::HashMap<u32, RecentIoObservation>>,
    /// Ephemeral explicit row confirmations; never consulted by PID-only checks.
    confirmed_agent_children: Vec<ConfirmedAgentChildAction>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl LivePreCheckProvider {
    /// Attach confirmations from the current interactive selection only. These
    /// are considered exclusively by `run_checks_for_plan` for an exact action.
    pub fn with_confirmed_agent_children(
        mut self,
        confirmations: Vec<ConfirmedAgentChildAction>,
    ) -> Self {
        self.confirmed_agent_children = confirmations;
        self
    }

    /// Limit new observations without reducing any policy safety requirement.
    /// Existing callers, including interactive execution, have no deadline
    /// unless they explicitly attach one.
    pub fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    fn io_deadline_refusal(&self, required_wait: Duration) -> Option<String> {
        let remaining = self.deadline?.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Some("operation deadline expired before recent-I/O observation".to_string())
        } else if remaining <= required_wait {
            Some(format!(
                "operation deadline cannot cover the complete {}s recent-I/O window ({:.3}s still required); the required window is not shortened",
                self.config.block_if_recent_io_seconds,
                required_wait.as_secs_f64(),
            ))
        } else {
            None
        }
    }

    /// Reuse identity-bound plan-time counters. A young baseline needs only the
    /// remaining interval; ambiguous or invalid baselines require a fresh window.
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
        let mut pending = Vec::new();
        let mut seen = HashSet::new();
        let mut observations = Vec::new();
        let mut by_pid = std::collections::HashMap::new();
        for baseline in baselines {
            // Duplicate rows cannot choose whichever observation grants action.
            by_pid
                .entry(baseline.target.pid.0)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(baseline));
        }
        for target in targets {
            if !seen.insert(target.pid.0) {
                continue;
            }
            if let Some(reason) = self.io_deadline_refusal(Duration::ZERO) {
                observations.push((
                    target.pid.0,
                    RecentIoObservation::unavailable(window, reason),
                ));
                continue;
            }
            let Some(baseline) = by_pid
                .get(&target.pid.0)
                .copied()
                .flatten()
                .filter(|baseline| baseline.target.matches(target))
            else {
                unobserved.push(target.pid.0);
                continue;
            };
            let Ok((current, sample)) = RecentIoBaseline::capture_with_sample(target) else {
                unobserved.push(target.pid.0);
                continue;
            };
            let Some(elapsed) = baseline.elapsed_until(&current) else {
                unobserved.push(target.pid.0);
                continue;
            };
            let remaining = window.saturating_sub(elapsed);
            let Some(ready_at) = sample.started_at.checked_add(remaining) else {
                unobserved.push(target.pid.0);
                continue;
            };
            if let Some(reason) =
                self.io_deadline_refusal(ready_at.saturating_duration_since(Instant::now()))
            {
                observations.push((
                    target.pid.0,
                    RecentIoObservation::unavailable(window, reason),
                ));
            } else if remaining.is_zero() {
                match baseline.observation(&current, sample, window) {
                    Some(observation) => observations.push((target.pid.0, observation)),
                    None => unobserved.push(target.pid.0),
                }
            } else {
                pending.push((ready_at, baseline, current));
            }
        }
        trace!(
            reused = observations.len(),
            partial = pending.len(),
            fresh = unobserved.len(),
            "priming identity-bound recent I/O evidence"
        );
        // Fresh windows overlap all partial windows. If the operation budget
        // refuses a full probe, eligible partial windows can still complete.
        self.prime_recent_io(&unobserved);
        if let Some(ready_at) = pending.iter().map(|(ready_at, _, _)| *ready_at).max() {
            std::thread::sleep(ready_at.saturating_duration_since(Instant::now()));
        }
        for (_, baseline, initial) in pending {
            let finish = || {
                if let Some(reason) = self.io_deadline_refusal(Duration::ZERO) {
                    return Err(reason);
                }
                let (end, sample) = RecentIoBaseline::capture_with_sample(&initial.target)?;
                // Recheck both intervals. A counter that decreased after the
                // intermediate read cannot be hidden by an older, lower value.
                initial.elapsed_until(&end).ok_or_else(|| {
                    "I/O identity, scope, clock or counters changed while completing the window"
                        .to_string()
                })?;
                baseline.observation(&end, sample, window).ok_or_else(|| {
                    "saved and live I/O samples do not cover the complete required window"
                        .to_string()
                })
            };
            observations.push((
                initial.target.pid.0,
                finish().unwrap_or_else(|reason| RecentIoObservation::unavailable(window, reason)),
            ));
        }
        self.recent_io
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(observations);
    }

    /// Sample recent I/O for all `pids` in ONE probe window and cache the results,
    /// so applying N destructive actions costs one window instead of N (it slept
    /// the full window, 60 s by default, per target). Pids not primed are probed
    /// individually as before.
    pub fn prime_recent_io(&self, pids: &[u32]) {
        if self.config.block_if_recent_io_seconds > 0 && !pids.is_empty() {
            let window = Duration::from_secs(self.config.block_if_recent_io_seconds);
            // Refuse before native counter reads when a full window cannot fit.
            // Cache unknown evidence so later checks cannot retry the full wait.
            if let Some(reason) = self.io_deadline_refusal(recent_io_probe_window(window)) {
                let mut cache = self.recent_io.lock().unwrap_or_else(|e| e.into_inner());
                for &pid in pids {
                    cache.insert(
                        pid,
                        RecentIoObservation::unavailable(window, reason.clone()),
                    );
                }
                return;
            }
            let before: Vec<_> = pids
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        self.io_deadline_refusal(Duration::ZERO)
                            .map_or_else(|| read_io_sample(pid), Err),
                    )
                })
                .collect();
            let refusal = self.io_deadline_refusal(recent_io_probe_window(window));
            if refusal.is_none() {
                std::thread::sleep(recent_io_probe_window(window));
            }
            let observations: Vec<_> = before
                .into_iter()
                .map(|(pid, before)| {
                    let after = refusal
                        .clone()
                        .or_else(|| self.io_deadline_refusal(Duration::ZERO))
                        .map_or_else(|| read_io_sample(pid), Err);
                    let after = match (after, self.io_deadline_refusal(Duration::ZERO)) {
                        (Ok(_), Some(reason)) => Err(reason),
                        (sample, _) => sample,
                    };
                    (
                        pid,
                        RecentIoObservation {
                            before,
                            after,
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
            deadline: None,
            known_supervisors,
            recent_io: Default::default(),
            confirmed_agent_children: Vec::new(),
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
            // e.g. `ssh -M`, `-zsh`, `ssh host nc -U .../sock`). A basename is not
            // a substitute when argv is unreadable: it could hide a protected rule.
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
        }
    }

    /// Read numeric ownership without disguising an unresolved name as a UID.
    fn read_owner(&self, pid: u32) -> Option<ProtectionOwner> {
        let uid = self.read_uid(pid)?;
        // Retain the existing macOS resolver. Linux uses the local account file;
        // missing NSS-only names remain unknown rather than adding an unbounded
        // network-backed resolver call to an action's safety checks.
        #[cfg(target_os = "macos")]
        let name = user_name_for_uid(uid);
        #[cfg(not(target_os = "macos"))]
        let name: Option<String> = None;
        let name = name.or_else(|| {
            let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
            passwd.lines().find_map(|line| {
                let mut fields = line.split(':');
                let username = fields.next()?;
                let _password = fields.next()?;
                let account_uid = fields.next()?.parse::<u32>().ok()?;
                (account_uid == uid && !username.trim().is_empty()).then(|| username.to_string())
            })
        });
        // A credential change during lookup invalidates the owner/name pair.
        if self.read_uid(pid)? != uid {
            return None;
        }
        Some(ProtectionOwner { uid, name })
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
            deadline: None,
            known_supervisors,
            recent_io: Default::default(),
            confirmed_agent_children: Vec::new(),
        }
    }

    /// Check if process has open write file descriptors.
    #[cfg(test)]
    fn has_open_write_fds(&self, pid: u32) -> Option<(bool, u32)> {
        let write_count = open_write_fd_count(pid)?;
        Some((write_count > self.config.max_open_write_fds, write_count))
    }

    /// Observe a full I/O window, retaining unreadable and invalid evidence.
    fn has_recent_io(&self, pid: u32, window: Duration) -> RecentIoEvidence {
        if let Some(reason) = self.io_deadline_refusal(Duration::ZERO) {
            return RecentIoEvidence::Unknown(reason);
        }
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
            let evidence = cached.evidence();
            if matches!(evidence, RecentIoEvidence::Unknown(_)) {
                return evidence;
            }
            let evidence = cached.revalidate(read_io_sample(pid));
            return match (evidence, self.io_deadline_refusal(Duration::ZERO)) {
                (RecentIoEvidence::Idle, Some(reason)) => RecentIoEvidence::Unknown(reason),
                (evidence, _) => evidence,
            };
        }
        if let Some(reason) = self.io_deadline_refusal(recent_io_probe_window(window)) {
            return RecentIoEvidence::Unknown(reason);
        }
        let before = read_io_sample(pid);
        if let Some(reason) = self.io_deadline_refusal(recent_io_probe_window(window)) {
            return RecentIoEvidence::Unknown(reason);
        }
        std::thread::sleep(recent_io_probe_window(window));
        let observation = RecentIoObservation {
            before,
            after: self
                .io_deadline_refusal(Duration::ZERO)
                .map_or_else(|| read_io_sample(pid), Err),
            window,
        };
        let evidence = match (
            observation.evidence(),
            self.io_deadline_refusal(Duration::ZERO),
        ) {
            (RecentIoEvidence::Idle, Some(reason)) => RecentIoEvidence::Unknown(reason),
            (evidence, _) => evidence,
        };
        self.recent_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pid, observation);
        evidence
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

    /// Read process state, distinguishing confirmed exit from unavailable data.
    fn read_process_state(&self, pid: u32) -> Result<Option<ProcessState>, String> {
        #[cfg(target_os = "linux")]
        {
            read_process_state_from_proc(pid, std::path::Path::new("/proc"))
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(stat) = crate::collect::macos::read_session_stat(pid) {
                Ok(Some(ProcessState::from_char(stat.state)))
            } else if process_is_absent(pid)? {
                Ok(None)
            } else {
                Err(format!(
                    "cannot read native process state for live PID {pid}"
                ))
            }
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
        parent_comm_from_observations(pid, read_precheck_stat)
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
        action: Action,
        bound_user_service: bool,
    ) -> PreCheckResult {
        trace!(pid, "checking protection status");

        if action == Action::Keep {
            return PreCheckResult::Passed;
        }

        if let Some(ref filter) = self.protected_filter {
            // Check protected PIDs first (fast lookup)
            if filter.protected_pids().contains(&pid) {
                debug!(pid, "process has protected PID");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckNotProtected,
                    reason: format!("protected PID: {pid}"),
                };
            }

            // Custom rules remain binding when built-in protection is disabled.
            // Do not let a missing read become an empty, non-matching string.
            let (comm, cmd, user) = match required_protection_metadata(
                pid,
                self.read_comm(pid),
                self.read_cmdline(pid),
                self.read_owner(pid),
                filter.protected_users(),
                cfg!(target_os = "macos") && filter.builtin_enabled(),
            ) {
                Ok(metadata) => metadata,
                Err(blocked) => return blocked,
            };
            trace!(pid, %comm, "read process identity for protection check");

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
                        action,
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
            let mut left = budget.saturating_sub(started.elapsed());
            if let Some(deadline) = self.deadline {
                left = left.min(deadline.saturating_duration_since(Instant::now()));
            }
            (!left.is_zero()).then_some(left)
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

/// Only the full-plan entrypoint can install this action-scoped view. Forward
/// every other gate unchanged, including live child, infrastructure, session,
/// data-loss and supervisor restrictions enforced by the surrounding executor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ConfirmedAgentChildPreChecks<'a> {
    provider: &'a LivePreCheckProvider,
    confirmation: &'a ConfirmedAgentChildAction,
    action: &'a PlanAction,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PreCheckProvider for ConfirmedAgentChildPreChecks<'_> {
    fn operation_deadline(&self) -> Option<Instant> {
        self.provider.operation_deadline()
    }

    fn check_not_protected(&self, pid: u32) -> PreCheckResult {
        self.provider.check_not_protected(pid)
    }

    fn check_not_protected_for_action(&self, pid: u32, action: Action) -> PreCheckResult {
        self.provider.check_not_protected_for_action(pid, action)
    }

    fn check_data_loss(&self, pid: u32) -> PreCheckResult {
        self.provider.check_data_loss(pid)
    }

    fn check_supervisor(&self, pid: u32) -> PreCheckResult {
        self.provider.check_supervisor(pid)
    }

    fn check_session_safety(&self, pid: u32, sid: Option<u32>) -> PreCheckResult {
        self.provider.check_session_safety(pid, sid)
    }

    fn check_process_state(&self, pid: u32) -> PreCheckResult {
        self.provider.check_process_state(pid)
    }

    fn check_agent_supervision(&self, pid: u32) -> PreCheckResult {
        if pid != self.action.target.pid.0 {
            return self.provider.check_agent_supervision(pid);
        }
        let refused = |reason| PreCheckResult::Blocked {
            check: PreCheck::CheckAgentSupervision,
            reason,
        };
        if let Err(reason) = self.confirmation.validate_live(self.action) {
            return refused(reason);
        }
        let supervision = match detect_supervision(pid) {
            Ok(observed) => observed,
            Err(error) => {
                return refused(format!("agent supervision evidence unavailable: {error}"));
            }
        };
        // Read failures and unavailable ancestry never become consent. Recheck
        // the original child/parent after the potentially longer detector walk.
        if supervision.ancestry.is_none() {
            return refused("agent supervision ancestry evidence is unavailable".to_string());
        }
        if let Err(reason) = self.confirmation.validate_live(self.action) {
            return refused(reason);
        }
        debug!(
            pid,
            agent_pid = self.confirmation.review.parent.pid.0,
            action_id = %self.action.action_id,
            observed_human_supervision = is_human_supervised(&supervision),
            "validated explicit interactive confirmation for this direct agent child"
        );
        PreCheckResult::Passed
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PreCheckProvider for LivePreCheckProvider {
    fn operation_deadline(&self) -> Option<Instant> {
        self.deadline
    }

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
        if let Some(confirmation) = self
            .confirmed_agent_children
            .iter()
            .find(|confirmation| confirmation.matches_action(action))
        {
            return ConfirmedAgentChildPreChecks {
                provider: self,
                confirmation,
                action,
            }
            .run_checks_for_action(
                &crate::plan::effective_pre_checks(action),
                action.target.pid.0,
                action.target.sid,
                action.action,
            );
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

        let unavailable = |error: &str| PreCheckResult::Blocked {
            check: PreCheck::CheckDataLossGate,
            reason: format!(
                "cannot inspect open files; refusing without complete data-loss evidence: {error}"
            ),
        };
        // Hard transaction/lock markers are mandatory even when the generic
        // writable-file policy is disabled or allows some ordinary writers.
        // The same complete observation supplies both rules. Preserve specific
        // configured-gate diagnostics when independent evidence also refuses.
        let descriptors = collect_descriptor_safety_evidence(pid);
        if let Ok(evidence) = &descriptors {
            if let Some(critical) = evidence
                .critical_writes
                .iter()
                .find(|file| file.strength == crate::collect::DetectionStrength::Hard)
            {
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckDataLossGate,
                    reason: format!(
                        "process has critical file '{}' (rule: {}): {}",
                        critical.path,
                        critical.rule_id,
                        critical.remediation_hint(),
                    ),
                };
            }
        }
        if self.config.block_if_open_write_fds {
            let evidence = match &descriptors {
                Ok(evidence) => evidence,
                Err(error) => return unavailable(error),
            };
            let write_count = evidence.open_write_fds;
            if write_count > self.config.max_open_write_fds {
                debug!(pid, write_count, "process has open write fds");
                return PreCheckResult::Blocked {
                    check: PreCheck::CheckDataLossGate,
                    reason: format!(
                        "{write_count} open write fds across task tables (conservative count; max: {})",
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
            let result = recent_io_precheck(self.has_recent_io(pid, window), window);
            if !result.is_passed() {
                return result;
            }
        }

        match descriptors {
            Ok(_) => PreCheckResult::Passed,
            Err(error) => unavailable(&error),
        }
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
        let observation = self.read_process_state(pid);
        #[cfg(target_os = "linux")]
        let wchan = if matches!(observation, Ok(Some(ProcessState::DiskSleep))) {
            self.read_wchan(pid)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let wchan: Option<String> = None;
        process_state_precheck(observation, wchan.as_deref())
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

    #[cfg(target_os = "linux")]
    fn reviewed_agent_family() -> (crate::collect::ProcessRecord, crate::collect::ProcessRecord) {
        use crate::collect::ProcessRecord;
        use pt_common::{ProcessId, StartId};

        let parent = ProcessRecord {
            pid: ProcessId(70),
            ppid: ProcessId(2),
            uid: 1000,
            user: "fixture".to_string(),
            pgid: Some(70),
            sid: Some(70),
            start_id: StartId::from_linux("12345678-1234-4321-8765-123456789abc", 10, 70),
            comm: "codex".to_string(),
            cmd: "codex exec review".to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 1,
            elapsed: Duration::from_secs(3600),
            source: "test".to_string(),
            container_info: None,
        };
        let mut child = parent.clone();
        child.pid = ProcessId(71);
        child.ppid = parent.pid;
        child.start_id = StartId::from_linux("12345678-1234-4321-8765-123456789abc", 20, 71);
        child.comm = "sleep".to_string();
        child.cmd = "sleep 600".to_string();
        (child, parent)
    }

    #[cfg(target_os = "linux")]
    fn reviewed_child_action(review: &AgentChildReview) -> PlanAction {
        PlanAction {
            action_id: "reviewed-child-kill".to_string(),
            target: review.child_identity.clone(),
            action: Action::Kill,
            order: 0,
            stage: 0,
            timeouts: crate::plan::ActionTimeouts::default(),
            pre_checks: vec![PreCheck::CheckAgentSupervision],
            rationale: crate::plan::ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: Vec::new(),
            on_failure: Vec::new(),
            blocked: false,
            routing: crate::plan::ActionRouting::Direct,
            confidence: crate::plan::ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
            supervisor_restart: None,
            memory_cap: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn agent_child_review_requires_live_same_user_direct_non_agent_child() {
        let (child, parent) = reviewed_agent_family();
        assert!(AgentChildReview::from_records(&child, &parent).is_some());
        for invalid in [
            "agent_child",
            "ordinary_parent",
            "owner",
            "parent",
            "loop",
            "weak_birth",
            "other_boot",
            "impossible_birth",
            "missing_job",
            "unknown",
            "zombie",
            "disk_sleep",
        ] {
            let mut child = child.clone();
            let mut parent = parent.clone();
            match invalid {
                "agent_child" => child.cmd = "claude --continue".to_string(),
                "ordinary_parent" => parent.cmd = "bash".to_string(),
                "owner" => child.uid += 1,
                "parent" => child.ppid.0 += 1,
                "loop" => parent.ppid = child.pid,
                "weak_birth" => child.start_id = pt_common::StartId::from_linux("unknown", 20, 71),
                "other_boot" => {
                    parent.start_id = pt_common::StartId::from_linux(
                        "aaaaaaaa-1234-4321-8765-123456789abc",
                        10,
                        70,
                    )
                }
                "impossible_birth" => {
                    parent.start_id = pt_common::StartId::from_linux(
                        "12345678-1234-4321-8765-123456789abc",
                        30,
                        70,
                    )
                }
                "missing_job" => child.pgid = None,
                "unknown" => parent.state = ProcessState::Unknown,
                "zombie" => parent.state = ProcessState::Zombie,
                "disk_sleep" => child.state = ProcessState::DiskSleep,
                _ => unreachable!(),
            }
            assert!(
                AgentChildReview::from_records(&child, &parent).is_none(),
                "{invalid}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confirmed_agent_child_consent_cannot_move_to_another_action_or_route() {
        let (child, parent) = reviewed_agent_family();
        let review = AgentChildReview::from_records(&child, &parent).unwrap();
        let action = reviewed_child_action(&review);
        let consent = review.confirm_kill(&action).unwrap();
        assert!(consent.matches_action(&action));
        for changed in [
            "id",
            "sibling",
            "parent",
            "birth",
            "owner",
            "group",
            "session",
            "quality",
            "kind",
            "blocked",
            "zombie_route",
            "supervisor_route",
            "original_zombie",
            "timeout",
            "prechecks",
            "order",
        ] {
            let mut action = action.clone();
            match changed {
                "id" => action.action_id.push_str("-new"),
                "sibling" => action.target.pid.0 += 1,
                "parent" => action.target.pid = parent.pid,
                "birth" => action.target.start_id = parent.start_id.clone(),
                "owner" => action.target.uid += 1,
                "group" => action.target.pgid = Some(99),
                "session" => action.target.sid = Some(99),
                "quality" => action.target.quality = pt_common::IdentityQuality::PidOnly,
                "kind" => action.action = Action::Pause,
                "blocked" => action.blocked = true,
                "zombie_route" => action.routing = crate::plan::ActionRouting::ZombieToParent,
                "supervisor_route" => action.routing = crate::plan::ActionRouting::Supervisor,
                "original_zombie" => action.original_zombie_target = Some(action.target.clone()),
                "timeout" => action.timeouts.execute_ms += 1,
                "prechecks" => action.pre_checks.clear(),
                "order" => action.order += 1,
                _ => unreachable!(),
            }
            assert!(
                !consent.matches_action(&action),
                "reused consent after {changed}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confirmed_agent_child_revalidates_both_original_processes_and_relationship() {
        let (child, parent) = reviewed_agent_family();
        let review = AgentChildReview::from_records(&child, &parent).unwrap();
        let action = reviewed_child_action(&review);
        let consent = review.confirm_kill(&action).unwrap();
        let original = vec![child, parent];
        assert!(consent.validate_population(&action, &original).is_ok());
        let mut scheduled = original.clone();
        scheduled[0].state = ProcessState::Running;
        scheduled[0].cpu_percent = 75.0;
        scheduled[1].elapsed += Duration::from_secs(2);
        assert!(consent.validate_population(&action, &scheduled).is_ok());
        for index in 0..2 {
            for changed in [
                "birth",
                "parent",
                "owner",
                "group",
                "session",
                "comm",
                "command",
                "tty",
                "zombie",
                "unknown",
                "missing",
                "duplicate",
            ] {
                let mut population = original.clone();
                let process = &mut population[index];
                match changed {
                    "birth" => {
                        process.start_id = pt_common::StartId::from_linux(
                            "12345678-1234-4321-8765-123456789abc",
                            100,
                            process.pid.0,
                        )
                    }
                    "parent" => process.ppid.0 += 1,
                    "owner" => process.uid += 1,
                    "group" => process.pgid = Some(99),
                    "session" => process.sid = Some(99),
                    "comm" => process.comm.push_str("-changed"),
                    "command" => process.cmd.push_str(" --changed"),
                    "tty" => process.tty = Some("pts/99".to_string()),
                    "zombie" => process.state = ProcessState::Zombie,
                    "unknown" => process.state = ProcessState::Unknown,
                    "missing" => {
                        population.remove(index);
                    }
                    "duplicate" => population.push(original[index].clone()),
                    _ => unreachable!(),
                }
                assert!(
                    consent.validate_population(&action, &population).is_err(),
                    "accepted changed reviewed process {index}: {changed}"
                );
            }
        }
    }

    #[test]
    fn parent_supervision_requires_complete_stable_child_and_parent_observations() {
        use crate::collect::proc_parsers::ProcessStat;
        let child = ProcessStat {
            pid: 42,
            ppid: 7,
            comm: "worker".to_string(),
            starttime: 20,
            ..ProcessStat::default()
        };
        let parent = ProcessStat {
            pid: 7,
            ppid: 1,
            comm: "supervisord".to_string(),
            starttime: 10,
            ..ProcessStat::default()
        };
        let complete = [child.clone(), parent.clone(), parent.clone(), child.clone()];
        let read = |observations: Vec<Result<ProcessStat, String>>| {
            let mut observations = observations.into_iter();
            let mut expected = [42, 7, 7, 42].into_iter();
            parent_comm_from_observations(42, |pid| {
                assert_eq!(Some(pid), expected.next());
                observations.next().expect("bounded parent observation")
            })
        };
        assert_eq!(
            read(complete.iter().cloned().map(Ok).collect()).unwrap(),
            Some("supervisord".to_string())
        );
        // Loss of any one required observation must not turn into "unsupervised".
        for missing in 0..complete.len() {
            let mut observations: Vec<_> = complete.iter().cloned().map(Ok).collect();
            observations[missing] = Err(format!("unreadable observation {missing}"));
            assert_eq!(
                read(observations).unwrap_err(),
                format!("unreadable observation {missing}")
            );
        }
        for changed in [
            "parent_birth",
            "child_birth",
            "parent_command",
            "child_command",
            "child_parent",
            "wrong_parent_pid",
            "empty_parent_name",
        ] {
            let mut observations = complete.clone();
            match changed {
                "parent_birth" => observations[2].starttime += 1,
                "child_birth" => observations[3].starttime += 1,
                "parent_command" => observations[2].comm = "replacement".to_string(),
                "child_command" => observations[3].comm = "replacement".to_string(),
                "child_parent" => observations[3].ppid = 8,
                "wrong_parent_pid" => observations[2].pid = 8,
                "empty_parent_name" => observations[1].comm.clear(),
                _ => unreachable!(),
            }
            assert!(
                read(observations.into_iter().map(Ok).collect()).is_err(),
                "accepted changed supervision evidence: {changed}"
            );
        }
        let mut parentless = child.clone();
        parentless.ppid = 0;
        assert_eq!(
            parent_comm_from_observations(42, |_| Ok(parentless.clone())).unwrap(),
            None
        );
        let mut reads = 0;
        assert!(parent_comm_from_observations(42, |_| {
            reads += 1;
            Ok(if reads == 1 {
                parentless.clone()
            } else {
                child.clone()
            })
        })
        .is_err());
        let mut self_parent = child;
        self_parent.ppid = self_parent.pid;
        assert!(parent_comm_from_observations(42, |_| Ok(self_parent.clone())).is_err());
    }

    #[test]
    fn process_state_characters_preserve_viability_policy() {
        for (raw, expected, viable) in [
            ('R', ProcessState::Running, true),
            ('S', ProcessState::Sleeping, true),
            ('D', ProcessState::DiskSleep, false),
            ('Z', ProcessState::Zombie, false),
            ('T', ProcessState::Stopped, true),
            ('t', ProcessState::Stopped, true),
            ('I', ProcessState::Idle, true),
            ('X', ProcessState::Dead, false),
            ('x', ProcessState::Dead, false),
        ] {
            let state = ProcessState::from_char(raw);
            assert_eq!(state, expected);
            assert_eq!(
                process_state_precheck(Ok(Some(state)), None).is_passed(),
                viable,
                "unexpected viability for state {raw}"
            );
        }
        for unknown in ['?', '\0', 'Q'] {
            assert!(matches!(
                process_state_precheck(Ok(Some(ProcessState::from_char(unknown))), None),
                PreCheckResult::Blocked { check: PreCheck::VerifyProcessState, reason }
                    if reason.contains("unknown process state")
            ));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_process_exit_probe_never_uses_process_group_ids() {
        assert!(process_is_absent(0).is_err());
        assert!(process_is_absent(u32::MAX).unwrap());
        assert!(!process_is_absent(std::process::id()).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_native_parent_and_state_checks_preserve_idle_and_exited_targets() {
        let provider = LivePreCheckProvider::with_defaults();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn owned idle target");
        let pid = child.id();
        let parent = provider.get_ppid_comm(pid);
        let state = provider.read_process_state(pid);
        let expected_parent = read_precheck_stat(std::process::id()).map(|stat| stat.comm);
        // Reap the owned process before assertions so a failure cannot leak it.
        let _ = child.kill();
        child.wait().expect("reap owned target");
        assert_eq!(parent.unwrap(), Some(expected_parent.unwrap()));
        assert!(state.unwrap().expect("live process state").is_active());
        assert_eq!(provider.read_process_state(pid).unwrap(), None);
        assert!(provider.check_process_state(pid).is_passed());
        assert!(matches!(
            provider.check_supervisor(pid),
            PreCheckResult::Blocked { check: PreCheck::CheckSupervisor, reason }
                if reason.contains("supervisor evidence unavailable")
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_io_windows_never_accept_missing_reset_or_reused_observations() {
        let start = Instant::now();
        let window = Duration::from_secs(10);
        let sample = |at, birth_ticks, logical, physical| IoSample {
            birth_ticks,
            wchar: logical,
            write_bytes: physical,
            started_at: at,
            finished_at: at,
        };
        let before = sample(start, 100, 4096, 8192);
        let after = sample(start + window, 100, 4096, 8192);
        let observation = |after| RecentIoObservation {
            before: Ok(before.clone()),
            after,
            window,
        };
        let idle = observation(Ok(after.clone()));
        assert_eq!(idle.evidence(), RecentIoEvidence::Idle);
        assert_eq!(
            observation(Ok(sample(start + window, 100, 8192, 8192))).evidence(),
            RecentIoEvidence::Active
        );
        assert_eq!(
            observation(Ok(sample(start + window, 100, 4096, 16384))).evidence(),
            RecentIoEvidence::Active
        );
        for invalid in [
            Err("native I/O API unavailable".to_string()),
            Ok(sample(start + window, 101, 4096, 8192)),
            Ok(sample(start + window, 100, 0, 8192)),
            Ok(sample(start + window, 100, 4096, 0)),
            Ok(sample(start, 100, 4096, 8192)),
        ] {
            assert!(matches!(
                observation(invalid).evidence(),
                RecentIoEvidence::Unknown(_)
            ));
        }
        assert!(matches!(
            idle.revalidate(Err("permission lost".to_string())),
            RecentIoEvidence::Unknown(reason) if reason.contains("permission lost")
        ));
        assert_eq!(
            idle.revalidate(Ok(sample(start + window * 2, 100, 8192, 8192))),
            RecentIoEvidence::Active
        );
        assert!(matches!(
            idle.revalidate(Ok(sample(start + window * 2, 101, 4096, 8192))),
            RecentIoEvidence::Unknown(reason) if reason.contains("birth changed")
        ));
    }

    #[test]
    fn expired_prechecks_do_not_probe_and_unbudgeted_checks_still_run() {
        let observed = std::cell::Cell::new(false);
        let result =
            precheck_with_deadline(Some(Instant::now()), PreCheck::CheckDataLossGate, || {
                observed.set(true);
                PreCheckResult::Passed
            });
        assert!(!observed.get(), "expired admission must not start a probe");
        assert!(matches!(
            result,
            PreCheckResult::Blocked { check: PreCheck::CheckDataLossGate, reason }
                if reason.contains("operation deadline")
        ));
        assert!(
            precheck_with_deadline(None, PreCheck::CheckDataLossGate, || {
                observed.set(true);
                PreCheckResult::Passed
            })
            .is_passed()
        );
        assert!(
            observed.get(),
            "unbudgeted callers keep normal observations"
        );
    }

    #[test]
    fn late_prechecks_preserve_observed_refusals_but_cannot_authorize_action() {
        for passed in [false, true] {
            let deadline = Instant::now() + Duration::from_secs(1);
            let result =
                precheck_with_deadline(Some(deadline), PreCheck::VerifyProcessState, || {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                    if passed {
                        PreCheckResult::Passed
                    } else {
                        PreCheckResult::Blocked {
                            check: PreCheck::VerifyProcessState,
                            reason: "target disappeared during observation".to_string(),
                        }
                    }
                });
            match result {
                PreCheckResult::Blocked { reason, .. } if passed => {
                    assert!(reason.contains("operation deadline"));
                }
                PreCheckResult::Blocked { reason, .. } => {
                    assert_eq!(reason, "target disappeared during observation");
                }
                PreCheckResult::Passed => panic!("expired observation permitted admission"),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn insufficient_operation_budget_keeps_native_recent_io_unknown_without_waiting() {
        let make_provider = || {
            LivePreCheckProvider::new(
                None,
                LivePreCheckConfig {
                    block_if_open_write_fds: false,
                    block_if_locked_files: false,
                    block_if_active_tty: false,
                    block_if_deleted_cwd: false,
                    block_if_recent_io_seconds: 60,
                    enhanced_session_safety: false,
                    ..LivePreCheckConfig::default()
                },
            )
            .expect("I/O-only provider")
        };
        let pid = std::process::id();
        let window = Duration::from_secs(60);
        let provider = make_provider().with_deadline(Some(Instant::now() + Duration::from_secs(5)));
        let started = Instant::now();
        provider.prime_recent_io(&[pid]);
        assert!(started.elapsed() < Duration::from_secs(2));
        let cache = provider.recent_io.lock().unwrap();
        let observation = cache.get(&pid).expect("cache the unavailable full window");
        assert_eq!(observation.window, window);
        assert!(matches!(
            observation.evidence(),
            RecentIoEvidence::Unknown(reason)
                if reason.contains("complete 60s") && reason.contains("not shortened")
        ));
        drop(cache);
        assert!(matches!(
            provider.check_data_loss(pid),
            PreCheckResult::Blocked { check: PreCheck::CheckDataLossGate, reason }
                if reason.contains("complete 60s")
        ));

        let unprimed = make_provider().with_deadline(Some(Instant::now() + Duration::from_secs(5)));
        assert!(matches!(
            unprimed.has_recent_io(pid, window),
            RecentIoEvidence::Unknown(reason) if reason.contains("complete 60s")
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(make_provider().operation_deadline(), None);
    }

    #[test]
    fn protection_metadata_requires_each_complete_observation() {
        let observed = ["sleep", "sleep 60", "worker"];
        let protected_users = HashSet::from(["administrator".to_string()]);
        for (missing, field) in [
            (0, "process name"),
            (1, "command line"),
            (2, "process owner"),
        ] {
            for unavailable in [None, Some(String::new()), Some(" \n".to_string())] {
                let mut values = observed.map(|value| Some(value.to_string()));
                values[missing] = unavailable;
                let [comm, cmdline, user] = values;
                let owner = user.map(|name| ProtectionOwner {
                    uid: 1000,
                    name: Some(name),
                });
                let result =
                    required_protection_metadata(42, comm, cmdline, owner, &protected_users, false);
                assert!(matches!(
                    result,
                    Err(PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason })
                        if reason.contains("PID 42") && reason.contains(field)
                            && reason.contains("protection evidence unavailable")
                ));
            }
        }
        assert_eq!(
            required_protection_metadata(
                42,
                Some("ssh".to_string()),
                Some("ssh -M -N host".to_string()),
                Some(ProtectionOwner {
                    uid: 1000,
                    name: Some("worker".to_string()),
                }),
                &protected_users,
                false,
            )
            .unwrap(),
            (
                "ssh".to_string(),
                "ssh -M -N host".to_string(),
                "worker".to_string()
            )
        );
    }

    #[test]
    fn numeric_owner_protection_survives_resolved_and_unavailable_names() {
        for name in [None, Some("alice"), Some("1000"), Some(""), Some(" \n")] {
            for users in [&["1000"][..], &["01000"][..], &["alice", "1000"][..]] {
                let protected_users = users.iter().map(|user| user.to_string()).collect();
                let result = required_protection_metadata(
                    42,
                    Some("sleep".to_string()),
                    Some("sleep 60".to_string()),
                    Some(ProtectionOwner {
                        uid: 1000,
                        name: name.map(str::to_string),
                    }),
                    &protected_users,
                    true,
                );
                assert!(matches!(
                    result,
                    Err(PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason })
                        if reason == "owned by protected user UID: 1000"
                ));
            }
        }
    }

    #[test]
    fn unresolved_owner_names_never_bypass_named_rules_or_macos_placement() {
        let metadata = |name: Option<&str>, users: &[&str], require_name: bool| {
            let protected_users = users.iter().map(|user| user.to_string()).collect();
            required_protection_metadata(
                42,
                Some("sleep".to_string()),
                Some("sleep 60".to_string()),
                Some(ProtectionOwner {
                    uid: 1000,
                    name: name.map(str::to_string),
                }),
                &protected_users,
                require_name,
            )
        };
        for name in [None, Some(""), Some(" \n")] {
            for users in [&["alice"][..], &["root"][..], &["alice", "2000"][..]] {
                assert!(matches!(
                    metadata(name, users, false),
                    Err(PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason })
                        if reason.contains("PID 42") && reason.contains("process owner name")
                            && reason.contains("protection evidence unavailable")
                ));
            }
            // Numeric ownership is sufficient only if no name-based rule or
            // platform placement requires a resolved account name.
            for users in [&[][..], &["2000"][..]] {
                assert_eq!(metadata(name, users, false).unwrap().2, "1000");
                assert!(matches!(
                    metadata(name, users, true),
                    Err(PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason })
                        if reason.contains("process owner name")
                ));
            }
        }
        assert_eq!(
            metadata(Some("worker"), &["alice"], true).unwrap().2,
            "worker"
        );
        assert!(matches!(
            required_protection_metadata(
                42,
                Some("sleep".to_string()),
                Some("sleep 60".to_string()),
                None,
                &HashSet::new(),
                false,
            ),
            Err(PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason })
                if reason.contains("process owner")
        ));
    }

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
            Action::CapMemory,
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
        assert!(
            proc_locks_mentions_target(content, |pid| pid == 12345).unwrap(),
            "holder"
        );
        assert!(
            proc_locks_mentions_target(content, |pid| pid == 12346).unwrap(),
            "blocked waiter"
        );
        assert!(
            proc_locks_mentions_target(content, |pid| pid == 777).unwrap(),
            "flock holder"
        );
        assert!(
            !proc_locks_mentions_target(content, |pid| pid == 1).unwrap(),
            "lock index is not a pid"
        );
        assert!(
            !proc_locks_mentions_target(content, |pid| pid == 99).unwrap(),
            "inode is not a pid"
        );
        assert!(!proc_locks_mentions_target("", |pid| pid == 12345).unwrap());
        assert!(proc_locks_mentions_target(content, |pid| [12345, 12346].contains(&pid)).unwrap());
        assert!(!proc_locks_mentions_target(content, |pid| [42, 43].contains(&pid)).unwrap());
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
            assert!(
                proc_locks_mentions_target(content, |pid| pid == 42).is_err(),
                "{content}"
            );
        }
        let leases = "1: LEASE ACTIVE READ 42 08:02:1234 0 EOF\n\
                      2: LEASE BREAKING UNLCK 43 08:02:1235 0 EOF\n\
                      3: DELEG BREAKER READ 44 <none>:0 0 EOF\n";
        for pid in [42, 43, 44] {
            assert_eq!(
                proc_locks_mentions_target(leases, |owner| owner == pid),
                Ok(true)
            );
        }
        assert_eq!(
            proc_locks_mentions_target(leases, |pid| pid == 45),
            Ok(false)
        );
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
    fn descriptor_safety_requires_full_identity_before_and_after_collection() {
        use pt_common::{IdentityQuality, ProcessIdentity, StartId};

        let target = ProcessIdentity::new(42, StartId::from_linux("boot", 100, 42), 1000);
        for quality in [IdentityQuality::NoBootId, IdentityQuality::PidOnly] {
            let mut weak = target.clone();
            weak.quality = quality;
            assert!(descriptor_safety_for_identity(
                &weak,
                || panic!("weak identities cannot begin inspection"),
                || panic!("weak identities cannot collect descriptor evidence"),
            )
            .unwrap_err()
            .contains("complete process identity"));
        }
        assert!(descriptor_safety_for_identity(
            &target,
            || Ok(false),
            || panic!("stale identities cannot collect descriptor evidence"),
        )
        .unwrap_err()
        .contains("before descriptor"));

        let mut validations = 0;
        let changed = descriptor_safety_for_identity(
            &target,
            || {
                validations += 1;
                Ok(validations == 1)
            },
            || Ok(DescriptorSafetyEvidence::default()),
        );
        assert_eq!(validations, 2);
        assert!(changed.unwrap_err().contains("during descriptor"));
        let unavailable = descriptor_safety_for_identity(
            &target,
            || Ok(true),
            || Err("partial descriptor census".to_string()),
        );
        assert_eq!(unavailable.unwrap_err(), "partial descriptor census");

        let mut validations = 0;
        let observed = descriptor_safety_for_identity(
            &target,
            || {
                validations += 1;
                Ok(true)
            },
            || {
                Ok(DescriptorSafetyEvidence {
                    open_write_fds: 2,
                    critical_writes: vec![crate::collect::proc_parsers::detect_critical_file(
                        3,
                        "/work/.git/index.lock",
                    )
                    .unwrap()],
                })
            },
        )
        .unwrap();
        assert_eq!(validations, 2);
        assert_eq!(observed.open_write_fds, 2);
        assert_eq!(observed.critical_writes[0].rule_id, "git_lock_file");
    }

    #[test]
    fn lsof_critical_files_require_regular_writers_and_complete_evidence() {
        let content = concat!(
            "p42\0\n",
            "f3\0aw\0tREG\0n/work/\nproject/.git/index.lock\0\n",
            "f4\0ar\0tREG\0n/work/state.sqlite-wal\0\n",
            "f5\0au\0tFIFO\0n/work/.git/index.lock\0\n",
            "f6\0au\0tREG\0n/work/state.sqlite\0\n",
            "f7\0aw\0tCHR\0n/dev/transaction-wal\0\n",
        );
        let observed = lsof_descriptor_safety_evidence(42, Ok(lsof_output(content))).unwrap();
        assert_eq!(observed.open_write_fds, 2);
        assert_eq!(observed.critical_writes.len(), 2);
        assert_eq!(observed.critical_writes[0].fd, 3);
        assert_eq!(observed.critical_writes[0].rule_id, "git_lock_file");
        assert_eq!(
            observed.critical_writes[0].strength,
            crate::collect::DetectionStrength::Hard
        );
        assert_eq!(observed.critical_writes[1].rule_id, "database_file");
        assert_eq!(
            observed.critical_writes[1].strength,
            crate::collect::DetectionStrength::Soft
        );
        let partial = format!("{content}f8\0aw\0tREG\0n/work/incomplete");
        assert!(lsof_descriptor_safety_evidence(42, Ok(lsof_output(&partial))).is_err());
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
        assert!(matches!(
            disabled.check_data_loss(u32::MAX),
            PreCheckResult::Blocked { check: PreCheck::CheckDataLossGate, reason }
                if reason.contains("complete data-loss evidence")
        ));
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

    #[cfg(target_os = "linux")]
    fn write_fd_test_observation(target: &str, flags: i32) -> WriteFdObservation {
        WriteFdObservation {
            target: target.into(),
            flags: flags as u32,
            inode: 42,
            mount_id: 7,
            has_lock: false,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_identity_requires_complete_unique_kernel_fields() {
        let valid = "pos:\t0\nflags:\t0100002\nmnt_id:\t7\nino:\t42\n";
        assert_eq!(write_fd_flags_and_identity(valid), Some((0o100002, 42, 7)));
        for invalid in [
            "flags:\t0100002\nmnt_id:\t7\n",
            "flags:\t0100002\nino:\t42\n",
            "mnt_id:\t7\nino:\t42\n",
            "flags:\t0100002\nmnt_id:\t7\nino:\t42",
            "flags:\t+2\nmnt_id:\t7\nino:\t42\n",
            "flags:\t0100002\nmnt_id:\t+7\nino:\t42\n",
            "flags:\t0100002\nmnt_id:\t7\nino:\t+42\n",
            "flags:\t0100003\nmnt_id:\t7\nino:\t42\n",
            "flags:\t0100002\nflags:\t0\nmnt_id:\t7\nino:\t42\n",
            "flags:\t0100002\nmnt_id:\t7\nmnt_id:\t8\nino:\t42\n",
            "flags:\t0100002\nmnt_id:\t7\nino:\t42\nino:\t43\n",
        ] {
            assert_eq!(write_fd_flags_and_identity(invalid), None, "{invalid:?}");
        }
    }

    #[cfg(target_os = "linux")]
    fn write_fd_fixture_task(process_dir: &std::path::Path, tid: u32, birth: u64) {
        let task = process_dir.join("task").join(tid.to_string());
        std::fs::create_dir_all(task.join("fd")).unwrap();
        std::fs::create_dir_all(task.join("fdinfo")).unwrap();
        let mut stat = vec!["0".to_string(); 22];
        stat[0] = "S".to_string();
        stat[1] = "1".to_string();
        stat[17] = "2".to_string();
        stat[19] = birth.to_string();
        std::fs::write(
            task.join("stat"),
            format!("{tid} (worker) {}\n", stat.join(" ")),
        )
        .unwrap();
        std::os::unix::fs::symlink("/data/pending", task.join("fd/3")).unwrap();
        std::fs::write(
            task.join("fdinfo/3"),
            "pos:\t0\nflags:\t0100001\nmnt_id:\t7\nino:\t42\n",
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_snapshot_covers_every_task_without_assuming_shared_tables() {
        let process = tempfile::tempdir().unwrap().keep();
        write_fd_fixture_task(&process, 42, 100);
        write_fd_fixture_task(&process, 43, 101);
        let snapshot =
            write_fd_snapshot_from(&process, 42, Instant::now() + Duration::from_secs(5), 2, 2)
                .unwrap();
        assert_eq!(snapshot.tasks.len(), 2);
        assert_eq!(snapshot.descriptors.len(), 2);
        // Matching inode, flags and fd number cannot prove shared tables. Each
        // task reference survives so a configured positive allowance is safe.
        for tid in [42, 43] {
            let path = process.join(format!("task/{tid}/fd/3"));
            assert!(snapshot.descriptors[path.to_str().unwrap()].writable());
        }
        write_fd_fixture_task(&process, 44, 102);
        let changed =
            write_fd_snapshot_from(&process, 42, Instant::now() + Duration::from_secs(5), 3, 3)
                .unwrap();
        assert_ne!(
            snapshot, changed,
            "task creation must invalidate the snapshot"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_snapshot_refuses_partial_tasks_invalid_evidence_and_global_limits() {
        for failure in [
            "missing_leader",
            "unreadable_task",
            "unreadable_fdinfo",
            "malformed_fdinfo",
            "oversized_fdinfo",
            "wrong_task_identity",
            "oversized_stat",
            "task_limit",
            "descriptor_limit",
            "deadline",
        ] {
            let process = tempfile::tempdir().unwrap().keep();
            write_fd_fixture_task(&process, 42, 100);
            write_fd_fixture_task(&process, 43, 101);
            let mut pid = 42;
            let mut max_tasks = 2;
            let mut max_descriptors = 2;
            let mut deadline = Instant::now() + Duration::from_secs(5);
            match failure {
                "missing_leader" => pid = 41,
                "unreadable_task" => {
                    std::fs::create_dir(process.join("task/44")).unwrap();
                    max_tasks = 3;
                }
                "unreadable_fdinfo" => {
                    std::os::unix::fs::symlink("/data/other", process.join("task/43/fd/4"))
                        .unwrap();
                    max_descriptors = 3;
                }
                "malformed_fdinfo" => {
                    std::fs::write(process.join("task/43/fdinfo/3"), "flags:\t1\n").unwrap();
                }
                "oversized_fdinfo" => {
                    std::fs::write(
                        process.join("task/43/fdinfo/3"),
                        format!(
                            "pos:\t0\nflags:\t0100000\nmnt_id:\t7\nino:\t42\n{}\n",
                            "x".repeat(64 * 1024)
                        ),
                    )
                    .unwrap();
                }
                "wrong_task_identity" => {
                    let leader = std::fs::read(process.join("task/42/stat")).unwrap();
                    std::fs::write(process.join("task/43/stat"), leader).unwrap();
                }
                "oversized_stat" => {
                    std::fs::write(process.join("task/43/stat"), "x".repeat(16 * 1024 + 1))
                        .unwrap();
                }
                "task_limit" => max_tasks = 1,
                "descriptor_limit" => max_descriptors = 1,
                "deadline" => deadline = Instant::now(),
                _ => unreachable!(),
            }
            assert!(
                write_fd_snapshot_from(&process, pid, deadline, max_tasks, max_descriptors)
                    .is_none(),
                "{failure} must not produce complete descriptor evidence"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_metadata_keeps_worker_critical_files_and_rejects_partial_census() {
        let ordinary = write_fd_test_observation("/work/output.log", libc::O_WRONLY);
        let mut critical = write_fd_test_observation("/work/.git/index.lock", libc::O_RDWR);
        critical.inode = 43;
        let requested = std::collections::BTreeMap::from([
            ("/proc/42/task/42/fd/3".to_string(), &ordinary),
            ("/proc/42/task/43/fd/3".to_string(), &critical),
        ]);
        let complete = "/proc/42/task/42/fd/3 81a4 1 42\n/proc/42/task/43/fd/3 81a4 1 43\n";
        let observed = descriptor_safety_from_metadata(&requested, &lsof_output(complete)).unwrap();
        assert_eq!(observed.open_write_fds, 2);
        assert_eq!(observed.critical_writes.len(), 1);
        assert_eq!(observed.critical_writes[0].fd, 3);
        assert_eq!(observed.critical_writes[0].path, "/work/.git/index.lock");
        assert_eq!(observed.critical_writes[0].rule_id, "git_lock_file");
        for partial in [
            "/proc/42/task/42/fd/3 81a4 1 42\n",
            "/proc/42/task/43/fd/3 81a4 1 43\n",
            "/proc/42/task/42/fd/3 81a4 1 42\n/proc/42/task/43/fd/3 81a4 1 44\n",
        ] {
            assert!(descriptor_safety_from_metadata(&requested, &lsof_output(partial)).is_none());
        }
        for mode in [libc::S_IFIFO, libc::S_IFSOCK, libc::S_IFCHR] {
            let output =
                format!("/proc/42/task/42/fd/3 81a4 1 42\n/proc/42/task/43/fd/3 {mode:x} 1 43\n");
            let observed =
                descriptor_safety_from_metadata(&requested, &lsof_output(&output)).unwrap();
            assert_eq!(observed.open_write_fds, 1);
            assert!(observed.critical_writes.is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_metadata_uses_kernel_type_and_links_instead_of_path_prefixes() {
        for target in [
            "/data/projects/app/db.sqlite",
            "/run/user/1000/work-in-progress.log",
            "/dev/shm/pending.data",
            "/dev/regular-data-file",
            "/proc/bind-mounted-file",
            "/sys/bind-mounted-file",
            "/memfd:ordinary-file",
            "/data/app/a.log (deleted)",
        ] {
            let observation = write_fd_test_observation(target, libc::O_WRONLY);
            let requested =
                std::collections::BTreeMap::from([("/proc/123/fd/3".to_string(), &observation)]);
            assert_eq!(
                count_write_fd_metadata(&requested, &lsof_output("/proc/123/fd/3 81a4 1 42\n")),
                Some(1),
                "linked regular file {target} must be protected"
            );
            // The same pathname never turns a FIFO, socket or character device
            // into a persistent regular file.
            for mode in [libc::S_IFIFO, libc::S_IFSOCK, libc::S_IFCHR] {
                let row = format!("/proc/123/fd/3 {mode:x} 1 42\n");
                assert_eq!(
                    count_write_fd_metadata(&requested, &lsof_output(&row)),
                    Some(0)
                );
            }
        }
        let anonymous = write_fd_test_observation("anon_inode:[eventfd]", libc::O_RDWR);
        let requested =
            std::collections::BTreeMap::from([("/proc/123/fd/3".to_string(), &anonymous)]);
        assert_eq!(
            count_write_fd_metadata(&requested, &lsof_output("/proc/123/fd/3 180 1 42\n")),
            Some(0)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_metadata_keeps_linkable_temporary_files_protected() {
        for target in [
            "/tmp/old.log (deleted)",
            "/dev/shm/.org.chromium.Chromium.XyZ123 (deleted)",
            "/memfd:wayland-cursor (deleted)",
            "/tmp/#5242881 (deleted)",
        ] {
            for temporary in [false, true] {
                let observation = write_fd_test_observation(
                    target,
                    libc::O_RDWR | if temporary { libc::O_TMPFILE } else { 0 },
                );
                let requested = std::collections::BTreeMap::from([(
                    "/proc/123/fd/3".to_string(),
                    &observation,
                )]);
                assert_eq!(
                    count_write_fd_metadata(&requested, &lsof_output("/proc/123/fd/3 81a4 0 42\n")),
                    Some(u32::from(temporary)),
                    "{target}: O_TMPFILE={temporary}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fd_metadata_refuses_partial_malformed_and_changed_evidence() {
        let observation = write_fd_test_observation("/tmp/data", libc::O_WRONLY);
        let requested =
            std::collections::BTreeMap::from([("/proc/123/fd/3".to_string(), &observation)]);
        let valid = "/proc/123/fd/3 81a4 1 42\n";
        assert_eq!(
            count_write_fd_metadata(&requested, &lsof_output(valid)),
            Some(1)
        );
        for content in [
            "",
            "/proc/123/fd/3 81a4 1 42",
            "/proc/123/fd/3 81a4 1\n",
            "/proc/123/fd/3 81a4 1 42 extra\n",
            "/proc/123/fd/3 81a4 1 43\n",
            "/proc/123/fd/4 81a4 1 42\n",
            "/proc/123/fd/3 ffff 1 42\n",
            "/proc/123/fd/3 181a4 1 42\n",
            "/proc/123/fd/3 180 1 42\n",
            "/proc/123/fd/3 a1ff 1 42\n",
            "/proc/123/fd/3 81a4 +1 42\n",
            "/proc/123/fd/3 81a4 1 +42\n",
            "/proc/123/fd/3 81a4 1 42\n/proc/123/fd/3 81a4 1 42\n",
        ] {
            assert_eq!(
                count_write_fd_metadata(&requested, &lsof_output(content)),
                None,
                "{content:?}"
            );
        }
        for failure in [
            "nonzero",
            "signal",
            "timeout",
            "truncated",
            "stderr",
            "utf8",
        ] {
            let mut output = lsof_output(valid);
            match failure {
                "nonzero" => output.exit_code = Some(1),
                "signal" => output.exit_code = None,
                "timeout" => output.timed_out = true,
                "truncated" => output.truncated = true,
                "stderr" => output.stderr = b"stat: cannot read descriptor".to_vec(),
                "utf8" => output.stdout.push(0xff),
                _ => unreachable!(),
            }
            assert_eq!(
                count_write_fd_metadata(&requested, &output),
                None,
                "{failure}"
            );
        }
        let missing = std::collections::BTreeMap::from([
            ("/proc/123/fd/3".to_string(), &observation),
            ("/proc/123/fd/4".to_string(), &observation),
        ]);
        assert_eq!(count_write_fd_metadata(&missing, &lsof_output(valid)), None);
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

    #[test]
    fn process_state_gate_refuses_unavailable_unknown_and_dead_evidence() {
        for (observation, expected) in [
            (Err("permission denied".to_string()), "permission denied"),
            (Ok(Some(ProcessState::Unknown)), "unknown process state"),
            (Ok(Some(ProcessState::Dead)), "already dead"),
            (Ok(Some(ProcessState::Zombie)), "parent process must reap"),
            (Ok(Some(ProcessState::DiskSleep)), "uninterruptible sleep"),
        ] {
            assert!(matches!(
                process_state_precheck(observation, Some("io_schedule")),
                PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::VerifyProcessState && reason.contains(expected)
            ));
        }
        assert!(matches!(
            process_state_precheck(Ok(Some(ProcessState::DiskSleep)), Some("io_schedule")),
            PreCheckResult::Blocked { reason, .. } if reason.contains("io_schedule")
        ));
    }

    #[test]
    fn process_state_gate_preserves_known_live_and_confirmed_exit_paths() {
        for state in [
            ProcessState::Running,
            ProcessState::Sleeping,
            ProcessState::Stopped,
            ProcessState::Idle,
        ] {
            assert!(process_state_precheck(Ok(Some(state)), None).is_passed());
        }
        assert!(process_state_precheck(Ok(None), None).is_passed());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn enabled_recent_io_gate_refuses_unsupported_and_unknown_observations() {
        let window = Duration::from_secs(60);
        for evidence in [
            RecentIoEvidence::Unknown(
                "native I/O API does not support this observation".to_string(),
            ),
            RecentIoEvidence::Unknown("permission denied".to_string()),
        ] {
            assert!(matches!(
                recent_io_precheck(evidence, window),
                PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::CheckDataLossGate
                        && reason.contains("recent I/O evidence unavailable")
            ));
        }
        assert!(recent_io_precheck(RecentIoEvidence::Idle, window).is_passed());
        assert!(matches!(
            recent_io_precheck(RecentIoEvidence::Active, window),
            PreCheckResult::Blocked { reason, .. } if reason.contains("60s window")
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn disabled_recent_io_gate_still_requires_mandatory_file_evidence() {
        let provider = LivePreCheckProvider::new(
            None,
            LivePreCheckConfig {
                block_if_open_write_fds: false,
                block_if_locked_files: false,
                block_if_active_tty: false,
                block_if_deleted_cwd: false,
                block_if_recent_io_seconds: 0,
                ..LivePreCheckConfig::default()
            },
        )
        .unwrap();
        assert_eq!(provider.config.block_if_recent_io_seconds, 0);
        assert!(matches!(
            provider.check_data_loss(u32::MAX),
            PreCheckResult::Blocked { check: PreCheck::CheckDataLossGate, reason }
                if reason.contains("complete data-loss evidence")
        ));
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

        fn io_only_provider(seconds: u64) -> LivePreCheckProvider {
            let config = LivePreCheckConfig {
                block_if_open_write_fds: false,
                block_if_locked_files: false,
                block_if_active_tty: false,
                block_if_deleted_cwd: false,
                block_if_recent_io_seconds: seconds,
                enhanced_session_safety: false,
                ..LivePreCheckConfig::default()
            };
            LivePreCheckProvider::new(None, config).expect("provider")
        }

        #[test]
        fn recent_io_gate_accepts_complete_native_idle_window_on_macos() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn owned idle target");
            let provider = io_only_provider(1);
            let began = Instant::now();
            provider.prime_recent_io(&[child.id()]);
            let elapsed = began.elapsed();
            let first = provider.check_data_loss(child.id());
            let cached = provider.check_data_loss(child.id());
            let _ = child.kill();
            child.wait().expect("reap owned idle target");
            assert!(elapsed >= Duration::from_secs(1));
            assert!(first.is_passed(), "{first:?}");
            assert!(cached.is_passed(), "{cached:?}");
            assert!(read_io_sample(child.id()).is_err());
        }

        #[test]
        fn recent_io_native_counters_detect_file_writes_on_macos() {
            use std::io::Write;

            let mut file = tempfile::tempfile().expect("create owned write target");
            let pid = std::process::id();
            let before = read_io_sample(pid).expect("read initial native I/O counters");
            for _ in 0..64 {
                file.write_all(&[0xa5; 16 * 1024])
                    .expect("write owned target");
            }
            file.sync_all().expect("flush owned write target");
            let window = Duration::from_millis(20);
            std::thread::sleep(window);
            let after = read_io_sample(pid).expect("read updated native I/O counters");
            assert!(
                after.wchar > before.wchar,
                "native logical writes did not account for a completed file write"
            );
            let observation = RecentIoObservation {
                before: Ok(before),
                after: Ok(after),
                window,
            };
            assert_eq!(observation.evidence(), RecentIoEvidence::Active);
        }

        #[test]
        fn recent_io_gate_blocks_missing_native_evidence_on_macos() {
            let provider = io_only_provider(1);
            provider.prime_recent_io(&[u32::MAX]);
            assert!(matches!(
                provider.check_data_loss(u32::MAX),
                PreCheckResult::Blocked { check: PreCheck::CheckDataLossGate, reason }
                    if reason.contains("recent I/O evidence unavailable")
                        && reason.contains("before sample")
                        && reason.contains("after sample")
            ));
            assert!(matches!(
                io_only_provider(0).check_data_loss(u32::MAX),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("complete data-loss evidence")
            ));
            assert!(read_io_sample(0).is_err());
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

        #[test]
        fn process_state_observation_refuses_hidden_live_and_invalid_proc_records() {
            let root = tempfile::tempdir().unwrap().keep();
            let pid = std::process::id();
            let path = root.join(pid.to_string()).join("stat");
            // ENOENT alone is ambiguous (for example, hidepid=2). A kernel
            // existence check must distinguish it from a confirmed exit.
            assert!(matches!(
                process_state_precheck(read_process_state_from_proc(pid, &root), None),
                PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::VerifyProcessState
                        && reason.contains("still-present process")
            ));
            assert_eq!(read_process_state_from_proc(u32::MAX, &root), Ok(None));

            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            assert!(read_process_state_from_proc(pid, &root).is_err());
            let fields = "1 42 42 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 123 0 0";
            std::fs::write(
                &path,
                format!("{pid} (fixture ) with parentheses) S {fields}"),
            )
            .unwrap();
            assert_eq!(
                read_process_state_from_proc(pid, &root),
                Ok(Some(ProcessState::Sleeping))
            );

            for content in [
                format!("{pid} (fixture) ? {fields}"),
                format!("{pid} (fixture) SS {fields}"),
                format!("{pid} (fixture) S 1"),
                format!("{} (fixture) S {fields}", pid + 1),
                "unparseable process state".to_string(),
            ] {
                std::fs::write(&path, content).unwrap();
                assert!(matches!(
                    process_state_precheck(read_process_state_from_proc(pid, &root), None),
                    PreCheckResult::Blocked { check, reason }
                        if check == PreCheck::VerifyProcessState
                            && reason.contains("process state evidence unavailable")
                ));
            }
            std::fs::write(&path, [0xff]).unwrap();
            assert!(read_process_state_from_proc(pid, &root).is_err());

            // A directory yields a real I/O error even for root, so this does
            // not depend on chmod succeeding against a privileged test runner.
            let unreadable = tempfile::tempdir().unwrap().keep();
            std::fs::create_dir_all(unreadable.join(pid.to_string()).join("stat")).unwrap();
            assert!(matches!(
                process_state_precheck(read_process_state_from_proc(pid, &unreadable), None),
                PreCheckResult::Blocked { check, reason }
                    if check == PreCheck::VerifyProcessState && reason.contains("cannot read")
            ));
        }

        #[test]
        fn process_state_observation_distinguishes_owned_live_process_and_exit() {
            use std::process::{Command, Stdio};

            let mut fixture = DescriptorChild {
                child: Command::new("sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
                reader: None,
            };
            let pid = fixture.child.id();
            let provider = LivePreCheckProvider::with_defaults();
            assert_eq!(process_is_absent(pid), Ok(false));
            let state = provider.read_process_state(pid).unwrap().unwrap();
            assert!(!matches!(
                state,
                ProcessState::Unknown | ProcessState::Dead | ProcessState::Zombie
            ));
            assert!(provider.check_process_state(pid).is_passed());

            fixture.child.kill().unwrap();
            fixture.child.wait().unwrap();
            assert_eq!(process_is_absent(pid), Ok(true));
            assert_eq!(provider.read_process_state(pid), Ok(None));
            assert!(provider.check_process_state(pid).is_passed());
            assert!(process_is_absent(0).is_err());
        }

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
            assert!(matches!(
                disabled.check_data_loss(u32::MAX),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("complete data-loss evidence")
            ));
        }

        #[test]
        fn locked_file_observation_preserves_proc_read_and_parse_failures() {
            let root = tempfile::tempdir().unwrap().keep();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("cannot read"));
            write_fd_fixture_task(&root.join("42"), 42, 100);
            std::fs::write(root.join("locks"), "1: truncated\n").unwrap();
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("invalid lock row"));
            std::fs::write(root.join("locks"), "").unwrap();
            assert!(read_locked_files_from_proc(43, &root)
                .unwrap_err()
                .contains("fdinfo"));
            let fdinfo = root.join("42/task/42/fdinfo");
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(false));
            std::fs::write(fdinfo.join("3"), "pos:\t0\n").unwrap();
            assert!(fdinfo_has_lock("pos:\t0\n")
                .unwrap_err()
                .contains("missing descriptor"));
            assert!(read_locked_files_from_proc(42, &root)
                .unwrap_err()
                .contains("fdinfo"));
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
            write_fd_fixture_task(&unreadable.join("42"), 42, 100);
            let descriptor = unreadable.join("42/task/42/fdinfo/3");
            std::fs::rename(&descriptor, unreadable.join("retained-fdinfo")).unwrap();
            std::fs::create_dir(descriptor).unwrap();
            assert!(read_locked_files_from_proc(42, &unreadable)
                .unwrap_err()
                .contains("fdinfo"));
        }

        #[test]
        fn locked_file_observation_covers_private_task_tables_and_read_only_locks() {
            let root = tempfile::tempdir().unwrap().keep();
            let process = root.join("42");
            let locks = root.join("locks");
            write_fd_fixture_task(&process, 42, 100);
            write_fd_fixture_task(&process, 43, 101);
            let private_fdinfo = process.join("task/43/fdinfo/3");
            let complete = "pos:\t0\nflags:\t0100000\nmnt_id:\t7\nino:\t42\n";
            std::fs::write(&private_fdinfo, complete).unwrap();
            std::fs::write(&locks, "1: OFDLCK ADVISORY READ -1 00:01:42 0 EOF\n").unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(false));
            for lock in ["OFDLCK ADVISORY READ -1", "FLOCK ADVISORY READ 99"] {
                std::fs::write(
                    &private_fdinfo,
                    format!("{complete}lock:\t1: {lock} 00:01:42 0 EOF\n"),
                )
                .unwrap();
                assert_eq!(
                    read_locked_files_from_proc(42, &root),
                    Ok(true),
                    "a read-only private-thread descriptor still holds {lock}"
                );
            }
            std::fs::write(&private_fdinfo, complete).unwrap();
            std::fs::write(&locks, "1: -> POSIX ADVISORY WRITE 43 00:01:42 0 EOF\n").unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(true));
            std::fs::write(&locks, "1: FLOCK ADVISORY READ 99 00:01:42 0 EOF\n").unwrap();
            assert_eq!(read_locked_files_from_proc(42, &root), Ok(false));
        }

        #[test]
        fn locked_file_observation_rejects_process_task_and_descriptor_churn() {
            for change in [
                "new_task",
                "leader_reused",
                "task_reused",
                "reopened_fd",
                "missing_fdinfo",
            ] {
                let root = tempfile::tempdir().unwrap().keep();
                let process = root.join("42");
                write_fd_fixture_task(&process, 42, 100);
                write_fd_fixture_task(&process, 43, 101);
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut reads = 0;
                let result = locked_file_evidence("", deadline, || {
                    if reads == 1 {
                        match change {
                            "new_task" => write_fd_fixture_task(&process, 44, 102),
                            "leader_reused" | "task_reused" => {
                                let (tid, birth) = if change == "leader_reused" {
                                    (42, 100)
                                } else {
                                    (43, 101)
                                };
                                let stat = process.join(format!("task/{tid}/stat"));
                                let original = std::fs::read_to_string(&stat).unwrap();
                                std::fs::write(stat, original.replace(&birth.to_string(), "999"))
                                    .unwrap();
                            }
                            "reopened_fd" => {
                                std::fs::write(
                                    process.join("task/43/fdinfo/3"),
                                    "pos:\t0\nflags:\t0100000\nmnt_id:\t7\nino:\t43\n",
                                )
                                .unwrap();
                            }
                            "missing_fdinfo" => {
                                std::fs::rename(
                                    process.join("task/43/fdinfo/3"),
                                    root.join("retained-fdinfo"),
                                )
                                .unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                    reads += 1;
                    write_fd_snapshot_from(&process, 42, deadline, 3, 3)
                });
                assert_eq!(reads, 2);
                assert!(result.is_err(), "{change} cannot prove absence of locks");
            }
        }

        #[test]
        fn locked_file_observation_enforces_byte_time_task_and_descriptor_bounds() {
            let root = tempfile::tempdir().unwrap().keep();
            let locks = root.join("locks");
            let content = "1: POSIX ADVISORY READ 99 00:01:42 0 EOF\n";
            std::fs::write(&locks, content).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            assert_eq!(
                read_bounded_lock_table(&locks, deadline, content.len() as u64),
                Ok(content.to_string())
            );
            assert!(
                read_bounded_lock_table(&locks, deadline, content.len() as u64 - 1)
                    .unwrap_err()
                    .contains("inspection limit")
            );
            assert!(read_bounded_lock_table(&locks, Instant::now(), u64::MAX)
                .unwrap_err()
                .contains("deadline"));
            assert!(locked_file_evidence("", Instant::now(), || {
                panic!("an expired probe cannot start new reads")
            })
            .is_err());

            let process = root.join("42");
            write_fd_fixture_task(&process, 42, 100);
            write_fd_fixture_task(&process, 43, 101);
            for (tasks, descriptors) in [(1, 2), (2, 1)] {
                assert!(locked_file_evidence("", deadline, || {
                    write_fd_snapshot_from(&process, 42, deadline, tasks, descriptors)
                })
                .is_err());
            }
            assert_eq!(
                locked_file_evidence("", deadline, || {
                    write_fd_snapshot_from(&process, 42, deadline, 2, 2)
                }),
                Ok(false)
            );
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

        struct ThreadDescriptorChild {
            fixture: DescriptorChild,
            events: std::sync::mpsc::Receiver<std::io::Result<String>>,
            tid: u32,
            fd: u32,
        }

        fn thread_descriptor_child(
            path: &std::path::Path,
            mode: &str,
            inherited: Option<std::fs::File>,
        ) -> Option<ThreadDescriptorChild> {
            use std::io::BufRead;
            use std::process::{Command, Stdio};

            const SCRIPT: &str = r#"
import ctypes, os, queue, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int
path, mode = sys.argv[1:]
ready = queue.Queue()
release = threading.Event()
shared = 2 if mode == 'inherited_lock' else os.open(path, os.O_WRONLY) if mode == 'shared' else None
def worker():
    if libc.unshare(0x400) != 0:
        ready.put(('unsupported', ctypes.get_errno()))
        return
    flags = os.O_RDONLY if mode == 'read_only' else os.O_RDWR if mode == 'fifo' else os.O_WRONLY
    fd = shared if shared is not None else os.open(path, flags)
    ready.put(('ready', threading.get_native_id(), fd))
    try:
        release.wait()
    finally:
        os.close(fd)
threads = [threading.Thread(target=worker)]
threads[0].start()
event = ready.get(timeout=5)
if event[0] == 'ready' and mode == 'inherited_lock':
    os.close(shared)
print(*event, flush=True)
if event[0] == 'unsupported':
    threads[0].join()
    sys.exit(0)
try:
    for command in sys.stdin:
        if command.strip() == 'new-thread':
            extra = threading.Thread(target=release.wait)
            extra.start()
            threads.append(extra)
            print('changed', flush=True)
finally:
    release.set()
    for thread in threads:
        thread.join()
    if shared is not None and mode != 'inherited_lock':
        os.close(shared)
"#;
            let mut fixture = DescriptorChild {
                child: Command::new("python3")
                    .args(["-u", "-c", SCRIPT])
                    .arg(path)
                    .arg(mode)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(inherited.map_or_else(Stdio::null, Stdio::from))
                    .spawn()
                    .expect("spawn owned thread descriptor fixture"),
                reader: None,
            };
            let stdout = fixture.child.stdout.take().unwrap();
            let (sender, events) = std::sync::mpsc::channel();
            fixture.reader = Some(std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }));
            let ready = events
                .recv_timeout(Duration::from_secs(10))
                .expect("bounded threaded fixture readiness")
                .unwrap();
            if let Some(errno) = ready.strip_prefix("unsupported ") {
                let errno = errno.parse::<i32>().unwrap();
                assert!(
                    matches!(errno, libc::EPERM | libc::EACCES | libc::ENOSYS),
                    "unexpected unshare(CLONE_FILES) failure: {errno}"
                );
                eprintln!(
                    "SKIP owned thread descriptor case {mode}: unshare(CLONE_FILES) unavailable: {}",
                    std::io::Error::from_raw_os_error(errno)
                );
                return None;
            }
            let fields: Vec<_> = ready.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "unexpected fixture message: {ready}");
            assert_eq!(fields[0], "ready");
            let tid = fields[1].parse().unwrap();
            let fd = fields[2].parse().unwrap();
            assert_ne!(tid, fixture.child.id());
            Some(ThreadDescriptorChild {
                fixture,
                events,
                tid,
                fd,
            })
        }

        #[test]
        fn data_loss_checks_private_thread_writers_and_preserves_harmless_descriptors() {
            let directory = tempfile::tempdir().unwrap().keep();
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
            for mode in ["writer", "read_only", "fifo", "device", "shared"] {
                let path = if mode == "device" {
                    std::path::PathBuf::from("/dev/null")
                } else {
                    directory.join(mode)
                };
                if mode == "fifo" {
                    let c_path =
                        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: this is the owned, NUL-terminated fixture pathname.
                    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
                } else if mode != "device" {
                    std::fs::write(&path, b"valuable data").unwrap();
                }
                let Some(mut child) = thread_descriptor_child(&path, mode, None) else {
                    return;
                };
                let pid = child.fixture.child.id();
                assert_eq!(
                    std::fs::read_link(format!("/proc/{pid}/task/{}/fd/{}", child.tid, child.fd))
                        .unwrap(),
                    path
                );
                if matches!(mode, "writer" | "read_only" | "fifo") {
                    assert!(std::fs::read_dir(format!("/proc/{pid}/fd"))
                        .unwrap()
                        .all(|entry| std::fs::read_link(entry.unwrap().path()).unwrap() != path));
                }
                let expected = match mode {
                    "writer" => 1,
                    "shared" => 2,
                    _ => 0,
                };
                assert_eq!(open_write_fd_count(pid), Some(expected), "mode={mode}");
                let result = provider.check_data_loss(pid);
                if expected > 0 {
                    assert!(matches!(result, PreCheckResult::Blocked { check, reason }
                        if check == PreCheck::CheckDataLossGate && reason.contains("open write fds")));
                } else {
                    assert!(result.is_passed(), "mode={mode}: {result:?}");
                }
                assert!(child.fixture.child.try_wait().unwrap().is_none());
            }
        }

        #[test]
        fn data_loss_refuses_task_creation_during_descriptor_metadata_probe() {
            use crate::collect::tool_runner::ToolSpec;
            use std::io::Write;

            let directory = tempfile::tempdir().unwrap().keep();
            let path = directory.join("read-only-data");
            std::fs::write(&path, b"valuable data").unwrap();
            let Some(mut child) = thread_descriptor_child(&path, "read_only", None) else {
                return;
            };
            let pid = child.fixture.child.id();
            assert_eq!(open_write_fd_count(pid), Some(0));
            let invoked = std::cell::Cell::new(false);
            let count = open_write_fd_count_with_probe(pid, |paths, remaining| {
                invoked.set(true);
                let mut args = vec![
                    "-L".to_string(),
                    "-c".to_string(),
                    "%n %f %h %i".to_string(),
                    "--".to_string(),
                ];
                args.extend_from_slice(paths);
                let output = write_fd_probe_runner(remaining)
                    .run(&ToolSpec::new("stat", args))
                    .unwrap();
                assert!(output.success(), "{output:?}");
                writeln!(child.fixture.child.stdin.as_mut().unwrap(), "new-thread").unwrap();
                assert_eq!(
                    child
                        .events
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap()
                        .unwrap(),
                    "changed"
                );
                Some(output)
            });
            assert!(invoked.get());
            assert_eq!(
                count, None,
                "a new task invalidates the complete-process observation"
            );
            let stable =
                write_fd_snapshot(pid, Instant::now() + WRITE_FD_INSPECTION_TIMEOUT).unwrap();
            assert_eq!(stable.tasks.len(), 3);
            assert_eq!(open_write_fd_count(pid), Some(0));
            assert!(child.fixture.child.try_wait().unwrap().is_none());
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
                assert_eq!(
                    proc_locks_mentions_target(&global, |owner| owner == pid),
                    Ok(false)
                );
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
        fn locked_file_observation_detects_inherited_locks_in_owned_private_threads() {
            use std::os::fd::AsRawFd;

            for ofd in [false, true] {
                let root = tempfile::tempdir().unwrap().keep();
                let path = root.join("thread.lock");
                std::fs::write(&path, b"valuable data").unwrap();
                let file = std::fs::File::open(&path).unwrap();
                let rc = if ofd {
                    // SAFETY: this initialized flock and owned read-only handle
                    // are valid for the nonblocking OFD read-lock operation.
                    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
                    lock.l_type = libc::F_RDLCK as i16;
                    lock.l_whence = libc::SEEK_SET as i16;
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) }
                } else {
                    // SAFETY: flock observes only our owned read-only handle.
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) }
                };
                assert_eq!(rc, 0, "owned lock: {}", std::io::Error::last_os_error());
                let Some(mut child) = thread_descriptor_child(&path, "inherited_lock", Some(file))
                else {
                    return;
                };
                let pid = child.fixture.child.id();
                // The original owner is this test process (flock) or -1 (OFD),
                // and the child leader has closed its copy. Only the private
                // worker table proves that this child still holds the lock.
                let global = std::fs::read_to_string("/proc/locks").unwrap();
                assert_eq!(
                    proc_locks_mentions_target(&global, |owner| owner == pid || owner == child.tid),
                    Ok(false)
                );
                assert_eq!(
                    std::fs::read_link(format!("/proc/{pid}/fd/{}", child.fd))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::NotFound
                );
                let private = std::fs::read_to_string(format!(
                    "/proc/{pid}/task/{}/fdinfo/{}",
                    child.tid, child.fd
                ))
                .unwrap();
                assert!(fdinfo_has_lock(&private).unwrap());
                assert_eq!(
                    read_locked_files_from_proc(pid, std::path::Path::new("/proc")),
                    Ok(true)
                );
                assert!(child.fixture.child.try_wait().unwrap().is_none());
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

            // A completed saved window is usable even when a fresh full window
            // would exceed the remaining operation budget.
            let bounded =
                io_only_provider(2).with_deadline(Some(Instant::now() + Duration::from_secs(1)));
            bounded.prime_recent_io_from_baselines(
                std::slice::from_ref(&target),
                std::slice::from_ref(&restored),
            );
            assert!(bounded.check_data_loss(pid).is_passed());

            // A two-second-old baseline can finish the four-second gate within
            // a three-second operation. A different target without a baseline
            // still requires an entire fresh window and is refused separately.
            let window = Duration::from_secs(4);
            let partial =
                io_only_provider(4).with_deadline(Some(Instant::now() + Duration::from_secs(3)));
            let missing = pt_common::ProcessIdentity::new(
                u32::MAX,
                pt_common::StartId::from_linux(&scope.boot_id, 1, u32::MAX),
                target.uid,
            );
            partial.prime_recent_io_from_baselines(
                &[target.clone(), missing],
                std::slice::from_ref(&restored),
            );
            assert_eq!(partial.has_recent_io(pid, window), RecentIoEvidence::Idle);
            assert!(matches!(
                partial.has_recent_io(u32::MAX, window),
                RecentIoEvidence::Unknown(reason) if reason.contains("complete 4s")
            ));
            let cache = partial.recent_io.lock().unwrap();
            let observed = &cache[&pid];
            assert!(
                observed.after.as_ref().unwrap().started_at
                    - observed.before.as_ref().unwrap().finished_at
                    >= window
            );
            drop(cache);

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
            provider.prime_recent_io_from_baselines(std::slice::from_ref(&target), &[baseline]);
            assert!(began.elapsed() < Duration::from_secs(2));
            assert!(matches!(
                provider.check_data_loss(pid),
                PreCheckResult::Blocked { reason, .. } if reason.contains("recent I/O")
            ));
            // New writes during a partially saved window must also be visible
            // in the live endpoint used for admission.
            let fresh = RecentIoBaseline::capture(&target).expect("second writer observation");
            std::thread::sleep(Duration::from_secs(2));
            let partial =
                io_only_provider(4).with_deadline(Some(Instant::now() + Duration::from_secs(3)));
            partial.prime_recent_io_from_baselines(&[target], &[fresh]);
            assert_eq!(
                partial.has_recent_io(pid, Duration::from_secs(4)),
                RecentIoEvidence::Active
            );
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
            assert!(matches!(
                io_only_provider(0).check_data_loss(u32::MAX),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("complete data-loss evidence")
            ));
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
                            crate::supervision::EnvironError::IoError { source, .. }
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
        fn data_loss_metadata_probe_has_one_deadline_and_preserves_the_target() {
            use crate::collect::tool_runner::ToolSpec;

            let file = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap();
            let mut fixture = descriptor_child(file, false);
            let pid = fixture.child.id();
            assert_eq!(open_write_fd_count(pid), Some(0));
            let invoked = std::cell::Cell::new(false);
            let began = Instant::now();
            let count = open_write_fd_count_with_probe(pid, |paths, remaining| {
                invoked.set(true);
                assert!(!paths.is_empty());
                assert!(remaining <= WRITE_FD_INSPECTION_TIMEOUT);
                // The same runner used by the stat probe must return while its
                // owned command is still asleep, without waiting for a target
                // filesystem or substituting a successful empty response.
                let output = write_fd_probe_runner(remaining)
                    .run(&ToolSpec::new(
                        "sh",
                        vec!["-c".to_string(), "exec sleep 5".to_string()],
                    ))
                    .unwrap();
                assert!(output.timed_out);
                Some(output)
            });
            assert!(invoked.get());
            assert_eq!(count, None);
            assert!(began.elapsed() < Duration::from_secs(2));
            assert!(fixture.child.try_wait().unwrap().is_none());
            assert_eq!(open_write_fd_count(pid), Some(0));
        }

        #[test]
        fn data_loss_refuses_a_read_only_descriptor_reopened_for_writing_during_the_probe() {
            use crate::collect::tool_runner::ToolSpec;
            use std::io::{BufRead, Write};
            use std::process::{Command, Stdio};

            let directory = tempfile::tempdir().unwrap().keep();
            let path = directory.join("data.log");
            std::fs::write(&path, b"valuable data").unwrap();
            let mut fixture = DescriptorChild {
                child: Command::new("sh")
                    .args([
                        "-c",
                        "exec 3<\"$1\"; printf 'ready\\n'; read -r change; exec 3>>\"$1\"; printf 'changed\\n'; read -r finish",
                        "pt-fd-reopen",
                    ])
                    .arg(&path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
                reader: None,
            };
            let stdout = fixture.child.stdout.take().unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            fixture.reader = Some(std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }));
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap()
                    .unwrap(),
                "ready"
            );
            let pid = fixture.child.id();
            assert_eq!(open_write_fd_count(pid), Some(0));
            let before = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/3")).unwrap();
            let (flags_before, inode_before, mount_before) =
                write_fd_flags_and_identity(&before).unwrap();
            assert_eq!(flags_before & libc::O_ACCMODE as u32, libc::O_RDONLY as u32);
            let invoked = std::cell::Cell::new(false);
            let count = open_write_fd_count_with_probe(pid, |paths, remaining| {
                invoked.set(true);
                assert!(!paths.iter().any(|path| path.ends_with("/3")));
                let mut args = vec![
                    "-L".to_string(),
                    "-c".to_string(),
                    "%n %f %h %i".to_string(),
                    "--".to_string(),
                ];
                args.extend_from_slice(paths);
                let output = write_fd_probe_runner(remaining)
                    .run(&ToolSpec::new("stat", args))
                    .unwrap();
                assert!(output.success(), "{output:?}");
                // Keep pathname, inode and mount unchanged. Only re-reading
                // every descriptor's access flags catches this new writer.
                writeln!(fixture.child.stdin.as_mut().unwrap(), "change").unwrap();
                assert_eq!(
                    receiver
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap()
                        .unwrap(),
                    "changed"
                );
                Some(output)
            });
            assert!(invoked.get());
            assert_eq!(count, None);
            let after = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/3")).unwrap();
            let (flags_after, inode_after, mount_after) =
                write_fd_flags_and_identity(&after).unwrap();
            assert_eq!(flags_after & libc::O_ACCMODE as u32, libc::O_WRONLY as u32);
            assert_eq!((inode_after, mount_after), (inode_before, mount_before));
            assert_eq!(open_write_fd_count(pid), Some(1));
            assert_eq!(std::fs::read(&path).unwrap(), b"valuable data");
            assert!(fixture.child.try_wait().unwrap().is_none());
        }

        #[test]
        fn critical_file_gate_survives_disabled_and_permissive_write_limits() {
            let directory = tempfile::tempdir().unwrap().keep();
            std::fs::create_dir(directory.join(".git")).unwrap();
            for (name, rule) in [
                (".git/index.lock", Some("git_lock_file")),
                ("state.sqlite-wal", Some("sqlite_wal_journal")),
                ("ordinary.log", None),
            ] {
                let path = directory.join(name);
                std::fs::write(&path, b"pending work").unwrap();
                for writable in [false, true] {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(writable)
                        .open(&path)
                        .unwrap();
                    let mut holder = descriptor_child(file, false);
                    let pid = holder.child.id();
                    let identity = crate::action::dispatch::read_cgroup_identity(pid).unwrap();
                    let observed = descriptor_safety_evidence(&identity).unwrap();
                    assert_eq!(observed.open_write_fds, u32::from(writable));
                    assert_eq!(
                        observed.critical_writes.len(),
                        usize::from(writable && rule.is_some())
                    );
                    for enabled in [false, true] {
                        let provider = LivePreCheckProvider::new(
                            None,
                            LivePreCheckConfig {
                                block_if_open_write_fds: enabled,
                                max_open_write_fds: 10,
                                block_if_locked_files: false,
                                block_if_deleted_cwd: false,
                                block_if_recent_io_seconds: 0,
                                ..LivePreCheckConfig::default()
                            },
                        )
                        .unwrap();
                        let result = provider.check_data_loss(pid);
                        if let (true, Some(rule)) = (writable, rule) {
                            assert!(matches!(
                                result,
                                PreCheckResult::Blocked { check, reason }
                                    if check == PreCheck::CheckDataLossGate
                                        && reason.contains("critical file")
                                        && reason.contains(rule)
                            ));
                        } else {
                            assert!(result.is_passed(), "{name}: {result:?}");
                        }
                    }
                    let mut wrong_owner = identity.clone();
                    wrong_owner.uid = wrong_owner.uid.wrapping_add(1);
                    assert!(descriptor_safety_evidence(&wrong_owner).is_err());
                    let mut wrong_birth = identity;
                    wrong_birth.start_id = pt_common::StartId::from_linux("other-boot", 1, pid);
                    assert!(descriptor_safety_evidence(&wrong_birth).is_err());
                    assert!(holder.child.try_wait().unwrap().is_none());
                }
            }
        }

        #[test]
        fn critical_file_gate_observes_private_worker_descriptor_tables() {
            let directory = tempfile::tempdir().unwrap().keep();
            std::fs::create_dir(directory.join(".git")).unwrap();
            let path = directory.join(".git/index.lock");
            std::fs::write(&path, b"pending index").unwrap();
            let Some(mut holder) = thread_descriptor_child(&path, "writer", None) else {
                return;
            };
            let pid = holder.fixture.child.id();
            assert!(std::fs::read_dir(format!("/proc/{pid}/fd"))
                .unwrap()
                .all(|entry| std::fs::read_link(entry.unwrap().path()).unwrap() != path));
            let identity = crate::action::dispatch::read_cgroup_identity(pid).unwrap();
            let observed = descriptor_safety_evidence(&identity).unwrap();
            assert_eq!(observed.open_write_fds, 1);
            assert!(observed
                .critical_writes
                .iter()
                .any(|file| file.rule_id == "git_lock_file" && file.fd == holder.fd));
            let mut provider = lock_only_provider();
            provider.config.block_if_locked_files = false;
            assert!(matches!(
                provider.check_data_loss(pid),
                PreCheckResult::Blocked { reason, .. }
                    if reason.contains("critical file") && reason.contains("git_lock_file")
            ));
            assert!(holder.fixture.child.try_wait().unwrap().is_none());
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
        fn infrastructure_gate_refuses_missing_process_metadata() {
            let provider = LivePreCheckProvider::with_defaults();
            assert!(matches!(
                provider.check_not_protected(u32::MAX),
                PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                    if reason.contains("protection evidence unavailable")
                        && reason.contains("process name")
            ));
        }

        #[test]
        fn custom_protection_refuses_missing_evidence_without_builtin_rules() {
            let filter = ProtectedFilter::new(
                &[(
                    "^protected-job$".to_string(),
                    "regex".to_string(),
                    false,
                    None,
                )],
                &["protected-owner".to_string()],
                &[],
                &[],
            )
            .unwrap()
            .with_builtin_protection(false);
            let mut provider =
                LivePreCheckProvider::new(None, LivePreCheckConfig::default()).unwrap();
            provider.protected_filter = Some(filter);
            for action in [Action::Kill, Action::Pause, Action::Renice, Action::Restart] {
                assert!(matches!(
                    provider.check_not_protected_for_action(u32::MAX, action),
                    PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                        if reason.contains("protection evidence unavailable")
                            && reason.contains(&u32::MAX.to_string())
                ));
            }
        }

        #[test]
        fn live_custom_protection_preserves_command_and_owner_rules() {
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let child = OwnedChild(
                std::process::Command::new("sleep")
                    .arg("60")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let provider = |patterns: &[(String, String, bool, Option<String>)],
                            users: &[String]| {
                let mut provider =
                    LivePreCheckProvider::new(None, LivePreCheckConfig::default()).unwrap();
                provider.protected_filter = Some(
                    ProtectedFilter::new(patterns, users, &[], &[])
                        .unwrap()
                        .with_builtin_protection(false),
                );
                provider
            };
            let control = provider(&[], &[]);
            assert!(control.check_not_protected(child.0.id()).is_passed());
            let cmdline = control.read_cmdline(child.0.id()).unwrap();
            let comm = control.read_comm(child.0.id()).unwrap();
            assert_ne!(
                cmdline, comm,
                "the command rule must require argv, not just comm"
            );
            let command_rule = format!("^{}$", regex::escape(&cmdline));
            let command_protected = provider(
                &[(command_rule.clone(), "regex".to_string(), false, None)],
                &[],
            );
            assert!(matches!(
                command_protected.check_not_protected(child.0.id()),
                PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                    if reason.contains(&command_rule)
            ));
            let owner = control.read_owner(child.0.id()).unwrap();
            let user = owner.name.unwrap_or_else(|| owner.uid.to_string());
            let owner_protected = provider(&[], std::slice::from_ref(&user));
            assert!(matches!(
                owner_protected.check_not_protected(child.0.id()),
                PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                    if reason.contains("owned by protected user") && reason.contains(&user)
            ));
            // A normal resolved account name must not hide an explicit UID rule.
            let numeric_protected = provider(&[], &[owner.uid.to_string()]);
            assert!(matches!(
                numeric_protected.check_not_protected(child.0.id()),
                PreCheckResult::Blocked { check: PreCheck::CheckNotProtected, reason }
                    if reason == format!("owned by protected user UID: {}", owner.uid)
            ));
            assert!(control.check_not_protected(child.0.id()).is_passed());
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
        fn live_provider_read_owner_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let owner = provider
                .read_owner(pid)
                .expect("read live numeric ownership");
            // SAFETY: getuid only reads this process's real credentials.
            assert_eq!(owner.uid, unsafe { libc::getuid() });
            assert!(owner
                .name
                .as_deref()
                .is_none_or(|name| !name.trim().is_empty()));
        }

        #[test]
        fn live_provider_read_process_state_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            let state = provider
                .read_process_state(pid)
                .expect("read live process state");
            assert!(state.is_some());
            // Test process should be running or sleeping, not zombie
            let state = state.unwrap();
            assert!(!state.is_zombie());
        }

        #[test]
        fn live_provider_read_process_state_nonexistent() {
            let provider = LivePreCheckProvider::with_defaults();
            let state = provider
                .read_process_state(u32::MAX)
                .expect("confirm absent process");
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
            // A parallel test runner opens/closes descriptors continuously; a
            // changing table must now refuse. Inspect an owned stable process
            // and require the actual no-writer result instead.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap();
            let fixture = descriptor_child(file, false);
            assert_eq!(
                provider.has_open_write_fds(fixture.child.id()),
                Some((false, 0))
            );
        }

        #[test]
        fn live_provider_has_deleted_cwd_self() {
            let provider = LivePreCheckProvider::with_defaults();
            let pid = std::process::id();
            // Our CWD should not be deleted.
            assert_eq!(provider.has_deleted_cwd(pid), Ok(false));
            // The complete data-loss gate requires a stable descriptor census,
            // unlike this test process's concurrently changing task/FD tables.
            let fixture = descriptor_child(std::fs::File::open("/dev/null").unwrap(), false);
            assert!(cwd_only_provider()
                .check_data_loss(fixture.child.id())
                .is_passed());
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
            let fixture = descriptor_child(std::fs::File::open("/dev/null").unwrap(), false);
            // Optional gates are disabled; the stable child still supplies the
            // mandatory complete observation excluding critical file writers.
            assert!(provider.check_data_loss(fixture.child.id()).is_passed());
        }
    }
}
