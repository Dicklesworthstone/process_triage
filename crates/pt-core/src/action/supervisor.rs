//! Supervisor-aware action execution.
//!
//! This module provides execution of actions through supervisor tools rather than
//! direct signals. When a process is managed by a supervisor (systemd, pm2, docker,
//! supervisord, etc.), killing it directly can cause respawns or leave the supervisor
//! in an inconsistent state.
//!
//! # Safety Features
//!
//! - **Respawn Detection**: After executing a stop command, verifies the process
//!   doesn't respawn within a configurable window.
//! - **Timeout Caps**: All supervisor commands run with hard timeouts to prevent hangs.
//! - **Protected Patterns**: Refuses to execute against protected supervisor units.
//! - **Session Safety**: Checks for session-related protections before execution.
//!
//! # Supported Supervisors
//!
//! - systemd (systemctl stop/restart)
//! - pm2 (pm2 stop/delete)
//! - supervisord (supervisorctl stop)
//! - docker (docker stop/kill)
//! - containerd (ctr task kill)
//! - podman (podman stop/kill)
//! - nodemon (SIGINT to graceful shutdown)
//! - forever (forever stop)

use crate::action::prechecks::{SupervisorAction, SupervisorInfo};
use crate::action::ActionError;
use crate::decision::Action;
use crate::plan::{ActionRouting, PlanAction};
#[cfg(target_os = "linux")]
use crate::supervision::ContainerSupervisionResult;
use crate::supervision::{AppSupervisionResult, AppSupervisorType};
#[cfg(target_os = "linux")]
use pt_common::IdentityQuality;
use pt_common::ProcessIdentity;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace, warn};

/// A read-only observation of one process in the current user's systemd service.
/// Persist the manager's invocation and cgroup together with the process birth;
/// a unit name or PID alone cannot authorize a later restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemdUserServiceBinding {
    pub target: ProcessIdentity,
    pub unit: String,
    pub control_group: String,
    pub invocation_id: String,
}

impl SystemdUserServiceBinding {
    /// Structural consistency only. This observation must be revalidated against
    /// both procfs and the user manager immediately before an actual command.
    pub fn matches_target(&self, target: &ProcessIdentity) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.target == *target
                && target.quality == IdentityQuality::Full
                && target.pid.0 > 1
                // SAFETY: geteuid only reads the caller's credentials.
                && target.uid == unsafe { libc::geteuid() }
                && user_service_at_path(&self.control_group, target.uid)
                    == Some(self.unit.as_str())
                && valid_invocation_id(&self.invocation_id)
                && !protected_restart_unit(&self.unit)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            false
        }
    }

    pub fn display_command(&self) -> String {
        format!(
            "systemctl --user --no-ask-password --job-mode=fail try-restart -- {}",
            self.unit
        )
    }
}

#[cfg(target_os = "linux")]
fn valid_invocation_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

/// Only a literal leaf service below this exact user's manager is eligible.
/// Reject container placement, scopes, the manager itself, delegated children,
/// another user's manager and ambiguous paths before invoking systemctl.
#[cfg(target_os = "linux")]
fn user_service_at_path(path: &str, uid: u32) -> Option<&str> {
    let prefix = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    let tail = path.strip_prefix(&prefix)?;
    let mut components = tail.rsplit('/');
    let unit = components.next()?;
    if !crate::collect::systemd::is_literal_service_unit(unit)
        || components.any(|component| {
            !component.ends_with(".slice")
                || component.len() <= ".slice".len()
                || component.starts_with('.')
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.@:-".contains(&byte))
        })
    {
        return None;
    }
    Some(unit)
}

#[cfg(target_os = "linux")]
fn protected_restart_unit(unit: &str) -> bool {
    let command = unit.trim_end_matches(".service");
    SupervisorActionRunner::new().is_protected_unit(unit)
        || crate::collect::protected::builtin_protection_match(command, command).is_some()
        || crate::collect::protected::builtin_force_review_match(command).is_some()
}

/// Discover one supported supervisor route without changing service state.
/// Ordinary processes are rejected from cgroup placement before any subprocess.
pub fn discover_systemd_user_restart(
    target: &ProcessIdentity,
) -> Result<Option<SystemdUserServiceBinding>, ActionError> {
    discover_systemd_user_restart_with_budget(target, Duration::from_secs(2))
}

fn discover_systemd_user_restart_with_budget(
    target: &ProcessIdentity,
    budget: Duration,
) -> Result<Option<SystemdUserServiceBinding>, ActionError> {
    #[cfg(target_os = "linux")]
    {
        let started = Instant::now();
        // SAFETY: geteuid only reads the caller's credentials.
        if target.uid != unsafe { libc::geteuid() } || target.pid.0 <= 1 {
            return Ok(None);
        }
        let Some(path) = crate::collect::collect_cgroup_details(target.pid.0)
            .and_then(|details| details.unified_path)
        else {
            return Ok(None);
        };
        let Some(unit) = user_service_at_path(&path, target.uid) else {
            return Ok(None);
        };
        if protected_restart_unit(unit) {
            return Ok(None);
        }
        ensure_restart_subject(target)?;
        if super::dispatch::ensure_exclusive_cgroup(target.pid.0)? != path {
            return Err(ActionError::IdentityMismatch);
        }
        let state = crate::collect::systemd::query_systemd_user_service(
            unit,
            target.uid,
            remaining_budget(started, budget)?,
        )
        .map_err(ActionError::Failed)?;
        let binding = binding_from_service_state(target, &path, &state)?;
        // Bracket manager IPC with a second incarnation/placement observation.
        ensure_restart_subject(target)?;
        if super::dispatch::ensure_exclusive_cgroup(target.pid.0)? != path {
            return Err(ActionError::IdentityMismatch);
        }
        remaining_budget(started, budget)?;
        Ok(Some(binding))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, budget);
        Ok(None)
    }
}

/// Revalidate an already reviewed route; a newly detected different invocation
/// or service is not a substitute for the binding saved in the plan.
pub fn validate_systemd_user_restart(
    target: &ProcessIdentity,
    binding: &SystemdUserServiceBinding,
    budget: Duration,
) -> Result<(), ActionError> {
    if !binding.matches_target(target) {
        return Err(ActionError::Failed(
            "restart binding does not match the complete target and current user manager"
                .to_string(),
        ));
    }
    let current = discover_systemd_user_restart_with_budget(target, budget)?;
    if current.as_ref() != Some(binding) {
        return Err(ActionError::Failed(
            "systemd service identity, invocation or cgroup changed since planning".to_string(),
        ));
    }
    Ok(())
}

/// A supervisor binding cannot turn a direct or zombie-parent action into a
/// service operation. In particular, hand-edited plans must name the route.
pub(crate) fn restart_binding_for_action(
    action: &PlanAction,
) -> Result<&SystemdUserServiceBinding, ActionError> {
    let binding = action.supervisor_restart.as_ref().ok_or_else(|| {
        ActionError::Failed("restart requires a recorded supervisor binding".to_string())
    })?;
    if action.action != Action::Restart
        || action.routing != ActionRouting::Supervisor
        || action.original_zombie_target.is_some()
        || !binding.matches_target(&action.target)
    {
        return Err(ActionError::Failed(
            "invalid supervisor restart route or target binding".to_string(),
        ));
    }
    Ok(binding)
}

#[cfg(target_os = "linux")]
fn remaining_budget(started: Instant, budget: Duration) -> Result<Duration, ActionError> {
    budget
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ActionError::Timeout)
}

#[cfg(target_os = "linux")]
fn binding_from_service_state(
    target: &ProcessIdentity,
    path: &str,
    state: &crate::collect::systemd::SystemdUserServiceState,
) -> Result<SystemdUserServiceBinding, ActionError> {
    let binding = SystemdUserServiceBinding {
        target: target.clone(),
        unit: state.unit.clone(),
        control_group: state.control_group.clone(),
        invocation_id: state.invocation_id.clone(),
    };
    if state.main_pid != target.pid.0
        || state.control_group != path
        || !binding.matches_target(target)
    {
        return Err(ActionError::Failed(
            "manager MainPID, invocation or cgroup does not match this service process".to_string(),
        ));
    }
    Ok(binding)
}

/// Mandatory protections also apply to callers using CompositeActionRunner
/// directly. Policy, session, data-loss and intent gates still run in apply.
#[cfg(target_os = "linux")]
fn ensure_restart_subject(target: &ProcessIdentity) -> Result<(), ActionError> {
    super::signal::ensure_action_pid_namespace()?;
    let pid = target.pid.0;
    if pid <= 1 || crate::collect::protected::live_invoker_chain_pids().contains(&pid) {
        return Err(ActionError::Failed(
            "refusing restart of init, pt or an invoking process".to_string(),
        ));
    }
    let current =
        super::dispatch::read_cgroup_identity(pid).ok_or(ActionError::IdentityMismatch)?;
    if target.quality != IdentityQuality::Full || !target.matches(&current) {
        return Err(ActionError::IdentityMismatch);
    }
    // SAFETY: geteuid only reads the caller's credentials.
    let uid = unsafe { libc::geteuid() };
    let credentials = crate::collect::proc_parsers::parse_proc_status(pid)
        .ok_or(ActionError::IdentityMismatch)?;
    if target.uid != uid
        || [
            credentials.ruid,
            credentials.euid,
            credentials.suid,
            credentials.fsuid,
        ]
        .iter()
        .any(|owner| *owner != uid)
    {
        return Err(ActionError::PermissionDenied);
    }
    let stat = crate::collect::proc_parsers::read_required_proc_stat(pid)
        .map_err(|error| ActionError::Failed(error.to_string()))?;
    if matches!(stat.state, 'Z' | 'X' | 'x') {
        return Err(ActionError::Failed(
            "dead processes require a reaping remedy, not a service restart".to_string(),
        ));
    }
    let raw_stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| ActionError::Failed(format!("TTY evidence unavailable: {error}")))?;
    if super::prechecks::parse_proc_tty(pid, &raw_stat).map_err(ActionError::Failed)? {
        return Err(ActionError::Failed(
            "interactive services are not eligible for bounded restart".to_string(),
        ));
    }
    let cmd = crate::collect::proc_parsers::parse_proc_cmdline(pid)
        .ok_or_else(|| ActionError::Failed("restart command evidence unavailable".to_string()))?;
    if crate::collect::protected::builtin_protection_match(&stat.comm, &cmd).is_some()
        || crate::collect::protected::builtin_force_review_match(&cmd).is_some()
        || crate::collect::protected::live_service_ancestor(pid).is_some()
    {
        return Err(ActionError::Failed(
            "refusing restart of protected infrastructure or an agent".to_string(),
        ));
    }
    let fuse = super::prechecks::fuse_action_precheck(
        crate::collect::protected::holds_fuse_device(pid),
        Action::Restart,
    );
    if let super::prechecks::PreCheckResult::Blocked { reason, .. } = fuse {
        return Err(ActionError::Failed(reason));
    }
    let supervision = crate::supervision::detect_supervision(pid).map_err(|error| {
        ActionError::Failed(format!("supervision evidence unavailable: {error}"))
    })?;
    if crate::supervision::is_human_supervised(&supervision) {
        return Err(ActionError::Failed(
            "human, agent, IDE or IPC supervision blocks service restart".to_string(),
        ));
    }
    let after = super::dispatch::read_cgroup_identity(pid).ok_or(ActionError::IdentityMismatch)?;
    if !target.matches(&after) {
        return Err(ActionError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn execute_systemd_user_restart(
    action: &PlanAction,
    on_submission: impl FnOnce(),
) -> Result<(), ActionError> {
    let binding = restart_binding_for_action(action)?;
    let started = Instant::now();
    let budget = Duration::from_millis(action.timeouts.execute_ms.min(120_000));
    validate_systemd_user_restart(&action.target, binding, remaining_budget(started, budget)?)?;
    let remaining = remaining_budget(started, budget)?;
    if remaining <= Duration::from_millis(600) {
        return Err(ActionError::Timeout);
    }
    on_submission();
    crate::collect::systemd::run_user_systemctl(
        action.target.uid,
        &["--job-mode=fail", "try-restart", "--", &binding.unit],
        remaining,
    )
    .map_err(|error| {
        ActionError::Failed(format!(
            "systemd --user restart was not confirmed: {error}; a submitted manager job may \
             still be pending or have changed the service; inspect the unit before retrying"
        ))
    })?;
    if remaining_budget(started, budget).is_err() {
        return Err(ActionError::Failed(
            "restart command exceeded its budget after submission; the manager job may still \
             be pending; inspect the unit before retrying"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_restarted_identity(
    binding: &SystemdUserServiceBinding,
    state: &crate::collect::systemd::SystemdUserServiceState,
    replacement: &ProcessIdentity,
    original_now: Option<&ProcessIdentity>,
) -> Result<(), ActionError> {
    if state.unit != binding.unit
        || state.control_group != binding.control_group
        || !valid_invocation_id(&state.invocation_id)
        || state
            .invocation_id
            .eq_ignore_ascii_case(&binding.invocation_id)
        || state.main_pid == binding.target.pid.0
        || replacement.pid.0 != state.main_pid
        || replacement.uid != binding.target.uid
        || replacement.quality != IdentityQuality::Full
        || replacement.start_id == binding.target.start_id
        || original_now.is_some_and(|current| binding.target.matches(current))
    {
        return Err(ActionError::Failed(
            "restart has not produced a new live MainPID and invocation in the bound service"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn observed_restart_identity(pid: u32) -> Result<Option<ProcessIdentity>, ActionError> {
    if let Some(identity) = super::dispatch::read_cgroup_identity(pid) {
        return Ok(Some(identity));
    }
    match std::fs::symlink_metadata(format!("/proc/{pid}")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(ActionError::Failed(format!(
            "cannot establish the current incarnation or exit of PID {pid}"
        ))),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_systemd_user_restart(action: &PlanAction) -> Result<(), ActionError> {
    let binding = restart_binding_for_action(action)?;
    let started = Instant::now();
    let budget = Duration::from_millis(action.timeouts.verify_ms.min(120_000));
    let mut last_error = "no replacement service observation".to_string();
    loop {
        let remaining = match remaining_budget(started, budget) {
            Ok(remaining) if remaining > Duration::from_millis(600) => remaining,
            _ => {
                return Err(ActionError::Failed(format!(
                    "restart verification budget exhausted: {last_error}; the manager job may \
                     still be pending; inspect the unit before retrying"
                )))
            }
        };
        let observe = || -> Result<(), ActionError> {
            let state = crate::collect::systemd::query_systemd_user_service(
                &binding.unit,
                action.target.uid,
                remaining,
            )
            .map_err(ActionError::Failed)?;
            let replacement =
                observed_restart_identity(state.main_pid)?.ok_or(ActionError::ProcessNotFound)?;
            let original_now = observed_restart_identity(binding.target.pid.0)?;
            verify_restarted_identity(binding, &state, &replacement, original_now.as_ref())?;
            ensure_restart_subject(&replacement)?;
            if super::dispatch::ensure_exclusive_cgroup(replacement.pid.0)? != binding.control_group
            {
                return Err(ActionError::IdentityMismatch);
            }
            let after = observed_restart_identity(replacement.pid.0)?
                .ok_or(ActionError::IdentityMismatch)?;
            if !replacement.matches(&after) {
                return Err(ActionError::IdentityMismatch);
            }
            remaining_budget(started, budget)?;
            Ok(())
        };
        match observe() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        let remaining = remaining_budget(started, budget).unwrap_or_default();
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

/// Errors from supervisor action execution.
#[derive(Debug, Error)]
pub enum SupervisorActionError {
    #[error("unsupported supervisor type: {0}")]
    UnsupportedSupervisor(String),

    #[error("command execution failed: {0}")]
    CommandFailed(String),

    #[error("command timed out after {0:?}")]
    Timeout(Duration),

    #[error("process respawned after stop")]
    ProcessRespawned,

    #[error("process still running after stop")]
    ProcessStillRunning,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("unit/container not found: {0}")]
    UnitNotFound(String),

    #[error("protected unit: {0}")]
    ProtectedUnit(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Type of supervisor managing the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorType {
    /// systemd service manager
    Systemd,
    /// macOS launchd service manager
    Launchd,
    /// pm2 Node.js process manager
    Pm2,
    /// supervisord process control system
    Supervisord,
    /// Docker container runtime
    Docker,
    /// containerd container runtime
    Containerd,
    /// Podman container runtime
    Podman,
    /// nodemon file watcher
    Nodemon,
    /// forever Node.js daemon
    Forever,
    /// Unknown/unsupported supervisor
    Unknown,
}

impl std::fmt::Display for SupervisorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorType::Systemd => write!(f, "systemd"),
            SupervisorType::Launchd => write!(f, "launchd"),
            SupervisorType::Pm2 => write!(f, "pm2"),
            SupervisorType::Supervisord => write!(f, "supervisord"),
            SupervisorType::Docker => write!(f, "docker"),
            SupervisorType::Containerd => write!(f, "containerd"),
            SupervisorType::Podman => write!(f, "podman"),
            SupervisorType::Nodemon => write!(f, "nodemon"),
            SupervisorType::Forever => write!(f, "forever"),
            SupervisorType::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<AppSupervisorType> for SupervisorType {
    fn from(app_type: AppSupervisorType) -> Self {
        match app_type {
            AppSupervisorType::Pm2 => SupervisorType::Pm2,
            AppSupervisorType::Supervisord => SupervisorType::Supervisord,
            AppSupervisorType::Nodemon => SupervisorType::Nodemon,
            AppSupervisorType::Forever => SupervisorType::Forever,
            AppSupervisorType::Unknown => SupervisorType::Unknown,
        }
    }
}

/// Supervisor-specific action to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorCommand {
    /// Stop the unit/container/process gracefully.
    Stop,
    /// Restart the unit/container/process.
    Restart,
    /// Force kill (escalated from stop timeout).
    Kill,
    /// Remove/delete the unit/container from the supervisor.
    Delete,
}

impl std::fmt::Display for SupervisorCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorCommand::Stop => write!(f, "stop"),
            SupervisorCommand::Restart => write!(f, "restart"),
            SupervisorCommand::Kill => write!(f, "kill"),
            SupervisorCommand::Delete => write!(f, "delete"),
        }
    }
}

/// A first-class supervisor action with all metadata for safe execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorPlanAction {
    /// Unique action identifier.
    pub action_id: String,

    /// Target process PID.
    pub pid: u32,

    /// Type of supervisor managing this process.
    pub supervisor_type: SupervisorType,

    /// Unit name, container ID, or process label (supervisor-specific identifier).
    pub unit_identifier: String,

    /// The command to execute (stop, restart, kill, delete).
    pub command: SupervisorCommand,

    /// Human-readable command string for review (e.g., "systemctl stop nginx.service").
    pub display_command: String,

    /// Structured parameters for safe execution.
    pub parameters: SupervisorParameters,

    /// Timeout for command execution.
    pub timeout: Duration,

    /// Whether this action is blocked by safety gates.
    pub blocked: bool,

    /// Reason for blocking (if blocked).
    pub block_reason: Option<String>,
}

/// Structured parameters for supervisor command execution.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SupervisorParameters {
    /// For systemd: unit name (e.g., "nginx.service")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,

    /// For launchd: service label (e.g., "com.apple.Spotlight")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launchd_label: Option<String>,

    /// For launchd: domain target (e.g., "gui/501", "system")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launchd_domain: Option<String>,

    /// For pm2: process name or ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pm2_name: Option<String>,

    /// For docker/podman/containerd: container ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// For supervisord: program name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisord_program: Option<String>,

    /// For forever: process UID or index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forever_uid: Option<String>,

    /// Force flag (skip graceful shutdown)
    #[serde(default)]
    pub force: bool,

    /// Signal to send for kill operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Configuration for supervisor action execution.
#[derive(Debug, Clone)]
pub struct SupervisorActionConfig {
    /// Default timeout for supervisor commands.
    pub default_timeout: Duration,

    /// Maximum allowed timeout (hard cap).
    pub max_timeout: Duration,

    /// Time to wait after stop before checking for respawn.
    pub respawn_check_delay: Duration,

    /// Number of respawn checks to perform.
    pub respawn_check_count: u32,

    /// Protected unit patterns (regex).
    pub protected_patterns: Vec<String>,

    /// Allow force kill if graceful stop times out.
    pub allow_escalation: bool,

    /// Dry run mode (log commands without executing).
    pub dry_run: bool,
}

impl Default for SupervisorActionConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(120),
            respawn_check_delay: Duration::from_secs(2),
            respawn_check_count: 3,
            protected_patterns: vec![
                // Critical system services
                r"^systemd-.*".to_string(),
                r"^dbus.*".to_string(),
                r"^sshd.*".to_string(),
                r"^cron.*".to_string(),
                // Docker daemon itself
                r"^docker\.service$".to_string(),
                r"^containerd\.service$".to_string(),
            ],
            allow_escalation: true,
            dry_run: false,
        }
    }
}

/// Result of supervisor action execution.
#[derive(Debug, Clone, Serialize)]
pub struct SupervisorActionResult {
    /// Whether the action succeeded.
    pub success: bool,

    /// Time taken to execute.
    pub duration: Duration,

    /// Output from the command (stdout).
    pub stdout: Option<String>,

    /// Error output from the command (stderr).
    pub stderr: Option<String>,

    /// Exit code if command completed.
    pub exit_code: Option<i32>,

    /// Whether the process respawned after stop.
    pub respawned: bool,

    /// Any warnings generated during execution.
    pub warnings: Vec<String>,
}

/// Executor for supervisor-aware actions.
pub struct SupervisorActionRunner {
    config: SupervisorActionConfig,
    compiled_patterns: Vec<regex::Regex>,
}

impl SupervisorActionRunner {
    /// Create a new supervisor action runner with default config.
    pub fn new() -> Self {
        Self::with_config(SupervisorActionConfig::default())
    }

    /// Create a runner with custom config.
    pub fn with_config(config: SupervisorActionConfig) -> Self {
        let compiled_patterns = config
            .protected_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        Self {
            config,
            compiled_patterns,
        }
    }

    /// Execute a supervisor action.
    pub fn execute_supervisor_action(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<SupervisorActionResult, SupervisorActionError> {
        // Check if blocked
        if action.blocked {
            return Err(SupervisorActionError::ProtectedUnit(
                action.block_reason.clone().unwrap_or_default(),
            ));
        }

        // Check protected patterns
        if self.is_protected_unit(&action.unit_identifier) {
            return Err(SupervisorActionError::ProtectedUnit(
                action.unit_identifier.clone(),
            ));
        }

        let start = Instant::now();

        // Build and execute the command
        let (program, args) = self.build_command(action)?;

        debug!(
            supervisor = %action.supervisor_type,
            unit = %action.unit_identifier,
            command = %action.command,
            "executing supervisor action: {} {}",
            program,
            args.join(" ")
        );

        if self.config.dry_run {
            return Ok(SupervisorActionResult {
                success: true,
                duration: start.elapsed(),
                stdout: Some(format!("[dry-run] {} {}", program, args.join(" "))),
                stderr: None,
                exit_code: Some(0),
                respawned: false,
                warnings: vec!["dry-run mode enabled".to_string()],
            });
        }

        let timeout = std::cmp::min(action.timeout, self.config.max_timeout);

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output =
            crate::collect::tool_runner::run_tool(&program, &args_refs, Some(timeout), None)
                .map_err(|e| match e {
                    crate::collect::tool_runner::ToolError::Timeout(d) => {
                        SupervisorActionError::Timeout(d)
                    }
                    other => SupervisorActionError::CommandFailed(other.to_string()),
                })?;

        let exit_code = output.exit_code;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let success = exit_code == Some(0);

        if !success {
            // Check for common error patterns
            if stderr.contains("permission denied") || stderr.contains("Access denied") {
                return Err(SupervisorActionError::PermissionDenied(stderr));
            }
            if stderr.contains("not found") || stderr.contains("does not exist") {
                return Err(SupervisorActionError::UnitNotFound(
                    action.unit_identifier.clone(),
                ));
            }
        }

        let mut result = SupervisorActionResult {
            success,
            duration: start.elapsed(),
            stdout: if stdout.is_empty() {
                None
            } else {
                Some(stdout)
            },
            stderr: if stderr.is_empty() {
                None
            } else {
                Some(stderr)
            },
            exit_code,
            respawned: false,
            warnings: vec![],
        };

        // If action was Stop or Kill, check for respawn
        if matches!(
            action.command,
            SupervisorCommand::Stop | SupervisorCommand::Kill
        ) && success
            && self.detect_respawn(action)
        {
            result.respawned = true;
            result.success = false;
            return Err(SupervisorActionError::ProcessRespawned);
        }

        Ok(result)
    }

    /// Verify the process stopped and check for respawns.
    pub fn verify_stopped(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<SupervisorActionResult, SupervisorActionError> {
        let start = Instant::now();
        let warnings = Vec::new();

        // Initial check - is process still running?
        if self.is_process_running(action.pid) {
            warn!(pid = action.pid, "process still running after stop command");
            return Err(SupervisorActionError::ProcessStillRunning);
        }

        // Respawn detection - check multiple times with delay
        for check in 0..self.config.respawn_check_count {
            std::thread::sleep(self.config.respawn_check_delay);

            // Check if a new process with similar characteristics appeared
            if self.detect_respawn(action) {
                warn!(
                    pid = action.pid,
                    unit = %action.unit_identifier,
                    check_number = check + 1,
                    "process respawned after stop"
                );
                return Err(SupervisorActionError::ProcessRespawned);
            }

            trace!(
                pid = action.pid,
                check_number = check + 1,
                "respawn check passed"
            );
        }

        debug!(
            pid = action.pid,
            unit = %action.unit_identifier,
            "verified process stopped without respawn"
        );

        Ok(SupervisorActionResult {
            success: true,
            duration: start.elapsed(),
            stdout: None,
            stderr: None,
            exit_code: None,
            respawned: false,
            warnings,
        })
    }

    /// Build the command and arguments for a supervisor action.
    fn build_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        match action.supervisor_type {
            SupervisorType::Systemd => self.build_systemd_command(action),
            SupervisorType::Launchd => self.build_launchd_command(action),
            SupervisorType::Pm2 => self.build_pm2_command(action),
            SupervisorType::Supervisord => self.build_supervisord_command(action),
            SupervisorType::Docker => self.build_docker_command(action),
            SupervisorType::Containerd => self.build_containerd_command(action),
            SupervisorType::Podman => self.build_podman_command(action),
            SupervisorType::Forever => self.build_forever_command(action),
            SupervisorType::Nodemon => {
                // Nodemon doesn't have a control command - use signal
                Ok((
                    "kill".to_string(),
                    vec!["-INT".to_string(), action.pid.to_string()],
                ))
            }
            SupervisorType::Unknown => Err(SupervisorActionError::UnsupportedSupervisor(
                "unknown".to_string(),
            )),
        }
    }

    fn build_systemd_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let unit = action
            .parameters
            .systemd_unit
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let subcmd = match action.command {
            SupervisorCommand::Stop => "stop",
            SupervisorCommand::Restart => "restart",
            SupervisorCommand::Kill => "kill",
            SupervisorCommand::Delete => "disable", // systemd doesn't "delete" - we disable
        };

        Ok((
            "systemctl".to_string(),
            vec![subcmd.to_string(), unit.clone()],
        ))
    }

    /// Build launchd command using launchctl.
    ///
    /// # launchctl Command Reference
    ///
    /// Modern launchctl (macOS 10.10+) uses domain-based commands:
    /// - `launchctl bootout <domain-target> [service-path]` - Stop and unload a service
    /// - `launchctl bootstrap <domain-target> <service-path>` - Load and start a service
    /// - `launchctl kickstart [-k] <service-target>` - Force start (with -k: kill and restart)
    /// - `launchctl kill <signal> <service-target>` - Send signal to service
    ///
    /// Domain targets:
    /// - `system` - System-wide services (root)
    /// - `gui/<uid>` - User GUI session (e.g., gui/501)
    /// - `user/<uid>` - User background services
    /// - `pid/<pid>` - Per-process services
    fn build_launchd_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let label = action
            .parameters
            .launchd_label
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // Default to system domain if not specified
        let domain = action
            .parameters
            .launchd_domain
            .as_deref()
            .unwrap_or("system");

        // Build the service-target for kickstart/kill commands
        let service_target = format!("{}/{}", domain, label);

        let args = match action.command {
            SupervisorCommand::Stop => {
                // bootout stops and unloads the service
                vec!["bootout".to_string(), service_target]
            }
            SupervisorCommand::Restart => {
                // kickstart -k kills the running process and restarts it
                vec!["kickstart".to_string(), "-k".to_string(), service_target]
            }
            SupervisorCommand::Kill => {
                // Send SIGKILL to the service
                vec!["kill".to_string(), "KILL".to_string(), service_target]
            }
            SupervisorCommand::Delete => {
                // bootout is also used to unload/remove
                // For persistent removal, the plist file would need to be deleted
                vec!["bootout".to_string(), service_target]
            }
        };

        Ok(("launchctl".to_string(), args))
    }

    fn build_pm2_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let name = action
            .parameters
            .pm2_name
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let subcmd = match action.command {
            SupervisorCommand::Stop => "stop",
            SupervisorCommand::Restart => "restart",
            SupervisorCommand::Kill => "stop", // pm2 stop is the strongest
            SupervisorCommand::Delete => "delete",
        };

        Ok(("pm2".to_string(), vec![subcmd.to_string(), name.clone()]))
    }

    fn build_supervisord_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let program = action
            .parameters
            .supervisord_program
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let subcmd = match action.command {
            SupervisorCommand::Stop => "stop",
            SupervisorCommand::Restart => "restart",
            SupervisorCommand::Kill => "stop", // supervisorctl uses stop
            SupervisorCommand::Delete => "remove",
        };

        Ok((
            "supervisorctl".to_string(),
            vec![subcmd.to_string(), program.clone()],
        ))
    }

    fn build_docker_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let container_id = action
            .parameters
            .container_id
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let (subcmd, mut args) = match action.command {
            SupervisorCommand::Stop => ("stop", vec![]),
            SupervisorCommand::Restart => ("restart", vec![]),
            SupervisorCommand::Kill => ("kill", vec![]),
            SupervisorCommand::Delete => ("rm", vec!["-f".to_string()]),
        };

        args.push(container_id.clone());
        Ok((
            "docker".to_string(),
            vec![subcmd.to_string()].into_iter().chain(args).collect(),
        ))
    }

    fn build_containerd_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let container_id = action
            .parameters
            .container_id
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // containerd uses ctr
        let args = match action.command {
            SupervisorCommand::Stop | SupervisorCommand::Kill => {
                vec!["task".to_string(), "kill".to_string(), container_id.clone()]
            }
            SupervisorCommand::Restart => {
                // containerd doesn't have restart - would need to kill and start
                vec!["task".to_string(), "kill".to_string(), container_id.clone()]
            }
            SupervisorCommand::Delete => {
                vec![
                    "container".to_string(),
                    "delete".to_string(),
                    container_id.clone(),
                ]
            }
        };

        Ok(("ctr".to_string(), args))
    }

    fn build_podman_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let container_id = action
            .parameters
            .container_id
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let (subcmd, mut args) = match action.command {
            SupervisorCommand::Stop => ("stop", vec![]),
            SupervisorCommand::Restart => ("restart", vec![]),
            SupervisorCommand::Kill => ("kill", vec![]),
            SupervisorCommand::Delete => ("rm", vec!["-f".to_string()]),
        };

        args.push(container_id.clone());
        Ok((
            "podman".to_string(),
            vec![subcmd.to_string()].into_iter().chain(args).collect(),
        ))
    }

    fn build_forever_command(
        &self,
        action: &SupervisorPlanAction,
    ) -> Result<(String, Vec<String>), SupervisorActionError> {
        let uid = action
            .parameters
            .forever_uid
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        let subcmd = match action.command {
            SupervisorCommand::Stop | SupervisorCommand::Kill => "stop",
            SupervisorCommand::Restart => "restart",
            SupervisorCommand::Delete => "stop", // forever stop removes the process
        };

        Ok(("forever".to_string(), vec![subcmd.to_string(), uid.clone()]))
    }

    /// Check if a unit identifier matches any protected pattern.
    fn is_protected_unit(&self, unit: &str) -> bool {
        for re in &self.compiled_patterns {
            if re.is_match(unit) {
                debug!(
                    unit,
                    pattern = re.as_str(),
                    "unit matches protected pattern"
                );
                return true;
            }
        }
        false
    }

    /// Check if a process is still running.
    fn is_process_running(&self, pid: u32) -> bool {
        #[cfg(unix)]
        {
            let result = unsafe { libc::kill(pid as i32, 0) };
            result == 0
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }

    /// Detect if a process respawned after being stopped.
    ///
    /// This checks for new processes with similar characteristics to the original.
    fn detect_respawn(&self, action: &SupervisorPlanAction) -> bool {
        match action.supervisor_type {
            SupervisorType::Systemd => self.detect_systemd_respawn(action),
            SupervisorType::Launchd => self.detect_launchd_respawn(action),
            SupervisorType::Pm2 => self.detect_pm2_respawn(action),
            SupervisorType::Docker | SupervisorType::Podman | SupervisorType::Containerd => {
                self.detect_container_respawn(action)
            }
            SupervisorType::Supervisord => self.detect_supervisord_respawn(action),
            _ => false, // No respawn detection for nodemon/forever/unknown
        }
    }

    fn detect_systemd_respawn(&self, action: &SupervisorPlanAction) -> bool {
        let unit = action
            .parameters
            .systemd_unit
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // Check if unit is active via systemctl
        let output = crate::collect::tool_runner::run_tool(
            "systemctl",
            &["is-active", unit],
            Some(Duration::from_secs(5)),
            None,
        );

        if let Ok(output) = output {
            let status = output.stdout_str();
            status.trim() == "active"
        } else {
            false
        }
    }

    /// Detect if a launchd service respawned after being stopped.
    ///
    /// Uses `launchctl list` to check if the service is running.
    /// Output format: `<pid>\t<last_exit_status>\t<label>`
    /// A non-hyphen PID indicates the service is running.
    fn detect_launchd_respawn(&self, action: &SupervisorPlanAction) -> bool {
        let label = action
            .parameters
            .launchd_label
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // launchctl list <label> returns info about a specific service
        // Output is a property list dictionary.
        // If the service is running, it will contain a "PID" key.
        let output = crate::collect::tool_runner::run_tool(
            "launchctl",
            &["list", label],
            Some(Duration::from_secs(5)),
            None,
        );

        if let Ok(output) = output {
            if !output.success() {
                // Service not found or not loaded
                return false;
            }
            let stdout = output.stdout_str();
            // Search for "PID" = <number>;
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("\"PID\" =") {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }

    fn detect_pm2_respawn(&self, action: &SupervisorPlanAction) -> bool {
        let name = action
            .parameters
            .pm2_name
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // Check pm2 status
        let output = crate::collect::tool_runner::run_tool(
            "pm2",
            &["show", name],
            Some(Duration::from_secs(5)),
            None,
        );

        if let Ok(output) = output {
            let stdout = output.stdout_str();
            stdout.contains("status") && stdout.contains("online")
        } else {
            false
        }
    }

    fn detect_container_respawn(&self, action: &SupervisorPlanAction) -> bool {
        let container_id = action
            .parameters
            .container_id
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // Check if container is running via docker/podman
        let tool = match action.supervisor_type {
            SupervisorType::Podman => "podman",
            _ => "docker",
        };

        let output = crate::collect::tool_runner::run_tool(
            tool,
            &["inspect", "-f", "{{.State.Running}}", container_id],
            Some(Duration::from_secs(5)),
            None,
        );

        if let Ok(output) = output {
            let status = output.stdout_str();
            status.trim() == "true"
        } else {
            false
        }
    }

    fn detect_supervisord_respawn(&self, action: &SupervisorPlanAction) -> bool {
        let program = action
            .parameters
            .supervisord_program
            .as_ref()
            .unwrap_or(&action.unit_identifier);

        // Check supervisorctl status
        let output = crate::collect::tool_runner::run_tool(
            "supervisorctl",
            &["status", program],
            Some(Duration::from_secs(5)),
            None,
        );

        if let Ok(output) = output {
            let stdout = output.stdout_str();
            stdout.contains("RUNNING")
        } else {
            false
        }
    }
}

impl Default for SupervisorActionRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert app supervision result to a supervisor plan action.
pub fn plan_action_from_app_supervision(
    action_id: &str,
    pid: u32,
    result: &AppSupervisionResult,
    command: SupervisorCommand,
) -> Option<SupervisorPlanAction> {
    if !result.is_supervised {
        return None;
    }

    let supervisor_type: SupervisorType = result.supervisor_type.into();
    if supervisor_type == SupervisorType::Unknown {
        return None;
    }

    let unit_identifier = result
        .supervisor_name
        .clone()
        .unwrap_or_else(|| format!("pid:{}", pid));

    let display_command = result
        .recommended_action
        .as_ref()
        .map(|a| a.command.clone())
        .unwrap_or_else(|| format!("{} {} {}", supervisor_type, command, unit_identifier));

    let mut parameters = SupervisorParameters::default();
    match supervisor_type {
        SupervisorType::Pm2 => {
            parameters.pm2_name = result.pm2_name.clone();
        }
        SupervisorType::Supervisord => {
            parameters.supervisord_program = result.supervisord_program.clone();
        }
        SupervisorType::Forever => {
            parameters.forever_uid = result.supervisor_name.clone();
        }
        _ => {}
    }

    Some(SupervisorPlanAction {
        action_id: action_id.to_string(),
        pid,
        supervisor_type,
        unit_identifier,
        command,
        display_command,
        parameters,
        timeout: Duration::from_secs(30),
        blocked: false,
        block_reason: None,
    })
}

/// Convert container supervision result to a supervisor plan action.
#[cfg(target_os = "linux")]
pub fn plan_action_from_container_supervision(
    action_id: &str,
    result: &ContainerSupervisionResult,
    command: SupervisorCommand,
) -> Option<SupervisorPlanAction> {
    use crate::collect::ContainerRuntime;

    if !result.in_container {
        return None;
    }

    let supervisor_type = match result.runtime {
        ContainerRuntime::Docker => SupervisorType::Docker,
        ContainerRuntime::Containerd => SupervisorType::Containerd,
        ContainerRuntime::Podman => SupervisorType::Podman,
        _ => return None, // LXC, CriO, Unknown not supported yet
    };

    let container_id = result.container_id.clone()?;
    let unit_identifier = container_id.clone();

    let display_command = result
        .recommended_action
        .as_ref()
        .map(|a| a.command.clone())
        .unwrap_or_else(|| format!("{} {} {}", supervisor_type, command, container_id));

    let parameters = SupervisorParameters {
        container_id: Some(container_id),
        ..Default::default()
    };

    Some(SupervisorPlanAction {
        action_id: action_id.to_string(),
        pid: result.pid,
        supervisor_type,
        unit_identifier,
        command,
        display_command,
        parameters,
        timeout: Duration::from_secs(30),
        blocked: false,
        block_reason: None,
    })
}

/// Convert existing SupervisorInfo (from prechecks) to a SupervisorPlanAction.
pub fn plan_action_from_supervisor_info(
    action_id: &str,
    pid: u32,
    info: &SupervisorInfo,
) -> SupervisorPlanAction {
    let supervisor_type = match info.supervisor.as_str() {
        "systemd" => SupervisorType::Systemd,
        "supervisord" => SupervisorType::Supervisord,
        "docker" | "containerd-shim" | "docker-containerd" => SupervisorType::Docker,
        "containerd" => SupervisorType::Containerd,
        _ => SupervisorType::Unknown,
    };

    let unit_identifier = info
        .unit_name
        .clone()
        .unwrap_or_else(|| format!("pid:{}", pid));

    let command = match &info.recommended_action {
        SupervisorAction::RestartUnit { .. } => SupervisorCommand::Restart,
        SupervisorAction::StopUnit { .. } => SupervisorCommand::Stop,
        SupervisorAction::KillProcess => SupervisorCommand::Kill,
    };

    let display_command = match &info.recommended_action {
        SupervisorAction::RestartUnit { command } => command.clone(),
        SupervisorAction::StopUnit { command } => command.clone(),
        SupervisorAction::KillProcess => format!("kill {}", pid),
    };

    let mut parameters = SupervisorParameters::default();
    if supervisor_type == SupervisorType::Systemd {
        parameters.systemd_unit = info.unit_name.clone();
    }

    SupervisorPlanAction {
        action_id: action_id.to_string(),
        pid,
        supervisor_type,
        unit_identifier,
        command,
        display_command,
        parameters,
        timeout: Duration::from_secs(30),
        blocked: false,
        block_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    mod user_restart {
        use super::*;
        use crate::collect::systemd::SystemdUserServiceState;
        use pt_common::StartId;

        fn binding() -> SystemdUserServiceBinding {
            // SAFETY: geteuid only reads the test process's credentials.
            let uid = unsafe { libc::geteuid() };
            SystemdUserServiceBinding {
                target: ProcessIdentity::full(
                    12345,
                    StartId::from_linux("restart-proof", 100, 12345),
                    uid,
                    Some(12345),
                    Some(12345),
                    IdentityQuality::Full,
                ),
                unit: "worker-proof.service".to_string(),
                control_group: format!(
                    "/user.slice/user-{uid}.slice/user@{uid}.service/worker-proof.service"
                ),
                invocation_id: "1234567890abcdef1234567890abcdef".to_string(),
            }
        }

        fn state(binding: &SystemdUserServiceBinding) -> SystemdUserServiceState {
            SystemdUserServiceState {
                unit: binding.unit.clone(),
                main_pid: binding.target.pid.0,
                control_group: binding.control_group.clone(),
                invocation_id: binding.invocation_id.clone(),
            }
        }

        fn action(binding: &SystemdUserServiceBinding) -> PlanAction {
            serde_json::from_value(serde_json::json!({
                "action_id": "user-restart-proof",
                "target": binding.target,
                "action": "restart",
                "order": 0,
                "stage": 0,
                "timeouts": {"preflight_ms": 5000, "execute_ms": 30000, "verify_ms": 10000},
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
                "routing": "supervisor",
                "supervisor_restart": binding,
            }))
            .expect("complete supervisor plan fixture")
        }

        #[test]
        fn binding_requires_exact_current_user_leaf_and_full_incarnation() {
            let valid = binding();
            assert!(valid.matches_target(&valid.target));
            let uid = valid.target.uid;
            for path in [
                "/system.slice/worker-proof.service".to_string(),
                format!("/user.slice/user-{uid}.slice/user@{uid}.service"),
                format!("/user.slice/user-{uid}.slice/user@{uid}.service/init.scope"),
                format!("{}/child", valid.control_group),
                format!("/user.slice/user-{uid}.slice/user@{uid}.service/../worker-proof.service"),
                format!("/user.slice/user-{uid}.slice/user@{uid}.service//worker-proof.service"),
                format!(
                    "/user.slice/user-{}.slice/user@{}.service/worker-proof.service",
                    uid + 1,
                    uid + 1
                ),
            ] {
                let mut changed = valid.clone();
                changed.control_group = path;
                assert!(
                    !changed.matches_target(&valid.target),
                    "{}",
                    changed.control_group
                );
            }
            for case in 0..7 {
                let mut changed = valid.clone();
                match case {
                    0 => changed.target.start_id = StartId::from_linux("restart-proof", 101, 12345),
                    1 => changed.target.uid = uid + 1,
                    2 => changed.target.quality = IdentityQuality::NoBootId,
                    3 => changed.target.sid = Some(54321),
                    4 => changed.invocation_id = "00000000000000000000000000000000".into(),
                    5 => changed.invocation_id = "not-an-invocation".into(),
                    _ => changed.unit = "*.service".into(),
                }
                assert!(!changed.matches_target(&valid.target), "case {case}");
            }
        }

        #[test]
        fn manager_binding_rejects_alias_pid_cgroup_and_invocation_mismatches() {
            let binding = binding();
            let ready = state(&binding);
            assert_eq!(
                binding_from_service_state(&binding.target, &binding.control_group, &ready)
                    .unwrap(),
                binding
            );
            for case in 0..4 {
                let mut changed = ready.clone();
                match case {
                    0 => changed.main_pid += 1,
                    1 => changed.unit = "alias.service".into(),
                    2 => changed.control_group.push_str("/child"),
                    _ => changed.invocation_id.clear(),
                }
                assert!(
                    binding_from_service_state(&binding.target, &binding.control_group, &changed)
                        .is_err(),
                    "case {case}"
                );
            }
        }

        #[test]
        fn verification_requires_new_invocation_live_replacement_and_original_exit() {
            let binding = binding();
            let replacement = ProcessIdentity::full(
                23456,
                StartId::from_linux("restart-proof", 200, 23456),
                binding.target.uid,
                Some(23456),
                Some(23456),
                IdentityQuality::Full,
            );
            let mut ready = state(&binding);
            ready.main_pid = replacement.pid.0;
            ready.invocation_id = "abcdef0123456789abcdef0123456789".to_string();
            verify_restarted_identity(&binding, &ready, &replacement, None).unwrap();
            assert!(verify_restarted_identity(
                &binding,
                &ready,
                &replacement,
                Some(&binding.target)
            )
            .is_err());
            for case in 0..8 {
                let mut changed = ready.clone();
                let mut process = replacement.clone();
                match case {
                    0 => changed.invocation_id = binding.invocation_id.clone(),
                    1 => changed.invocation_id = binding.invocation_id.to_uppercase(),
                    2 => changed.main_pid = binding.target.pid.0,
                    3 => changed.control_group.push_str("/other"),
                    4 => process.uid += 1,
                    5 => process.start_id = binding.target.start_id.clone(),
                    6 => process.quality = IdentityQuality::NoBootId,
                    _ => changed.unit = "other.service".into(),
                }
                assert!(
                    verify_restarted_identity(&binding, &changed, &process, None).is_err(),
                    "case {case}"
                );
            }
        }

        #[test]
        fn supervisor_route_cannot_be_smuggled_into_direct_or_zombie_actions() {
            let binding = binding();
            let valid = action(&binding);
            restart_binding_for_action(&valid).unwrap();
            for case in 0..6 {
                let mut changed = valid.clone();
                match case {
                    0 => changed.routing = ActionRouting::Direct,
                    1 => changed.routing = ActionRouting::ZombieToParent,
                    2 => changed.original_zombie_target = Some(binding.target.clone()),
                    3 => changed.action = Action::Kill,
                    4 => changed.supervisor_restart = None,
                    _ => changed.target.start_id = StartId::from_linux("restart-proof", 101, 12345),
                }
                let submitted = std::cell::Cell::new(false);
                assert!(
                    execute_systemd_user_restart(&changed, || submitted.set(true)).is_err(),
                    "case {case}"
                );
                assert!(
                    !submitted.get(),
                    "invalid route submitted a manager command"
                );
            }
        }

        #[test]
        fn zero_execution_and_verification_budgets_never_submit_or_report_success() {
            let mut action = action(&binding());
            action.timeouts.execute_ms = 0;
            action.timeouts.verify_ms = 0;
            let submitted = std::cell::Cell::new(false);
            assert!(execute_systemd_user_restart(&action, || submitted.set(true)).is_err());
            assert!(!submitted.get());
            assert!(verify_systemd_user_restart(&action).is_err());
        }
    }

    #[test]
    fn test_supervisor_type_display() {
        assert_eq!(SupervisorType::Systemd.to_string(), "systemd");
        assert_eq!(SupervisorType::Pm2.to_string(), "pm2");
        assert_eq!(SupervisorType::Docker.to_string(), "docker");
    }

    #[test]
    fn test_supervisor_command_display() {
        assert_eq!(SupervisorCommand::Stop.to_string(), "stop");
        assert_eq!(SupervisorCommand::Restart.to_string(), "restart");
        assert_eq!(SupervisorCommand::Kill.to_string(), "kill");
        assert_eq!(SupervisorCommand::Delete.to_string(), "delete");
    }

    #[test]
    fn test_supervisor_parameters_default() {
        let params = SupervisorParameters::default();
        assert!(params.systemd_unit.is_none());
        assert!(params.pm2_name.is_none());
        assert!(!params.force);
    }

    #[test]
    fn test_supervisor_action_config_default() {
        let config = SupervisorActionConfig::default();
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert_eq!(config.max_timeout, Duration::from_secs(120));
        assert!(config.allow_escalation);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_protected_patterns() {
        let runner = SupervisorActionRunner::new();
        assert!(runner.is_protected_unit("systemd-logind.service"));
        assert!(runner.is_protected_unit("dbus.service"));
        assert!(runner.is_protected_unit("sshd.service"));
        assert!(!runner.is_protected_unit("nginx.service"));
        assert!(!runner.is_protected_unit("my-app.service"));
    }

    #[test]
    fn test_build_systemd_command() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-1".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Systemd,
            unit_identifier: "nginx.service".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "systemctl stop nginx.service".to_string(),
            parameters: SupervisorParameters {
                systemd_unit: Some("nginx.service".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "systemctl");
        assert_eq!(args, vec!["stop", "nginx.service"]);
    }

    #[test]
    fn test_build_pm2_command() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-2".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Pm2,
            unit_identifier: "my-app".to_string(),
            command: SupervisorCommand::Restart,
            display_command: "pm2 restart my-app".to_string(),
            parameters: SupervisorParameters {
                pm2_name: Some("my-app".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "pm2");
        assert_eq!(args, vec!["restart", "my-app"]);
    }

    #[test]
    fn test_build_docker_command() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-3".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Docker,
            unit_identifier: "abc123".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "docker stop abc123".to_string(),
            parameters: SupervisorParameters {
                container_id: Some("abc123".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "docker");
        assert_eq!(args, vec!["stop", "abc123"]);
    }

    #[test]
    fn test_blocked_action_returns_error() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-blocked".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Systemd,
            unit_identifier: "test.service".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "systemctl stop test.service".to_string(),
            parameters: SupervisorParameters::default(),
            timeout: Duration::from_secs(30),
            blocked: true,
            block_reason: Some("protected by policy".to_string()),
        };

        let result = runner.execute_supervisor_action(&action);
        assert!(matches!(
            result,
            Err(SupervisorActionError::ProtectedUnit(_))
        ));
    }

    #[test]
    fn test_dry_run_mode() {
        let config = SupervisorActionConfig {
            dry_run: true,
            ..Default::default()
        };
        let runner = SupervisorActionRunner::with_config(config);

        let action = SupervisorPlanAction {
            action_id: "test-dry".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Pm2,
            unit_identifier: "my-app".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "pm2 stop my-app".to_string(),
            parameters: SupervisorParameters::default(),
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let result = runner.execute_supervisor_action(&action).unwrap();
        assert!(result.success);
        assert!(result.stdout.unwrap().contains("[dry-run]"));
    }

    #[test]
    fn test_supervisor_type_from_app_type() {
        assert_eq!(
            SupervisorType::from(AppSupervisorType::Pm2),
            SupervisorType::Pm2
        );
        assert_eq!(
            SupervisorType::from(AppSupervisorType::Supervisord),
            SupervisorType::Supervisord
        );
        assert_eq!(
            SupervisorType::from(AppSupervisorType::Nodemon),
            SupervisorType::Nodemon
        );
    }

    #[test]
    fn test_launchd_type_display() {
        assert_eq!(SupervisorType::Launchd.to_string(), "launchd");
    }

    #[test]
    fn test_build_launchd_command_stop() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-launchd-stop".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Launchd,
            unit_identifier: "com.example.myservice".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "launchctl bootout system/com.example.myservice".to_string(),
            parameters: SupervisorParameters {
                launchd_label: Some("com.example.myservice".to_string()),
                launchd_domain: Some("system".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "launchctl");
        assert_eq!(args, vec!["bootout", "system/com.example.myservice"]);
    }

    #[test]
    fn test_build_launchd_command_restart() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-launchd-restart".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Launchd,
            unit_identifier: "com.apple.Spotlight".to_string(),
            command: SupervisorCommand::Restart,
            display_command: "launchctl kickstart -k gui/501/com.apple.Spotlight".to_string(),
            parameters: SupervisorParameters {
                launchd_label: Some("com.apple.Spotlight".to_string()),
                launchd_domain: Some("gui/501".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "launchctl");
        assert_eq!(args, vec!["kickstart", "-k", "gui/501/com.apple.Spotlight"]);
    }

    #[test]
    fn test_build_launchd_command_kill() {
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-launchd-kill".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Launchd,
            unit_identifier: "com.example.daemon".to_string(),
            command: SupervisorCommand::Kill,
            display_command: "launchctl kill KILL system/com.example.daemon".to_string(),
            parameters: SupervisorParameters {
                launchd_label: Some("com.example.daemon".to_string()),
                launchd_domain: Some("system".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "launchctl");
        assert_eq!(args, vec!["kill", "KILL", "system/com.example.daemon"]);
    }

    #[test]
    fn test_build_launchd_command_default_domain() {
        // Test that system domain is used when launchd_domain is not specified
        let runner = SupervisorActionRunner::new();
        let action = SupervisorPlanAction {
            action_id: "test-launchd-default".to_string(),
            pid: 1234,
            supervisor_type: SupervisorType::Launchd,
            unit_identifier: "com.example.service".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "launchctl bootout system/com.example.service".to_string(),
            parameters: SupervisorParameters {
                launchd_label: Some("com.example.service".to_string()),
                // launchd_domain is None - should default to "system"
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };

        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "launchctl");
        assert_eq!(args, vec!["bootout", "system/com.example.service"]);
    }

    #[test]
    fn test_supervisor_parameters_launchd_fields() {
        let params = SupervisorParameters {
            launchd_label: Some("com.example.myservice".to_string()),
            launchd_domain: Some("gui/501".to_string()),
            ..Default::default()
        };

        assert_eq!(
            params.launchd_label,
            Some("com.example.myservice".to_string())
        );
        assert_eq!(params.launchd_domain, Some("gui/501".to_string()));
        assert!(params.systemd_unit.is_none());
    }

    // ── SupervisorType serde roundtrip ──────────────────────────────

    #[test]
    fn supervisor_type_serde_all_variants() {
        let variants = [
            SupervisorType::Systemd,
            SupervisorType::Launchd,
            SupervisorType::Pm2,
            SupervisorType::Supervisord,
            SupervisorType::Docker,
            SupervisorType::Containerd,
            SupervisorType::Podman,
            SupervisorType::Nodemon,
            SupervisorType::Forever,
            SupervisorType::Unknown,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SupervisorType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn supervisor_type_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&SupervisorType::Systemd).unwrap(),
            "\"systemd\""
        );
        assert_eq!(
            serde_json::to_string(&SupervisorType::Containerd).unwrap(),
            "\"containerd\""
        );
        assert_eq!(
            serde_json::to_string(&SupervisorType::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    // ── SupervisorType Display all remaining variants ────────────────

    #[test]
    fn supervisor_type_display_all() {
        assert_eq!(SupervisorType::Supervisord.to_string(), "supervisord");
        assert_eq!(SupervisorType::Containerd.to_string(), "containerd");
        assert_eq!(SupervisorType::Podman.to_string(), "podman");
        assert_eq!(SupervisorType::Nodemon.to_string(), "nodemon");
        assert_eq!(SupervisorType::Forever.to_string(), "forever");
        assert_eq!(SupervisorType::Unknown.to_string(), "unknown");
    }

    // ── SupervisorCommand serde roundtrip ────────────────────────────

    #[test]
    fn supervisor_command_serde_all_variants() {
        let variants = [
            SupervisorCommand::Stop,
            SupervisorCommand::Restart,
            SupervisorCommand::Kill,
            SupervisorCommand::Delete,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SupervisorCommand = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{}", v), format!("{}", back));
        }
    }

    // ── SupervisorActionError display all variants ───────────────────

    #[test]
    fn supervisor_action_error_display_all() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SupervisorActionError::UnsupportedSupervisor(
                "exotic".to_string(),
            )),
            Box::new(SupervisorActionError::CommandFailed("exit 1".to_string())),
            Box::new(SupervisorActionError::Timeout(Duration::from_secs(30))),
            Box::new(SupervisorActionError::ProcessRespawned),
            Box::new(SupervisorActionError::ProcessStillRunning),
            Box::new(SupervisorActionError::PermissionDenied(
                "no sudo".to_string(),
            )),
            Box::new(SupervisorActionError::UnitNotFound(
                "missing.service".to_string(),
            )),
            Box::new(SupervisorActionError::ProtectedUnit(
                "sshd.service".to_string(),
            )),
        ];
        let expected_fragments = [
            "unsupported supervisor",
            "command execution failed",
            "timed out",
            "respawned",
            "still running",
            "permission denied",
            "not found",
            "protected unit",
        ];
        for (err, frag) in errors.iter().zip(expected_fragments.iter()) {
            let msg = format!("{}", err);
            assert!(msg.contains(frag), "Expected '{}' in: {}", frag, msg);
        }
    }

    #[test]
    fn supervisor_action_error_io_variant() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = SupervisorActionError::from(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("io error"));
    }

    // ── SupervisorPlanAction serde roundtrip ─────────────────────────

    #[test]
    fn supervisor_plan_action_serde_roundtrip() {
        let action = SupervisorPlanAction {
            action_id: "test-serde".to_string(),
            pid: 5678,
            supervisor_type: SupervisorType::Docker,
            unit_identifier: "abc123".to_string(),
            command: SupervisorCommand::Stop,
            display_command: "docker stop abc123".to_string(),
            parameters: SupervisorParameters {
                container_id: Some("abc123".to_string()),
                ..Default::default()
            },
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: SupervisorPlanAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action_id, "test-serde");
        assert_eq!(back.pid, 5678);
        assert_eq!(back.supervisor_type, SupervisorType::Docker);
        assert_eq!(back.command.to_string(), "stop");
        assert!(!back.blocked);
    }

    // ── SupervisorParameters serde roundtrip ─────────────────────────

    #[test]
    fn supervisor_parameters_serde_roundtrip() {
        let params = SupervisorParameters {
            systemd_unit: Some("nginx.service".to_string()),
            launchd_label: None,
            launchd_domain: None,
            pm2_name: Some("my-app".to_string()),
            container_id: None,
            supervisord_program: Some("myworker".to_string()),
            forever_uid: Some("abc123".to_string()),
            force: true,
            signal: Some("SIGTERM".to_string()),
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: SupervisorParameters = serde_json::from_str(&json).unwrap();
        assert_eq!(back.systemd_unit, Some("nginx.service".to_string()));
        assert_eq!(back.pm2_name, Some("my-app".to_string()));
        assert!(back.force);
        assert_eq!(back.signal, Some("SIGTERM".to_string()));
    }

    #[test]
    fn supervisor_parameters_serde_skips_none_fields() {
        let params = SupervisorParameters::default();
        let json = serde_json::to_string(&params).unwrap();
        // None fields should be omitted due to skip_serializing_if
        assert!(!json.contains("systemd_unit"));
        assert!(!json.contains("pm2_name"));
        assert!(json.contains("\"force\":false"));
    }

    // ── Build commands for remaining supervisors ─────────────────────

    fn make_action(
        supervisor_type: SupervisorType,
        command: SupervisorCommand,
        params: SupervisorParameters,
    ) -> SupervisorPlanAction {
        SupervisorPlanAction {
            action_id: "test-build".to_string(),
            pid: 1234,
            supervisor_type,
            unit_identifier: "test-unit".to_string(),
            command,
            display_command: "test command".to_string(),
            parameters: params,
            timeout: Duration::from_secs(30),
            blocked: false,
            block_reason: None,
        }
    }

    #[test]
    fn build_containerd_stop_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Containerd,
            SupervisorCommand::Stop,
            SupervisorParameters {
                container_id: Some("ctr-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "ctr");
        assert_eq!(args, vec!["task", "kill", "ctr-abc"]);
    }

    #[test]
    fn build_containerd_delete_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Containerd,
            SupervisorCommand::Delete,
            SupervisorParameters {
                container_id: Some("ctr-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "ctr");
        assert_eq!(args, vec!["container", "delete", "ctr-abc"]);
    }

    #[test]
    fn build_supervisord_stop_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Supervisord,
            SupervisorCommand::Stop,
            SupervisorParameters {
                supervisord_program: Some("myworker".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "supervisorctl");
        assert_eq!(args, vec!["stop", "myworker"]);
    }

    #[test]
    fn build_supervisord_restart_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Supervisord,
            SupervisorCommand::Restart,
            SupervisorParameters {
                supervisord_program: Some("myworker".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "supervisorctl");
        assert_eq!(args, vec!["restart", "myworker"]);
    }

    #[test]
    fn build_supervisord_delete_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Supervisord,
            SupervisorCommand::Delete,
            SupervisorParameters {
                supervisord_program: Some("myworker".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "supervisorctl");
        assert_eq!(args, vec!["remove", "myworker"]);
    }

    #[test]
    fn build_podman_stop_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Podman,
            SupervisorCommand::Stop,
            SupervisorParameters {
                container_id: Some("pod-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "podman");
        assert_eq!(args, vec!["stop", "pod-abc"]);
    }

    #[test]
    fn build_podman_kill_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Podman,
            SupervisorCommand::Kill,
            SupervisorParameters {
                container_id: Some("pod-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "podman");
        assert_eq!(args, vec!["kill", "pod-abc"]);
    }

    #[test]
    fn build_podman_delete_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Podman,
            SupervisorCommand::Delete,
            SupervisorParameters {
                container_id: Some("pod-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "podman");
        assert_eq!(args, vec!["rm", "-f", "pod-abc"]);
    }

    #[test]
    fn build_forever_stop_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Forever,
            SupervisorCommand::Stop,
            SupervisorParameters {
                forever_uid: Some("uid-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "forever");
        assert_eq!(args, vec!["stop", "uid-abc"]);
    }

    #[test]
    fn build_forever_restart_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Forever,
            SupervisorCommand::Restart,
            SupervisorParameters {
                forever_uid: Some("uid-abc".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "forever");
        assert_eq!(args, vec!["restart", "uid-abc"]);
    }

    #[test]
    fn build_nodemon_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Nodemon,
            SupervisorCommand::Stop,
            SupervisorParameters::default(),
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "kill");
        assert_eq!(args, vec!["-INT", "1234"]);
    }

    #[test]
    fn build_unknown_supervisor_returns_error() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Unknown,
            SupervisorCommand::Stop,
            SupervisorParameters::default(),
        );
        let result = runner.build_command(&action);
        assert!(matches!(
            result,
            Err(SupervisorActionError::UnsupportedSupervisor(_))
        ));
    }

    // ── Systemd additional commands ──────────────────────────────────

    #[test]
    fn build_systemd_restart_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Systemd,
            SupervisorCommand::Restart,
            SupervisorParameters {
                systemd_unit: Some("nginx.service".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "systemctl");
        assert_eq!(args, vec!["restart", "nginx.service"]);
    }

    #[test]
    fn build_systemd_kill_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Systemd,
            SupervisorCommand::Kill,
            SupervisorParameters {
                systemd_unit: Some("nginx.service".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "systemctl");
        assert_eq!(args, vec!["kill", "nginx.service"]);
    }

    #[test]
    fn build_systemd_delete_disables() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Systemd,
            SupervisorCommand::Delete,
            SupervisorParameters {
                systemd_unit: Some("nginx.service".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "systemctl");
        assert_eq!(args, vec!["disable", "nginx.service"]);
    }

    // ── Docker additional commands ───────────────────────────────────

    #[test]
    fn build_docker_kill_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Docker,
            SupervisorCommand::Kill,
            SupervisorParameters {
                container_id: Some("abc123".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "docker");
        assert_eq!(args, vec!["kill", "abc123"]);
    }

    #[test]
    fn build_docker_delete_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Docker,
            SupervisorCommand::Delete,
            SupervisorParameters {
                container_id: Some("abc123".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "docker");
        assert_eq!(args, vec!["rm", "-f", "abc123"]);
    }

    // ── PM2 additional commands ──────────────────────────────────────

    #[test]
    fn build_pm2_stop_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Pm2,
            SupervisorCommand::Stop,
            SupervisorParameters {
                pm2_name: Some("my-app".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "pm2");
        assert_eq!(args, vec!["stop", "my-app"]);
    }

    #[test]
    fn build_pm2_kill_uses_stop() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Pm2,
            SupervisorCommand::Kill,
            SupervisorParameters {
                pm2_name: Some("my-app".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "pm2");
        assert_eq!(args, vec!["stop", "my-app"]); // Kill maps to stop for pm2
    }

    #[test]
    fn build_pm2_delete_command() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Pm2,
            SupervisorCommand::Delete,
            SupervisorParameters {
                pm2_name: Some("my-app".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "pm2");
        assert_eq!(args, vec!["delete", "my-app"]);
    }

    // ── From<AppSupervisorType> remaining variants ───────────────────

    #[test]
    fn supervisor_type_from_app_type_remaining() {
        assert_eq!(
            SupervisorType::from(AppSupervisorType::Forever),
            SupervisorType::Forever
        );
        assert_eq!(
            SupervisorType::from(AppSupervisorType::Unknown),
            SupervisorType::Unknown
        );
    }

    // ── SupervisorActionRunner Default trait ─────────────────────────

    #[test]
    fn supervisor_action_runner_default() {
        let runner = SupervisorActionRunner::default();
        assert_eq!(runner.config.default_timeout, Duration::from_secs(30));
        assert!(!runner.config.dry_run);
    }

    // ── SupervisorActionResult serde ─────────────────────────────────

    #[test]
    fn supervisor_action_result_serde() {
        let result = SupervisorActionResult {
            success: true,
            duration: Duration::from_millis(250),
            stdout: Some("stopped".to_string()),
            stderr: None,
            exit_code: Some(0),
            respawned: false,
            warnings: vec!["check later".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"respawned\":false"));
    }

    // ── Protected patterns: cron, docker.service, containerd.service ─

    #[test]
    fn protected_patterns_additional() {
        let runner = SupervisorActionRunner::new();
        assert!(runner.is_protected_unit("cron.service"));
        assert!(runner.is_protected_unit("docker.service"));
        assert!(runner.is_protected_unit("containerd.service"));
        // Partial match shouldn't work (cron pattern is ^cron.*)
        assert!(!runner.is_protected_unit("my-cron-app"));
    }

    // ── SupervisorActionConfig custom values ─────────────────────────

    #[test]
    fn supervisor_action_config_custom() {
        let config = SupervisorActionConfig {
            default_timeout: Duration::from_secs(10),
            max_timeout: Duration::from_secs(60),
            respawn_check_delay: Duration::from_secs(1),
            respawn_check_count: 5,
            protected_patterns: vec![r"^myapp.*".to_string()],
            allow_escalation: false,
            dry_run: true,
        };
        let runner = SupervisorActionRunner::with_config(config);
        assert!(runner.is_protected_unit("myapp.service"));
        assert!(!runner.is_protected_unit("otherapp.service"));
    }

    // ── Launchd delete command ───────────────────────────────────────

    #[test]
    fn build_launchd_delete_uses_bootout() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Launchd,
            SupervisorCommand::Delete,
            SupervisorParameters {
                launchd_label: Some("com.example.service".to_string()),
                launchd_domain: Some("system".to_string()),
                ..Default::default()
            },
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "launchctl");
        assert_eq!(args, vec!["bootout", "system/com.example.service"]);
    }

    // ── Build command uses unit_identifier as fallback ────────────────

    #[test]
    fn build_command_uses_unit_identifier_fallback() {
        let runner = SupervisorActionRunner::new();
        let action = make_action(
            SupervisorType::Systemd,
            SupervisorCommand::Stop,
            SupervisorParameters::default(), // No systemd_unit set
        );
        let (program, args) = runner.build_command(&action).unwrap();
        assert_eq!(program, "systemctl");
        assert_eq!(args, vec!["stop", "test-unit"]); // Falls back to unit_identifier
    }
}
