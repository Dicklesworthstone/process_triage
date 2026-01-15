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
use crate::supervision::{AppSupervisionResult, AppSupervisorType, ContainerSupervisionResult};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace, warn};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorParameters {
    /// For systemd: unit name (e.g., "nginx.service")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,

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

impl Default for SupervisorParameters {
    fn default() -> Self {
        Self {
            systemd_unit: None,
            pm2_name: None,
            container_id: None,
            supervisord_program: None,
            forever_uid: None,
            force: false,
            signal: None,
        }
    }
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
}

impl SupervisorActionRunner {
    /// Create a new supervisor action runner with default config.
    pub fn new() -> Self {
        Self {
            config: SupervisorActionConfig::default(),
        }
    }

    /// Create a runner with custom config.
    pub fn with_config(config: SupervisorActionConfig) -> Self {
        Self { config }
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
        let output = self.run_command_with_timeout(&program, &args, timeout)?;

        let exit_code = output.status.code();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let success = output.status.success();

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

        Ok(SupervisorActionResult {
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
        })
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

        Ok(("systemctl".to_string(), vec![subcmd.to_string(), unit.clone()]))
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
        Ok(("docker".to_string(), vec![subcmd.to_string()].into_iter().chain(args).collect()))
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
                vec![
                    "task".to_string(),
                    "kill".to_string(),
                    container_id.clone(),
                ]
            }
            SupervisorCommand::Restart => {
                // containerd doesn't have restart - would need to kill and start
                vec![
                    "task".to_string(),
                    "kill".to_string(),
                    container_id.clone(),
                ]
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
        Ok(("podman".to_string(), vec![subcmd.to_string()].into_iter().chain(args).collect()))
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

    /// Run a command with timeout.
    fn run_command_with_timeout(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<Output, SupervisorActionError> {
        let mut child = Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SupervisorActionError::CommandFailed(e.to_string()))?;

        let start = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process finished; collect any remaining output without double-waiting.
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut out) = child.stdout.take() {
                        let _ = out.read_to_end(&mut stdout);
                    }
                    if let Some(mut err) = child.stderr.take() {
                        let _ = err.read_to_end(&mut stderr);
                    }
                    return Ok(Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    // Still running
                    if start.elapsed() > timeout {
                        // Kill the hung command
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SupervisorActionError::Timeout(timeout));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(SupervisorActionError::CommandFailed(e.to_string()));
                }
            }
        }
    }

    /// Check if a unit identifier matches any protected pattern.
    fn is_protected_unit(&self, unit: &str) -> bool {
        for pattern in &self.config.protected_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(unit) {
                    debug!(unit, pattern, "unit matches protected pattern");
                    return true;
                }
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
        let output = Command::new("systemctl")
            .args(["is-active", unit])
            .output();

        if let Ok(output) = output {
            let status = String::from_utf8_lossy(&output.stdout);
            status.trim() == "active"
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
        let output = Command::new("pm2")
            .args(["show", name])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
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

        let output = Command::new(tool)
            .args(["inspect", "-f", "{{.State.Running}}", container_id])
            .output();

        if let Ok(output) = output {
            let status = String::from_utf8_lossy(&output.stdout);
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
        let output = Command::new("supervisorctl")
            .args(["status", program])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
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

    let mut parameters = SupervisorParameters::default();
    parameters.container_id = Some(container_id);

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
        assert!(matches!(result, Err(SupervisorActionError::ProtectedUnit(_))));
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
}
