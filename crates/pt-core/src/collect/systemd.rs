//! Systemd unit detection and collection.
//!
//! This module provides systemd unit information for process triage:
//! - Unit name and type detection via `systemctl status <pid>`
//! - Active state and sub-state
//! - Main PID tracking for service restart detection
//!
//! # Data Sources
//! - `systemctl show --property=... <pid>` - structured unit info
//! - Cgroup path parsing (fallback when systemctl unavailable)

use crate::collect::tool_runner::run_tool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Ready-to-restart service state from the current user's actual systemd manager.
/// Cgroup-only fallback evidence is deliberately insufficient for this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUserServiceState {
    pub unit: String,
    pub main_pid: u32,
    pub control_group: String,
    pub invocation_id: String,
}

#[cfg(target_os = "linux")]
const USER_RESTART_PROPERTIES: &str = "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,Type,KillMode,Delegate,CanStart,CanStop,RefuseManualStart,RefuseManualStop,DefaultDependencies,Requires,Wants,Requisite,BindsTo,Upholds,Conflicts,ConflictedBy,ConsistsOf,BoundBy,RequiredBy,RequisiteOf,PropagatesStopTo,OnFailure,OnSuccess,FailureAction,SuccessAction,StartLimitAction,StopWhenUnneeded";

/// Names passed to systemctl must name one literal service, never a pattern,
/// option, path, template without an instance, or escaped alternative spelling.
pub fn is_literal_service_unit(unit: &str) -> bool {
    unit.len() <= 255
        && unit.len() > ".service".len()
        && unit.ends_with(".service")
        && !unit.starts_with(['-', '.'])
        && !unit.ends_with("@.service")
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@:-".contains(&byte))
}

/// Query the current user's manager, with no fallback to the system manager or
/// a guessed unit. The timeout includes the tool runner's termination grace.
#[cfg(target_os = "linux")]
pub fn query_systemd_user_service(
    unit: &str,
    uid: u32,
    timeout: Duration,
) -> Result<SystemdUserServiceState, String> {
    let started = std::time::Instant::now();
    if !is_literal_service_unit(unit) {
        return Err("restart requires one literal .service unit".to_string());
    }
    let output = run_user_systemctl(
        uid,
        &["show", "--all", USER_RESTART_PROPERTIES, "--", unit],
        timeout,
    )?;
    let state = parse_systemd_user_service(&output.stdout_str())?;
    if state.unit != unit {
        return Err("systemd returned an alias or a different service identity".to_string());
    }
    // Every service implicitly Requires its slice. Permit only the manager's
    // perpetual root slice, and prove its START transaction cannot pull in any
    // further units. Even active ordinary slices/targets can expand a start job.
    let remaining = timeout
        .checked_sub(started.elapsed())
        .ok_or_else(|| "user-manager scope proof exhausted its budget".to_string())?;
    let root = run_user_systemctl(
        uid,
        &["show", "--all", USER_RESTART_PROPERTIES, "--", "-.slice"],
        remaining,
    )?;
    validate_user_root_slice(&root.stdout_str())?;
    Ok(state)
}

/// Run a literal command against `/run/user/<uid>/bus`. ToolRunner clears the
/// environment, so passing --user alone cannot select the user's manager; using
/// inherited DBUS_SESSION_BUS_ADDRESS would also permit a different manager.
#[cfg(target_os = "linux")]
pub(crate) fn run_user_systemctl(
    uid: u32,
    args: &[&str],
    timeout: Duration,
) -> Result<crate::collect::tool_runner::ToolOutput, String> {
    use crate::collect::tool_runner::{ToolConfig, ToolRunner};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::time::Instant;

    let started = Instant::now();
    // SAFETY: geteuid only reads the caller's credentials.
    if uid != unsafe { libc::geteuid() } {
        return Err("restart is restricted to the current user's manager".to_string());
    }
    let runtime = format!("/run/user/{uid}");
    let directory = std::fs::symlink_metadata(&runtime)
        .map_err(|error| format!("user manager runtime directory unavailable: {error}"))?;
    if !directory.is_dir() || directory.uid() != uid || directory.mode() & 0o077 != 0 {
        return Err("user manager runtime directory is not private to this user".to_string());
    }
    let bus = std::fs::symlink_metadata(format!("{runtime}/bus"))
        .map_err(|error| format!("user manager bus unavailable: {error}"))?;
    if !bus.file_type().is_socket() || bus.uid() != uid {
        return Err("user manager bus is not a socket owned by this user".to_string());
    }
    let systemctl = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or_else(|| "systemctl is unavailable".to_string())?;
    let env = ["/usr/bin/env", "/bin/env"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or_else(|| "env is unavailable".to_string())?;
    let owned_args = user_systemctl_arguments(uid, systemctl, args);
    let borrowed_args: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    // ToolRunner allows 500 ms for SIGTERM cleanup and polls every 10 ms. Reserve
    // that time before spawning, rather than exceeding the caller's whole budget.
    let command_timeout = timeout
        .checked_sub(started.elapsed())
        .and_then(|remaining| remaining.checked_sub(Duration::from_millis(600)))
        .filter(|remaining| *remaining >= Duration::from_millis(1))
        .ok_or_else(|| "systemctl time budget exhausted before invocation".to_string())?;
    let config = ToolConfig {
        default_timeout: command_timeout,
        budget_ms: u64::try_from(command_timeout.as_millis()).unwrap_or(u64::MAX),
        max_output_bytes: 64 * 1024,
        use_nice: false,
        use_ionice: false,
        ..ToolConfig::default()
    };
    let output = ToolRunner::new(config)
        .run_tool(env, &borrowed_args, Some(command_timeout))
        .map_err(|error| format!("systemctl failed: {error}"))?;
    if started.elapsed() >= timeout || output.timed_out {
        return Err("systemctl time budget exhausted".to_string());
    }
    if output.truncated {
        return Err("systemctl evidence exceeded the output limit".to_string());
    }
    if !output.success() {
        return Err(format!(
            "systemctl exited with {:?}: {}",
            output.exit_code,
            output.stderr_str().trim()
        ));
    }
    Ok(output)
}

#[cfg(any(target_os = "linux", test))]
fn user_systemctl_arguments(uid: u32, systemctl: &str, args: &[&str]) -> Vec<String> {
    let mut result = vec![
        format!("XDG_RUNTIME_DIR=/run/user/{uid}"),
        format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"),
        systemctl.to_string(),
        "--user".to_string(),
        "--no-pager".to_string(),
        "--no-ask-password".to_string(),
    ];
    result.extend(args.iter().map(|argument| (*argument).to_string()));
    result
}

/// Parse complete properties without turning missing or duplicate evidence into
/// empty dependency lists. `show --all` is required to retain empty properties.
#[cfg(any(target_os = "linux", test))]
fn user_unit_properties(output: &str) -> Result<HashMap<&str, &str>, String> {
    let mut properties = HashMap::new();
    if !output.ends_with('\n') {
        return Err("incomplete systemd service evidence".to_string());
    }
    for line in output.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "malformed systemd service property".to_string())?;
        if properties.insert(key, value).is_some() {
            return Err(format!("duplicate systemd service property {key}"));
        }
    }
    Ok(properties)
}

#[cfg(any(target_os = "linux", test))]
fn required_user_property<'a>(
    properties: &HashMap<&str, &'a str>,
    key: &str,
) -> Result<&'a str, String> {
    properties
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing systemd service property {key}"))
}

/// A restart recursively adds START jobs for forward requirements, even if they
/// are already active, and STOP jobs for conflicts. No dependency-bypass mode is
/// used: require an isolated service and prove the sole root-slice START is inert.
#[cfg(any(target_os = "linux", test))]
fn validate_user_start_scope(properties: &HashMap<&str, &str>, root: bool) -> Result<(), String> {
    let requires = required_user_property(properties, "Requires")?;
    if requires != if root { "" } else { "-.slice" } {
        return Err(format!(
            "bounded restart requires DefaultDependencies=no and Slice=-.slice; Requires={requires}"
        ));
    }
    for key in [
        "Wants",
        "Requisite",
        "BindsTo",
        "Upholds",
        "Conflicts",
        "ConflictedBy",
        "OnFailure",
        "OnSuccess",
    ] {
        let actual = required_user_property(properties, key)?;
        if !actual.is_empty() {
            return Err(format!(
                "service transaction would extend its scope: {key}={actual}"
            ));
        }
    }
    for (key, expected) in [
        ("DefaultDependencies", "no"),
        ("FailureAction", "none"),
        ("SuccessAction", "none"),
        ("StartLimitAction", "none"),
        ("StopWhenUnneeded", "no"),
    ] {
        let actual = required_user_property(properties, key)?;
        if actual != expected {
            return Err(format!(
                "service transaction has unsafe side effects: {key}={actual}"
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn validate_user_root_slice(output: &str) -> Result<(), String> {
    let properties = user_unit_properties(output)?;
    for (key, expected) in [
        ("Id", "-.slice"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
    ] {
        if required_user_property(&properties, key)? != expected {
            return Err(format!(
                "user manager root slice is unavailable or changed: {key}"
            ));
        }
    }
    // RequiredBy/BoundBy are intentionally not rejected here: this perpetual
    // slice receives START, never STOP/RESTART, so reverse propagation cannot
    // occur. Its RequiredBy list normally includes every service in this slice.
    validate_user_start_scope(&properties, true)
}

/// Require a complete ready state and no stop/restart propagation to other units.
/// Only simple/exec services with control-group termination are supported.
#[cfg(any(target_os = "linux", test))]
fn parse_systemd_user_service(output: &str) -> Result<SystemdUserServiceState, String> {
    let properties = user_unit_properties(output)?;
    validate_user_start_scope(&properties, false)?;
    let required = |key: &str| required_user_property(&properties, key);
    for (key, expected) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("ControlPID", "0"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("CanStart", "yes"),
        ("CanStop", "yes"),
        ("RefuseManualStart", "no"),
        ("RefuseManualStop", "no"),
        ("ConsistsOf", ""),
        ("BoundBy", ""),
        ("RequiredBy", ""),
        ("RequisiteOf", ""),
        ("PropagatesStopTo", ""),
    ] {
        let actual = required(key)?;
        if actual != expected {
            return Err(format!(
                "service is not eligible for bounded restart: {key}={actual}"
            ));
        }
    }
    if !matches!(required("Type")?, "simple" | "exec") {
        return Err("bounded restart requires Type=simple or Type=exec".to_string());
    }
    let unit = required("Id")?;
    if !is_literal_service_unit(unit) {
        return Err("systemd returned an invalid literal service name".to_string());
    }
    let main_pid = required("MainPID")?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| "systemd returned no usable MainPID".to_string())?;
    Ok(SystemdUserServiceState {
        unit: unit.to_string(),
        main_pid,
        control_group: required("ControlGroup")?.to_string(),
        invocation_id: required("InvocationID")?.to_string(),
    })
}

/// Systemd unit information for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemdUnit {
    /// Full unit name (e.g., "nginx.service", "session-1.scope").
    pub name: String,

    /// Unit type (service, scope, slice, socket, etc.).
    pub unit_type: SystemdUnitType,

    /// Current active state.
    pub active_state: SystemdActiveState,

    /// Sub-state (running, exited, dead, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_state: Option<String>,

    /// Main PID of the unit (for services).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_pid: Option<u32>,

    /// Control PID (for units with control processes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_pid: Option<u32>,

    /// Fragment path (unit file location).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_path: Option<String>,

    /// Unit description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether this process is the main process of the unit.
    pub is_main_process: bool,

    /// Provenance tracking.
    pub provenance: SystemdProvenance,
}

/// Systemd unit type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemdUnitType {
    /// .service units (daemons, services).
    Service,
    /// .scope units (externally started processes).
    Scope,
    /// .slice units (resource management).
    Slice,
    /// .socket units (socket activation).
    Socket,
    /// .target units (synchronization points).
    Target,
    /// .mount units (mount points).
    Mount,
    /// .timer units (timer activation).
    Timer,
    /// .path units (path-based activation).
    Path,
    /// Unknown or not a systemd unit.
    #[default]
    Unknown,
}

impl SystemdUnitType {
    /// Parse unit type from unit name suffix.
    pub fn from_unit_name(name: &str) -> Self {
        if name.ends_with(".service") {
            SystemdUnitType::Service
        } else if name.ends_with(".scope") {
            SystemdUnitType::Scope
        } else if name.ends_with(".slice") {
            SystemdUnitType::Slice
        } else if name.ends_with(".socket") {
            SystemdUnitType::Socket
        } else if name.ends_with(".target") {
            SystemdUnitType::Target
        } else if name.ends_with(".mount") {
            SystemdUnitType::Mount
        } else if name.ends_with(".timer") {
            SystemdUnitType::Timer
        } else if name.ends_with(".path") {
            SystemdUnitType::Path
        } else {
            SystemdUnitType::Unknown
        }
    }
}

/// Systemd active state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemdActiveState {
    /// Unit is active and running.
    Active,
    /// Unit is being activated.
    Activating,
    /// Unit is being deactivated.
    Deactivating,
    /// Unit is inactive (stopped).
    Inactive,
    /// Unit has failed.
    Failed,
    /// Unit is being reloaded.
    Reloading,
    /// Unknown state.
    #[default]
    Unknown,
}

impl SystemdActiveState {
    /// Parse active state from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "active" => SystemdActiveState::Active,
            "activating" => SystemdActiveState::Activating,
            "deactivating" => SystemdActiveState::Deactivating,
            "inactive" => SystemdActiveState::Inactive,
            "failed" => SystemdActiveState::Failed,
            "reloading" => SystemdActiveState::Reloading,
            _ => SystemdActiveState::Unknown,
        }
    }

    /// Whether the unit is in a running/active state.
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            SystemdActiveState::Active | SystemdActiveState::Reloading
        )
    }
}

/// Provenance tracking for systemd data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemdProvenance {
    /// Source of the unit info (systemctl, cgroup_path, etc.).
    pub source: SystemdDataSource,

    /// Any warnings during collection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Source of systemd unit information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemdDataSource {
    /// From `systemctl show` command.
    SystemctlShow,
    /// From cgroup path parsing.
    CgroupPath,
    /// Not available.
    #[default]
    None,
}

/// Collect systemd unit information for a process.
///
/// First tries `systemctl show`, falls back to cgroup path parsing.
///
/// # Arguments
/// * `pid` - Process ID
/// * `cgroup_unit` - Unit name from cgroup path (fallback)
///
/// # Returns
/// * `Option<SystemdUnit>` - Unit info or None if not managed by systemd
pub fn collect_systemd_unit(pid: u32, cgroup_unit: Option<&str>) -> Option<SystemdUnit> {
    if let Some(unit_name) = cgroup_unit {
        // Try systemctl show first
        if let Some(unit) = query_systemctl(unit_name, pid) {
            return Some(unit);
        }

        // Fall back to cgroup path info
        return Some(unit_from_cgroup_path(unit_name, pid));
    }

    None
}

/// Query systemctl for unit information.
fn query_systemctl(unit_name: &str, pid: u32) -> Option<SystemdUnit> {
    // Properties to query
    let properties = [
        "Id",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "FragmentPath",
        "Description",
    ];

    let property_arg = properties.join(",");
    let output = run_tool(
        "systemctl",
        &["show", "--property", &property_arg, unit_name],
        Some(Duration::from_secs(5)),
        None,
    )
    .ok()?;

    if !output.success() {
        return None;
    }

    let stdout = output.stdout_str();
    parse_systemctl_output(&stdout, pid)
}

/// Parse systemctl show output.
pub fn parse_systemctl_output(output: &str, pid: u32) -> Option<SystemdUnit> {
    let props = parse_properties(output);

    // Get unit name (Id)
    let name = props.get("Id")?.clone();

    // Skip if it's just "-" or empty (not managed by systemd)
    if name.is_empty() || name == "-" {
        return None;
    }

    let unit_type = SystemdUnitType::from_unit_name(&name);

    let active_state = props
        .get("ActiveState")
        .map(|s| SystemdActiveState::parse(s))
        .unwrap_or_default();

    let sub_state = props
        .get("SubState")
        .cloned()
        .filter(|s| !s.is_empty() && s != "-");

    let main_pid = props
        .get("MainPID")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&p| p > 0);

    let control_pid = props
        .get("ControlPID")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&p| p > 0);

    let fragment_path = props
        .get("FragmentPath")
        .cloned()
        .filter(|s| !s.is_empty() && s != "-");

    let description = props
        .get("Description")
        .cloned()
        .filter(|s| !s.is_empty() && s != "-");

    // Check if this PID is the main process
    let is_main_process = main_pid.map(|mp| mp == pid).unwrap_or(false);

    Some(SystemdUnit {
        name,
        unit_type,
        active_state,
        sub_state,
        main_pid,
        control_pid,
        fragment_path,
        description,
        is_main_process,
        provenance: SystemdProvenance {
            source: SystemdDataSource::SystemctlShow,
            warnings: Vec::new(),
        },
    })
}

/// Parse key=value properties from systemctl output.
fn parse_properties(output: &str) -> HashMap<String, String> {
    let mut props = HashMap::new();

    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            props.insert(key.to_string(), value.to_string());
        }
    }

    props
}

/// Create unit info from cgroup path (fallback).
fn unit_from_cgroup_path(unit_name: &str, _pid: u32) -> SystemdUnit {
    let unit_type = SystemdUnitType::from_unit_name(unit_name);

    SystemdUnit {
        name: unit_name.to_string(),
        unit_type,
        active_state: SystemdActiveState::Unknown,
        sub_state: None,
        main_pid: None,
        control_pid: None,
        fragment_path: None,
        description: None,
        is_main_process: false,
        provenance: SystemdProvenance {
            source: SystemdDataSource::CgroupPath,
            warnings: vec!["Unit info from cgroup path only; systemctl unavailable".to_string()],
        },
    }
}

/// Check if systemd is available on the system.
pub fn is_systemd_available() -> bool {
    // Check if systemctl exists and is functional
    run_tool(
        "systemctl",
        &["--version"],
        Some(Duration::from_secs(2)),
        None,
    )
    .map(|o| o.success())
    .unwrap_or(false)
}

/// Check if a process is managed by systemd.
pub fn is_systemd_managed(pid: u32) -> bool {
    let pid_str = pid.to_string();
    run_tool(
        "systemctl",
        &["status", &pid_str],
        Some(Duration::from_secs(2)),
        None,
    )
    .map(|o| o.success())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_user_service() -> String {
        [
            "Id=pt-restart-test.service",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "MainPID=1234",
            "ControlPID=0",
            "ControlGroup=/user.slice/user-1000.slice/user@1000.service/pt-restart-test.service",
            "InvocationID=1234567890abcdef1234567890abcdef",
            "Type=exec",
            "KillMode=control-group",
            "Delegate=no",
            "CanStart=yes",
            "CanStop=yes",
            "RefuseManualStart=no",
            "RefuseManualStop=no",
            "DefaultDependencies=no",
            "Requires=-.slice",
            "Wants=",
            "Requisite=",
            "BindsTo=",
            "Upholds=",
            "Conflicts=",
            "ConflictedBy=",
            "ConsistsOf=",
            "BoundBy=",
            "RequiredBy=",
            "RequisiteOf=",
            "PropagatesStopTo=",
            "OnFailure=",
            "OnSuccess=",
            "FailureAction=none",
            "SuccessAction=none",
            "StartLimitAction=none",
            "StopWhenUnneeded=no",
            "",
        ]
        .join("\n")
    }

    #[test]
    fn user_service_requires_complete_inert_transaction_scope() {
        let fixture = isolated_user_service();
        let state = parse_systemd_user_service(&fixture).expect("isolated service");
        assert_eq!(state.main_pid, 1234);
        assert_eq!(state.unit, "pt-restart-test.service");
        for key in [
            "Wants",
            "Requisite",
            "BindsTo",
            "Upholds",
            "Conflicts",
            "ConflictedBy",
            "ConsistsOf",
            "BoundBy",
            "RequiredBy",
            "RequisiteOf",
            "PropagatesStopTo",
            "OnFailure",
            "OnSuccess",
        ] {
            let old = format!("{key}=\n");
            let expanded = fixture.replace(&old, &format!("{key}=other.service\n"));
            assert!(parse_systemd_user_service(&expanded).is_err(), "{key}");
            assert!(
                parse_systemd_user_service(&fixture.replace(&old, "")).is_err(),
                "missing {key}"
            );
        }
        for (before, after) in [
            ("Requires=-.slice", "Requires=basic.target -.slice"),
            ("Requires=-.slice", "Requires=app.slice"),
            ("DefaultDependencies=no", "DefaultDependencies=yes"),
            ("FailureAction=none", "FailureAction=exit"),
            ("SuccessAction=none", "SuccessAction=exit-force"),
            ("StartLimitAction=none", "StartLimitAction=reboot"),
            ("StopWhenUnneeded=no", "StopWhenUnneeded=yes"),
            ("KillMode=control-group", "KillMode=process"),
            ("Delegate=no", "Delegate=yes"),
            ("ControlPID=0", "ControlPID=4321"),
            ("Type=exec", "Type=oneshot"),
            ("ActiveState=active", "ActiveState=activating"),
            ("SubState=running", "SubState=exited"),
            ("MainPID=1234", "MainPID=0"),
            ("CanStop=yes", "CanStop=no"),
            ("RefuseManualStart=no", "RefuseManualStart=yes"),
        ] {
            assert!(
                parse_systemd_user_service(&fixture.replace(before, after)).is_err(),
                "{after}"
            );
        }
        assert!(parse_systemd_user_service(&format!("{fixture}MainPID=4321\n")).is_err());
        assert!(parse_systemd_user_service(fixture.trim_end()).is_err());
    }

    #[test]
    fn root_slice_start_proof_rejects_outward_jobs_but_not_reverse_dependents() {
        let fixture = isolated_user_service()
            .replace("Id=pt-restart-test.service", "Id=-.slice")
            .replace("Requires=-.slice", "Requires=")
            .replace(
                "RequiredBy=\n",
                "RequiredBy=pt-restart-test.service other.service\n",
            );
        validate_user_root_slice(&fixture).expect("perpetual root-slice START is inert");
        for (before, after) in [
            ("Requires=\n", "Requires=basic.target\n"),
            ("Wants=\n", "Wants=unrelated.service\n"),
            ("Conflicts=\n", "Conflicts=other.service\n"),
            ("ActiveState=active", "ActiveState=inactive"),
            ("OnFailure=\n", "OnFailure=recovery.service\n"),
            ("FailureAction=none", "FailureAction=exit"),
        ] {
            assert!(
                validate_user_root_slice(&fixture.replace(before, after)).is_err(),
                "{after}"
            );
        }
    }

    #[test]
    fn user_manager_command_has_explicit_scope_and_literal_arguments() {
        let args = user_systemctl_arguments(
            1234,
            "/usr/bin/systemctl",
            &[
                "--job-mode=fail",
                "try-restart",
                "--",
                "worker@blue.service",
            ],
        );
        assert_eq!(args[0], "XDG_RUNTIME_DIR=/run/user/1234");
        assert_eq!(
            args[1],
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1234/bus"
        );
        assert_eq!(
            &args[2..],
            &[
                "/usr/bin/systemctl",
                "--user",
                "--no-pager",
                "--no-ask-password",
                "--job-mode=fail",
                "try-restart",
                "--",
                "worker@blue.service",
            ]
        );
        for name in [
            "worker.service",
            "worker@blue.service",
            "build-worker_1.service",
        ] {
            assert!(is_literal_service_unit(name), "{name}");
        }
        for name in [
            ".service",
            "--all.service",
            "*.service",
            "a?.service",
            "a[b].service",
            "../worker.service",
            "a/b.service",
            "worker@.service",
            "a\\x2db.service",
            "a\nb.service",
            "a b.service",
            "worker.scope",
            "worker.service\0",
        ] {
            assert!(!is_literal_service_unit(name), "{name:?}");
        }
    }

    #[test]
    fn test_unit_type_from_name() {
        assert_eq!(
            SystemdUnitType::from_unit_name("nginx.service"),
            SystemdUnitType::Service
        );
        assert_eq!(
            SystemdUnitType::from_unit_name("session-1.scope"),
            SystemdUnitType::Scope
        );
        assert_eq!(
            SystemdUnitType::from_unit_name("user-1000.slice"),
            SystemdUnitType::Slice
        );
        assert_eq!(
            SystemdUnitType::from_unit_name("ssh.socket"),
            SystemdUnitType::Socket
        );
        assert_eq!(
            SystemdUnitType::from_unit_name("graphical.target"),
            SystemdUnitType::Target
        );
        assert_eq!(
            SystemdUnitType::from_unit_name("random-name"),
            SystemdUnitType::Unknown
        );
    }

    #[test]
    fn test_active_state_from_str() {
        assert_eq!(
            SystemdActiveState::parse("active"),
            SystemdActiveState::Active
        );
        assert_eq!(
            SystemdActiveState::parse("Active"),
            SystemdActiveState::Active
        );
        assert_eq!(
            SystemdActiveState::parse("inactive"),
            SystemdActiveState::Inactive
        );
        assert_eq!(
            SystemdActiveState::parse("failed"),
            SystemdActiveState::Failed
        );
        assert_eq!(
            SystemdActiveState::parse("unknown-state"),
            SystemdActiveState::Unknown
        );
    }

    #[test]
    fn test_active_state_is_running() {
        assert!(SystemdActiveState::Active.is_running());
        assert!(SystemdActiveState::Reloading.is_running());
        assert!(!SystemdActiveState::Inactive.is_running());
        assert!(!SystemdActiveState::Failed.is_running());
    }

    #[test]
    fn test_parse_systemctl_output() {
        let output = r#"Id=nginx.service
ActiveState=active
SubState=running
MainPID=1234
ControlPID=0
FragmentPath=/usr/lib/systemd/system/nginx.service
Description=The nginx HTTP and reverse proxy server
"#;

        let unit = parse_systemctl_output(output, 1234).unwrap();

        assert_eq!(unit.name, "nginx.service");
        assert_eq!(unit.unit_type, SystemdUnitType::Service);
        assert_eq!(unit.active_state, SystemdActiveState::Active);
        assert_eq!(unit.sub_state, Some("running".to_string()));
        assert_eq!(unit.main_pid, Some(1234));
        assert_eq!(unit.control_pid, None); // 0 should be filtered
        assert!(unit.fragment_path.is_some());
        assert!(unit.description.is_some());
        assert!(unit.is_main_process);
    }

    #[test]
    fn test_parse_systemctl_output_not_main_process() {
        let output = r#"Id=nginx.service
ActiveState=active
SubState=running
MainPID=1234
ControlPID=0
FragmentPath=/usr/lib/systemd/system/nginx.service
Description=The nginx HTTP and reverse proxy server
"#;

        // PID 5678 is not the main process
        let unit = parse_systemctl_output(output, 5678).unwrap();
        assert!(!unit.is_main_process);
    }

    #[test]
    fn test_parse_systemctl_output_scope() {
        let output = r#"Id=session-1.scope
ActiveState=active
SubState=running
MainPID=0
ControlPID=0
FragmentPath=
Description=Session 1 of user ubuntu
"#;

        let unit = parse_systemctl_output(output, 1234).unwrap();

        assert_eq!(unit.name, "session-1.scope");
        assert_eq!(unit.unit_type, SystemdUnitType::Scope);
        assert_eq!(unit.main_pid, None); // 0 filtered
        assert_eq!(unit.fragment_path, None); // Empty filtered
    }

    #[test]
    fn test_parse_systemctl_output_empty_id() {
        let output = r#"Id=-
ActiveState=inactive
"#;

        let unit = parse_systemctl_output(output, 1234);
        assert!(unit.is_none());
    }

    #[test]
    fn test_unit_from_cgroup_path() {
        let unit = unit_from_cgroup_path("nginx.service", 1234);

        assert_eq!(unit.name, "nginx.service");
        assert_eq!(unit.unit_type, SystemdUnitType::Service);
        assert_eq!(unit.active_state, SystemdActiveState::Unknown);
        assert_eq!(unit.provenance.source, SystemdDataSource::CgroupPath);
        assert!(!unit.provenance.warnings.is_empty());
    }

    #[test]
    fn test_parse_properties() {
        let output = "Key1=value1\nKey2=value2\nKey3=\n";
        let props = parse_properties(output);

        assert_eq!(props.get("Key1"), Some(&"value1".to_string()));
        assert_eq!(props.get("Key2"), Some(&"value2".to_string()));
        assert_eq!(props.get("Key3"), Some(&"".to_string()));
    }

    // =====================================================
    // No-mock tests using real systemd commands
    // =====================================================

    #[test]
    fn test_nomock_is_systemd_available() {
        // This test just checks if is_systemd_available works without panicking
        crate::test_log!(INFO, "systemd availability test starting");

        let available = is_systemd_available();

        crate::test_log!(INFO, "systemd availability result", available = available);

        // The result depends on the system, but the function should not panic
        // On most modern Linux systems with systemd, this should be true
    }

    #[test]
    fn test_nomock_is_systemd_managed_self() {
        // Test if our own process is systemd-managed
        if !is_systemd_available() {
            crate::test_log!(INFO, "Skipping test: systemd not available");
            return;
        }

        let my_pid = std::process::id();
        crate::test_log!(INFO, "systemd managed check for self", pid = my_pid);

        let managed = is_systemd_managed(my_pid);

        crate::test_log!(
            INFO,
            "systemd managed result",
            pid = my_pid,
            managed = managed
        );

        // On a systemd system, most processes should be managed
        // (but don't fail the test if not - depends on system config)
    }

    #[test]
    fn test_nomock_collect_systemd_unit_self() {
        // Test collecting systemd unit info for our own process
        if !is_systemd_available() {
            crate::test_log!(INFO, "Skipping test: systemd not available");
            return;
        }

        let my_pid = std::process::id();
        crate::test_log!(INFO, "systemd unit collection for self", pid = my_pid);

        let cgroup = crate::collect::cgroup::collect_cgroup_details(my_pid);
        let cgroup_unit = cgroup.as_ref().and_then(|c| c.systemd_unit.as_deref());

        let unit = collect_systemd_unit(my_pid, cgroup_unit);

        crate::test_log!(
            INFO,
            "systemd unit result",
            pid = my_pid,
            has_unit = unit.is_some()
        );

        if let Some(unit) = unit {
            crate::test_log!(
                INFO,
                "systemd unit details",
                name = unit.name.as_str(),
                unit_type = format!("{:?}", unit.unit_type).as_str(),
                active_state = format!("{:?}", unit.active_state).as_str(),
                is_main_process = unit.is_main_process
            );

            // Verify the data is reasonable
            assert!(!unit.name.is_empty());
            assert_ne!(unit.provenance.source, SystemdDataSource::None);
        }
    }

    #[test]
    fn test_nomock_collect_systemd_unit_spawned() {
        use crate::test_utils::ProcessHarness;

        if !is_systemd_available() {
            crate::test_log!(INFO, "Skipping test: systemd not available");
            return;
        }

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness;
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(
            INFO,
            "systemd unit collection for spawned process",
            pid = proc.pid()
        );

        let cgroup = crate::collect::cgroup::collect_cgroup_details(proc.pid());
        let cgroup_unit = cgroup.as_ref().and_then(|c| c.systemd_unit.as_deref());

        let unit = collect_systemd_unit(proc.pid(), cgroup_unit);

        crate::test_log!(
            INFO,
            "systemd unit result for spawned",
            pid = proc.pid(),
            has_unit = unit.is_some()
        );

        if let Some(unit) = unit {
            crate::test_log!(
                INFO,
                "systemd unit details for spawned",
                name = unit.name.as_str(),
                unit_type = format!("{:?}", unit.unit_type).as_str(),
                active_state = format!("{:?}", unit.active_state).as_str()
            );
        }
    }

    #[test]
    fn test_nomock_collect_systemd_unit_with_fallback() {
        // Test the fallback path using cgroup_unit parameter
        crate::test_log!(INFO, "systemd unit fallback test");

        // Simulate fallback case where systemctl fails but we have cgroup info
        let unit = unit_from_cgroup_path("test-session.scope", 99999);

        crate::test_log!(
            INFO,
            "systemd unit fallback result",
            name = unit.name.as_str(),
            unit_type = format!("{:?}", unit.unit_type).as_str(),
            source = format!("{:?}", unit.provenance.source).as_str()
        );

        assert_eq!(unit.name, "test-session.scope");
        assert_eq!(unit.unit_type, SystemdUnitType::Scope);
        assert_eq!(unit.provenance.source, SystemdDataSource::CgroupPath);
        assert!(!unit.provenance.warnings.is_empty()); // Should have warning about systemctl
    }

    #[test]
    fn test_nomock_systemd_active_state_running() {
        // Test active state running detection
        assert!(SystemdActiveState::Active.is_running());
        assert!(SystemdActiveState::Reloading.is_running());
        assert!(!SystemdActiveState::Inactive.is_running());
        assert!(!SystemdActiveState::Failed.is_running());
        assert!(!SystemdActiveState::Activating.is_running());
        assert!(!SystemdActiveState::Deactivating.is_running());
        assert!(!SystemdActiveState::Unknown.is_running());

        crate::test_log!(INFO, "systemd active state is_running tests passed");
    }
}
