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
