//! No-mock supervision detection tests backed by real fixtures.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use pt_core::supervision::{
    is_human_supervised, CombinedResult, EnvironAnalyzer, SupervisorCategory,
};

#[cfg(target_os = "linux")]
use pt_core::collect::container::detect_container_from_cgroup;
#[cfg(target_os = "linux")]
use pt_core::collect::container::ContainerRuntime;
#[cfg(target_os = "linux")]
use pt_core::collect::systemd::parse_systemctl_output;
#[cfg(target_os = "linux")]
use pt_core::collect::systemd::{SystemdActiveState, SystemdUnitType};

#[derive(Debug, Deserialize)]
struct FixtureFile {
    schema_version: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CaseKind {
    SystemdShow,
    CgroupPath,
    EnvMap,
}

// Fixture structs mirror the JSON schema; the systemd/cgroup fields are only read by
// the Linux cases.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FixtureCase {
    id: String,
    kind: CaseKind,
    input: FixtureInput,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FixtureInput {
    pid: Option<u32>,
    systemctl_show: Option<String>,
    cgroup_path: Option<String>,
    env: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FixtureExpected {
    unit_name: Option<String>,
    unit_type: Option<String>,
    active_state: Option<String>,
    is_main_process: Option<bool>,
    runtime: Option<String>,
    in_container: Option<bool>,
    container_id_short: Option<String>,
    kubernetes_pod_uid: Option<String>,
    supervisor_name: Option<String>,
    category: Option<String>,
    is_human_supervised: Option<bool>,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test")
        .join("fixtures")
        .join("supervision")
}

fn load_cases() -> FixtureFile {
    let path = fixtures_dir().join("cases.json");
    let contents = fs::read_to_string(&path).expect("read supervision cases fixture");
    let cases: FixtureFile =
        serde_json::from_str(&contents).expect("parse supervision cases fixture");
    assert_eq!(
        cases.schema_version, "1.0.0",
        "unexpected supervision fixture schema version"
    );
    cases
}

fn parse_category(value: &str) -> SupervisorCategory {
    match value {
        "agent" => SupervisorCategory::Agent,
        "ide" => SupervisorCategory::Ide,
        "ci" => SupervisorCategory::Ci,
        "orchestrator" => SupervisorCategory::Orchestrator,
        "terminal" => SupervisorCategory::Terminal,
        _ => SupervisorCategory::Other,
    }
}

#[cfg(target_os = "linux")]
fn parse_unit_type(value: &str) -> SystemdUnitType {
    match value {
        "service" => SystemdUnitType::Service,
        "scope" => SystemdUnitType::Scope,
        "slice" => SystemdUnitType::Slice,
        "socket" => SystemdUnitType::Socket,
        "target" => SystemdUnitType::Target,
        "mount" => SystemdUnitType::Mount,
        "timer" => SystemdUnitType::Timer,
        "path" => SystemdUnitType::Path,
        _ => SystemdUnitType::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn parse_runtime(value: &str) -> ContainerRuntime {
    match value {
        "docker" => ContainerRuntime::Docker,
        "containerd" => ContainerRuntime::Containerd,
        "podman" => ContainerRuntime::Podman,
        "lxc" => ContainerRuntime::Lxc,
        "crio" => ContainerRuntime::Crio,
        "generic" => ContainerRuntime::Generic,
        _ => ContainerRuntime::None,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_systemd_fixture_cases() {
    let fixtures = load_cases();

    for case in fixtures
        .cases
        .iter()
        .filter(|c| matches!(c.kind, CaseKind::SystemdShow))
    {
        let pid = case.input.pid.expect("systemd case requires pid");
        let output = case
            .input
            .systemctl_show
            .as_ref()
            .expect("systemd case requires systemctl_show");
        let unit = parse_systemctl_output(output, pid).expect("parse systemctl fixture");

        if let Some(ref expected_name) = case.expected.unit_name {
            assert_eq!(&unit.name, expected_name, "{} unit name", case.id);
        }
        if let Some(ref expected_type) = case.expected.unit_type {
            let expected = parse_unit_type(expected_type);
            assert_eq!(unit.unit_type, expected, "{} unit type", case.id);
        }
        if let Some(ref expected_state) = case.expected.active_state {
            let expected = SystemdActiveState::parse(expected_state);
            assert_eq!(unit.active_state, expected, "{} active state", case.id);
        }
        if let Some(expected_main) = case.expected.is_main_process {
            assert_eq!(
                unit.is_main_process, expected_main,
                "{} is_main_process",
                case.id
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_container_fixture_cases() {
    let fixtures = load_cases();

    for case in fixtures
        .cases
        .iter()
        .filter(|c| matches!(c.kind, CaseKind::CgroupPath))
    {
        let path = case
            .input
            .cgroup_path
            .as_ref()
            .expect("cgroup case requires cgroup_path");
        let info = detect_container_from_cgroup(path);

        if let Some(ref expected_runtime) = case.expected.runtime {
            let expected = parse_runtime(expected_runtime);
            assert_eq!(info.runtime, expected, "{} runtime", case.id);
        }
        if let Some(expected_in_container) = case.expected.in_container {
            assert_eq!(
                info.in_container, expected_in_container,
                "{} in_container",
                case.id
            );
        }
        if let Some(ref expected_short) = case.expected.container_id_short {
            assert_eq!(
                info.container_id_short.as_deref(),
                Some(expected_short.as_str()),
                "{} container_id_short",
                case.id
            );
        }
        if let Some(ref expected_uid) = case.expected.kubernetes_pod_uid {
            let actual = info
                .kubernetes
                .as_ref()
                .and_then(|k8s| k8s.pod_uid.as_deref());
            assert_eq!(actual, Some(expected_uid.as_str()), "{} pod uid", case.id);
        }
    }
}

#[test]
fn test_environ_fixture_cases() {
    let fixtures = load_cases();
    let analyzer = EnvironAnalyzer::new();

    for case in fixtures
        .cases
        .iter()
        .filter(|c| matches!(c.kind, CaseKind::EnvMap))
    {
        let env = case.input.env.as_ref().expect("env case requires env map");
        let result = analyzer.analyze_env(env);

        if let Some(ref expected_name) = case.expected.supervisor_name {
            assert_eq!(
                result.supervisor_name.as_deref(),
                Some(expected_name.as_str())
            );
        }
        if let Some(ref expected_category) = case.expected.category {
            let expected = parse_category(expected_category);
            assert_eq!(result.category, Some(expected));
        }
        if let Some(expected_human) = case.expected.is_human_supervised {
            let combined = CombinedResult {
                is_supervised: result.is_supervised,
                supervisor_name: result.supervisor_name.clone(),
                supervisor_type: result.category,
                confidence: result.confidence,
                evidence: result.evidence.clone(),
                ancestry: None,
                environ: Some(result.clone()),
                ipc: None,
            };
            assert_eq!(is_human_supervised(&combined), expected_human);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_nomock_environ_supervision_spawned_process() {
    use pt_core::supervision::detect_environ_supervision;
    use pt_core::supervision::read_environ;
    use std::process::Command;

    let mut child = Command::new("sleep")
        .arg("5")
        .env("CLAUDE_CODE_SESSION_ID", "session-1234")
        .spawn()
        .expect("spawn sleep process with CLAUDE_CODE_SESSION_ID");

    let pid = child.id();
    let env = match read_environ(pid) {
        Ok(env) => env,
        Err(err) => {
            eprintln!(
                "Skipping no-mock env test: failed to read environ ({:?})",
                err
            );
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };
    if !env.contains_key("CLAUDE_CODE_SESSION_ID") {
        eprintln!("Skipping no-mock env test: CLAUDE_CODE_SESSION_ID not visible in /proc");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    let result = detect_environ_supervision(pid).expect("read environ for spawned process");

    assert!(result.is_supervised);
    assert_eq!(result.supervisor_name.as_deref(), Some("claude"));
    assert_eq!(result.category, Some(SupervisorCategory::Agent));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_supervision_log_fixture_schema() {
    let log_path = fixtures_dir()
        .join("logs")
        .join("supervision_detection.jsonl");
    let contents = fs::read_to_string(&log_path).expect("read supervision log fixture");

    for (idx, line) in contents.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("invalid json at line {}", idx + 1));
        let obj = value
            .as_object()
            .unwrap_or_else(|| panic!("log line {} not object", idx + 1));

        for key in [
            "event",
            "timestamp",
            "supervisor_type",
            "pid",
            "duration_ms",
            "artifacts",
        ] {
            assert!(
                obj.contains_key(key),
                "log line {} missing {}",
                idx + 1,
                key
            );
        }

        assert!(obj.get("artifacts").unwrap().is_array());
    }
}

#[test]
fn test_fixture_manifest_validates() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("validate_fixture_manifest.py");
    let manifest = fixtures_dir().join("fixture_manifest.json");
    let status = std::process::Command::new("python3")
        .args([
            script.to_str().expect("validator script path"),
            manifest.to_str().expect("manifest path"),
        ])
        .status()
        .expect("run fixture manifest validator");

    assert!(status.success(), "fixture manifest validation failed");
}
