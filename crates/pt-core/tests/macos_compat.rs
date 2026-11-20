use pt_common::IdentityQuality;
use pt_core::action::{SupervisorAction, SupervisorInfo};

#[test]
fn identity_quality_variants_exhaustive() {
    let variants = [
        IdentityQuality::Full,
        IdentityQuality::NoBootId,
        IdentityQuality::PidOnly,
    ];

    let labels: Vec<&'static str> = variants
        .iter()
        .map(|variant| match variant {
            IdentityQuality::Full => "full",
            IdentityQuality::NoBootId => "no_boot_id",
            IdentityQuality::PidOnly => "pid_only",
        })
        .collect();

    assert_eq!(labels, vec!["full", "no_boot_id", "pid_only"]);
}

#[test]
fn supervisor_info_construction_without_systemd() {
    let info = SupervisorInfo {
        supervisor: "supervisord".to_string(),
        unit_name: None,
        unit_type: None,
        is_main_process: false,
        recommended_action: SupervisorAction::KillProcess,
        systemd_unit: None,
    };

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

#[cfg(target_os = "linux")]
#[test]
fn supervisor_info_with_systemd() {
    use pt_core::collect::systemd::{
        SystemdActiveState, SystemdDataSource, SystemdProvenance, SystemdUnit, SystemdUnitType,
    };

    let unit = SystemdUnit {
        name: "test.service".to_string(),
        unit_type: SystemdUnitType::Service,
        active_state: SystemdActiveState::Active,
        sub_state: Some("running".to_string()),
        main_pid: Some(4242),
        control_pid: None,
        fragment_path: None,
        description: Some("test unit".to_string()),
        is_main_process: true,
        provenance: SystemdProvenance {
            source: SystemdDataSource::SystemctlShow,
            warnings: vec![],
        },
    };

    let info = SupervisorInfo {
        supervisor: "systemd".to_string(),
        unit_name: Some(unit.name.clone()),
        unit_type: Some(SystemdUnitType::Service),
        is_main_process: true,
        recommended_action: SupervisorAction::RestartUnit {
            command: "systemctl restart test.service".to_string(),
        },
        systemd_unit: Some(unit),
    };

    assert_eq!(info.supervisor, "systemd");
    assert_eq!(info.unit_name.as_deref(), Some("test.service"));
    assert_eq!(info.unit_type, Some(SystemdUnitType::Service));
    assert!(info.is_main_process);
    assert!(matches!(
        info.recommended_action,
        SupervisorAction::RestartUnit { .. }
    ));
    assert!(info.systemd_unit.is_some());
}

#[cfg(target_os = "macos")]
#[test]
fn deep_scan_cli_collects_a_native_identity_without_other_processes() {
    use std::process::{Child, Command, Stdio};

    struct OwnedTarget(Child);
    impl Drop for OwnedTarget {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut target = OwnedTarget(
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owned read-only scan target"),
    );
    let native = pt_core::collect::read_bsd_info(target.0.id()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pt-core"))
        .args([
            "--format",
            "json",
            "deep-scan",
            "--pids",
            &target.0.id().to_string(),
            "--budget",
            "20",
        ])
        .output()
        .expect("run native deep-scan command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value.get("status").is_none(),
        "must not return the old success-shaped stub"
    );
    let scan = &value["deep_scan"];
    assert_eq!(scan["metadata"]["collection"]["complete"], true);
    assert_eq!(scan["metadata"]["collection"]["requested_count"], 1);
    let processes = scan["processes"].as_array().unwrap();
    assert_eq!(
        processes.len(),
        1,
        "target-only collection must not become a full-host scan"
    );
    let process = &processes[0];
    assert_eq!(process["pid"], target.0.id());
    assert_eq!(process["uid"], native.uid);
    assert_eq!(process["start_time_unix"], native.start_us / 1_000_000);
    assert!(process["start_id"]
        .as_str()
        .unwrap()
        .contains(&format!(":{}:", native.start_us)));
    assert!(process.get("environ").is_none());
    if process["lsof_complete"] == false {
        assert!(!process["unavailable"].as_array().unwrap().is_empty());
    }
    assert!(
        target.0.try_wait().unwrap().is_none(),
        "a scan must never signal its target"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn deep_scan_cli_deadline_requires_explicit_partial_opt_in() {
    use std::process::Command;

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pt-core"))
            .args(["--format", "json"])
            .args(args)
            .output()
            .unwrap()
    };
    let strict = run(&["deep-scan", "--budget", "0"]);
    assert_eq!(strict.status.code(), Some(22));
    assert!(strict.stdout.is_empty());
    let partial = run(&[
        "--timeout",
        "0",
        "deep-scan",
        "--budget",
        "20",
        "--allow-partial",
    ]);
    assert_eq!(partial.status.code(), Some(22));
    let value: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(
        value["deep_scan"]["metadata"]["collection"]["timed_out"],
        true
    );
    assert_eq!(
        value["deep_scan"]["metadata"]["collection"]["complete"],
        false
    );
    assert!(value["deep_scan"]["processes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(value["deep_scan"]["metadata"]["collection"]["requested_count"].is_null());
    let invalid = run(&["deep-scan", "--allow-partial"]);
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
}
