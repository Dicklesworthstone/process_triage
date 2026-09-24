//! The learning loop end to end: `agent label` records a human verdict for a live
//! process's command pattern, and the next `agent plan` uses it as the prior.

#![cfg(unix)]

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand};
use std::time::Duration;
use tempfile::TempDir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pt_core(config_dir: &Path, data_dir: &Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(180))
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off");
    cmd
}

/// The plan candidate for `pid` (plan run with every process eligible).
fn plan_candidate(config_dir: &Path, data_dir: &Path, pid: u32) -> Value {
    let out = pt_core(config_dir, data_dir)
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run agent plan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "plan output not JSON ({e}): {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    json["candidates"]
        .as_array()
        .expect("candidates array")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .cloned()
        .unwrap_or_else(|| panic!("pid {pid} not among plan candidates"))
}

#[test]
fn human_kill_labels_raise_the_plan_prior_for_that_pattern() {
    let config_dir = TempDir::new().expect("config dir");
    let data_dir = TempDir::new().expect("data dir");
    let child = ProcessCommand::new("sleep")
        .arg("613")
        .spawn()
        .expect("spawn sleep");
    let guard = ChildGuard(child);
    let pid = guard.0.id();

    let before = plan_candidate(config_dir.path(), data_dir.path(), pid);
    assert!(
        before["inference"]["learned_prior"].is_null(),
        "no decisions yet: {before}"
    );

    for _ in 0..3 {
        let out = pt_core(config_dir.path(), data_dir.path())
            .args(["--format", "json", "agent", "label", "--pid"])
            .arg(pid.to_string())
            .arg("--kill")
            .output()
            .expect("run agent label");
        assert!(
            out.status.success(),
            "label failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let store: Value = serde_json::from_str(
        &std::fs::read_to_string(config_dir.path().join("decisions.json")).expect("store"),
    )
    .expect("store is JSON");
    assert!(
        store
            .as_object()
            .expect("object")
            .values()
            .all(|c| c["kill"] == 3 && c["spare"] == 0),
        "each pattern level counts 3 kills: {store}"
    );

    let after = plan_candidate(config_dir.path(), data_dir.path(), pid);
    let learned = &after["inference"]["learned_prior"];
    assert_eq!(learned["kill"], 3, "learned prior in plan: {after}");
    let p_before = before["posterior"]["abandoned"].as_f64().unwrap()
        + before["posterior"]["zombie"].as_f64().unwrap();
    let p_after = after["posterior"]["abandoned"].as_f64().unwrap()
        + after["posterior"]["zombie"].as_f64().unwrap();
    assert!(
        p_after > p_before,
        "human kills must raise P(abandoned): before {p_before}, after {p_after}"
    );
}

#[test]
fn label_rejects_missing_verdict_and_target() {
    let config_dir = TempDir::new().expect("config dir");
    let data_dir = TempDir::new().expect("data dir");
    pt_core(config_dir.path(), data_dir.path())
        .args(["agent", "label", "--cmd", "sleep 5"])
        .assert()
        .code(2);
    pt_core(config_dir.path(), data_dir.path())
        .args(["agent", "label", "--kill"])
        .assert()
        .code(2);
    assert!(!config_dir.path().join("decisions.json").exists());
}
