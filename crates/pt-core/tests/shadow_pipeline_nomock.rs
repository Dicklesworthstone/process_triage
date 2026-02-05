//! Shadow mode export/report integration tests using real observations.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn pt_core() -> Command {
    cargo_bin_cmd!("pt-core")
}

fn fixture_observations_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test")
        .join("fixtures")
        .join("shadow")
        .join("observations")
        .join("shadow")
        .join("shadow_observations.json")
}

#[test]
fn shadow_export_and_report_from_fixture() -> Result<(), Box<dyn Error>> {
    let dir = TempDir::new()?;
    let data_dir = dir.path().join("data");
    let shadow_dir = data_dir.join("shadow").join("hot").join("pid_4242");
    fs::create_dir_all(&shadow_dir)?;

    let fixture_payload = fs::read_to_string(fixture_observations_path())?;
    fs::write(shadow_dir.join("shadow_observations.json"), fixture_payload)?;

    let export_path = dir.path().join("shadow_export.json");
    pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .args(["shadow", "export", "--output"])
        .arg(&export_path)
        .assert()
        .success();

    let export_json: Value = serde_json::from_str(&fs::read_to_string(&export_path)?)?;
    let export_count = export_json.as_array().map(|arr| arr.len()).unwrap_or(0);
    assert_eq!(export_count, 3);

    let report_path = dir.path().join("shadow_report.json");
    pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .args(["shadow", "report", "--output"])
        .arg(&report_path)
        .assert()
        .success();

    let report_json: Value = serde_json::from_str(&fs::read_to_string(&report_path)?)?;
    assert_eq!(report_json.get("total_predictions").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(report_json.get("resolved_predictions").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(report_json.get("pending_predictions").and_then(|v| v.as_u64()), Some(1));

    Ok(())
}
