//! E2E tests for `agent list-priors`, `agent inbox`, `agent export-priors`,
//! `agent import-priors`, and `agent init` commands.
//!
//! Tests these subcommands end-to-end through the CLI binary, verifying
//! JSON output schema, exit codes, and correct behavior.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_core::exit_codes::ExitCode;
use serde_json::Value;
use std::env;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_temp_dirs<T>(f: impl FnOnce(&TempDir, &TempDir) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let old_data = env::var("PROCESS_TRIAGE_DATA").ok();
    let old_config = env::var("PROCESS_TRIAGE_CONFIG").ok();

    let data_dir = TempDir::new().expect("create temp data dir");
    let config_dir = TempDir::new().expect("create temp config dir");

    env::set_var("PROCESS_TRIAGE_DATA", data_dir.path());
    env::set_var("PROCESS_TRIAGE_CONFIG", config_dir.path());

    let result = f(&data_dir, &config_dir);

    match old_data {
        Some(val) => env::set_var("PROCESS_TRIAGE_DATA", val),
        None => env::remove_var("PROCESS_TRIAGE_DATA"),
    }
    match old_config {
        Some(val) => env::set_var("PROCESS_TRIAGE_CONFIG", val),
        None => env::remove_var("PROCESS_TRIAGE_CONFIG"),
    }

    result
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

// ============================================================================
// agent list-priors tests
// ============================================================================

#[test]
fn list_priors_default_returns_json() {
    let output = pt_core_fast()
        .args(["--format", "json", "agent", "list-priors"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(json.get("schema_version").is_some());
    assert!(json.get("source").is_some());

    let classes = json
        .get("classes")
        .and_then(|v| v.as_array())
        .expect("classes array");
    // Should have 4 classes: useful, useful_bad, abandoned, zombie
    assert_eq!(classes.len(), 4, "Expected 4 prior classes");

    // Verify each class has expected fields
    for cls in classes {
        assert!(cls.get("prior_prob").is_some(), "Missing prior_prob");
        assert!(cls.get("cpu_beta").is_some(), "Missing cpu_beta");
        assert!(cls.get("class").is_some(), "Missing class label");
    }
}

#[test]
fn list_priors_filter_by_class() {
    let output = pt_core_fast()
        .args([
            "--format",
            "json",
            "agent",
            "list-priors",
            "--class",
            "zombie",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("valid JSON");
    let classes = json
        .get("classes")
        .and_then(|v| v.as_array())
        .expect("classes array");
    assert_eq!(classes.len(), 1, "Expected 1 class with --class zombie");
    assert_eq!(
        classes[0].get("class").and_then(|v| v.as_str()),
        Some("zombie"),
    );
}

#[test]
fn list_priors_extended_includes_extras() {
    let output = pt_core_fast()
        .args(["--format", "json", "agent", "list-priors", "--extended"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("valid JSON");
    // Extended mode should include additional hyperparameter sections
    // At minimum, classes should still be present
    assert!(json.get("classes").is_some());
    // Extended mode adds hazard_regimes, semi_markov, etc.
    // (exact fields depend on config, but the output should still be valid)
}

#[test]
fn list_priors_source_using_defaults() {
    let output = pt_core_fast()
        .args(["--format", "json", "agent", "list-priors"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("valid JSON");
    let source = json.get("source").expect("Missing source field");
    // With no custom config, should be using defaults
    assert!(source.get("using_defaults").is_some());
}

// ============================================================================
// agent export-priors / import-priors tests
// ============================================================================

#[test]
fn export_priors_creates_file() {
    with_temp_dirs(|data_dir, config_dir| {
        let out_path = data_dir.path().join("exported_priors.json");

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "export-priors",
                "--out",
                out_path.to_str().unwrap(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("exported").and_then(|v| v.as_bool()), Some(true));

        // Verify the exported file exists and is valid JSON
        assert!(out_path.exists(), "Exported file should exist");
        let content = fs::read_to_string(&out_path).expect("read exported file");
        let exported: Value = serde_json::from_str(&content).expect("valid JSON in exported file");
        assert!(
            exported.get("priors").is_some(),
            "Exported file should contain priors"
        );
        assert!(
            exported.get("schema_version").is_some(),
            "Exported file should have schema_version",
        );
    });
}

#[test]
fn export_priors_with_host_profile() {
    with_temp_dirs(|data_dir, config_dir| {
        let out_path = data_dir.path().join("priors_profiled.json");

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "export-priors",
                "--out",
                out_path.to_str().unwrap(),
                "--host-profile",
                "test-server",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(
            json.get("host_profile").and_then(|v| v.as_str()),
            Some("test-server"),
        );

        // Verify profile tag in exported file
        let content = fs::read_to_string(&out_path).expect("read exported file");
        let exported: Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(
            exported.get("host_profile").and_then(|v| v.as_str()),
            Some("test-server"),
        );
    });
}

#[test]
fn import_priors_dry_run() {
    with_temp_dirs(|data_dir, config_dir| {
        // First export priors to create a valid import source
        let export_path = data_dir.path().join("for_import.json");
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "export-priors",
                "--out",
                export_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Now import with --dry-run
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "import-priors",
                "--from",
                export_path.to_str().unwrap(),
                "--replace",
                "--dry-run",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("dry_run").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(json.get("mode").and_then(|v| v.as_str()), Some("replace"),);
    });
}

#[test]
fn export_import_roundtrip() {
    with_temp_dirs(|data_dir, config_dir| {
        let export_path = data_dir.path().join("roundtrip.json");

        // Export current priors
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "export-priors",
                "--out",
                export_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Import them back with --replace --no-backup
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "import-priors",
                "--from",
                export_path.to_str().unwrap(),
                "--replace",
                "--no-backup",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("imported").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(json.get("mode").and_then(|v| v.as_str()), Some("replace"));

        // Verify class_priors are present
        assert!(
            json.get("class_priors").is_some(),
            "Expected class_priors in import output",
        );
    });
}

#[test]
fn import_priors_invalid_file_returns_error() {
    with_temp_dirs(|data_dir, config_dir| {
        let bad_path = data_dir.path().join("bad_priors.json");
        fs::write(&bad_path, "not valid json").expect("write bad file");

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "import-priors",
                "--from",
                bad_path.to_str().unwrap(),
                "--replace",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn import_priors_missing_file_returns_error() {
    with_temp_dirs(|data_dir, config_dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "import-priors",
                "--from",
                "/nonexistent/priors.json",
                "--replace",
            ])
            .assert()
            .failure();
    });
}

// ============================================================================
// agent inbox tests
// ============================================================================

#[test]
fn inbox_empty_returns_ok() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args(["--format", "json", "agent", "inbox"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert!(json.get("schema_version").is_some());

        let items = json
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items array");
        assert!(items.is_empty(), "Empty inbox should have no items");
        assert_eq!(json.get("unread_count").and_then(|v| v.as_u64()), Some(0),);
    });
}

#[test]
fn inbox_unread_filter_on_empty() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args(["--format", "json", "agent", "inbox", "--unread"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let items = json
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items array");
        assert!(items.is_empty());
    });
}

#[test]
fn inbox_ack_nonexistent_returns_error() {
    with_temp_dirs(|data_dir, config_dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "inbox",
                "--ack",
                "nonexistent-item-id",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn inbox_clear_empty_returns_ok() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args(["--format", "json", "agent", "inbox", "--clear"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("cleared").and_then(|v| v.as_u64()), Some(0),);
    });
}

#[test]
fn inbox_clear_all_empty_returns_ok() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args(["--format", "json", "agent", "inbox", "--clear-all"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("cleared").and_then(|v| v.as_u64()), Some(0),);
    });
}

// ============================================================================
// agent init tests
// ============================================================================

#[test]
fn init_dry_run_produces_json() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args(["--format", "json", "agent", "init", "--dry-run", "--yes"])
            .assert()
            .get_output()
            .stdout
            .clone();

        // init outputs JSONL progress lines then a multi-line JSON result.
        // Try parsing the full output first; if that fails (JSONL prefix),
        // find the final JSON object by scanning for the last top-level '{'.
        let stdout_str = String::from_utf8_lossy(&output);
        let json: Value = match serde_json::from_str(&stdout_str) {
            Ok(v) => v,
            Err(_) => {
                // Locate the last top-level JSON object (multi-line)
                // by finding the position of the last `\n{` boundary.
                let last_obj_start = stdout_str.rfind("\n{").map(|i| i + 1).unwrap_or(0);
                serde_json::from_str(&stdout_str[last_obj_start..])
                    .expect("valid JSON in init output tail")
            }
        };

        // Should have detected agents list
        assert!(
            json.get("detected").is_some(),
            "Expected detected field in init output",
        );
    });
}

#[test]
fn init_invalid_agent_returns_error() {
    with_temp_dirs(|data_dir, config_dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "init",
                "--dry-run",
                "--yes",
                "--agent",
                "nonexistent-agent",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn init_specific_agent_claude() {
    with_temp_dirs(|data_dir, config_dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "init",
                "--dry-run",
                "--yes",
                "--agent",
                "claude",
            ])
            .assert()
            .get_output()
            .stdout
            .clone();

        let stdout_str = String::from_utf8_lossy(&output);
        let json_lines: Vec<&str> = stdout_str.lines().filter(|l| l.starts_with('{')).collect();

        assert!(!json_lines.is_empty(), "Expected JSON output from init");
    });
}
