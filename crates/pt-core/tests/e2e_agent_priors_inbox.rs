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

fn prior_transfer_command(data_dir: &TempDir, config_dir: &TempDir) -> Command {
    let mut cmd = pt_core_fast();
    cmd.env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env_remove("PROCESS_TRIAGE_PRIORS")
        .env_remove("PROCESS_TRIAGE_POLICY")
        .env_remove("PT_CONFIG_DIR");
    cmd
}

fn distinct_transfer_priors() -> (pt_core::config::Priors, pt_core::config::Priors) {
    use pt_core::config::priors::{BetaParams, GammaParams, Priors};

    let mut local = Priors {
        description: Some("local model".to_string()),
        host_profile: Some("workstation".to_string()),
        ..Default::default()
    };
    local.classes.useful.prior_prob = 0.6;
    local.classes.useful_bad.prior_prob = 0.2;
    local.classes.abandoned.prior_prob = 0.1;
    local.classes.zombie.prior_prob = 0.1;
    local.classes.useful.cpu_beta = BetaParams::new(2.0, 6.0);
    local.classes.useful.runtime_gamma = Some(GammaParams::new(2.0, 3.0));
    local.classes.abandoned.io_active_beta = Some(BetaParams::new(4.0, 8.0));
    local.classes.abandoned.queue_saturation_beta = Some(BetaParams::new(2.0, 4.0));

    let mut incoming = local.clone();
    incoming.description = Some("incoming model".to_string());
    incoming.host_profile = Some("build-worker".to_string());
    incoming.classes.useful.prior_prob = 0.2;
    incoming.classes.useful_bad.prior_prob = 0.2;
    incoming.classes.abandoned.prior_prob = 0.4;
    incoming.classes.zombie.prior_prob = 0.2;
    incoming.classes.useful.cpu_beta = BetaParams::new(10.0, 14.0);
    incoming.classes.useful.runtime_gamma = Some(GammaParams::new(8.0, 7.0));
    incoming.classes.abandoned.io_active_beta = Some(BetaParams::new(12.0, 16.0));
    incoming.classes.abandoned.queue_saturation_beta = Some(BetaParams::new(6.0, 8.0));
    (local, incoming)
}

#[cfg(unix)]
#[test]
fn import_priors_refuses_a_fleet_writer_and_reloads_its_published_merge_base() {
    use pt_core::config::priors::{BetaParams, GammaParams};
    use pt_core::fleet::transfer::TransferImport;

    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, incoming) = distinct_transfer_priors();
    let priors_path = config_dir.path().join("priors.json");
    let backup_path = config_dir.path().join("priors.json.bak");
    let input_path = data_dir.path().join("incoming.json");
    let original = serde_json::to_vec_pretty(&local).unwrap();
    let source = serde_json::to_vec_pretty(&incoming).unwrap();
    fs::write(&priors_path, &original).unwrap();
    fs::write(&input_path, &source).unwrap();

    // Hold the actual fleet writer lock in this process, then invoke the real
    // priors CLI in another process. Refusal must precede its read/merge/save.
    let fleet = TransferImport::begin(config_dir.path()).unwrap();
    prior_transfer_command(&data_dir, &config_dir)
        .args(["--format", "json", "agent", "import-priors", "--from"])
        .arg(&input_path)
        .assert()
        .code(ExitCode::IoError.as_i32())
        .stderr(predicates::str::contains(
            "cannot lock configuration directory",
        ));
    assert_eq!(fs::read(&priors_path).unwrap(), original);
    assert!(!backup_path.exists());

    // Publish a materially different fleet model while retaining the lock.
    // Retrying the ordinary import must merge this state, not its former base.
    let mut fleet_priors = local;
    fleet_priors.classes.useful.prior_prob = 0.1;
    fleet_priors.classes.useful_bad.prior_prob = 0.1;
    fleet_priors.classes.abandoned.prior_prob = 0.6;
    fleet_priors.classes.zombie.prior_prob = 0.2;
    fleet_priors.classes.useful.cpu_beta = BetaParams::new(20.0, 30.0);
    fleet_priors.classes.useful.runtime_gamma = Some(GammaParams::new(5.0, 9.0));
    let fleet_bytes = serde_json::to_vec_pretty(&fleet_priors).unwrap();
    fleet
        .publish(vec![("priors.json".into(), fleet_bytes.clone())], false)
        .unwrap();
    assert_eq!(fs::read(&priors_path).unwrap(), fleet_bytes);
    assert!(!backup_path.exists());

    let preview = prior_transfer_command(&data_dir, &config_dir)
        .args([
            "--format",
            "json",
            "agent",
            "import-priors",
            "--dry-run",
            "--from",
        ])
        .arg(&input_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let preview: Value = serde_json::from_slice(&preview).unwrap();
    assert_eq!(preview["dry_run"], true);
    assert_eq!(fs::read(&priors_path).unwrap(), fleet_bytes);
    assert!(!backup_path.exists());
    drop(fleet);

    prior_transfer_command(&data_dir, &config_dir)
        .args(["--format", "json", "agent", "import-priors", "--from"])
        .arg(&input_path)
        .assert()
        .success();
    let saved: pt_core::config::Priors =
        serde_json::from_slice(&fs::read(&priors_path).unwrap()).unwrap();
    assert!((saved.classes.useful.prior_prob - 0.15).abs() < 1e-12);
    assert!((saved.classes.abandoned.prior_prob - 0.5).abs() < 1e-12);
    assert_eq!(saved.classes.useful.cpu_beta.alpha, 15.0);
    assert_eq!(saved.classes.useful.cpu_beta.beta, 22.0);
    let runtime = saved.classes.useful.runtime_gamma.as_ref().unwrap();
    assert_eq!(runtime.shape, 5.0);
    assert_eq!(runtime.rate, 9.0);
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        preview["resulting_priors"]
    );
    assert_eq!(fs::read(&backup_path).unwrap(), fleet_bytes);
    assert_eq!(fs::read(&input_path).unwrap(), source);
}

#[test]
fn import_priors_weighted_merge_matches_preview_and_retains_local_settings() {
    for explicit_merge in [false, true] {
        let data_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let (local, incoming) = distinct_transfer_priors();
        let priors_path = config_dir.path().join("priors.json");
        let backup_path = config_dir.path().join("priors.json.bak");
        let input_path = data_dir.path().join("incoming.json");
        let original = serde_json::to_vec_pretty(&local).unwrap();
        let source = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1.0.0",
            "host_profile": "build-worker",
            "priors": incoming,
        }))
        .unwrap();
        fs::write(&priors_path, &original).unwrap();
        fs::write(&input_path, &source).unwrap();

        let mut preview = prior_transfer_command(&data_dir, &config_dir);
        preview.args([
            "--format",
            "jsonl",
            "agent",
            "import-priors",
            "--from",
            input_path.to_str().unwrap(),
            "--host-profile",
            "build-worker",
            "--dry-run",
        ]);
        if explicit_merge {
            preview.arg("--merge");
        }
        let preview_output = preview.assert().success().get_output().stdout.clone();
        assert_eq!(String::from_utf8_lossy(&preview_output).lines().count(), 1);
        let preview: Value = serde_json::from_slice(&preview_output).unwrap();
        assert_eq!(preview["merge_strategy"], "weighted");
        assert_eq!(fs::read(&priors_path).unwrap(), original);
        assert!(!backup_path.exists());

        let mut import = prior_transfer_command(&data_dir, &config_dir);
        import.args([
            "--format",
            "jsonl",
            "agent",
            "import-priors",
            "--from",
            input_path.to_str().unwrap(),
            "--host-profile",
            "build-worker",
        ]);
        if explicit_merge {
            import.arg("--merge");
        }
        let output = import.assert().success().get_output().stdout.clone();
        assert_eq!(String::from_utf8_lossy(&output).lines().count(), 1);
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["imported"], true);
        assert_eq!(response["mode"], "merge");

        let mut saved: Value = serde_json::from_slice(&fs::read(&priors_path).unwrap()).unwrap();
        assert!((saved["classes"]["useful"]["prior_prob"].as_f64().unwrap() - 0.4).abs() < 1e-12);
        assert!(
            (saved["classes"]["abandoned"]["prior_prob"]
                .as_f64()
                .unwrap()
                - 0.25)
                .abs()
                < 1e-12
        );
        assert_eq!(saved["classes"]["useful"]["cpu_beta"]["alpha"], 6.0);
        assert_eq!(saved["classes"]["useful"]["cpu_beta"]["beta"], 10.0);
        assert_eq!(
            saved["classes"]["abandoned"]["io_active_beta"]["alpha"],
            8.0
        );
        assert_eq!(
            saved["classes"]["abandoned"]["io_active_beta"]["beta"],
            12.0
        );
        assert_eq!(
            saved["classes"]["abandoned"]["queue_saturation_beta"]["alpha"],
            4.0
        );
        assert_eq!(
            saved["classes"]["abandoned"]["queue_saturation_beta"]["beta"],
            6.0
        );
        assert_eq!(saved["classes"]["useful"]["runtime_gamma"]["shape"], 2.0);
        assert_eq!(saved["description"], "local model");
        assert_eq!(saved["host_profile"], "workstation");
        assert_eq!(fs::read(&backup_path).unwrap(), original);
        assert_eq!(fs::read(&input_path).unwrap(), source);

        // Separate invocations have separate update times; every configuration
        // value in the preview must agree with the model actually persisted.
        let mut previewed = preview["resulting_priors"].clone();
        assert!(saved["updated_at"].as_str().is_some());
        assert!(previewed["updated_at"].as_str().is_some());
        saved["updated_at"] = Value::Null;
        previewed["updated_at"] = Value::Null;
        assert_eq!(saved, previewed);
        prior_transfer_command(&data_dir, &config_dir)
            .args(["agent", "list-priors"])
            .assert()
            .success();
    }
}

#[test]
fn import_priors_replace_preserves_the_complete_incoming_model() {
    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, incoming) = distinct_transfer_priors();
    let priors_path = config_dir.path().join("priors.json");
    let input_path = data_dir.path().join("incoming.json");
    fs::write(&priors_path, serde_json::to_vec_pretty(&local).unwrap()).unwrap();
    let source = serde_json::to_vec_pretty(&incoming).unwrap();
    fs::write(&input_path, &source).unwrap();

    let output = prior_transfer_command(&data_dir, &config_dir)
        .args([
            "--format",
            "json",
            "agent",
            "import-priors",
            "--from",
            input_path.to_str().unwrap(),
            "--replace",
            "--no-backup",
            "--host-profile",
            "build-worker",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["merge_strategy"], "replace");
    let saved: Value = serde_json::from_slice(&fs::read(&priors_path).unwrap()).unwrap();
    assert_eq!(saved, serde_json::to_value(&incoming).unwrap());
    assert_eq!(fs::read(&input_path).unwrap(), source);
    assert!(!config_dir.path().join("priors.json.bak").exists());
    prior_transfer_command(&data_dir, &config_dir)
        .args(["agent", "list-priors"])
        .assert()
        .success();
}

#[test]
fn import_priors_rejects_invalid_models_before_preview_backup_or_publication() {
    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, incoming) = distinct_transfer_priors();
    let priors_path = config_dir.path().join("priors.json");
    let backup_path = config_dir.path().join("priors.json.bak");
    let input_path = data_dir.path().join("invalid.json");
    let original = serde_json::to_vec_pretty(&local).unwrap();
    fs::write(&priors_path, &original).unwrap();
    fs::write(&backup_path, b"previous backup").unwrap();

    for (path, value) in [
        ("/schema_version", serde_json::json!("99.0.0")),
        ("/classes/useful/cpu_beta/alpha", serde_json::json!(-1.0)),
        (
            "/classes/abandoned/queue_saturation_beta/beta",
            serde_json::json!(-1.0),
        ),
        ("/classes/useful/prior_prob", serde_json::json!(0.9)),
        ("/classes/useful/runtime_gamma/rate", serde_json::json!(0.0)),
    ] {
        let mut invalid = serde_json::to_value(&incoming).unwrap();
        *invalid.pointer_mut(path).expect("known prior field") = value;
        let source = serde_json::to_vec_pretty(&invalid).unwrap();
        fs::write(&input_path, &source).unwrap();
        for mode in ["--merge", "--replace"] {
            for dry_run in [false, true] {
                let mut cmd = prior_transfer_command(&data_dir, &config_dir);
                cmd.args([
                    "agent",
                    "import-priors",
                    "--from",
                    input_path.to_str().unwrap(),
                    mode,
                ]);
                if dry_run {
                    cmd.arg("--dry-run");
                }
                cmd.assert()
                    .code(ExitCode::ArgsError.as_i32())
                    .stderr(predicates::str::contains("invalid imported priors"));
                assert_eq!(fs::read(&priors_path).unwrap(), original, "{path}");
                assert_eq!(
                    fs::read(&backup_path).unwrap(),
                    b"previous backup",
                    "{path}"
                );
                assert_eq!(fs::read(&input_path).unwrap(), source, "{path}");
                assert!(!config_dir.path().join("priors.json.tmp").exists());
            }
        }
    }
}

#[test]
fn import_priors_requires_an_observed_matching_host_profile() {
    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, mut incoming) = distinct_transfer_priors();
    incoming.host_profile = None;
    let priors_path = config_dir.path().join("priors.json");
    let backup_path = config_dir.path().join("priors.json.bak");
    let input_path = data_dir.path().join("profiled.json");
    let original = serde_json::to_vec_pretty(&local).unwrap();
    fs::write(&priors_path, &original).unwrap();
    fs::write(&backup_path, b"previous backup").unwrap();

    for profile in [
        serde_json::json!("another-host"),
        Value::Null,
        serde_json::json!(42),
    ] {
        let source = serde_json::to_vec_pretty(&serde_json::json!({
            "priors": incoming,
            "host_profile": profile,
        }))
        .unwrap();
        fs::write(&input_path, &source).unwrap();
        for dry_run in [false, true] {
            let mut cmd = prior_transfer_command(&data_dir, &config_dir);
            cmd.args([
                "agent",
                "import-priors",
                "--from",
                input_path.to_str().unwrap(),
                "--replace",
                "--host-profile",
                "build-worker",
            ]);
            if dry_run {
                cmd.arg("--dry-run");
            }
            cmd.assert()
                .code(ExitCode::ArgsError.as_i32())
                .stderr(predicates::str::contains("must match --host-profile"));
            assert_eq!(fs::read(&priors_path).unwrap(), original);
            assert_eq!(fs::read(&backup_path).unwrap(), b"previous backup");
            assert_eq!(fs::read(&input_path).unwrap(), source);
        }
    }
}

#[test]
fn import_priors_backup_failure_preserves_the_current_model() {
    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, incoming) = distinct_transfer_priors();
    let priors_path = config_dir.path().join("priors.json");
    let input_path = data_dir.path().join("incoming.json");
    let original = serde_json::to_vec_pretty(&local).unwrap();
    fs::write(&priors_path, &original).unwrap();
    fs::write(&input_path, serde_json::to_vec_pretty(&incoming).unwrap()).unwrap();
    fs::create_dir(config_dir.path().join("priors.json.bak")).unwrap();

    prior_transfer_command(&data_dir, &config_dir)
        .args([
            "agent",
            "import-priors",
            "--from",
            input_path.to_str().unwrap(),
            "--replace",
        ])
        .assert()
        .code(ExitCode::IoError.as_i32())
        .stderr(predicates::str::contains("failed to create backup"));
    assert_eq!(fs::read(&priors_path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn import_priors_backup_replaces_links_without_writing_through_them() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    for hard_link in [false, true] {
        let data_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let (local, incoming) = distinct_transfer_priors();
        let priors_path = config_dir.path().join("priors.json");
        let backup_path = config_dir.path().join("priors.json.bak");
        let input_path = data_dir.path().join("incoming.json");
        let canary = data_dir.path().join("unrelated.txt");
        // Noncanonical whitespace must survive an exact backup as well.
        let mut original = b"\n ".to_vec();
        original.extend(serde_json::to_vec_pretty(&local).unwrap());
        original.extend_from_slice(b"\n \n");
        fs::write(&priors_path, &original).unwrap();
        fs::write(&input_path, serde_json::to_vec_pretty(&incoming).unwrap()).unwrap();
        fs::write(&canary, b"unrelated contents").unwrap();
        if hard_link {
            fs::hard_link(&canary, &backup_path).unwrap();
        } else {
            symlink(&canary, &backup_path).unwrap();
        }

        prior_transfer_command(&data_dir, &config_dir)
            .args([
                "agent",
                "import-priors",
                "--from",
                input_path.to_str().unwrap(),
                "--replace",
            ])
            .assert()
            .success();
        assert_eq!(fs::read(&canary).unwrap(), b"unrelated contents");
        assert_eq!(fs::read(&backup_path).unwrap(), original);
        assert!(fs::symlink_metadata(&backup_path).unwrap().is_file());
        assert_eq!(
            fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let saved: Value = serde_json::from_slice(&fs::read(&priors_path).unwrap()).unwrap();
        assert_eq!(saved, serde_json::to_value(&incoming).unwrap());
    }
}

#[cfg(unix)]
#[test]
fn prior_transfer_ignores_legacy_temporary_symlinks_and_exports_the_configured_profile() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let data_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let (local, _) = distinct_transfer_priors();
    let priors_path = config_dir.path().join("priors.json");
    let export_path = data_dir.path().join("exported.json");
    let canary = data_dir.path().join("unrelated.txt");
    fs::write(&priors_path, serde_json::to_vec_pretty(&local).unwrap()).unwrap();
    fs::write(&canary, b"unrelated contents").unwrap();
    let old_export_temp = export_path.with_extension("tmp");
    let old_import_temp = priors_path.with_extension("json.tmp");
    symlink(&canary, &old_export_temp).unwrap();
    symlink(&canary, &old_import_temp).unwrap();

    let output = prior_transfer_command(&data_dir, &config_dir)
        .args([
            "--format",
            "jsonl",
            "agent",
            "export-priors",
            "--out",
            export_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&output).lines().count(), 1);
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["host_profile"], "workstation");
    let exported: Value = serde_json::from_slice(&fs::read(&export_path).unwrap()).unwrap();
    assert_eq!(exported["host_profile"], "workstation");

    prior_transfer_command(&data_dir, &config_dir)
        .args([
            "agent",
            "import-priors",
            "--from",
            export_path.to_str().unwrap(),
            "--replace",
            "--no-backup",
            "--host-profile",
            "workstation",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&canary).unwrap(), b"unrelated contents");
    assert_eq!(fs::read_link(&old_export_temp).unwrap(), canary);
    assert_eq!(fs::read_link(&old_import_temp).unwrap(), canary);
    for path in [&priors_path, &export_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

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
