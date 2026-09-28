//! E2E tests for `agent fleet transfer` workflows.
//!
//! Covers JSON and PTB export/import/diff paths with real config files.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_bundle::{BundleReader, ExportProfile};
use pt_config::priors::Priors;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

fn write_priors(config_dir: &Path, priors: &Priors) {
    fs::create_dir_all(config_dir).expect("create config dir");
    let priors_path = config_dir.join("priors.json");
    let payload = serde_json::to_string_pretty(priors).expect("serialize priors");
    fs::write(priors_path, payload).expect("write priors");
}

fn priors_with_useful_prob(useful: f64, useful_bad: f64, abandoned: f64, zombie: f64) -> Priors {
    let mut priors = Priors::default();
    priors.classes.useful.prior_prob = useful;
    priors.classes.useful_bad.prior_prob = useful_bad;
    priors.classes.abandoned.prior_prob = abandoned;
    priors.classes.zombie.prior_prob = zombie;
    priors
}

fn assert_prob(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected {}, got {}",
        expected,
        actual
    );
}

#[test]
fn fleet_transfer_json_export_import_replace_roundtrip() {
    let temp = TempDir::new().expect("create temp dir");
    let config_dir = temp.path().join("config");
    let export_path = temp.path().join("fleet_transfer.json");

    let exported_priors = priors_with_useful_prob(0.62, 0.11, 0.19, 0.08);
    write_priors(&config_dir, &exported_priors);

    // Export bundle from config A.
    pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "export",
            "--out",
            export_path.to_str().expect("utf8 path"),
            "--host-profile",
            "prod",
        ])
        .assert()
        .success();

    let exported_bundle: Value = serde_json::from_str(
        &fs::read_to_string(&export_path).expect("read exported transfer bundle"),
    )
    .expect("bundle json");

    assert_eq!(
        exported_bundle
            .get("schema_version")
            .and_then(|v| v.as_str()),
        Some("1.0.0")
    );
    assert_eq!(
        exported_bundle
            .get("source_host_profile")
            .and_then(|v| v.as_str()),
        Some("prod")
    );
    let source_host_id = exported_bundle
        .get("source_host_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        source_host_id.starts_with("host-"),
        "expected hashed/safe host id, got {}",
        source_host_id
    );
    let checksum = exported_bundle
        .get("checksum")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(checksum.len(), 64);
    assert!(
        exported_bundle.get("priors").is_some(),
        "bundle should include priors"
    );

    // Overwrite local priors with config B so import must change them back.
    let local_priors = priors_with_useful_prob(0.30, 0.20, 0.30, 0.20);
    write_priors(&config_dir, &local_priors);

    // Import with replace strategy.
    pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "import",
            "--from",
            export_path.to_str().expect("utf8 path"),
            "--merge-strategy",
            "replace",
            "--no-backup",
        ])
        .assert()
        .success();

    let imported_priors: Priors = serde_json::from_str(
        &fs::read_to_string(config_dir.join("priors.json")).expect("read imported priors"),
    )
    .expect("parse imported priors");
    assert_prob(
        imported_priors.classes.useful.prior_prob,
        exported_priors.classes.useful.prior_prob,
    );
    assert_prob(
        imported_priors.classes.useful_bad.prior_prob,
        exported_priors.classes.useful_bad.prior_prob,
    );
    assert_prob(
        imported_priors.classes.abandoned.prior_prob,
        exported_priors.classes.abandoned.prior_prob,
    );
    assert_prob(
        imported_priors.classes.zombie.prior_prob,
        exported_priors.classes.zombie.prior_prob,
    );

    // Diff should now show no prior changes.
    let diff_stdout = pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "diff",
            "--from",
            export_path.to_str().expect("utf8 path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let diff_json: Value = serde_json::from_slice(&diff_stdout).expect("diff json");
    let prior_changes = diff_json["diff"]["priors_changes"]
        .as_array()
        .map(|v| v.len())
        .unwrap_or(0);
    assert_eq!(prior_changes, 0, "replace import should converge priors");
}

#[test]
fn fleet_transfer_ptb_export_and_passphrase_reads() {
    let temp = TempDir::new().expect("create temp dir");
    let config_dir = temp.path().join("config");
    let ptb_path: PathBuf = temp.path().join("fleet_transfer.ptb");
    let passphrase = "fleet-transfer-secret";

    let priors = priors_with_useful_prob(0.58, 0.12, 0.21, 0.09);
    write_priors(&config_dir, &priors);

    // Export encrypted PTB bundle.
    pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "export",
            "--out",
            ptb_path.to_str().expect("utf8 path"),
            "--host-profile",
            "staging",
            "--export-profile",
            "minimal",
            "--passphrase",
            passphrase,
        ])
        .assert()
        .success();

    let mut reader =
        BundleReader::open_with_passphrase(&ptb_path, Some(passphrase)).expect("open ptb");
    assert_eq!(reader.manifest().export_profile, ExportProfile::Minimal);
    let transfer_bundle: Value = reader
        .read_json("transfer_bundle.json")
        .expect("read transfer bundle payload");
    assert_eq!(
        transfer_bundle
            .get("source_host_profile")
            .and_then(|v| v.as_str()),
        Some("staging")
    );
    let source_host_id = transfer_bundle
        .get("source_host_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(source_host_id.starts_with("host-"));

    // Ensure diff and dry-run import can read encrypted PTB input.
    pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "diff",
            "--from",
            ptb_path.to_str().expect("utf8 path"),
            "--passphrase",
            passphrase,
        ])
        .assert()
        .success();

    pt_core_fast()
        .args([
            "--format",
            "json",
            "--config",
            config_dir.to_str().expect("utf8 path"),
            "agent",
            "fleet",
            "transfer",
            "import",
            "--from",
            ptb_path.to_str().expect("utf8 path"),
            "--passphrase",
            passphrase,
            "--dry-run",
        ])
        .assert()
        .success();
}

/// A pattern file that fails to load must not let the import rewrite the user's
/// pattern files: save() writes every file from memory, so after a failed load it
/// replaced disabled.json (and the unreadable file) with whatever had loaded
/// before the error. Nor may the import merge the priors and then report success
/// with the signatures silently skipped: it fails and writes nothing.
#[test]
fn fleet_transfer_import_leaves_pattern_files_alone_when_they_fail_to_load() {
    use pt_core::supervision::pattern_persistence::PatternLibrary;
    use pt_core::supervision::signature::SupervisorSignature;
    use pt_core::supervision::SupervisorCategory;

    let temp = TempDir::new().expect("create temp dir");
    let source_dir = temp.path().join("source");
    let target_dir = temp.path().join("target");
    let export_path = temp.path().join("fleet_transfer.json");

    let sig = |name: &str| {
        SupervisorSignature::new(name, SupervisorCategory::Other)
            .with_process_patterns(vec![format!("^{name}$").as_str()])
            .with_confidence(0.8)
    };
    write_priors(
        &source_dir,
        &priors_with_useful_prob(0.62, 0.11, 0.19, 0.08),
    );
    write_priors(&target_dir, &Priors::default());
    let target_priors = fs::read(target_dir.join("priors.json")).expect("read priors");
    let mut source = PatternLibrary::new(&source_dir);
    source.add_custom(sig("exported")).expect("add exported");
    source.save().expect("save source");

    let mut target = PatternLibrary::new(&target_dir);
    target
        .add_learned(sig("local_learned"))
        .expect("add learned");
    target.add_custom(sig("local_custom")).expect("add custom");
    target
        .disable_pattern("local_learned", Some("noisy"))
        .expect("disable");
    target.save().expect("save target");
    let patterns = target_dir.join("patterns");
    fs::write(patterns.join("custom.json"), "{ not json").expect("corrupt custom.json");
    let snapshot = |dir: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = fs::read_dir(dir)
            .expect("read patterns dir")
            .map(|e| {
                let path = e.expect("entry").path();
                let bytes = fs::read(&path).expect("read pattern file");
                (path, bytes)
            })
            .collect();
        files.sort();
        files
    };
    let before = snapshot(&patterns);

    pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&source_dir)
        .args(["agent", "fleet", "transfer", "export", "--out"])
        .arg(&export_path)
        .assert()
        .success();
    let bundle: Value =
        serde_json::from_str(&fs::read_to_string(&export_path).expect("read bundle"))
            .expect("bundle json");
    assert!(
        bundle["signatures"]["patterns"]
            .as_array()
            .is_some_and(|p| !p.is_empty()),
        "bundle carries the exported pattern: {bundle}"
    );
    assert!(
        !bundle["priors"].is_null(),
        "bundle carries priors: {bundle}"
    );

    let out = pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&target_dir)
        .args(["agent", "fleet", "transfer", "import", "--from"])
        .arg(&export_path)
        .args(["--merge-strategy", "replace", "--no-backup"])
        .output()
        .expect("run import");
    let response: Value = serde_json::from_slice(&out.stdout).expect("import output is JSON");
    assert_eq!(snapshot(&patterns), before, "pattern files were rewritten");
    assert!(!out.status.success(), "import reported success: {response}");
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(
        fs::read(target_dir.join("priors.json")).expect("read priors"),
        target_priors,
        "priors were merged although the signature import failed"
    );
}
