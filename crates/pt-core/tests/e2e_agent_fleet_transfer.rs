//! E2E tests for `agent fleet transfer` workflows.
//!
//! Covers JSON and PTB export/import/diff paths with real config files.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_bundle::{BundleReader, BundleWriter, ExportProfile, FileEntry, FileType};
use pt_config::priors::{BetaParams, Priors};
use pt_core::fleet::transfer::{validate_bundle, BaselineStats, TransferBundle};
use pt_core::supervision::pattern_persistence::{PatternLibrary, PatternLifecycle};
use pt_core::supervision::signature::{
    ProcessMatchContext, SignatureDatabase, SupervisorSignature,
};
use pt_core::supervision::SupervisorCategory;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
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

fn retained_dir() -> PathBuf {
    let path = TempDir::new().expect("create temp dir").keep();
    eprintln!("Retained fleet transfer fixture: {}", path.display());
    path
}

fn transfer_command(config_dir: &Path) -> Command {
    let mut command = pt_core_fast();
    command
        .args(["--format", "json", "--config"])
        .arg(config_dir)
        .args(["agent", "fleet", "transfer"]);
    command
}

fn run_retained(mut command: Command, artifacts: &Path, step: &str) -> Output {
    fs::create_dir_all(artifacts).expect("create artifact dir");
    fs::write(
        artifacts.join(format!("{step}.command.txt")),
        format!("{command:?}"),
    )
    .expect("retain command");
    let output = command.output().expect("run transfer command");
    fs::write(artifacts.join(format!("{step}.stdout")), &output.stdout).expect("retain stdout");
    fs::write(artifacts.join(format!("{step}.stderr")), &output.stderr).expect("retain stderr");
    fs::write(
        artifacts.join(format!("{step}.result.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "exit_code": output.status.code(),
            "status": format!("{:?}", output.status),
            "stdout_sha256": FileEntry::compute_checksum(&output.stdout),
            "stderr_sha256": FileEntry::compute_checksum(&output.stderr)
        }))
        .expect("serialize result"),
    )
    .expect("retain result");
    output
}

fn config_snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn collect(dir: &Path, root: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(dir).expect("read owned config") {
            let entry = entry.expect("config entry");
            let path = entry.path();
            let kind = entry.file_type().expect("config file type");
            if kind.is_dir() {
                collect(&path, root, files);
            } else {
                assert!(kind.is_file(), "unexpected owned config entry: {path:?}");
                files.push((
                    path.strip_prefix(root).expect("owned config path").into(),
                    fs::read(&path).expect("read owned config file"),
                ));
            }
        }
    }
    let mut files = Vec::new();
    collect(dir, dir, &mut files);
    files.sort();
    files
}

// Construct valid checksums only for planted rejection/normalization fixtures.
// Positive CLI exports are validated with their supplied checksum unchanged.
fn checksum_planted_fixture(bundle: &mut TransferBundle) {
    fn canonicalize(value: &mut Value) {
        match value {
            Value::Object(map) => {
                let fields = std::mem::take(map);
                let mut fields: Vec<_> = fields.into_iter().collect();
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                for (key, mut child) in fields {
                    canonicalize(&mut child);
                    map.insert(key, child);
                }
            }
            Value::Array(values) => values.iter_mut().for_each(canonicalize),
            _ => {}
        }
    }
    bundle.checksum.clear();
    let mut value = serde_json::to_value(&*bundle).expect("serialize invalid typed fixture");
    canonicalize(&mut value);
    bundle.checksum = FileEntry::compute_checksum(
        &serde_json::to_vec(&value).expect("serialize canonical input"),
    );
}

#[test]
fn fleet_transfer_json_export_import_replace_roundtrip() {
    let temp = retained_dir();
    let config_dir = temp.join("config");
    let export_path = temp.join("fleet_transfer.json");

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

    // Exercise the CLI's shipped defaults, without supplying a simplified
    // priors fixture or omitting legitimate free-form default comments.
    let defaults_config = temp.join("empty-default-config");
    fs::create_dir_all(&defaults_config).expect("create empty config dir");
    assert!(fs::read_dir(&defaults_config)
        .expect("read empty config")
        .next()
        .is_none());
    let defaults_path = temp.join("actual-defaults.json");
    let mut defaults_export = transfer_command(&defaults_config);
    defaults_export
        .args(["export", "--out"])
        .arg(&defaults_path);
    let out = run_retained(
        defaults_export,
        &temp.join("artifacts"),
        "shipped-defaults-export",
    );
    assert!(
        out.status.success(),
        "actual default configuration export failed: {out:?}"
    );
    let defaults: TransferBundle =
        serde_json::from_slice(&fs::read(&defaults_path).expect("read actual default export"))
            .expect("typed default export");
    validate_bundle(&defaults).expect("actual default export validates intact");
    assert_eq!(
        serde_json::to_value(defaults.priors.as_ref().expect("actual default priors"))
            .expect("actual defaults JSON"),
        serde_json::to_value(Priors::default()).expect("shipped defaults JSON")
    );
    assert!(defaults
        .priors
        .as_ref()
        .expect("default priors")
        .command_categories
        .as_ref()
        .expect("shipped category priors")
        .comment
        .as_ref()
        .is_some_and(|comment| comment.contains("Dirichlet priors over 13 command categories")));
    assert!(
        !defaults_config.join("priors.json").exists(),
        "default export wrote config"
    );

    // Preview actual strategy results for distinct configurations, then compare
    // those same previewed values with the priors saved by real CLI imports.
    let preview_source = temp.join("preview-source");
    let preview_path = temp.join("actual-preview-transfer.json");
    let artifacts = temp.join("artifacts");
    let mut incoming = priors_with_useful_prob(0.62, 0.11, 0.19, 0.08);
    incoming.classes.useful.cpu_beta = BetaParams::new(20.0, 80.0);
    write_priors(&preview_source, &incoming);
    let mut export = transfer_command(&preview_source);
    export.args(["export", "--out"]).arg(&preview_path);
    let out = run_retained(export, &artifacts, "preview-source-export");
    assert!(
        out.status.success(),
        "preview source export failed: {out:?}"
    );
    let incoming_bytes = fs::read(&preview_path).expect("actual preview input bytes");
    let supplied: TransferBundle =
        serde_json::from_slice(&incoming_bytes).expect("typed actual preview export");
    validate_bundle(&supplied).expect("supplied preview checksum validates unchanged");
    let mut local = priors_with_useful_prob(0.30, 0.20, 0.30, 0.20);
    local.classes.useful.cpu_beta = BetaParams::new(4.0, 16.0);
    for (strategy, expected_probability, expected_alpha, expected_beta) in [
        ("weighted", 0.46, 12.0, 48.0),
        ("replace", 0.62, 20.0, 80.0),
        ("keep-local", 0.30, 4.0, 16.0),
    ] {
        let target = temp.join(format!("preview-{strategy}"));
        write_priors(&target, &local);
        let before = config_snapshot(&target);
        let mut comparison = transfer_command(&target);
        comparison.args(["diff", "--from"]).arg(&preview_path);
        let out = run_retained(
            comparison,
            &artifacts,
            &format!("preview-{strategy}-comparison"),
        );
        assert!(out.status.success(), "comparison failed: {out:?}");
        let response: Value = serde_json::from_slice(&out.stdout).expect("comparison JSON");
        let comparison_changes = response["diff"]["priors_changes"]
            .as_array()
            .expect("comparison changes");
        assert!(
            !comparison_changes.is_empty(),
            "distinct inputs had no diff"
        );
        assert!(comparison_changes
            .iter()
            .all(|change| change.get("merged_value") == Some(&Value::Null)));
        assert_eq!(config_snapshot(&target), before);

        let mut preview = transfer_command(&target);
        preview.args(["import", "--from"]).arg(&preview_path).args([
            "--merge-strategy",
            strategy,
            "--dry-run",
        ]);
        let out = run_retained(preview, &artifacts, &format!("preview-{strategy}-dry-run"));
        assert!(out.status.success(), "strategy dry-run failed: {out:?}");
        let preview: Value = serde_json::from_slice(&out.stdout).expect("strategy preview JSON");
        assert_eq!(preview["dry_run"], true);
        let changes = preview["diff"]["details"]["priors_changes"]
            .as_array()
            .expect("preview changes");
        for (field, local_value, incoming_value, expected) in [
            ("prior_prob", 0.30, 0.62, expected_probability),
            ("cpu_beta.alpha", 4.0, 20.0, expected_alpha),
            ("cpu_beta.beta", 16.0, 80.0, expected_beta),
        ] {
            let matching: Vec<_> = changes
                .iter()
                .filter(|change| change["class"] == "useful" && change["field"] == field)
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "missing/duplicate useful {field} preview"
            );
            let change = matching[0];
            assert_prob(
                change["local_value"].as_f64().expect("local preview value"),
                local_value,
            );
            assert_prob(
                change["incoming_value"]
                    .as_f64()
                    .expect("incoming preview value"),
                incoming_value,
            );
            assert_prob(
                change["merged_value"]
                    .as_f64()
                    .expect("actual merged preview value"),
                expected,
            );
        }
        assert_eq!(config_snapshot(&target), before, "dry-run modified config");

        let mut import = transfer_command(&target);
        import.args(["import", "--from"]).arg(&preview_path).args([
            "--merge-strategy",
            strategy,
            "--no-backup",
        ]);
        let out = run_retained(import, &artifacts, &format!("preview-{strategy}-live"));
        assert!(out.status.success(), "strategy live import failed: {out:?}");
        let saved: Priors = serde_json::from_slice(
            &fs::read(target.join("priors.json")).expect("read actual strategy priors"),
        )
        .expect("parse actual saved strategy priors");
        pt_config::validate::validate_priors(&saved).expect("actual saved strategy priors valid");
        for (field, actual, expected) in [
            (
                "prior_prob",
                saved.classes.useful.prior_prob,
                expected_probability,
            ),
            (
                "cpu_beta.alpha",
                saved.classes.useful.cpu_beta.alpha,
                expected_alpha,
            ),
            (
                "cpu_beta.beta",
                saved.classes.useful.cpu_beta.beta,
                expected_beta,
            ),
        ] {
            let change = changes
                .iter()
                .find(|change| change["class"] == "useful" && change["field"] == field)
                .expect("same previewed field");
            assert_prob(actual, expected);
            assert_prob(
                actual,
                change["merged_value"]
                    .as_f64()
                    .expect("previewed saved value"),
            );
        }
        assert_eq!(
            fs::read(&preview_path).expect("unchanged actual CLI input"),
            incoming_bytes
        );
        let unchanged: TransferBundle =
            serde_json::from_slice(&incoming_bytes).expect("unchanged supplied export");
        assert_eq!(unchanged.checksum, supplied.checksum);
        validate_bundle(&unchanged).expect("original supplied checksum remains valid");
    }
}

#[test]
fn fleet_transfer_ptb_export_and_passphrase_reads() {
    let temp = retained_dir();
    let config_dir = temp.join("config");
    let target_dir = temp.join("target");
    let artifacts = temp.join("artifacts");
    let ptb_path = temp.join("fleet_transfer.ptb");
    let passphrase = "fleet-transfer-secret";

    let priors = priors_with_useful_prob(0.58, 0.12, 0.21, 0.09);
    write_priors(&config_dir, &priors);
    write_priors(&target_dir, &Priors::default());
    let env_patterns: HashMap<String, String> = [
        ("FLEET_MODE", "^worker$"),
        ("FLEET_ZONE", "^west$"),
        ("FLEET_ROLE", "^batch$"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    let signature = SupervisorSignature::new("fleet-env", SupervisorCategory::Other)
        .with_process_patterns(vec!["^fleet-env$"])
        .with_env_patterns(env_patterns)
        .with_min_matches(2);
    let mut source = PatternLibrary::new(&config_dir);
    source
        .add_custom(signature.clone())
        .expect("add source signature");
    source.save().expect("save source signature");

    // Operational configuration is intact, explicitly Forensic, and encrypted.
    let mut export = transfer_command(&config_dir);
    export.args(["export", "--out"]).arg(&ptb_path).args([
        "--host-profile",
        "staging",
        "--export-profile",
        "forensic",
        "--passphrase",
        passphrase,
    ]);
    let out = run_retained(export, &artifacts, "export");
    assert!(out.status.success(), "export failed: {out:?}");
    let archive_bytes = fs::read(&ptb_path).expect("read encrypted archive");

    let mut reader =
        BundleReader::open_with_passphrase(&ptb_path, Some(passphrase)).expect("open ptb");
    assert_eq!(reader.manifest().export_profile, ExportProfile::Forensic);
    let outer_checksum = reader
        .manifest()
        .files
        .iter()
        .find(|entry| entry.path == "transfer_bundle.json")
        .expect("original transfer entry")
        .sha256
        .clone();
    let payload = reader
        .read_verified("transfer_bundle.json")
        .expect("read verified transfer payload");
    assert_eq!(FileEntry::compute_checksum(&payload), outer_checksum);
    assert!(reader.verify_all().is_empty(), "archive integrity failed");
    let transfer_bundle: TransferBundle =
        serde_json::from_slice(&payload).expect("fresh typed transfer payload");
    validate_bundle(&transfer_bundle).expect("validate supplied inner checksum/config");
    assert_eq!(transfer_bundle.schema_version, "1.0.0");
    assert_eq!(
        transfer_bundle.source_host_profile.as_deref(),
        Some("staging")
    );
    assert!(transfer_bundle.source_host_id.starts_with("host-"));
    let inner_checksum = transfer_bundle.checksum.clone();
    assert_eq!(inner_checksum.len(), 64);
    assert_eq!(
        serde_json::to_value(transfer_bundle.priors.as_ref().expect("transfer priors"))
            .expect("serialize transferred priors"),
        serde_json::to_value(&priors).expect("serialize original priors")
    );
    let transferred_signature = &transfer_bundle
        .signatures
        .as_ref()
        .expect("transfer signatures")
        .patterns
        .iter()
        .find(|pattern| pattern.signature.name == signature.name)
        .expect("transferred custom signature")
        .signature;
    assert_eq!(transferred_signature, &signature);
    assert_eq!(transferred_signature.patterns.environment_vars.len(), 3);
    // Fresh HashMap reconstruction must not invalidate either supplied checksum.
    for _ in 0..4 {
        let fresh: TransferBundle = serde_json::from_slice(&payload).expect("fresh deserialize");
        validate_bundle(&fresh).expect("unchanged supplied checksum validates");
        assert_eq!(fresh.checksum, inner_checksum);
    }

    // Ensure diff and dry-run import can read encrypted PTB input.
    let source_before = config_snapshot(&config_dir);
    let target_before = config_snapshot(&target_dir);
    let mut diff = transfer_command(&config_dir);
    diff.args(["diff", "--from"])
        .arg(&ptb_path)
        .args(["--passphrase", passphrase]);
    let out = run_retained(diff, &artifacts, "diff");
    assert!(out.status.success(), "diff failed: {out:?}");
    let response: Value = serde_json::from_slice(&out.stdout).expect("diff JSON");
    assert_eq!(
        response["diff"]["priors_changes"]
            .as_array()
            .expect("prior changes")
            .len(),
        0
    );
    assert_eq!(config_snapshot(&config_dir), source_before);

    let mut dry_run = transfer_command(&target_dir);
    dry_run.args(["import", "--from"]).arg(&ptb_path).args([
        "--passphrase",
        passphrase,
        "--dry-run",
        "--merge-strategy",
        "replace",
    ]);
    let out = run_retained(dry_run, &artifacts, "dry-run");
    assert!(out.status.success(), "dry-run failed: {out:?}");
    let response: Value = serde_json::from_slice(&out.stdout).expect("dry-run JSON");
    assert_eq!(response["dry_run"], true);
    assert_eq!(config_snapshot(&target_dir), target_before);

    for operation in ["diff", "import"] {
        let mut wrong_key = transfer_command(&target_dir);
        wrong_key
            .args([operation, "--from"])
            .arg(&ptb_path)
            .args(["--passphrase", "wrong-passphrase"]);
        let out = run_retained(wrong_key, &artifacts, &format!("wrong-key-{operation}"));
        assert!(!out.status.success(), "wrong passphrase accepted: {out:?}");
        assert_eq!(config_snapshot(&target_dir), target_before);
    }

    let mut import = transfer_command(&target_dir);
    import.args(["import", "--from"]).arg(&ptb_path).args([
        "--passphrase",
        passphrase,
        "--merge-strategy",
        "replace",
        "--no-backup",
    ]);
    let out = run_retained(import, &artifacts, "replace");
    assert!(out.status.success(), "replace import failed: {out:?}");
    let imported_priors: Priors = serde_json::from_slice(
        &fs::read(target_dir.join("priors.json")).expect("read replaced priors"),
    )
    .expect("parse replaced priors");
    assert_eq!(
        serde_json::to_value(imported_priors).expect("imported priors JSON"),
        serde_json::to_value(&priors).expect("source priors JSON")
    );
    let mut imported = PatternLibrary::new(&target_dir);
    imported.load().expect("load actually imported patterns");
    let actual_signature = &imported
        .get_pattern(&signature.name)
        .expect("actually imported signature")
        .signature;
    assert_eq!(actual_signature, &signature);
    let mut database = SignatureDatabase::new();
    database
        .add(actual_signature.clone())
        .expect("activate intact imported matcher");
    let environment: HashMap<String, String> = [
        ("FLEET_MODE", "worker"),
        ("FLEET_ZONE", "west"),
        ("FLEET_ROLE", "batch"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    for (key, value) in &environment {
        let one_match = HashMap::from([(key.clone(), value.clone())]);
        let matches = database
            .match_process(&ProcessMatchContext::with_comm("fleet-env").env_vars(&one_match));
        assert_eq!(matches.len(), 1, "lost imported env matcher {key}");
        assert_eq!(matches[0].signature.name, "fleet-env");
    }
    assert!(database
        .match_process(&ProcessMatchContext::with_comm("unrelated").env_vars(&environment))
        .is_empty());
    let wrong_environment = HashMap::from([("FLEET_MODE".to_string(), "wrong".to_string())]);
    assert!(database
        .match_process(&ProcessMatchContext::with_comm("fleet-env").env_vars(&wrong_environment))
        .is_empty());
    assert_eq!(
        fs::read(&ptb_path).expect("retained archive"),
        archive_bytes
    );
    let mut final_reader = BundleReader::open_with_passphrase(&ptb_path, Some(passphrase))
        .expect("reopen unchanged archive");
    assert_eq!(
        final_reader
            .read_verified("transfer_bundle.json")
            .expect("unchanged payload"),
        payload
    );
    assert_eq!(
        final_reader
            .manifest()
            .files
            .iter()
            .find(|entry| entry.path == "transfer_bundle.json")
            .expect("unchanged entry")
            .sha256,
        outer_checksum
    );
}

#[test]
fn fleet_transfer_export_refuses_sharing_profiles_before_creating_output() {
    let temp = retained_dir();
    let config_dir = temp.join("config");
    let artifacts = temp.join("artifacts");
    write_priors(&config_dir, &Priors::default());
    let before = config_snapshot(&config_dir);
    for (case, extension, profile) in [
        ("minimal-ptb", "ptb", Some("minimal")),
        ("safe-ptb", "ptb", Some("safe")),
        ("default-ptb", "ptb", None),
        ("invalid-profile", "ptb", Some("invalid")),
        ("safe-json", "json", Some("safe")),
        ("minimal-json", "json", Some("minimal")),
    ] {
        let parent = temp.join(case);
        let destination = parent.join(format!("transfer.{extension}"));
        assert!(!parent.exists(), "refusal fixture already exists");
        let mut command = transfer_command(&config_dir);
        command.args(["export", "--out"]).arg(&destination);
        if let Some(profile) = profile {
            command.args(["--export-profile", profile]);
        }
        let out = run_retained(command, &artifacts, case);
        assert!(!out.status.success(), "{case} export accepted: {out:?}");
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            diagnostic.contains(if profile == Some("invalid") {
                "invalid"
            } else {
                "forensic"
            }),
            "wrong profile refusal: {diagnostic}"
        );
        assert!(!destination.exists(), "refused destination was published");
        assert!(!parent.exists(), "refused export created its output parent");
        assert_eq!(config_snapshot(&config_dir), before);
    }
}

#[test]
fn fleet_transfer_export_refuses_detected_credentials_without_echoing_them() {
    let temp = retained_dir();
    let artifacts = temp.join("artifacts");
    // An inert regex-shaped test token, not a live credential.
    let canary = format!("ghp_{}", "a".repeat(36));
    assert!(pt_redact::SecretDetector::new().detect(&canary).is_some());
    for case in ["freeform-value", "matcher-key"] {
        let config_dir = temp.join(case);
        let mut priors = Priors::default();
        if case == "freeform-value" {
            priors.description = Some(format!("private transfer note {canary}"));
        }
        write_priors(&config_dir, &priors);
        if case == "matcher-key" {
            let signature = SupervisorSignature::new("credential-key", SupervisorCategory::Other)
                .with_process_patterns(vec!["^credential-key$"])
                .with_env_patterns(HashMap::from([(canary.clone(), "^value$".to_string())]));
            let mut library = PatternLibrary::new(&config_dir);
            library
                .add_custom(signature)
                .expect("save planted credential key");
            library.save().expect("save credential fixture");
        }
        let before = config_snapshot(&config_dir);
        for extension in ["json", "ptb"] {
            let step = format!("{case}-{extension}");
            let parent = temp.join(format!("out-{step}"));
            let destination = parent.join(format!("transfer.{extension}"));
            let mut command = transfer_command(&config_dir);
            command
                .args(["export", "--out"])
                .arg(&destination)
                .args(["--export-profile", "forensic"]);
            let out = run_retained(command, &artifacts, &step);
            assert!(!out.status.success(), "credential exported: {out:?}");
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                diagnostic.contains("detected sensitive content"),
                "{diagnostic}"
            );
            assert!(
                !diagnostic.contains(&canary),
                "credential echoed in diagnostic"
            );
            assert!(!destination.exists(), "credential artifact was published");
            assert!(!parent.exists(), "credential refusal created output parent");
            assert_eq!(config_snapshot(&config_dir), before);
        }
    }
}

#[test]
fn fleet_transfer_import_and_diff_refuse_invalid_intact_configuration() {
    let temp = retained_dir();
    let source_dir = temp.join("source");
    let target_dir = temp.join("target");
    let artifacts = temp.join("artifacts");
    write_priors(
        &source_dir,
        &priors_with_useful_prob(0.58, 0.12, 0.21, 0.09),
    );
    write_priors(&target_dir, &Priors::default());
    let mut source = PatternLibrary::new(&source_dir);
    source
        .add_custom(
            SupervisorSignature::new("incoming", SupervisorCategory::Other)
                .with_process_patterns(vec!["^incoming$"]),
        )
        .expect("add incoming signature");
    source.save().expect("save source");
    let mut target = PatternLibrary::new(&target_dir);
    target
        .add_custom(
            SupervisorSignature::new("local", SupervisorCategory::Other)
                .with_process_patterns(vec!["^local$"]),
        )
        .expect("add local signature");
    target.save().expect("save target");
    let before = config_snapshot(&target_dir);
    let valid_path = temp.join("actual-export.json");
    let mut export = transfer_command(&source_dir);
    export.args(["export", "--out"]).arg(&valid_path);
    let out = run_retained(export, &artifacts, "valid-source-export");
    assert!(out.status.success(), "source export failed: {out:?}");
    let valid: TransferBundle =
        serde_json::from_slice(&fs::read(&valid_path).expect("read actual CLI export"))
            .expect("typed actual export");
    validate_bundle(&valid).expect("actual export valid without checksum replacement");
    let canary = format!("ghp_{}", "a".repeat(36));
    let baseline_refusal = "baseline normalization requires comparable measured learning observations; local baseline evidence is unavailable";

    for (case, expected_reason) in [
        ("redacted-active", "redacted matcher"),
        ("redacted-inactive", "redacted matcher"),
        ("invalid-beta", "cpu_beta"),
        ("inner-checksum", "checksum mismatch"),
        ("credential-value", "detected sensitive content"),
        ("credential-key", "detected sensitive content"),
        ("credential-schema-version", "detected sensitive content"),
        ("credential-checksum", "detected sensitive content"),
        ("malformed-enum", "invalid fleet transfer configuration"),
    ] {
        let mut planted = valid.clone();
        match case {
            "redacted-active" | "redacted-inactive" => {
                let pattern = &mut planted
                    .signatures
                    .as_mut()
                    .expect("source signatures")
                    .patterns[0];
                pattern.signature.patterns.process_names =
                    vec!["[HASH: private_matcher]".to_string()];
                if case == "redacted-inactive" {
                    pattern.lifecycle = PatternLifecycle::Removed;
                }
            }
            "invalid-beta" => {
                planted
                    .priors
                    .as_mut()
                    .expect("source priors")
                    .classes
                    .useful
                    .cpu_beta
                    .alpha = 0.0
            }
            "credential-value" => {
                planted.priors.as_mut().expect("source priors").description = Some(canary.clone())
            }
            "credential-key" => {
                planted
                    .signatures
                    .as_mut()
                    .expect("source signatures")
                    .patterns[0]
                    .signature
                    .patterns
                    .environment_vars
                    .insert(canary.clone(), ".*".to_string());
            }
            "credential-schema-version" => planted.schema_version = canary.clone(),
            "inner-checksum" | "credential-checksum" | "malformed-enum" => {}
            _ => unreachable!("enumerated planted case"),
        }
        checksum_planted_fixture(&mut planted);
        if case == "inner-checksum" {
            planted.checksum = "0".repeat(64);
        } else if case == "credential-checksum" {
            planted.checksum = canary.clone();
        }
        let mut value = serde_json::to_value(&planted).expect("serialize planted input");
        if case == "malformed-enum" {
            // The enum fails typed parsing before checksum/content validation.
            // Its diagnostic must not include serde's supplied variant value.
            value["signatures"]["patterns"][0]["category"] = Value::String(canary.clone());
            assert!(serde_json::from_value::<TransferBundle>(value.clone()).is_err());
        } else {
            let error = validate_bundle(&planted)
                .expect_err("planted config must fail")
                .to_string();
            assert!(
                error.contains(expected_reason),
                "wrong planted error: {error}"
            );
            assert!(!error.contains(&canary), "validator echoed credential");
        }
        let payload = serde_json::to_vec_pretty(&value).expect("serialize planted payload");
        for extension in ["json", "ptb"] {
            let input = temp.join(format!("{case}.{extension}"));
            if extension == "ptb" {
                let mut writer =
                    BundleWriter::new("transfer", "host-fixture", ExportProfile::Forensic);
                writer.add_file(
                    "transfer_bundle.json",
                    payload.clone(),
                    Some(FileType::Binary),
                );
                writer
                    .write(&input)
                    .expect("write planted opaque Forensic archive");
                let mut reader = BundleReader::open(&input).expect("open planted archive");
                assert_eq!(
                    reader
                        .read_verified("transfer_bundle.json")
                        .expect("outer checksum valid"),
                    payload
                );
            } else {
                fs::write(&input, &payload).expect("write planted JSON");
            }
            let input_before = fs::read(&input).expect("retain planted bytes");
            for operation in ["import", "dry-run", "diff"] {
                let mut command = transfer_command(&target_dir);
                command
                    .args([
                        if operation == "diff" {
                            "diff"
                        } else {
                            "import"
                        },
                        "--from",
                    ])
                    .arg(&input);
                if operation == "dry-run" {
                    command.arg("--dry-run");
                }
                let step = format!("{case}-{extension}-{operation}");
                let out = run_retained(command, &artifacts, &step);
                assert!(!out.status.success(), "invalid input accepted: {out:?}");
                let diagnostic = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(
                    diagnostic.contains(expected_reason),
                    "wrong CLI refusal: {diagnostic}"
                );
                assert!(!diagnostic.contains(&canary), "credential echoed by CLI");
                assert_eq!(
                    config_snapshot(&target_dir),
                    before,
                    "{step} mutated config"
                );
                assert_eq!(
                    fs::read(&input).expect("unchanged planted input"),
                    input_before
                );
            }
        }
    }

    // Finite incoming parameters and a supplied source baseline cannot stand in
    // for comparable measured local learning observations. Normalization must
    // refuse before both dry-run and persistence, rather than invent exposure.
    let mut normalization = valid.clone();
    normalization
        .priors
        .as_mut()
        .expect("incoming priors")
        .classes
        .useful
        .cpu_beta
        .alpha = 1e308;
    normalization.baseline_stats = Some(BaselineStats {
        total_processes_seen: 1,
        observation_window_hours: 1.0,
        class_distribution: BTreeMap::new(),
        mean_cpu_utilization: 50.0,
        host_type: None,
    });
    checksum_planted_fixture(&mut normalization);
    validate_bundle(&normalization).expect("finite normalization input validates");
    let payload = serde_json::to_vec_pretty(&normalization).expect("finite normalization input");
    for extension in ["json", "ptb"] {
        let input = temp.join(format!("normalization-large-finite.{extension}"));
        if extension == "ptb" {
            let mut writer = BundleWriter::new("transfer", "host-fixture", ExportProfile::Forensic);
            writer.add_file(
                "transfer_bundle.json",
                payload.clone(),
                Some(FileType::Binary),
            );
            writer
                .write(&input)
                .expect("write finite normalization archive");
            let mut reader = BundleReader::open(&input).expect("open finite input archive");
            assert_eq!(
                reader
                    .read_verified("transfer_bundle.json")
                    .expect("outer checksum valid"),
                payload
            );
        } else {
            fs::write(&input, &payload).expect("write finite normalization JSON");
        }
        let input_before = fs::read(&input).expect("finite input bytes");
        let mut unscaled = transfer_command(&target_dir);
        unscaled.args(["import", "--from"]).arg(&input).args([
            "--merge-strategy",
            "replace",
            "--dry-run",
        ]);
        let out = run_retained(unscaled, &artifacts, &format!("finite-{extension}-dry-run"));
        assert!(
            out.status.success(),
            "finite unscaled input refused: {out:?}"
        );
        let response: Value = serde_json::from_slice(&out.stdout).expect("finite dry-run JSON");
        assert_eq!(response["dry_run"], true);
        assert_eq!(config_snapshot(&target_dir), before);
        for dry_run in [true, false] {
            let mut command = transfer_command(&target_dir);
            command.args(["import", "--from"]).arg(&input).args([
                "--merge-strategy",
                "replace",
                "--normalize-baseline",
                "--no-backup",
            ]);
            if dry_run {
                command.arg("--dry-run");
            }
            let step = format!(
                "large-finite-normalize-refused-{extension}-{}",
                if dry_run { "dry-run" } else { "live" }
            );
            let out = run_retained(command, &artifacts, &step);
            assert!(
                !out.status.success(),
                "normalization accepted without measured local evidence: {out:?}"
            );
            assert_eq!(
                out.status.code(),
                Some(pt_core::exit_codes::ExitCode::ArgsError.as_i32())
            );
            let response: Value =
                serde_json::from_slice(&out.stdout).expect("normalization refusal JSON");
            assert_eq!(response["status"], "error");
            assert_eq!(response["error"].as_str(), Some(baseline_refusal));
            assert_eq!(
                config_snapshot(&target_dir),
                before,
                "refused normalization modified config"
            );
            assert_eq!(
                fs::read(&input).expect("unchanged finite input"),
                input_before
            );
        }
    }

    // Ordinary intact configuration still transfers without normalization.
    // Refusal-only normalization does not establish its positive capability.
    let mut finite = normalization.clone();
    finite
        .priors
        .as_mut()
        .expect("finite priors")
        .classes
        .useful
        .cpu_beta
        .alpha = 2.0;
    checksum_planted_fixture(&mut finite);
    validate_bundle(&finite).expect("ordinary finite input validates");
    let payload = serde_json::to_vec_pretty(&finite).expect("finite intact payload");
    for extension in ["json", "ptb"] {
        let finite_target = temp.join(format!("finite-target-{extension}"));
        write_priors(&finite_target, &Priors::default());
        let before_finite = config_snapshot(&finite_target);
        let input = temp.join(format!("normalization-finite.{extension}"));
        if extension == "ptb" {
            let mut writer = BundleWriter::new("transfer", "host-fixture", ExportProfile::Forensic);
            writer.add_file(
                "transfer_bundle.json",
                payload.clone(),
                Some(FileType::Binary),
            );
            writer.write(&input).expect("write finite intact archive");
            let mut reader = BundleReader::open(&input).expect("open finite intact archive");
            assert_eq!(
                reader
                    .read_verified("transfer_bundle.json")
                    .expect("verified finite payload"),
                payload
            );
        } else {
            fs::write(&input, &payload).expect("write finite intact JSON");
        }
        let input_before = fs::read(&input).expect("finite intact bytes");
        for dry_run in [true, false] {
            let mut command = transfer_command(&finite_target);
            command.args(["import", "--from"]).arg(&input).args([
                "--merge-strategy",
                "replace",
                "--normalize-baseline",
                "--no-backup",
            ]);
            if dry_run {
                command.arg("--dry-run");
            }
            let step = format!(
                "ordinary-normalize-refused-{extension}-{}",
                if dry_run { "dry-run" } else { "live" }
            );
            let out = run_retained(command, &artifacts, &step);
            assert_eq!(
                out.status.code(),
                Some(pt_core::exit_codes::ExitCode::ArgsError.as_i32())
            );
            let response: Value =
                serde_json::from_slice(&out.stdout).expect("ordinary normalization refusal JSON");
            assert_eq!(response["status"], "error");
            assert_eq!(response["error"].as_str(), Some(baseline_refusal));
            assert_eq!(config_snapshot(&finite_target), before_finite);
            assert_eq!(
                fs::read(&input).expect("unchanged finite input"),
                input_before
            );
        }
        for dry_run in [true, false] {
            let mut command = transfer_command(&finite_target);
            command.args(["import", "--from"]).arg(&input).args([
                "--merge-strategy",
                "replace",
                "--no-backup",
            ]);
            if dry_run {
                command.arg("--dry-run");
            }
            let step = format!(
                "unscaled-finite-{extension}-{}",
                if dry_run { "dry-run" } else { "live" }
            );
            let out = run_retained(command, &artifacts, &step);
            assert!(out.status.success(), "finite intact import failed: {out:?}");
            if dry_run {
                assert_eq!(config_snapshot(&finite_target), before_finite);
            } else {
                let imported: Priors = serde_json::from_slice(
                    &fs::read(finite_target.join("priors.json"))
                        .expect("read actual unscaled saved priors"),
                )
                .expect("parse actual unscaled saved priors");
                pt_config::validate::validate_priors(&imported)
                    .expect("persisted unscaled priors valid");
                assert_prob(imported.classes.useful.cpu_beta.alpha, 2.0);
                let source_priors = finite.priors.as_ref().expect("source priors");
                assert_prob(
                    imported.classes.useful.cpu_beta.beta,
                    source_priors.classes.useful.cpu_beta.beta,
                );
                assert_prob(
                    imported.classes.useful.prior_prob,
                    source_priors.classes.useful.prior_prob,
                );
                assert_eq!(
                    serde_json::to_value(&imported).expect("saved intact priors"),
                    serde_json::to_value(source_priors).expect("source intact priors")
                );
                let mut imported_library = PatternLibrary::new(&finite_target);
                imported_library
                    .load()
                    .expect("load finite imported signature");
                let imported_signature = &imported_library
                    .get_pattern("incoming")
                    .expect("imported intact signature")
                    .signature;
                assert_eq!(
                    imported_signature,
                    &finite
                        .signatures
                        .as_ref()
                        .expect("source signatures")
                        .patterns[0]
                        .signature
                );
                let mut database = SignatureDatabase::new();
                database
                    .add(imported_signature.clone())
                    .expect("activate actual imported signature");
                assert_eq!(
                    database
                        .match_process(&ProcessMatchContext::with_comm("incoming"))
                        .len(),
                    1
                );
                assert!(database
                    .match_process(&ProcessMatchContext::with_comm("unrelated"))
                    .is_empty());
            }
            assert_eq!(
                fs::read(&input).expect("unchanged finite input"),
                input_before
            );
        }
    }

    // Missing source evidence is also an explicit refusal, never a silent
    // no-op normalization followed by successful configuration persistence.
    assert!(valid.baseline_stats.is_none());
    let payload = fs::read(&valid_path).expect("original source export without baseline");
    for extension in ["json", "ptb"] {
        let input = temp.join(format!("normalization-missing-source.{extension}"));
        if extension == "ptb" {
            let mut writer = BundleWriter::new("transfer", "host-fixture", ExportProfile::Forensic);
            writer.add_file(
                "transfer_bundle.json",
                payload.clone(),
                Some(FileType::Binary),
            );
            writer.write(&input).expect("write missing-source archive");
        } else {
            fs::write(&input, &payload).expect("write missing-source JSON");
        }
        let input_before = fs::read(&input).expect("missing-source input bytes");
        for dry_run in [true, false] {
            let mut command = transfer_command(&target_dir);
            command
                .args(["import", "--from"])
                .arg(&input)
                .arg("--normalize-baseline");
            if dry_run {
                command.arg("--dry-run");
            }
            let step = format!(
                "missing-source-refused-{extension}-{}",
                if dry_run { "dry-run" } else { "live" }
            );
            let out = run_retained(command, &artifacts, &step);
            assert_eq!(
                out.status.code(),
                Some(pt_core::exit_codes::ExitCode::ArgsError.as_i32())
            );
            let response: Value =
                serde_json::from_slice(&out.stdout).expect("missing-source refusal JSON");
            assert_eq!(response["status"], "error");
            assert_eq!(response["error"].as_str(), Some(baseline_refusal));
            assert_eq!(config_snapshot(&target_dir), before);
            assert_eq!(
                fs::read(&input).expect("unchanged missing-source input"),
                input_before
            );
        }
    }

    // A sharing manifest cannot become executable configuration, even if its
    // payload is irrelevant: the profile must be rejected before payload reads.
    for profile in [ExportProfile::Safe, ExportProfile::Minimal] {
        let label = if profile == ExportProfile::Safe {
            "safe"
        } else {
            "minimal"
        };
        let input = temp.join(format!("shared-{label}.ptb"));
        let mut writer = BundleWriter::new("pt-20261005-120000-abcd", "host-fixture", profile);
        writer.add_file(
            "summary.json",
            b"{\"process_count\":1}".to_vec(),
            Some(FileType::Json),
        );
        writer.write(&input).expect("write actual sharing bundle");
        let input_before = fs::read(&input).expect("sharing input bytes");
        for operation in ["import", "dry-run", "diff"] {
            let mut command = transfer_command(&target_dir);
            command
                .args([
                    if operation == "diff" {
                        "diff"
                    } else {
                        "import"
                    },
                    "--from",
                ])
                .arg(&input);
            if operation == "dry-run" {
                command.arg("--dry-run");
            }
            let out = run_retained(command, &artifacts, &format!("shared-{label}-{operation}"));
            assert!(
                !out.status.success(),
                "sharing activation accepted: {out:?}"
            );
            assert_eq!(
                out.status.code(),
                Some(pt_core::exit_codes::ExitCode::ArgsError.as_i32())
            );
            let response: Value =
                serde_json::from_slice(&out.stdout).expect("sharing refusal JSON");
            let expected = if operation == "diff" {
                "redacted sharing bundle cannot be used as intact fleet configuration"
            } else {
                "redacted sharing bundle cannot be activated as fleet configuration"
            };
            assert_eq!(response["status"], "error");
            assert_eq!(response["error"].as_str(), Some(expected));
            assert_eq!(config_snapshot(&target_dir), before);
            assert_eq!(
                fs::read(&input).expect("unchanged sharing input"),
                input_before
            );
        }
    }
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

    let temp = retained_dir();
    let source_dir = temp.join("source");
    let target_dir = temp.join("target");
    let export_path = temp.join("fleet_transfer.json");

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

/// `transfer diff` and `import --dry-run` compare the bundle with the local pattern
/// library: before, they passed no local signatures, so every incoming signature
/// was reported as new and nothing as unchanged or local-only.
#[test]
fn fleet_transfer_diff_compares_against_local_patterns() {
    use pt_core::supervision::pattern_persistence::PatternLibrary;
    use pt_core::supervision::signature::SupervisorSignature;
    use pt_core::supervision::SupervisorCategory;

    let temp = retained_dir();
    let source_dir = temp.join("source");
    let target_dir = temp.join("target");
    let export_path = temp.join("fleet_transfer.json");

    let sig = |name: &str, confidence: f64| {
        SupervisorSignature::new(name, SupervisorCategory::Other)
            .with_process_patterns(vec![format!("^{name}$").as_str()])
            .with_confidence(confidence)
    };
    write_priors(&source_dir, &Priors::default());
    write_priors(&target_dir, &Priors::default());
    let mut source = PatternLibrary::new(&source_dir);
    source.add_custom(sig("shared", 0.8)).expect("add shared");
    source.add_custom(sig("retuned", 0.9)).expect("add retuned");
    source.add_custom(sig("brand_new", 0.7)).expect("add new");
    source.save().expect("save source");
    let mut target = PatternLibrary::new(&target_dir);
    target.add_custom(sig("shared", 0.8)).expect("add shared");
    target
        .add_learned(sig("retuned", 0.5))
        .expect("add retuned");
    target
        .add_custom(sig("local_only", 0.6))
        .expect("add local");
    target.save().expect("save target");

    pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&source_dir)
        .args(["agent", "fleet", "transfer", "export", "--out"])
        .arg(&export_path)
        .assert()
        .success();

    let change_types = |changes: &Value| -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = changes
            .as_array()
            .expect("signature_changes array")
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().expect("name").to_string(),
                    c["change_type"].as_str().expect("change_type").to_string(),
                )
            })
            .collect();
        out.sort();
        out
    };
    let expected: Vec<(String, String)> = [
        ("brand_new", "added"),
        ("local_only", "removed"),
        ("retuned", "updated"),
        ("shared", "unchanged"),
    ]
    .iter()
    .map(|(n, t)| (n.to_string(), t.to_string()))
    .collect();

    let out = pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&target_dir)
        .args(["agent", "fleet", "transfer", "diff", "--from"])
        .arg(&export_path)
        .output()
        .expect("run diff");
    assert!(out.status.success(), "diff failed: {out:?}");
    let response: Value = serde_json::from_slice(&out.stdout).expect("diff output is JSON");
    assert_eq!(
        change_types(&response["diff"]["signature_changes"]),
        expected,
        "{response}"
    );

    let out = pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&target_dir)
        .args(["agent", "fleet", "transfer", "import", "--from"])
        .arg(&export_path)
        .arg("--dry-run")
        .output()
        .expect("run dry-run import");
    assert!(out.status.success(), "dry-run import failed: {out:?}");
    let response: Value = serde_json::from_slice(&out.stdout).expect("import output is JSON");
    assert_eq!(
        change_types(&response["diff"]["details"]["signature_changes"]),
        expected,
        "{response}"
    );
}

/// An unreadable pattern library fails the export instead of silently producing a
/// bundle without signatures.
#[test]
fn fleet_transfer_export_fails_when_patterns_cannot_load() {
    let temp = retained_dir();
    let config_dir = temp.join("config");
    let export_path = temp.join("fleet_transfer.json");
    write_priors(&config_dir, &Priors::default());
    fs::create_dir_all(config_dir.join("patterns")).expect("mkdir patterns");
    fs::write(
        config_dir.join("patterns").join("custom.json"),
        "{ not json",
    )
    .expect("corrupt custom.json");

    let out = pt_core_fast()
        .args(["--format", "json", "--config"])
        .arg(&config_dir)
        .args(["agent", "fleet", "transfer", "export", "--out"])
        .arg(&export_path)
        .output()
        .expect("run export");
    assert!(!out.status.success(), "export succeeded: {out:?}");
    assert!(!export_path.exists(), "a bundle was written");
}
