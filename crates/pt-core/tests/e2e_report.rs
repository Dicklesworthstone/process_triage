//! End-to-end tests for `agent report` command.
//!
//! Tests the HTML report generation pipeline through the CLI:
//! - Argument validation (missing session/bundle, invalid theme/format)
//! - CDN mode: pinned versions + SRI integrity on all external assets
//! - embed-assets mode: no external http/https URLs
//! - Galaxy-brain tab rendering
//! - Session accuracy: session_id and schema_version consistency
//! - Redaction: sensitive data not present in output
//!
//! Requires the `report` feature: `cargo test --features report --test e2e_report`

#![cfg(feature = "report")]

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use regex::Regex;
use serde_json::Value;
use std::time::Duration;
use tempfile::tempdir;

/// Get a Command for pt-core binary with report feature.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(180));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Get a fast pt-core command with standalone + sample limiting.
fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd.args(["--standalone"]);
    cmd
}

const TEST_SAMPLE_SIZE: &str = "5";

/// Run `agent plan` with JSON output and return the parsed JSON + session_id.
fn create_session(data_dir: &std::path::Path) -> (Value, String) {
    let output = pt_core_fast()
        .env("PROCESS_TRIAGE_DATA", data_dir.display().to_string())
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--sample-size",
            TEST_SAMPLE_SIZE,
        ])
        .output()
        .expect("failed to run agent plan");

    assert!(
        output.status.success() || output.status.code() == Some(1),
        "agent plan failed with code {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan: Value =
        serde_json::from_slice(&output.stdout).expect("agent plan should produce valid JSON");
    let session_id = plan["session_id"]
        .as_str()
        .expect("plan must have session_id")
        .to_string();

    (plan, session_id)
}

/// Generate an HTML report from a session and return the HTML string.
fn generate_report(data_dir: &std::path::Path, session_id: &str, extra_args: &[&str]) -> String {
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.display().to_string())
        .args(["agent", "report", "--session", session_id])
        .args(extra_args)
        .output()
        .expect("failed to run agent report");

    assert!(
        output.status.success(),
        "agent report failed with code {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("report HTML should be valid UTF-8")
}

// ============================================================================
// Argument Validation Tests
// ============================================================================

mod args_validation {
    use super::*;

    #[test]
    fn report_requires_session_or_bundle() {
        pt_core()
            .args(["agent", "report"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "must specify either --session or --bundle",
            ));
    }

    #[test]
    fn report_rejects_invalid_theme() {
        let tmp = tempdir().unwrap();
        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args([
                "agent",
                "report",
                "--session",
                "pt-00000000-000000-xxxx",
                "--theme",
                "neon",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid theme"));
    }

    #[test]
    fn report_rejects_invalid_format() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());

        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args([
                "agent",
                "report",
                "--session",
                &session_id,
                "--report-format",
                "pdf",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid format"));
    }

    #[test]
    fn report_rejects_nonexistent_bundle() {
        pt_core()
            .args(["agent", "report", "--bundle", "/nonexistent/path.ptb"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("bundle file not found"));
    }

    #[test]
    fn report_rejects_nonexistent_session() {
        let tmp = tempdir().unwrap();
        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args(["agent", "report", "--session", "pt-99991231-235959-zzzz"])
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("session not found")
                    .or(predicate::str::contains("invalid session ID")),
            );
    }
}

// ============================================================================
// CDN Mode Tests (default)
// ============================================================================

mod cdn_mode {
    use super::*;

    #[test]
    fn report_html_is_valid_structure() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Report must start with DOCTYPE"
        );
        assert!(html.contains("<body>"), "Report must have body");
        assert!(html.contains("</html>"), "Report must close html tag");
        assert!(html.contains("<header"), "Report must have header");
        assert!(html.contains("<main>"), "Report must have main section");
        assert!(html.contains("<footer"), "Report must have footer");
    }

    #[test]
    fn cdn_urls_have_pinned_versions() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        let cdn_pattern =
            Regex::new(r#"cdn\.jsdelivr\.net/npm/([a-z-]+)@(\d+\.\d+\.\d+)"#).unwrap();

        let mut found = false;
        for cap in cdn_pattern.captures_iter(&html) {
            found = true;
            let version = &cap[2];
            let parts: Vec<&str> = version.split('.').collect();
            assert_eq!(parts.len(), 3, "CDN version must be semver: {}", version);
            for part in parts {
                assert!(
                    part.parse::<u32>().is_ok(),
                    "Version part must be numeric: {}",
                    part
                );
            }
        }

        assert!(found, "Report should contain CDN URLs with pinned versions");
    }

    #[test]
    fn cdn_scripts_have_sri_integrity() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        let script_re =
            Regex::new(r#"<script[^>]+src="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>"#).unwrap();

        for m in script_re.find_iter(&html) {
            let tag = m.as_str();
            assert!(
                tag.contains("integrity="),
                "CDN script must have integrity: {}",
                tag
            );
            assert!(
                tag.contains(r#"crossorigin="anonymous""#),
                "CDN script must have crossorigin: {}",
                tag
            );
        }
    }

    #[test]
    fn cdn_stylesheets_have_sri_integrity() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        let link_re = Regex::new(r#"<link[^>]+href="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>"#).unwrap();

        for m in link_re.find_iter(&html) {
            let tag = m.as_str();
            assert!(
                tag.contains("integrity="),
                "CDN link must have integrity: {}",
                tag
            );
            assert!(
                tag.contains(r#"crossorigin="anonymous""#),
                "CDN link must have crossorigin: {}",
                tag
            );
        }
    }

    #[test]
    fn sri_hashes_are_valid_format() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        let sri_re = Regex::new(r#"integrity="(sha\d+-[A-Za-z0-9+/=]+)""#).unwrap();

        let mut found = false;
        for cap in sri_re.captures_iter(&html) {
            found = true;
            let hash = &cap[1];
            assert!(
                hash.starts_with("sha384-")
                    || hash.starts_with("sha256-")
                    || hash.starts_with("sha512-"),
                "SRI hash must use sha256/sha384/sha512: {}",
                hash
            );
            let hash_part = hash.split('-').nth(1).unwrap();
            assert!(hash_part.len() >= 32, "SRI hash too short: {}", hash);
        }

        assert!(found, "Report should contain SRI integrity hashes");
    }
}

// ============================================================================
// Embed Assets Mode Tests
// ============================================================================

mod embed_assets_mode {
    use super::*;

    #[test]
    fn embed_mode_flag_accepted() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        // --embed-assets flag should be accepted without error
        let html = generate_report(tmp.path(), &session_id, &["--embed-assets"]);

        // The report should still be valid HTML even in embed mode
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "embed-assets report must be valid HTML"
        );
        // Inline styles and JS should always be present
        assert!(
            html.contains("<style>"),
            "embed mode must have inline styles"
        );
        assert!(
            html.contains("const REPORT_DATA ="),
            "embed mode must have inline REPORT_DATA"
        );
    }

    #[test]
    fn embed_mode_has_inline_styles() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--embed-assets"]);

        assert!(
            html.contains("<style>"),
            "embed mode must have inline styles"
        );
        assert!(
            html.contains("--bg-primary:"),
            "embed mode must define CSS variables"
        );
    }

    #[test]
    fn embed_mode_has_inline_javascript() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--embed-assets"]);

        assert!(
            html.contains("const REPORT_DATA ="),
            "embed mode must have inline REPORT_DATA"
        );
        assert!(
            html.contains("function switchTab"),
            "embed mode must have inline tab switching"
        );
    }

    #[test]
    fn embed_mode_no_remote_fetch_calls() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--embed-assets"]);

        // Check there are no fetch() calls to remote URLs
        let fetch_re = Regex::new(r#"fetch\s*\(\s*["']https?://"#).unwrap();
        assert!(
            !fetch_re.is_match(&html),
            "embed-assets mode must not have remote fetch() calls"
        );
    }
}

// ============================================================================
// Session Accuracy Tests
// ============================================================================

mod session_accuracy {
    use super::*;

    #[test]
    fn report_contains_session_id() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(&session_id),
            "Report must contain the session ID: {}",
            session_id
        );
    }

    #[test]
    fn report_contains_schema_version() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(r#""schema_version":"1.0.0""#),
            "Report must embed schema_version 1.0.0"
        );
    }

    #[test]
    fn report_contains_generator_meta_tag() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(r#"name="generator" content="pt-report "#),
            "Report must have generator meta tag"
        );
    }

    #[test]
    fn report_has_overview_tab() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        // Overview tab is always present
        assert!(
            html.contains(r#"data-tab="overview""#),
            "Report must have overview tab button"
        );
        assert!(
            html.contains(r#"id="tab-overview""#),
            "Report must have overview tab content"
        );
    }

    #[test]
    fn report_tabs_conditional_on_data() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        // The report should have tab navigation infrastructure
        assert!(
            html.contains("function switchTab"),
            "Report must have tab switching JavaScript"
        );
        assert!(
            html.contains(".tab-btn"),
            "Report must reference tab button CSS class"
        );
    }

    #[test]
    fn report_output_to_file() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let out_path = tmp.path().join("report.html");

        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "report",
                "--session",
                &session_id,
                "--out",
                out_path.to_str().unwrap(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("success"));

        let html = std::fs::read_to_string(&out_path).expect("output file should exist");
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Output file must contain valid HTML"
        );
        assert!(
            html.contains(&session_id),
            "Output file must contain session ID"
        );
    }
}

// ============================================================================
// Galaxy Brain Tab Tests
// ============================================================================

mod galaxy_brain {
    use super::*;

    #[test]
    fn recorded_ledger_present_when_flag_set() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--galaxy-brain"]);

        assert!(
            html.contains("Recorded Evidence Ledger"),
            "Report must expose its recorded ledger when --galaxy-brain is set"
        );
        assert!(
            html.contains(r#"id="recorded-evidence""#),
            "Report must have recorded evidence content"
        );
    }

    #[test]
    fn galaxy_brain_tab_absent_by_default() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            !html.contains(r#"data-tab="galaxy-brain""#),
            "Report must NOT have galaxy-brain tab by default"
        );
    }

    #[test]
    fn galaxy_brain_includes_prior_config() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--galaxy-brain"]);

        // Galaxy brain section should contain Bayesian prior information
        assert!(
            html.contains("P(") || html.contains("prior") || html.contains("Prior"),
            "Galaxy brain must reference priors"
        );
    }

    #[test]
    fn galaxy_brain_includes_katex_math() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--galaxy-brain"]);

        // Galaxy brain mode should include KaTeX library for math rendering
        assert!(
            html.contains("katex") || html.contains("KaTeX"),
            "Galaxy brain must include KaTeX for math rendering"
        );
    }
}

/// Exercise the actual session -> CLI export -> ZIP reader -> CLI HTML paths.
/// The planted candidate/outcome values are routing and privacy fixtures, not
/// proof of a live kill or calibrated inference quality.
#[test]
fn recorded_session_bundle_and_report_preserve_data_without_leaking_canaries() {
    use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
    use pt_core::supervision::signature::{
        ProcessExpectations, SignaturePriors, SignatureSchema, SupervisorSignature,
    };
    use pt_core::supervision::SupervisorCategory;
    use std::collections::HashMap;
    use std::fs;
    let data_dir = tempdir().unwrap().keep();
    let config_dir = tempdir().unwrap().keep();
    eprintln!(
        "recorded session report case retained at {}",
        data_dir.display()
    );
    let session_id = pt_common::SessionId::new();
    let handle = SessionStore::at_data_dir(&data_dir)
        .create(&SessionManifest::new(
            &session_id,
            None,
            SessionMode::RobotPlan,
            None,
        ))
        .unwrap();
    let started_at = handle.read_manifest().unwrap().timing.created_at;
    let started_instant = chrono::DateTime::parse_from_rfc3339(&started_at).unwrap();
    handle
        .write_context(&SessionContext::new(
            &session_id,
            "private-customer-host".to_string(),
            "run-test".to_string(),
            None,
        ))
        .unwrap();
    for directory in ["decision", "scan", "inference", "action", "logs"] {
        fs::create_dir_all(handle.dir.join(directory)).unwrap();
    }
    let command = "python /home/private-customer/work.py --token AKIAIOSFODNN7EXAMPLE";
    let local_command = "python /home/local-user/work.py --verbose";
    let plan = serde_json::json!({
        "session_id": session_id.0,
        "scan": {"total_processes": 42},
        "candidates": [{
            "pid": 1234, "command": command, "score": 87,
            "recommended_action": "review",
            "posterior": {"useful": 0.1, "useful_bad": 0.03, "abandoned": 0.8, "zombie": 0.07},
            "evidence_ledger": {"evidence_terms": [{"feature": "cpu", "log_likelihood": {"abandoned": -0.4, "useful": -2.0}}]},
            "environment": {"API_KEY": "AKIAIOSFODNN7EXAMPLE"}
        }],
    });
    fs::write(
        handle.dir.join("decision/plan.json"),
        serde_json::to_vec(&plan).unwrap(),
    )
    .unwrap();
    for (path, payload) in [
        (
            "scan/inventory.json",
            serde_json::json!({"records": [
                {"pid": 1234, "cmd": command},
                {"pid": 1235, "cmd": local_command,
                 "cwd": "/home/local-user/project", "username": "local-user"}
            ]}),
        ),
        (
            "inference/results.json",
            serde_json::json!({"candidates": [{"pid": 1234, "posterior_useful_bad": 0.03}]}),
        ),
    ] {
        let envelope = serde_json::json!({
            "schema_version": "1.0.0", "session_id": session_id.0,
            "payload": payload,
            "integrity_sha256": pt_bundle::FileEntry::compute_checksum(&serde_json::to_vec(&payload).unwrap()),
        });
        fs::write(
            handle.dir.join(path),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
    }
    let outcome =
        serde_json::json!({"pid": 1234, "action": "kill", "status": "blocked", "command": command});
    fs::write(
        handle.dir.join("action/outcomes.jsonl"),
        format!("{outcome}\n"),
    )
    .unwrap();
    fs::write(
        handle.dir.join("logs/session.jsonl"),
        "{\"event\":\"plan_ready\",\"candidate_count\":1}\n",
    )
    .unwrap();

    // Export the actual signature producer's schema, including its typed
    // environment map, rather than a reduced JSON fixture with only public keys.
    let mut signatures = SignatureSchema::new();
    let mut signature =
        SupervisorSignature::new("private-customer-worker", SupervisorCategory::Other)
            .with_process_patterns(vec!["private-customer-worker"])
            .with_env_patterns(HashMap::from([(
                "PRIVATE_CUSTOMER_TOKEN".to_string(),
                "AKIAIOSFODNN7EXAMPLE".to_string(),
            )]));
    signature.priors = SignaturePriors::likely_abandoned();
    signature.expectations = ProcessExpectations::short_lived_task();
    signatures.add(signature);
    signatures.validate().unwrap();
    fs::write(
        pt_core::signature_cli::user_signatures_path(&config_dir),
        signatures.to_json().unwrap(),
    )
    .unwrap();

    let plain_bundle = data_dir.join("session.ptb");
    for encrypted in [false, true] {
        let destination = if encrypted {
            data_dir.join("encrypted.ptb")
        } else {
            plain_bundle.clone()
        };
        let mut command = pt_core();
        command
            .env("PROCESS_TRIAGE_DATA", &data_dir)
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .arg("--config")
            .arg(&config_dir)
            .args([
                "--format",
                "json",
                "bundle",
                "create",
                "--session",
                &session_id.0,
                "--output",
            ])
            .arg(&destination);
        if encrypted {
            command.args(["--encrypt", "--passphrase", "test-passphrase"]);
        }
        command.assert().success();
        let mut reader = pt_bundle::BundleReader::open_with_passphrase(
            &destination,
            encrypted.then_some("test-passphrase"),
        )
        .unwrap();
        assert!(reader.verify_all().is_empty());
        assert!(reader.has_file("scan/inventory.json"));
        assert!(reader.has_file("inference/results.json"));
        assert!(reader.has_file("logs/session.jsonl"));
        let saved_signatures: SignatureSchema = reader
            .read_json(pt_core::signature_cli::BUNDLE_SIGNATURES_PATH)
            .unwrap();
        saved_signatures.validate().unwrap();
        assert_eq!(saved_signatures.schema_version, signatures.schema_version);
        assert_eq!(saved_signatures.signatures.len(), 1);
        let saved_signature = &saved_signatures.signatures[0];
        assert_eq!(saved_signature.category, SupervisorCategory::Other);
        assert_eq!(saved_signature.priors, signatures.signatures[0].priors);
        assert_eq!(
            saved_signature.expectations,
            signatures.signatures[0].expectations
        );
        assert_eq!(saved_signature.patterns.environment_vars.len(), 1);
        for (name, value) in &saved_signature.patterns.environment_vars {
            assert_ne!(name, "PRIVATE_CUSTOMER_TOKEN");
            assert_eq!(value, "[REDACTED]");
        }
        // Exercise activation through the CLI, not only typed decoding. The
        // existing file must survive both the archive and extracted-JSON paths.
        let import_config = data_dir.join(if encrypted {
            "encrypted-import-config"
        } else {
            "plain-import-config"
        });
        fs::create_dir_all(&import_config).unwrap();
        let existing_bytes = signatures.to_json().unwrap().into_bytes();
        let import_signature_path = pt_core::signature_cli::user_signatures_path(&import_config);
        fs::write(&import_signature_path, &existing_bytes).unwrap();
        let mut import = pt_core();
        import
            .arg("--config")
            .arg(&import_config)
            .args(["--format", "json", "signature", "import"])
            .arg(&destination);
        if encrypted {
            import.args(["--passphrase", "test-passphrase"]);
        }
        import
            .assert()
            .code(10)
            .stdout(predicate::str::contains("cannot activate signatures"));
        assert_eq!(fs::read(&import_signature_path).unwrap(), existing_bytes);
        let extracted = import_config.join("shared-signatures.json");
        fs::write(&extracted, saved_signatures.to_json().unwrap()).unwrap();
        pt_core()
            .arg("--config")
            .arg(&import_config)
            .args(["--format", "json", "signature", "import"])
            .arg(&extracted)
            .assert()
            .code(10)
            .stdout(predicate::str::contains("cannot be activated"));
        assert_eq!(fs::read(&import_signature_path).unwrap(), existing_bytes);
        let saved_manifest: Value = reader.read_json("session/manifest.json").unwrap();
        assert_eq!(saved_manifest["timing"]["created_at"], started_at);
        assert_eq!(saved_manifest["state"], "created");
        assert_eq!(saved_manifest["mode"], "robot_plan");
        let saved: Value = reader.read_json("inference/results.json").unwrap();
        assert_eq!(
            saved["payload"]["candidates"][0]["posterior_useful_bad"],
            0.03
        );
        assert_eq!(
            saved["integrity_sha256"],
            pt_bundle::FileEntry::compute_checksum(&serde_json::to_vec(&saved["payload"]).unwrap())
        );
        let entries = reader.manifest().files.clone();
        for entry in entries {
            let bytes = reader.read_verified(&entry.path).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(
                !text.contains("private-customer"),
                "leaked in {}",
                entry.path
            );
            assert!(
                !text.contains("AKIAIOSFODNN7EXAMPLE"),
                "leaked in {}",
                entry.path
            );
        }
    }
    // An intact original remains importable and retains its exact matching
    // behavior. In particular, it must not match unrelated commands containing
    // letters from a hash marker's regex character class.
    let positive_config = data_dir.join("original-import-config");
    let mut original = SignatureSchema::new();
    original.add(
        SupervisorSignature::new("private-original-worker", SupervisorCategory::Other)
            .with_process_patterns(vec!["^private-original-worker$"])
            .with_priors(SignaturePriors::likely_abandoned()),
    );
    let original_path = data_dir.join("original-signatures.json");
    fs::write(&original_path, original.to_json().unwrap()).unwrap();
    let forensic_producer_config = data_dir.join("forensic-producer-config");
    fs::create_dir_all(&forensic_producer_config).unwrap();
    fs::write(
        pt_core::signature_cli::user_signatures_path(&forensic_producer_config),
        original.to_json().unwrap(),
    )
    .unwrap();
    let forensic_path = data_dir.join("original-signatures.ptb");
    // Exercise the default production writer through the CLI. A custom
    // library redaction engine would conceal a missing Forensic allowlist.
    let forensic_export = pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(&forensic_producer_config)
        .args([
            "--format",
            "json",
            "bundle",
            "create",
            "--profile",
            "forensic",
            "--session",
            &session_id.0,
            "--output",
        ])
        .arg(&forensic_path)
        .assert();
    fs::write(
        data_dir.join("forensic-create.stdout.json"),
        &forensic_export.get_output().stdout,
    )
    .unwrap();
    fs::write(
        data_dir.join("forensic-create.stderr"),
        &forensic_export.get_output().stderr,
    )
    .unwrap();
    forensic_export.success();
    let mut forensic_reader = pt_bundle::BundleReader::open(&forensic_path).unwrap();
    assert_eq!(
        forensic_reader.export_profile(),
        pt_redact::ExportProfile::Forensic
    );
    assert!(forensic_reader.verify_all().is_empty());
    let archived_original: SignatureSchema = forensic_reader
        .read_json(pt_core::signature_cli::BUNDLE_SIGNATURES_PATH)
        .unwrap();
    archived_original.validate_for_activation().unwrap();
    assert_eq!(archived_original, original);
    let forensic_context: Value = forensic_reader.read_json("session/context.json").unwrap();
    assert_eq!(forensic_context["host_id"], "private-customer-host");
    let forensic_inventory: Value = forensic_reader.read_json("scan/inventory.json").unwrap();
    assert_eq!(forensic_inventory["payload"]["records"][0]["cmd"], "[REDACTED]");
    assert_eq!(forensic_inventory["payload"]["records"][1]["cmd"], local_command);
    assert_eq!(
        forensic_inventory["payload"]["records"][1]["cwd"],
        "/home/local-user/project"
    );
    assert_eq!(forensic_inventory["payload"]["records"][1]["username"], "local-user");
    let forensic_plan: Value = forensic_reader.read_json("plan.json").unwrap();
    assert_eq!(forensic_plan["candidates"][0]["command"], "[REDACTED]");
    assert_eq!(forensic_plan["candidates"][0]["environment"], "[REDACTED]");
    let forensic_entries = forensic_reader.manifest().files.clone();
    for entry in forensic_entries {
        let bytes = forensic_reader.read_verified(&entry.path).unwrap();
        assert!(
            !String::from_utf8(bytes).unwrap().contains("AKIAIOSFODNN7EXAMPLE"),
            "Forensic credential leaked in {}",
            entry.path
        );
    }
    pt_core()
        .arg("--config")
        .arg(&positive_config)
        .args(["--format", "json", "signature", "import"])
        .arg(&original_path)
        .assert()
        .success();
    // Activate the CLI-produced archive in a separate config: the raw import
    // must not supply the match that is supposed to prove archive activation.
    let forensic_config = data_dir.join("forensic-import-config");
    pt_core()
        .arg("--config")
        .arg(&forensic_config)
        .args(["--format", "json", "signature", "import"])
        .arg(&forensic_path)
        .assert()
        .success();
    for imported_config in [&positive_config, &forensic_config] {
        let matched = pt_core()
            .arg("--config")
            .arg(imported_config)
            .args([
                "--format",
                "json",
                "signature",
                "test",
                "private-original-worker",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let matched: Value = serde_json::from_slice(&matched).unwrap();
        assert!(matched["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "private-original-worker"));
        let unrelated = pt_core()
            .arg("--config")
            .arg(imported_config)
            .args(["--format", "json", "signature", "test", "awk"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let unrelated: Value = serde_json::from_slice(&unrelated).unwrap();
        assert!(!unrelated["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "private-original-worker"));
    }

    for bundle_input in [false, true] {
        let mut command = pt_core();
        command
            .env("PROCESS_TRIAGE_DATA", &data_dir)
            .arg("--config")
            .arg(&config_dir);
        if bundle_input {
            command
                .args(["agent", "report", "--bundle"])
                .arg(&plain_bundle)
                .args(["--galaxy-brain", "--embed-assets"]);
        } else {
            command.args([
                "report",
                "--session",
                &session_id.0,
                "--include-ledger",
                "--embed-assets",
            ]);
        }
        let assertion = command.assert();
        let artifact = if bundle_input {
            "bundle-report"
        } else {
            "session-report"
        };
        fs::write(
            data_dir.join(format!("{artifact}.stdout.html")),
            &assertion.get_output().stdout,
        )
        .unwrap();
        fs::write(
            data_dir.join(format!("{artifact}.stderr")),
            &assertion.get_output().stderr,
        )
        .unwrap();
        let html = String::from_utf8(assertion.success().get_output().stdout.clone()).unwrap();
        assert!(html.contains("<td>1234</td>"));
        assert!(html.contains("<td>87</td><td>review</td>"));
        assert!(html.contains("log_likelihood"));
        assert!(html.contains("Recorded Actions and Outcomes"));
        assert!(html.contains("blocked"));
        assert!(!html.contains("private-customer"));
        assert!(!html.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!html.contains("<script src="));
        assert!(!html.contains("<link rel=\"stylesheet\""));
        let recorded_json = html
            .split("id=\"recorded-session-data\">")
            .nth(1)
            .expect("report must embed the actual recorded session overview")
            .split("</script>")
            .next()
            .unwrap();
        let recorded: Value = serde_json::from_str(recorded_json).unwrap();
        let reported_started_at = recorded["overview"]["started_at"]
            .as_str()
            .expect("recorded overview must contain a start timestamp");
        // DateTime serializes UTC as Z; preserve the exact saved instant,
        // including nanoseconds, rather than requiring its original spelling.
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(reported_started_at).unwrap(),
            started_instant
        );
        let started_row = Regex::new(&format!(
            r"Started</dt>\s*<dd>{}</dd>",
            regex::escape(reported_started_at),
        ))
        .unwrap();
        assert!(
            started_row.is_match(&html),
            "visible Started row must display the actual recorded start timestamp"
        );
        assert!(html.contains("robot_plan"));
        assert!(html.contains("created"));
    }

    let signature_path = pt_core::signature_cli::user_signatures_path(&config_dir);
    fs::write(&signature_path, b"not-json").unwrap();
    let refused = data_dir.join("invalid-signatures-refused.ptb");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(&config_dir)
        .args(["bundle", "create", "--session", &session_id.0, "--output"])
        .arg(&refused)
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid user signatures"));
    assert!(!refused.exists());
    fs::write(&signature_path, signatures.to_json().unwrap()).unwrap();

    // A present malformed artifact must refuse publication, rather than produce
    // a successful export silently missing part of the recorded session.
    let inference_path = handle.dir.join("inference/results.json");
    let original_inference = fs::read(&inference_path).unwrap();
    fs::write(&inference_path, b"not-json").unwrap();
    let refused = data_dir.join("malformed-refused.ptb");
    pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(&config_dir)
        .args(["bundle", "create", "--session", &session_id.0, "--output"])
        .arg(&refused)
        .assert()
        .failure();
    assert!(!refused.exists());
    fs::write(&inference_path, original_inference).unwrap();

    fs::write(handle.dir.join("scan/provenance.json"), b"{}").unwrap();
    fs::write(
        handle.dir.join("scan/provenance_audit.json"),
        br#"{"warning_count":0}"#,
    )
    .unwrap();
    let refused = data_dir.join("invalid-provenance-audit-refused.ptb");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(&config_dir)
        .args(["bundle", "create", "--session", &session_id.0, "--output"])
        .arg(&refused)
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid provenance audit"));
    assert!(!refused.exists());

    // A requested telemetry directory that cannot be enumerated must stop the
    // export. Use another real session so the malformed audit above cannot be
    // the cause of this refusal, and retain both fixtures for diagnosis.
    let telemetry_session = pt_common::SessionId::new();
    let telemetry_handle = SessionStore::at_data_dir(&data_dir)
        .create(&SessionManifest::new(
            &telemetry_session,
            None,
            SessionMode::RobotPlan,
            None,
        ))
        .unwrap();
    let telemetry_dir = telemetry_handle.dir.join("telemetry");
    let retained_telemetry_dir = telemetry_handle
        .dir
        .join(format!("telemetry-retained-{}", uuid::Uuid::new_v4()));
    assert!(
        telemetry_dir.is_dir(),
        "session creation must prepare telemetry"
    );
    assert_eq!(
        fs::symlink_metadata(&retained_telemetry_dir)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound,
        "retention destination must not exist, including a dangling symlink"
    );
    // Keep the genuine precreated directory; obstruct only this owned session's
    // requested telemetry path without deletion or permission-based ambiguity.
    fs::rename(&telemetry_dir, &retained_telemetry_dir).unwrap();
    assert!(retained_telemetry_dir.is_dir());
    fs::write(&telemetry_dir, b"not a directory").unwrap();
    assert!(telemetry_dir.is_file());
    let refused = data_dir.join("unreadable-telemetry-refused.ptb");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", &data_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(&config_dir)
        .args([
            "bundle",
            "create",
            "--session",
            &telemetry_session.0,
            "--include-telemetry",
            "--output",
        ])
        .arg(&refused)
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read requested telemetry"));
    assert!(!refused.exists());
}

// ============================================================================
// Theme Tests
// ============================================================================

mod themes {
    use super::*;

    #[test]
    fn light_theme_applied() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--theme", "light"]);

        assert!(
            html.contains(r#"class="light""#),
            "Light theme must set light class"
        );
    }

    #[test]
    fn dark_theme_applied() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--theme", "dark"]);

        assert!(
            html.contains(r#"class="dark""#),
            "Dark theme must set dark class"
        );
    }

    #[test]
    fn auto_theme_is_default() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        // Auto theme uses empty class
        assert!(
            html.contains(r#"<html lang="en" class="">"#),
            "Auto theme should have empty class on html element"
        );
    }

    #[test]
    fn custom_title_applied() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(
            tmp.path(),
            &session_id,
            &["--title", "My Custom Triage Report"],
        );

        assert!(
            html.contains("<title>My Custom Triage Report</title>"),
            "Custom title must appear in HTML"
        );
    }
}

// ============================================================================
// Security Tests
// ============================================================================

mod security {
    use super::*;

    #[test]
    fn no_eval_or_document_write() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(!html.contains("eval("), "Report must not use eval()");
        assert!(
            !html.contains("document.write"),
            "Report must not use document.write"
        );
        assert!(
            !html.contains("javascript:"),
            "Report must not have javascript: URLs"
        );
    }

    #[test]
    fn no_inline_event_handlers() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            !html.contains("onclick="),
            "Report should not use inline onclick"
        );
        assert!(
            !html.contains("onload="),
            "Report should not use inline onload"
        );
    }

    #[test]
    fn external_links_have_noopener() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        let link_re = Regex::new(r#"<a[^>]+target="_blank"[^>]*>"#).unwrap();
        for m in link_re.find_iter(&html) {
            let tag = m.as_str();
            assert!(
                tag.contains("noopener"),
                "External link must have noopener: {}",
                tag
            );
        }
    }

    #[test]
    fn robots_noindex_present() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(r#"name="robots" content="noindex, nofollow""#),
            "Report must have noindex robots meta tag"
        );
    }
}

// ============================================================================
// Output Format Tests
// ============================================================================

mod output_formats {
    use super::*;

    #[test]
    fn slack_format_produces_text() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());

        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "report",
                "--session",
                &session_id,
                "--report-format",
                "slack",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("slack"));
    }

    #[test]
    fn prose_format_produces_text() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());

        pt_core()
            .env("PROCESS_TRIAGE_DATA", tmp.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "report",
                "--session",
                &session_id,
                "--report-format",
                "prose",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("prose"));
    }
}

// ============================================================================
// Print Styles Tests
// ============================================================================

mod print_styles {
    use super::*;

    #[test]
    fn print_media_query_present() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains("@media print"),
            "Report should have print media query"
        );
    }

    #[test]
    fn no_print_class_present() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(".no-print"),
            "Report should define .no-print class"
        );
    }
}

// ============================================================================
// Responsive Design Tests
// ============================================================================

mod responsive {
    use super::*;

    #[test]
    fn viewport_meta_tag_present() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(r#"name="viewport""#),
            "Report must have viewport meta tag for mobile"
        );
    }

    #[test]
    fn charset_utf8_declared() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &[]);

        assert!(
            html.contains(r#"charset="UTF-8""#),
            "Report must declare UTF-8 charset"
        );
    }
}

/// Real CLI extraction tests. Archives and output files are retained for
/// inspection; planted unsafe metadata is only a negative input fixture.
#[cfg(unix)]
mod bundle_extraction {
    use super::*;
    use pt_bundle::{
        BundleManifest, BundleReader, BundleWriter, ExportProfile, FileEntry, FileType,
    };
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Output;

    const PAYLOAD: &[u8] = b"exact archive bytes\0\xff\n  preserved spacing\n";

    fn retained_case() -> PathBuf {
        let path = tempfile::Builder::new()
            .prefix("pt-bundle-extract-")
            .tempdir()
            .unwrap()
            .keep();
        let path = fs::canonicalize(path).unwrap();
        fs::create_dir(path.join("working")).unwrap();
        eprintln!("bundle extraction case retained at {}", path.display());
        path
    }

    fn genuine_bundle(case: &Path, files: &[(&str, &[u8])]) -> (PathBuf, String) {
        let session = pt_common::SessionId::new().0;
        let mut writer = BundleWriter::new(&session, "extraction-host", ExportProfile::Forensic);
        for (path, bytes) in files {
            writer.add_file(*path, bytes.to_vec(), Some(FileType::Binary));
        }
        let bundle = case.join("genuine.ptb");
        writer.write(&bundle).unwrap();
        let mut reader = BundleReader::open(&bundle).unwrap();
        for (path, bytes) in files {
            assert_eq!(reader.read_verified(path).unwrap(), *bytes);
        }
        (bundle, session)
    }

    fn extract(
        case: &Path,
        bundle: &Path,
        destination: Option<&Path>,
        verify: bool,
    ) -> (Output, Value) {
        let mut command = pt_core_fast();
        command
            .current_dir(case.join("working"))
            .env("PROCESS_TRIAGE_DATA", case.join("state"))
            .args(["--format", "json", "bundle", "extract"])
            .arg(bundle);
        if let Some(destination) = destination {
            command.arg("--output").arg(destination);
        }
        if verify {
            command.arg("--verify");
        }
        let output = command
            .output()
            .expect("execute actual bundle extraction CLI");
        fs::write(case.join("extract.stdout"), &output.stdout).unwrap();
        fs::write(case.join("extract.stderr"), &output.stderr).unwrap();
        eprintln!(
            "extraction stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "extract JSON: {error}; stdout: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        (output, value)
    }

    fn assert_verified_payloads(bundle: &Path, destination: &Path) {
        let mut reader = BundleReader::open(bundle).unwrap();
        let entries = reader.files().to_vec();
        for entry in entries {
            let expected = reader.read_verified(&entry.path).unwrap();
            assert_eq!(fs::read(destination.join(&entry.path)).unwrap(), expected);
        }
    }

    /// Two stored ZIP entries for deliberately untrusted negative fixtures.
    /// This never supplies a positive extraction oracle; positives use BundleWriter.
    fn untrusted_negative_bundle(case: &Path, session: &str, corrupt_checksum: bool) -> PathBuf {
        let mut manifest = BundleManifest::new(session, "untrusted-host", ExportProfile::Forensic);
        let checksum = if corrupt_checksum {
            "0".repeat(64)
        } else {
            FileEntry::compute_checksum(PAYLOAD)
        };
        manifest.add_file(FileEntry::new(
            "payload.bin",
            checksum,
            PAYLOAD.len() as u64,
        ));
        manifest.validate().unwrap();
        let manifest_bytes = manifest.to_json().unwrap().into_bytes();
        let entries = [
            ("manifest.json", manifest_bytes.as_slice()),
            ("payload.bin", PAYLOAD),
        ];
        let mut archive = Vec::new();
        let mut central = Vec::new();
        for (name, bytes) in entries {
            let offset = u32::try_from(archive.len()).unwrap();
            let length = u32::try_from(bytes.len()).unwrap();
            let name_length = u16::try_from(name.len()).unwrap();
            let mut crc = u32::MAX;
            for byte in bytes {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
                }
            }
            crc = !crc;
            archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            for value in [20u16, 0, 0, 0, 33] {
                archive.extend_from_slice(&value.to_le_bytes());
            }
            for value in [crc, length, length] {
                archive.extend_from_slice(&value.to_le_bytes());
            }
            for value in [name_length, 0] {
                archive.extend_from_slice(&value.to_le_bytes());
            }
            archive.extend_from_slice(name.as_bytes());
            archive.extend_from_slice(bytes);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            for value in [20u16, 20, 0, 0, 0, 33] {
                central.extend_from_slice(&value.to_le_bytes());
            }
            for value in [crc, length, length] {
                central.extend_from_slice(&value.to_le_bytes());
            }
            for value in [name_length, 0, 0, 0, 0] {
                central.extend_from_slice(&value.to_le_bytes());
            }
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let central_offset = u32::try_from(archive.len()).unwrap();
        let central_length = u32::try_from(central.len()).unwrap();
        archive.extend_from_slice(&central);
        archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        for value in [0u16, 0, 2, 2] {
            archive.extend_from_slice(&value.to_le_bytes());
        }
        archive.extend_from_slice(&central_length.to_le_bytes());
        archive.extend_from_slice(&central_offset.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        let bundle = case.join("untrusted-negative.ptb");
        fs::write(&bundle, archive).unwrap();
        // Prove this reaches the intended manifest/checksum boundary, rather
        // than merely supplying a ZIP that cannot be opened.
        let mut reader = BundleReader::open(&bundle).unwrap();
        assert_eq!(reader.session_id(), session);
        assert_eq!(reader.read_raw("payload.bin").unwrap(), PAYLOAD);
        bundle
    }

    #[test]
    fn valid_default_destination_extracts_exact_verified_payloads() {
        let case = retained_case();
        let (bundle, session) = genuine_bundle(
            &case,
            &[
                ("payload.bin", PAYLOAD),
                ("nested/deeper/evidence.bin", b"\0\x01\x02\xff"),
            ],
        );
        let destination = case.join("working").join(&session);
        assert!(!destination.exists());
        let (output, value) = extract(&case, &bundle, None, true);
        assert!(output.status.success(), "{value}");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["output_dir"], session);
        assert_eq!(value["extracted"], 2);
        assert_eq!(value["total"], 2);
        assert_verified_payloads(&bundle, &destination);
    }

    #[test]
    fn explicit_existing_and_new_destinations_preserve_verified_bytes() {
        for existing in [false, true] {
            let case = retained_case();
            let (bundle, _) = genuine_bundle(&case, &[("nested/payload.bin", PAYLOAD)]);
            let destination = if existing {
                let destination = case.join("working/existing");
                fs::create_dir(&destination).unwrap();
                fs::write(
                    destination.join("unrelated.bin"),
                    b"preserve existing bytes",
                )
                .unwrap();
                destination
            } else {
                case.join("working/new/tree/output")
            };
            let argument = if existing {
                destination.as_path()
            } else {
                Path::new("new/tree/output")
            };
            let (output, value) = extract(&case, &bundle, Some(argument), true);
            assert!(output.status.success(), "{value}");
            assert_eq!(value["status"], "ok");
            assert_eq!(value["extracted"], 1);
            assert_eq!(value["total"], 1);
            assert_verified_payloads(&bundle, &destination);
            if existing {
                assert_eq!(
                    fs::read(destination.join("unrelated.bin")).unwrap(),
                    b"preserve existing bytes"
                );
            }
        }
    }

    #[test]
    fn malicious_manifest_session_ids_refuse_before_default_destination_creation() {
        for absolute in [false, true] {
            let case = retained_case();
            let outside = case.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("payload.bin"), b"outside bytes must survive").unwrap();
            let session = if absolute {
                outside.to_str().unwrap()
            } else {
                "../outside"
            };
            let bundle = untrusted_negative_bundle(&case, session, false);
            let (output, value) = extract(&case, &bundle, None, true);
            assert!(!output.status.success());
            assert_eq!(value["status"], "error");
            assert_eq!(value["error_code"], "INVALID_SESSION_ID");
            assert_eq!(
                fs::read(outside.join("payload.bin")).unwrap(),
                b"outside bytes must survive"
            );
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
            assert_eq!(fs::read_dir(case.join("working")).unwrap().count(), 0);
        }
    }

    #[test]
    fn destination_and_ancestor_symlinks_refuse_without_outside_writes() {
        for placement in ["default", "destination", "ancestor"] {
            let case = retained_case();
            let outside = case.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("payload.bin"), b"outside bytes must survive").unwrap();
            let (bundle, session) = genuine_bundle(&case, &[("payload.bin", PAYLOAD)]);
            let link = case.join("working").join(if placement == "default" {
                &session
            } else {
                "jump"
            });
            symlink(&outside, &link).unwrap();
            let destination = match placement {
                "default" => None,
                "ancestor" => Some(Path::new("jump/new/output")),
                "destination" => Some(Path::new("jump")),
                _ => unreachable!(),
            };
            let (output, value) = extract(&case, &bundle, destination, true);
            assert!(!output.status.success());
            assert_eq!(value["status"], "error");
            assert_eq!(value["error_code"], "UNSAFE_EXTRACTION_DESTINATION");
            assert_eq!(
                fs::read(outside.join("payload.bin")).unwrap(),
                b"outside bytes must survive"
            );
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
            assert!(fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read_link(&link).unwrap(), outside);
        }
    }

    #[test]
    fn artifact_parent_and_final_symlinks_preserve_outside_bytes() {
        for parent in [false, true] {
            let case = retained_case();
            let outside = case.join("outside");
            let destination = case.join("working/output");
            fs::create_dir(&outside).unwrap();
            fs::create_dir(&destination).unwrap();
            fs::write(outside.join("payload.bin"), b"outside bytes must survive").unwrap();
            let (artifact, link, target) = if parent {
                let link = destination.join("nested");
                symlink(&outside, &link).unwrap();
                ("nested/payload.bin", link, outside.clone())
            } else {
                let link = destination.join("payload.bin");
                let target = outside.join("payload.bin");
                symlink(&target, &link).unwrap();
                ("payload.bin", link, target)
            };
            let (bundle, _) = genuine_bundle(&case, &[(artifact, PAYLOAD)]);
            let (output, value) = extract(&case, &bundle, Some(&destination), true);
            assert!(!output.status.success());
            assert_eq!(value["status"], "partial");
            assert_eq!(value["extracted"], 0);
            assert_eq!(value["total"], 1);
            assert!(value["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error.as_str().unwrap().contains(artifact)));
            assert_eq!(
                fs::read(outside.join("payload.bin")).unwrap(),
                b"outside bytes must survive"
            );
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
            assert_eq!(fs::read_link(&link).unwrap(), target);
        }
    }

    #[test]
    fn existing_regular_files_are_never_overwritten_with_or_without_verification() {
        for verify in [false, true] {
            let case = retained_case();
            let destination = case.join("working/output");
            fs::create_dir(&destination).unwrap();
            fs::write(
                destination.join("payload.bin"),
                b"existing bytes must survive",
            )
            .unwrap();
            let (bundle, _) = genuine_bundle(&case, &[("payload.bin", PAYLOAD)]);
            let (output, value) = extract(&case, &bundle, Some(&destination), verify);
            assert!(!output.status.success());
            assert_eq!(value["status"], "partial");
            assert_eq!(value["extracted"], 0);
            assert_eq!(value["total"], 1);
            assert_eq!(value["errors"].as_array().unwrap().len(), 1);
            assert_eq!(
                fs::read(destination.join("payload.bin")).unwrap(),
                b"existing bytes must survive"
            );
        }
    }

    #[test]
    fn checksum_corruption_refuses_before_payload_is_written() {
        let case = retained_case();
        let session = pt_common::SessionId::new().0;
        let bundle = untrusted_negative_bundle(&case, &session, true);
        let mut reader = BundleReader::open(&bundle).unwrap();
        assert!(matches!(
            reader.read_verified("payload.bin"),
            Err(pt_bundle::BundleError::ChecksumMismatch { .. })
        ));
        let destination = case.join("working/output");
        let (output, value) = extract(&case, &bundle, Some(&destination), true);
        assert!(!output.status.success());
        assert_eq!(value["status"], "partial");
        assert_eq!(value["extracted"], 0);
        assert_eq!(value["total"], 1);
        assert!(value["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("checksum mismatch")));
        assert!(!destination.join("payload.bin").exists());
    }
}
