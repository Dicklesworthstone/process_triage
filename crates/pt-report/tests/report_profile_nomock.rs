//! No-mock profile-aware report generation tests for bd-yaps.
//!
//! Validates report generation respects redaction profile constraints:
//! - Reports generate successfully from bundles of every export profile
//! - Export profile is reflected in generated HTML
//! - Redacted secrets do not leak through report HTML
//! - Galaxy-brain mode works with all profiles
//! - Theme variants produce valid HTML structure

use pt_bundle::{BundleError, BundleReader, BundleWriter};
use pt_redact::{ExportProfile, KeyMaterial, RedactionEngine, RedactionPolicy};
use pt_report::{ReportConfig, ReportError, ReportGenerator, ReportTheme};
use serde_json::json;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Submit raw structured data to the writer; only Forensic carries opaque data.
fn build_bundle_with_profile(profile: ExportProfile) -> Vec<u8> {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([42u8; 32], "report-profile-test");
    let engine = RedactionEngine::with_key(policy, key);

    let secret = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    let mut writer = BundleWriter::new("pt-20260205-120600-abcd", "host-report-test", profile)
        .with_pt_version("2.0.0-test")
        .with_redaction_policy("1.0.0", "sha256-test")
        .with_redaction_engine(engine);

    writer
        .add_summary(&json!({
            "total_processes": 150,
            "candidates": 5,
            "kills": 2,
            "spares": 3,
            "note": secret,
            "profile": format!("{:?}", profile),
        }))
        .expect("add summary");

    if profile == ExportProfile::Forensic {
        // This opaque fixture tests ZIP packaging, not Parquet sanitization.
        writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31]);
    }

    let (bytes, _) = writer.write_to_vec().expect("write bundle");
    bytes
}

// ============================================================================
// Profile-Aware Report Generation
// ============================================================================

#[test]
fn test_report_generates_for_all_export_profiles() {
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let bytes = build_bundle_with_profile(profile);
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

        let generator = ReportGenerator::default_config();
        let html = generator
            .generate_from_bundle(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to generate report for {:?}: {}", profile, e));

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Profile {:?}: report should start with DOCTYPE",
            profile
        );
        assert!(
            html.contains("</html>"),
            "Profile {:?}: report should have closing html tag",
            profile
        );
        assert!(
            html.contains("pt-report"),
            "Profile {:?}: report should contain generator name",
            profile
        );

        eprintln!(
            "[INFO] Profile {:?}: report generated, {} bytes",
            profile,
            html.len()
        );
    }
}

#[test]
fn test_report_contains_export_profile_in_overview() {
    let profiles = [
        (ExportProfile::Minimal, "minimal"),
        (ExportProfile::Safe, "safe"),
        (ExportProfile::Forensic, "forensic"),
    ];

    for (profile, profile_name) in profiles {
        let bytes = build_bundle_with_profile(profile);
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

        let mut config = ReportConfig::new();
        config.redaction_profile = profile.to_string();
        let generator = ReportGenerator::new(config);
        let html = generator
            .generate_from_bundle(&mut reader)
            .expect("generate report");

        // The overview section serializes export_profile into the report data JSON
        assert!(
            html.contains(&format!("\"export_profile\":\"{profile_name}\"")),
            "Profile {:?}: report should contain profile name '{}' in HTML",
            profile,
            profile_name
        );
    }
}

#[test]
fn test_report_session_id_from_bundle() {
    let bytes = build_bundle_with_profile(ExportProfile::Safe);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    // Session ID should appear in report
    assert!(
        html.contains("pt-20260205-120600-abcd"),
        "Report should contain session ID from bundle"
    );
}

// ============================================================================
// Secret Leak Prevention Through Report
// ============================================================================

#[test]
fn test_report_does_not_leak_secrets_from_bundle() {
    let secret = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let bytes = build_bundle_with_profile(profile);
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");
        assert!(reader.verify_all().is_empty());
        let summary: serde_json::Value = reader.read_summary().expect("read sanitized summary");
        assert_eq!(summary["total_processes"], 150);
        assert_eq!(summary["candidates"], 5);
        assert!(
            !summary.to_string().contains(secret),
            "writer must sanitize raw secret input"
        );

        let generator = ReportGenerator::default_config();
        let html = generator
            .generate_from_bundle(&mut reader)
            .expect("generate report");

        assert!(
            !html.contains(secret),
            "Profile {:?}: secret leaked through report HTML",
            profile
        );
    }
}

// ============================================================================
// Galaxy-Brain Mode With Profiles
// ============================================================================

#[test]
fn test_report_galaxy_brain_mode_with_all_profiles() {
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let bytes = build_bundle_with_profile(profile);
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

        let config = ReportConfig::new().with_galaxy_brain(true);
        let generator = ReportGenerator::new(config);
        let html = generator
            .generate_from_bundle(&mut reader)
            .expect("generate report");

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Galaxy-brain {:?}: should produce valid HTML",
            profile
        );
        // Galaxy-brain mode includes KaTeX for math rendering
        assert!(
            html.contains("katex"),
            "Galaxy-brain {:?}: should include KaTeX reference",
            profile
        );
        assert!(
            !html.contains("Prior Probabilities"),
            "no historical priors were recorded"
        );

        eprintln!(
            "[INFO] Galaxy-brain {:?}: report generated, {} bytes",
            profile,
            html.len()
        );
    }
}

// ============================================================================
// Theme Variants
// ============================================================================

#[test]
fn test_report_theme_variants_produce_valid_html() {
    let themes = [
        (ReportTheme::Light, "light"),
        (ReportTheme::Dark, "dark"),
        (ReportTheme::Auto, ""),
    ];

    let bytes = build_bundle_with_profile(ExportProfile::Safe);

    for (theme, expected_class) in themes {
        let mut reader = BundleReader::from_bytes(bytes.clone()).expect("open bundle");

        let config = ReportConfig::new().with_theme(theme);
        let generator = ReportGenerator::new(config);
        let html = generator
            .generate_from_bundle(&mut reader)
            .expect("generate report");

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Theme {:?}: should produce valid HTML",
            theme
        );

        if !expected_class.is_empty() {
            assert!(
                html.contains(&format!("class=\"{}\"", expected_class)),
                "Theme {:?}: should have class '{}' in HTML",
                theme,
                expected_class
            );
        }
    }
}

// ============================================================================
// Report Config Integration
// ============================================================================

#[test]
fn test_report_config_redaction_profile_default() {
    let config = ReportConfig::default();
    assert_eq!(
        config.redaction_profile, "safe",
        "Default redaction profile should be 'safe'"
    );
}

#[test]
fn test_report_custom_title_with_bundle() {
    let bytes = build_bundle_with_profile(ExportProfile::Safe);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    let config = ReportConfig::new().with_title("Custom Test Report");
    let generator = ReportGenerator::new(config);
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    assert!(
        html.contains("Custom Test Report"),
        "Report should use custom title"
    );
}

#[test]
fn test_report_contains_standard_html_structure() {
    let bytes = build_bundle_with_profile(ExportProfile::Safe);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    // Basic HTML structure
    assert!(html.contains("<head>"));
    assert!(html.contains("<body"));
    assert!(html.contains("<meta charset=\"UTF-8\">"));
    assert!(html.contains("viewport"));

    // Report-specific structure
    assert!(
        html.contains("id=\"tab-overview\""),
        "Report should have overview tab"
    );
}

// ============================================================================
// Report Data Roundtrip
// ============================================================================

#[test]
fn test_report_data_json_roundtrip() {
    let bytes = build_bundle_with_profile(ExportProfile::Safe);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    // Parse the actual first JSON value assigned to REPORT_DATA, including
    // escaped strings. A missing or corrupt data assignment must fail.
    let assignment = regex::Regex::new(r"\b(?:const|let|var)\s+REPORT_DATA\s*=\s*")
        .expect("assignment regex")
        .find(&html)
        .expect("embedded report data assignment");
    let embedded: serde_json::Value = serde_json::Deserializer::from_str(&html[assignment.end()..])
        .into_iter()
        .next()
        .expect("embedded JSON value")
        .expect("valid embedded JSON");
    assert_eq!(
        embedded["overview"]["session_id"],
        "pt-20260205-120600-abcd"
    );
    assert_eq!(embedded["config"]["redaction_profile"], "safe");

    // Verify CDN references are present (default non-embed mode)
    assert!(
        html.contains("cdn.jsdelivr.net") || html.contains("tailwind"),
        "Default mode should reference CDN"
    );
}

#[test]
fn test_forensic_no_plan_manifest_is_private_in_sharing_reports() {
    for profile in [ExportProfile::Safe, ExportProfile::Minimal] {
        let mut writer = BundleWriter::new(
            "private-customer-session",
            "private-customer-host",
            ExportProfile::Forensic,
        )
        .with_description("private-customer-description");
        writer
            .add_summary(&json!({"total_processes": 3, "candidates": 1}))
            .expect("add summary");
        writer.add_telemetry("audit", b"opaque local archive".to_vec());
        let (bytes, manifest) = writer.write_to_vec().expect("write Forensic bundle");
        assert_eq!(manifest.session_id, "private-customer-session");
        assert_eq!(manifest.host_id, "private-customer-host");
        let mut reader = BundleReader::from_bytes(bytes).expect("open Forensic bundle");
        assert!(!reader.has_file("plan.json"), "exercise the no-plan branch");
        assert!(reader.verify_all().is_empty());

        let mut config = ReportConfig::new();
        config.redaction_profile = profile.to_string();
        let html = ReportGenerator::new(config)
            .generate_from_bundle(&mut reader)
            .expect("generate sharing report");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("id=\"tab-overview\""));
        for canary in [
            "private-customer-session",
            "private-customer-host",
            "private-customer-description",
        ] {
            assert!(
                !html.contains(canary),
                "no-plan report leaked {canary} under {profile}"
            );
        }
    }
}

#[test]
fn test_no_plan_report_rejects_invalid_profile() {
    let bytes = build_bundle_with_profile(ExportProfile::Forensic);
    let mut reader = BundleReader::from_bytes(bytes).expect("open no-plan bundle");
    assert!(!reader.has_file("plan.json"));
    let mut config = ReportConfig::new();
    config.redaction_profile = "invalid-private-profile".to_string();
    assert!(matches!(
        ReportGenerator::new(config).generate_from_bundle(&mut reader),
        Err(ReportError::InvalidConfig(_))
    ));
}

#[test]
fn test_minimal_keeps_actual_agent_plan_summary_counts() {
    // Use the real agent-plan summary shape. Minimal retains numeric counts and
    // deliberately omits per-rule maps; this checks saved-value export routing,
    // not live scanning or inference quality.
    let counts = json!({
        "total_processes_scanned": 70,
        "candidates_evaluated": 9,
        "candidates_returned": 2,
        "kill_recommendations": 1,
        "review_recommendations": 1,
        "policy_blocked": 1,
        "protected_filtered": 3,
        "above_threshold": 2
    });
    let mut summary = counts.clone();
    summary["protected_by_rule"] = json!({
        "builtin.database": 3,
        "private-customer-rule": 1
    });
    summary["threshold_used"] = json!(0.95);
    summary["private_note"] = json!("private-customer-summary");
    let mut writer = BundleWriter::new(
        "pt-20260205-120700-abcd",
        "private-host",
        ExportProfile::Minimal,
    );
    writer
        .add_plan(&json!({
            "summary": summary,
            "scan": {"total_processes": 70},
            "candidates": [{"pid": 1234, "command": "private-worker"}, {"pid": 5678}]
        }))
        .expect("add actual-shaped plan");
    writer.add_log("events", b"{\"event\":\"private-event\"}\n".to_vec());
    let (bytes, manifest) = writer.write_to_vec().expect("write Minimal export");
    assert_eq!(manifest.file_count(), 1);
    let mut reader = BundleReader::from_bytes(bytes).expect("read Minimal export");
    let exported: serde_json::Value = reader.read_summary().expect("read aggregate counts");
    assert_eq!(
        exported, counts,
        "retain recorded numeric aggregates, and only numeric aggregates"
    );
    assert!(
        exported.get("protected_by_rule").is_none(),
        "the count-only profile deliberately omits per-rule maps"
    );
    assert!(!exported.to_string().contains("private-customer-rule"));
    assert!(!reader.has_file("plan.json"));
    assert!(reader.log_files().is_empty());
    assert!(reader.verify_all().is_empty());
}

#[test]
fn test_safe_opaque_archive_refusal_leaves_no_destination() {
    let temp_dir = TempDir::new().expect("tempdir");
    let destination = temp_dir.path().join("safe-refused.ptb");
    let mut writer = BundleWriter::new(
        "pt-20260205-120800-abcd",
        "private-host",
        ExportProfile::Safe,
    );
    writer
        .add_summary(&json!({"total_processes": 150, "candidates": 5}))
        .expect("add raw Safe summary");
    writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31]);
    assert!(matches!(
        writer.write(&destination),
        Err(BundleError::UnsanitizedPayload { path, profile })
            if path == "telemetry/audit.parquet" && profile == "safe"
    ));
    assert!(
        !destination.exists(),
        "privacy refusal must not create output"
    );
}
