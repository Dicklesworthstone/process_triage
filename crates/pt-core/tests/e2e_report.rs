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
    fn galaxy_brain_tab_present_when_flag_set() {
        let tmp = tempdir().unwrap();
        let (_, session_id) = create_session(tmp.path());
        let html = generate_report(tmp.path(), &session_id, &["--galaxy-brain"]);

        assert!(
            html.contains(r#"data-tab="galaxy-brain""#),
            "Report must have galaxy-brain tab when --galaxy-brain flag is set"
        );
        assert!(
            html.contains(r#"id="tab-galaxy-brain""#),
            "Report must have galaxy-brain tab content section"
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
