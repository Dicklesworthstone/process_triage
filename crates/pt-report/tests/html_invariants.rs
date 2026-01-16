//! HTML report invariant tests.
//!
//! These tests validate the generated HTML structure without requiring a browser:
//! - Required top-level sections present
//! - `schema_version` + `session_id` embedded consistently
//! - CDN mode: external URLs are pinned with SRI integrity
//! - embed-assets mode: no external http/https URLs

use chrono::Utc;
use pt_report::config::{CdnConfig, ReportConfig, ReportTheme};
use pt_report::generator::{ReportData, ReportGenerator};
use pt_report::sections::{
    ActionsSection, CandidatesSection, EvidenceSection, GalaxyBrainSection, OverviewSection,
};
use regex::Regex;

/// Create a minimal test overview section.
fn test_overview() -> OverviewSection {
    OverviewSection {
        session_id: "test-session-abc123".to_string(),
        host_id: "host-xyz789".to_string(),
        hostname: Some("testhost.local".to_string()),
        started_at: Utc::now(),
        ended_at: None,
        duration_ms: Some(60000),
        state: "completed".to_string(),
        mode: "interactive".to_string(),
        deep_scan: false,
        processes_scanned: 150,
        candidates_found: 12,
        kills_attempted: 5,
        kills_successful: 4,
        spares: 7,
        os_family: Some("linux".to_string()),
        os_version: Some("Ubuntu 24.04".to_string()),
        kernel_version: Some("6.8.0-1-generic".to_string()),
        arch: Some("x86_64".to_string()),
        cores: Some(8),
        memory_bytes: Some(32_000_000_000),
        pt_version: Some("0.1.0".to_string()),
        export_profile: "safe".to_string(),
    }
}

/// Create empty candidates section for testing.
fn test_candidates() -> CandidatesSection {
    CandidatesSection::new(vec![], 0)
}

/// Create empty evidence section for testing.
fn test_evidence() -> EvidenceSection {
    EvidenceSection::new(vec![])
}

/// Create empty actions section for testing.
fn test_actions() -> ActionsSection {
    ActionsSection::new(vec![])
}

/// Create a full test report data with all sections.
fn full_test_report_data(config: ReportConfig) -> ReportData {
    ReportData {
        config: config.clone(),
        generated_at: Utc::now(),
        generator_version: "0.1.0-test".to_string(),
        overview: Some(test_overview()),
        candidates: Some(test_candidates()),
        evidence: Some(test_evidence()),
        actions: Some(test_actions()),
        galaxy_brain: if config.galaxy_brain {
            Some(GalaxyBrainSection::default())
        } else {
            None
        },
    }
}

// ============================================================================
// HTML Structure Tests
// ============================================================================

mod structure {
    use super::*;

    #[test]
    fn test_html_doctype_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "HTML must start with DOCTYPE declaration"
        );
    }

    #[test]
    fn test_html_has_required_meta_tags() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"charset="UTF-8""#),
            "HTML must specify UTF-8 charset"
        );
        assert!(
            html.contains(r#"name="viewport""#),
            "HTML must have viewport meta tag"
        );
        assert!(
            html.contains(r#"name="generator""#),
            "HTML must have generator meta tag"
        );
        assert!(
            html.contains(r#"name="robots" content="noindex, nofollow""#),
            "HTML must have noindex robots meta tag"
        );
    }

    #[test]
    fn test_html_has_title() {
        let config = ReportConfig::new().with_title("Custom Test Report");
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains("<title>Custom Test Report</title>"),
            "HTML must contain the configured title"
        );
    }

    #[test]
    fn test_html_has_body_structure() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(html.contains("<body>"), "HTML must have body tag");
        assert!(html.contains("</body>"), "HTML must close body tag");
        assert!(html.contains("<header"), "HTML must have header section");
        assert!(html.contains("<main>"), "HTML must have main section");
        assert!(html.contains("<footer"), "HTML must have footer section");
    }

    #[test]
    fn test_overview_tab_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"data-tab="overview""#),
            "HTML must have overview tab button"
        );
        assert!(
            html.contains(r#"id="tab-overview""#),
            "HTML must have overview tab content section"
        );
    }

    #[test]
    fn test_candidates_tab_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"data-tab="candidates""#),
            "HTML must have candidates tab button"
        );
        assert!(
            html.contains(r#"id="tab-candidates""#),
            "HTML must have candidates tab content section"
        );
    }

    #[test]
    fn test_evidence_tab_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"data-tab="evidence""#),
            "HTML must have evidence tab button"
        );
        assert!(
            html.contains(r#"id="tab-evidence""#),
            "HTML must have evidence tab content section"
        );
    }

    #[test]
    fn test_actions_tab_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"data-tab="actions""#),
            "HTML must have actions tab button"
        );
        assert!(
            html.contains(r#"id="tab-actions""#),
            "HTML must have actions tab content section"
        );
    }

    #[test]
    fn test_galaxy_brain_tab_present_when_enabled() {
        let config = ReportConfig::new().with_galaxy_brain(true);
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"data-tab="galaxy-brain""#),
            "HTML must have galaxy-brain tab button when enabled"
        );
        assert!(
            html.contains(r#"id="tab-galaxy-brain""#),
            "HTML must have galaxy-brain tab content section when enabled"
        );
    }

    #[test]
    fn test_galaxy_brain_tab_absent_when_disabled() {
        let config = ReportConfig::default(); // galaxy_brain defaults to false
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        assert!(
            !html.contains(r#"data-tab="galaxy-brain""#),
            "HTML must NOT have galaxy-brain tab button when disabled"
        );
    }

    #[test]
    fn test_tab_switching_javascript_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains("function switchTab("),
            "HTML must contain tab switching JavaScript"
        );
        assert!(
            html.contains(".tab-btn"),
            "HTML must reference tab button class in JS"
        );
        assert!(
            html.contains(".tab-content"),
            "HTML must reference tab content class in JS"
        );
    }
}

// ============================================================================
// Schema and Session ID Tests
// ============================================================================

mod schema_session {
    use super::*;

    #[test]
    fn test_session_id_embedded_in_report_data_json() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let session_id = data.overview.as_ref().unwrap().session_id.clone();
        let html = generator.generate(data).unwrap();

        // The session ID should appear in the embedded REPORT_DATA JSON
        assert!(
            html.contains(&format!(r#""session_id":"{}""#, session_id)),
            "HTML must contain session_id in REPORT_DATA JSON"
        );
    }

    #[test]
    fn test_session_id_displayed_in_overview() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let session_id = data.overview.as_ref().unwrap().session_id.clone();
        let html = generator.generate(data).unwrap();

        // Session ID should appear in the visible HTML (overview section)
        assert!(
            html.contains(&session_id),
            "HTML must display session_id in overview section"
        );
    }

    #[test]
    fn test_schema_version_in_config() {
        let config = ReportConfig::default();
        assert_eq!(
            config.schema_version, "1.0.0",
            "Default schema version should be 1.0.0"
        );
    }

    #[test]
    fn test_schema_version_embedded_in_report_data_json() {
        let generator = ReportGenerator::default_config();
        let config = ReportConfig::default();
        let schema_version = config.schema_version.clone();
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        // Schema version should appear in the embedded REPORT_DATA JSON
        assert!(
            html.contains(&format!(r#""schema_version":"{}""#, schema_version)),
            "HTML must contain schema_version in REPORT_DATA JSON"
        );
    }

    #[test]
    fn test_generator_version_in_meta_tag() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Generator meta tag should include version
        assert!(
            html.contains(r#"name="generator" content="pt-report "#),
            "HTML must have generator meta tag with version"
        );
    }

    #[test]
    fn test_host_id_embedded() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let host_id = data.overview.as_ref().unwrap().host_id.clone();
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(&host_id),
            "HTML must contain host_id from session"
        );
    }
}

// ============================================================================
// CDN Pinning and SRI Tests
// ============================================================================

mod cdn_pinning {
    use super::*;

    #[test]
    fn test_cdn_urls_have_pinned_versions() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // All CDN URLs should have @version pinning
        // Pattern: jsdelivr.net/npm/package@X.Y.Z/
        let cdn_url_pattern = Regex::new(r#"cdn\.jsdelivr\.net/npm/([a-z-]+)@(\d+\.\d+\.\d+)"#)
            .expect("valid regex");

        let mut found_cdn_urls = false;
        for cap in cdn_url_pattern.captures_iter(&html) {
            found_cdn_urls = true;
            let package = &cap[1];
            let version = &cap[2];

            // Ensure version is a proper semver (X.Y.Z format)
            let version_parts: Vec<&str> = version.split('.').collect();
            assert_eq!(
                version_parts.len(),
                3,
                "CDN URL for {} must have semver version, got: {}",
                package,
                version
            );

            // Ensure each part is numeric
            for part in version_parts {
                assert!(
                    part.parse::<u32>().is_ok(),
                    "Version part {} in {} must be numeric",
                    part,
                    version
                );
            }
        }

        assert!(found_cdn_urls, "HTML should contain CDN URLs with pinned versions");
    }

    #[test]
    fn test_cdn_scripts_have_sri_integrity() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Find all script tags with CDN src
        let script_pattern =
            Regex::new(r#"<script[^>]+src="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>"#)
                .expect("valid regex");

        for script_match in script_pattern.find_iter(&html) {
            let script_tag = script_match.as_str();

            // Check for integrity attribute
            assert!(
                script_tag.contains("integrity="),
                "CDN script tag must have integrity attribute: {}",
                script_tag
            );

            // Check for crossorigin attribute (required for SRI)
            assert!(
                script_tag.contains(r#"crossorigin="anonymous""#),
                "CDN script tag must have crossorigin attribute: {}",
                script_tag
            );
        }
    }

    #[test]
    fn test_cdn_stylesheets_have_sri_integrity() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Find all link tags with CDN href
        let link_pattern =
            Regex::new(r#"<link[^>]+href="[^"]*cdn\.jsdelivr\.net[^"]*"[^>]*>"#)
                .expect("valid regex");

        for link_match in link_pattern.find_iter(&html) {
            let link_tag = link_match.as_str();

            // Check for integrity attribute
            assert!(
                link_tag.contains("integrity="),
                "CDN link tag must have integrity attribute: {}",
                link_tag
            );

            // Check for crossorigin attribute (required for SRI)
            assert!(
                link_tag.contains(r#"crossorigin="anonymous""#),
                "CDN link tag must have crossorigin attribute: {}",
                link_tag
            );
        }
    }

    #[test]
    fn test_sri_hashes_are_valid_format() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // SRI hashes should be sha384-... format
        let sri_pattern = Regex::new(r#"integrity="(sha\d+-[A-Za-z0-9+/=]+)""#).expect("valid regex");

        let mut found_sri = false;
        for cap in sri_pattern.captures_iter(&html) {
            found_sri = true;
            let hash = &cap[1];

            // Should start with sha384- (preferred) or sha256- or sha512-
            assert!(
                hash.starts_with("sha384-") || hash.starts_with("sha256-") || hash.starts_with("sha512-"),
                "SRI hash must use sha256, sha384, or sha512: {}",
                hash
            );

            // Base64 encoded hash should be reasonable length
            let hash_part = hash.split('-').nth(1).unwrap();
            assert!(
                hash_part.len() >= 32,
                "SRI hash should have sufficient length: {}",
                hash
            );
        }

        assert!(found_sri, "HTML should contain SRI integrity hashes");
    }

    #[test]
    fn test_configured_libraries_have_versions() {
        let config = CdnConfig::default();

        // All configured libraries should have version and SRI
        for (name, lib) in &config.libraries {
            assert!(
                !lib.version.is_empty(),
                "Library {} must have a version",
                name
            );
            assert!(
                !lib.sri.is_empty(),
                "Library {} must have an SRI hash",
                name
            );

            // Version should be semver format
            let parts: Vec<&str> = lib.version.split('.').collect();
            assert!(
                parts.len() >= 2,
                "Library {} version {} must be semver format",
                name,
                lib.version
            );
        }
    }

    #[test]
    fn test_expected_libraries_present() {
        let config = CdnConfig::default();

        // Core libraries that should always be present
        let expected = ["tailwindcss", "tabulator-tables", "echarts"];

        for lib_name in expected {
            assert!(
                config.libraries.contains_key(lib_name),
                "CDN config must include {} library",
                lib_name
            );
        }
    }

    #[test]
    fn test_katex_library_present_for_galaxy_brain() {
        let config = CdnConfig::default();

        assert!(
            config.libraries.contains_key("katex"),
            "CDN config must include katex library for galaxy-brain mode"
        );

        let katex = config.libraries.get("katex").unwrap();
        assert!(
            !katex.sri.is_empty(),
            "KaTeX library must have SRI hash"
        );
    }
}

// ============================================================================
// Embed Assets Mode Tests
// ============================================================================

mod embed_assets {
    use super::*;

    // Note: Full embed mode requires the "embed" feature and network access.
    // These tests verify the configuration and structural invariants.

    #[test]
    fn test_embed_config_flag() {
        let config = ReportConfig::new().with_embed_assets(true);
        assert!(config.embed_assets, "embed_assets flag should be settable");
    }

    #[test]
    fn test_default_not_embedded() {
        let config = ReportConfig::default();
        assert!(
            !config.embed_assets,
            "Default config should not embed assets"
        );
    }

    #[test]
    fn test_non_embed_mode_has_cdn_urls() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        // In non-embed mode, we should have external CDN URLs
        assert!(
            html.contains("cdn.jsdelivr.net"),
            "Non-embed mode should reference CDN URLs"
        );
    }

    #[test]
    fn test_inline_styles_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Critical CSS should be inlined even in CDN mode
        assert!(
            html.contains("<style>"),
            "HTML should have inline style block"
        );
        assert!(
            html.contains("--bg-primary:"),
            "Inline styles should define CSS variables"
        );
    }

    #[test]
    fn test_inline_javascript_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Core JS should be inlined
        assert!(
            html.contains("const REPORT_DATA ="),
            "HTML should have inline REPORT_DATA"
        );
        assert!(
            html.contains("function switchTab"),
            "HTML should have inline tab switching function"
        );
    }

    #[test]
    fn test_no_inline_event_handlers() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // For CSP safety, avoid inline event handlers like onclick=
        // We use addEventListener instead
        assert!(
            !html.contains("onclick="),
            "HTML should not use inline onclick handlers"
        );
        assert!(
            !html.contains("onload="),
            "HTML should not use inline onload handlers"
        );
    }
}

// ============================================================================
// Theme Tests
// ============================================================================

mod themes {
    use super::*;

    #[test]
    fn test_light_theme_class() {
        let config = ReportConfig::new().with_theme(ReportTheme::Light);
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"class="light""#),
            "Light theme should set 'light' class on html element"
        );
    }

    #[test]
    fn test_dark_theme_class() {
        let config = ReportConfig::new().with_theme(ReportTheme::Dark);
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(r#"class="dark""#),
            "Dark theme should set 'dark' class on html element"
        );
    }

    #[test]
    fn test_auto_theme_no_class() {
        let config = ReportConfig::new().with_theme(ReportTheme::Auto);
        let generator = ReportGenerator::new(config.clone());
        let data = full_test_report_data(config);
        let html = generator.generate(data).unwrap();

        // Auto theme should use empty class (system preference via CSS)
        assert!(
            html.contains(r#"<html lang="en" class="">"#),
            "Auto theme should have empty class on html element"
        );
    }

    #[test]
    fn test_css_variables_defined() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Core CSS variables should be defined
        let expected_vars = [
            "--bg-primary",
            "--bg-secondary",
            "--text-primary",
            "--text-secondary",
            "--border-color",
            "--accent-color",
        ];

        for var in expected_vars {
            assert!(
                html.contains(var),
                "HTML must define CSS variable {}",
                var
            );
        }
    }

    #[test]
    fn test_dark_mode_media_query() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Should have prefers-color-scheme media query for auto mode
        assert!(
            html.contains("prefers-color-scheme: dark"),
            "HTML should have dark mode media query"
        );
    }
}

// ============================================================================
// Security Tests
// ============================================================================

mod security {
    use super::*;

    #[test]
    fn test_html_escaping_in_session_id() {
        let generator = ReportGenerator::default_config();
        let mut data = full_test_report_data(ReportConfig::default());

        // Inject potentially dangerous characters in session ID
        data.overview.as_mut().unwrap().session_id = "<script>alert('xss')</script>".to_string();

        let html = generator.generate(data).unwrap();

        // The dangerous string should be escaped
        assert!(
            !html.contains("<script>alert"),
            "HTML must escape dangerous characters in session_id"
        );
        assert!(
            html.contains("&lt;script&gt;") || html.contains("\\u003cscript\\u003e"),
            "Dangerous characters should be HTML-escaped or JSON-escaped"
        );
    }

    #[test]
    fn test_json_script_safety() {
        let generator = ReportGenerator::default_config();
        let mut data = full_test_report_data(ReportConfig::default());

        // Inject script-breaking content
        data.overview.as_mut().unwrap().hostname = Some("</script><script>evil()".to_string());

        let html = generator.generate(data).unwrap();

        // The embedded JSON should not break out of script tag
        assert!(
            !html.contains("</script><script>"),
            "JSON embedding must escape script-breaking sequences"
        );
    }

    #[test]
    fn test_no_external_javascript_execution() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // No javascript: URLs
        assert!(
            !html.contains("javascript:"),
            "HTML must not contain javascript: URLs"
        );

        // No eval() calls
        assert!(
            !html.contains("eval("),
            "HTML must not use eval()"
        );

        // No document.write
        assert!(
            !html.contains("document.write"),
            "HTML must not use document.write"
        );
    }

    #[test]
    fn test_external_links_have_rel_noopener() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        // Find external links (target="_blank")
        let link_pattern = Regex::new(r#"<a[^>]+target="_blank"[^>]*>"#).expect("valid regex");

        for link_match in link_pattern.find_iter(&html) {
            let link_tag = link_match.as_str();
            assert!(
                link_tag.contains("rel=") && link_tag.contains("noopener"),
                "External links must have rel=\"noopener\": {}",
                link_tag
            );
        }
    }
}

// ============================================================================
// Print Styles Tests
// ============================================================================

mod print {
    use super::*;

    #[test]
    fn test_print_media_query_present() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains("@media print"),
            "HTML should have print media query styles"
        );
    }

    #[test]
    fn test_no_print_class_defined() {
        let generator = ReportGenerator::default_config();
        let data = full_test_report_data(ReportConfig::default());
        let html = generator.generate(data).unwrap();

        assert!(
            html.contains(".no-print"),
            "HTML should define .no-print class for hiding elements"
        );
    }
}
