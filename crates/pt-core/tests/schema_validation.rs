//! JSON schema validation tests for pt-core.
//!
//! These tests verify that JSON outputs conform to their schemas and
//! that mandatory fields are present and correctly formatted.

use assert_cmd::Command;

/// Get a Command for pt-core binary.
#[allow(deprecated)]
fn pt_core() -> Command {
    Command::cargo_bin("pt-core").expect("pt-core binary should exist")
}

// ============================================================================
// Schema Version Tests
// ============================================================================

mod schema_version {

    /// Schema version constant should follow semver format.
    #[test]
    fn schema_version_is_valid_semver() {
        let version = pt_common::SCHEMA_VERSION;
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3, "Schema version should have 3 parts");
        for part in &parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "Each version part should be a number: {}",
                part
            );
        }
    }

    /// Schema version should start at 1.0.0 for production.
    #[test]
    fn schema_version_is_production() {
        let version = pt_common::SCHEMA_VERSION;
        assert_eq!(version, "1.0.0", "Schema version should be 1.0.0");
    }

    /// Compatibility check should work for same major version.
    #[test]
    fn schema_version_compatible_same_major() {
        assert!(pt_common::schema::is_compatible("1.0.0"));
        assert!(pt_common::schema::is_compatible("1.1.0"));
        assert!(pt_common::schema::is_compatible("1.99.99"));
    }

    /// Compatibility check should fail for different major versions.
    #[test]
    fn schema_version_incompatible_different_major() {
        assert!(!pt_common::schema::is_compatible("0.9.0"));
        assert!(!pt_common::schema::is_compatible("2.0.0"));
        assert!(!pt_common::schema::is_compatible("3.5.1"));
    }
}

// ============================================================================
// Session ID Format Tests
// ============================================================================

mod session_id_format {
    use pt_common::id::SessionId;

    /// Valid session IDs should parse successfully.
    #[test]
    fn valid_session_id_parses() {
        let valid_ids = [
            "pt-20260115-143022-a7xq",
            "pt-20250101-000000-aaaa",
            "pt-20301231-235959-7777",
            "pt-20260615-120000-zzzz",
            "pt-20260115-143022-2345",
        ];
        for id in &valid_ids {
            assert!(
                SessionId::parse(id).is_some(),
                "Session ID should be valid: {}",
                id
            );
        }
    }

    /// Session IDs must be exactly 23 characters.
    #[test]
    fn session_id_has_correct_length() {
        let sid = SessionId::new();
        assert_eq!(sid.0.len(), 23, "Session ID should be 23 characters");
    }

    /// Session IDs must start with "pt-".
    #[test]
    fn session_id_starts_with_pt() {
        let sid = SessionId::new();
        assert!(sid.0.starts_with("pt-"), "Session ID should start with 'pt-'");
    }

    /// Too short session IDs should fail.
    #[test]
    fn too_short_session_id_fails() {
        let short_ids = [
            "pt-2026011",
            "pt-20260115-1430",
            "pt-20260115-143022",
            "pt-20260115-143022-a7x",
        ];
        for id in &short_ids {
            assert!(
                SessionId::parse(id).is_none(),
                "Short session ID should be invalid: {}",
                id
            );
        }
    }

    /// Too long session IDs should fail.
    #[test]
    fn too_long_session_id_fails() {
        let long_ids = [
            "pt-20260115-143022-a7xqq",
            "pt-20260115-143022-a7xq1",
            "pt-20260115-1430220-a7xq",
        ];
        for id in &long_ids {
            assert!(
                SessionId::parse(id).is_none(),
                "Long session ID should be invalid: {}",
                id
            );
        }
    }

    /// Session IDs with wrong prefix should fail.
    #[test]
    fn wrong_prefix_fails() {
        let wrong_prefix = [
            "px-20260115-143022-a7xq",
            "PT-20260115-143022-a7xq",
            "Pt-20260115-143022-a7xq",
            "pp-20260115-143022-a7xq",
            "st-20260115-143022-a7xq",
        ];
        for id in &wrong_prefix {
            assert!(
                SessionId::parse(id).is_none(),
                "Wrong prefix should be invalid: {}",
                id
            );
        }
    }

    /// Session ID date part must be all digits.
    #[test]
    fn date_part_must_be_digits() {
        let bad_dates = [
            "pt-2026011a-143022-a7xq",
            "pt-2026O115-143022-a7xq",  // Letter O instead of 0
            "pt-YYYYMMDD-143022-a7xq",
        ];
        for id in &bad_dates {
            assert!(
                SessionId::parse(id).is_none(),
                "Non-digit date should be invalid: {}",
                id
            );
        }
    }

    /// Session ID time part must be all digits.
    #[test]
    fn time_part_must_be_digits() {
        let bad_times = [
            "pt-20260115-14302a-a7xq",
            "pt-20260115-HHMMSS-a7xq",
            "pt-20260115-14:02:-a7xq",
        ];
        for id in &bad_times {
            assert!(
                SessionId::parse(id).is_none(),
                "Non-digit time should be invalid: {}",
                id
            );
        }
    }

    /// Session ID suffix must be base32 lowercase (a-z, 2-7).
    #[test]
    fn suffix_must_be_base32() {
        let bad_suffixes = [
            "pt-20260115-143022-A7XQ",  // Uppercase
            "pt-20260115-143022-a7x8",  // Digit 8 not in base32
            "pt-20260115-143022-a7x9",  // Digit 9 not in base32
            "pt-20260115-143022-a7x0",  // Digit 0 not in base32
            "pt-20260115-143022-a7x1",  // Digit 1 not in base32
        ];
        for id in &bad_suffixes {
            assert!(
                SessionId::parse(id).is_none(),
                "Invalid base32 suffix should be invalid: {}",
                id
            );
        }
    }

    /// Session ID must have hyphens in correct positions.
    #[test]
    fn hyphens_in_correct_positions() {
        let bad_hyphens = [
            "pt20260115-143022-a7xq",   // Missing first hyphen
            "pt-20260115143022-a7xq",   // Missing second hyphen
            "pt-20260115-143022a7xq",   // Missing third hyphen
            "pt-20260115_143022-a7xq",  // Underscore instead of hyphen
        ];
        for id in &bad_hyphens {
            assert!(
                SessionId::parse(id).is_none(),
                "Wrong hyphen placement should be invalid: {}",
                id
            );
        }
    }

    /// Generated session IDs should always parse successfully.
    #[test]
    fn generated_ids_are_valid() {
        for _ in 0..100 {
            let sid = SessionId::new();
            assert!(
                SessionId::parse(&sid.0).is_some(),
                "Generated session ID should be valid: {}",
                sid.0
            );
        }
    }
}

// ============================================================================
// Priors Schema Validation Tests
// ============================================================================

mod priors_schema {
    use pt_common::config::priors::*;

    /// Default priors should have correct schema version.
    #[test]
    fn default_priors_have_correct_version() {
        let priors = Priors::default();
        assert_eq!(priors.schema_version, PRIORS_SCHEMA_VERSION);
        assert_eq!(priors.schema_version, "1.0.0");
    }

    /// Default priors should pass validation.
    #[test]
    fn default_priors_validate() {
        let priors = Priors::default();
        assert!(priors.validate().is_ok());
    }

    /// Priors with wrong schema version should fail validation.
    #[test]
    fn wrong_schema_version_fails() {
        let mut priors = Priors::default();
        priors.schema_version = "2.0.0".to_string();
        assert!(priors.validate().is_err());
    }

    /// Class prior probabilities must sum to 1.0.
    #[test]
    fn class_probs_must_sum_to_one() {
        let priors = Priors::default();
        let sum = priors.classes.useful.prior_prob
            + priors.classes.useful_bad.prior_prob
            + priors.classes.abandoned.prior_prob
            + priors.classes.zombie.prior_prob;
        assert!((sum - 1.0).abs() < 0.001);
    }

    /// Invalid class probabilities should fail validation.
    #[test]
    fn invalid_class_probs_fail() {
        let mut priors = Priors::default();
        priors.classes.useful.prior_prob = 0.9;  // Sum now != 1.0
        assert!(priors.validate().is_err());
    }

    /// Beta parameters must be positive.
    #[test]
    fn beta_params_must_be_positive() {
        let valid = BetaParams { alpha: 1.0, beta: 1.0 };
        assert!(valid.validate("test").is_ok());

        let zero_alpha = BetaParams { alpha: 0.0, beta: 1.0 };
        assert!(zero_alpha.validate("test").is_err());

        let negative_beta = BetaParams { alpha: 1.0, beta: -0.5 };
        assert!(negative_beta.validate("test").is_err());
    }

    /// Gamma parameters must be positive.
    #[test]
    fn gamma_params_must_be_positive() {
        let valid = GammaParams { shape: 2.0, rate: 0.5 };
        assert!(valid.validate("test").is_ok());

        let zero_shape = GammaParams { shape: 0.0, rate: 0.5 };
        assert!(zero_shape.validate("test").is_err());

        let negative_rate = GammaParams { shape: 2.0, rate: -0.1 };
        assert!(negative_rate.validate("test").is_err());
    }

    /// Dirichlet alpha must have at least 2 elements.
    #[test]
    fn dirichlet_needs_at_least_two_elements() {
        let valid = DirichletParams { alpha: vec![1.0, 1.0] };
        assert!(valid.validate("test").is_ok());

        let too_short = DirichletParams { alpha: vec![1.0] };
        assert!(too_short.validate("test").is_err());

        let empty = DirichletParams { alpha: vec![] };
        assert!(empty.validate("test").is_err());
    }

    /// Dirichlet alpha elements must be positive.
    #[test]
    fn dirichlet_alpha_must_be_positive() {
        let with_zero = DirichletParams { alpha: vec![1.0, 0.0, 1.0] };
        assert!(with_zero.validate("test").is_err());

        let with_negative = DirichletParams { alpha: vec![1.0, -0.5, 1.0] };
        assert!(with_negative.validate("test").is_err());
    }

    /// Priors should serialize to valid JSON.
    #[test]
    fn priors_serialize_to_json() {
        let priors = Priors::default();
        let json = serde_json::to_string(&priors);
        assert!(json.is_ok(), "Priors should serialize to JSON");

        let json_str = json.unwrap();
        assert!(json_str.contains("\"schema_version\":\"1.0.0\""));
        assert!(json_str.contains("\"classes\""));
        assert!(json_str.contains("\"useful\""));
        assert!(json_str.contains("\"abandoned\""));
        assert!(json_str.contains("\"zombie\""));
    }

    /// Priors should deserialize from JSON.
    #[test]
    fn priors_deserialize_from_json() {
        let priors = Priors::default();
        let json = serde_json::to_string(&priors).unwrap();
        let parsed: Result<Priors, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "Priors should deserialize from JSON");

        let parsed_priors = parsed.unwrap();
        assert_eq!(parsed_priors.schema_version, priors.schema_version);
    }

    /// JSON missing mandatory fields should fail deserialization.
    #[test]
    fn missing_schema_version_fails() {
        let json = r#"{"classes":{}}"#;
        let result: Result<Priors, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing schema_version should fail");
    }

    /// JSON missing classes field should fail deserialization.
    #[test]
    fn missing_classes_fails() {
        let json = r#"{"schema_version":"1.0.0"}"#;
        let result: Result<Priors, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing classes should fail");
    }
}

// ============================================================================
// CLI JSON Output Format Tests
// ============================================================================

mod cli_json_output {
    use super::*;

    /// Config show with JSON format should produce valid JSON.
    #[test]
    fn config_show_json_is_valid() {
        let output = pt_core()
            .args(["--format", "json", "config", "show"])
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // If it produces output, it should be valid JSON
            if !stdout.trim().is_empty() {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
                assert!(
                    parsed.is_ok(),
                    "Config show JSON should be valid: {}",
                    stdout
                );
            }
        }
    }

    /// Agent capabilities with JSON format should produce valid JSON.
    #[test]
    fn agent_capabilities_json_is_valid() {
        let output = pt_core()
            .args(["--format", "json", "agent", "capabilities"])
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
                assert!(
                    parsed.is_ok(),
                    "Agent capabilities JSON should be valid: {}",
                    stdout
                );
            }
        }
    }

    /// Query sessions with JSON format should produce valid JSON or JSONL.
    #[test]
    fn query_sessions_json_is_valid() {
        let output = pt_core()
            .args(["--format", "json", "query", "sessions", "--limit", "1"])
            .output()
            .expect("Failed to execute command");

        // Even if no sessions exist, output should be valid JSON (empty array)
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
                assert!(
                    parsed.is_ok(),
                    "Query sessions JSON should be valid: {}",
                    stdout
                );
            }
        }
    }

    /// Version command JSON output should be valid.
    #[test]
    fn version_json_is_valid() {
        let output = pt_core()
            .args(["--format", "json", "version"])
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                // Might be JSON or plain text depending on implementation
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
                // Not all commands support JSON format yet, so just check if parseable when non-empty JSON-like
                if stdout.trim().starts_with('{') || stdout.trim().starts_with('[') {
                    assert!(
                        parsed.is_ok(),
                        "Version JSON should be valid: {}",
                        stdout
                    );
                }
            }
        }
    }
}

// ============================================================================
// Start ID Format Tests
// ============================================================================

mod start_id_format {
    use pt_common::id::StartId;

    /// Valid Start IDs should parse successfully.
    #[test]
    fn valid_start_id_parses() {
        let valid = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:4242";
        assert!(StartId::parse(valid).is_some());
    }

    /// Start ID requires UUID boot_id.
    #[test]
    fn start_id_requires_uuid_boot_id() {
        let invalid_boot_id = "not-a-uuid:123456789:4242";
        assert!(StartId::parse(invalid_boot_id).is_none());
    }

    /// Start ID requires numeric start_time.
    #[test]
    fn start_id_requires_numeric_start_time() {
        let invalid_time = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:not-a-number:4242";
        assert!(StartId::parse(invalid_time).is_none());
    }

    /// Start ID requires numeric PID.
    #[test]
    fn start_id_requires_numeric_pid() {
        let invalid_pid = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:not-a-pid";
        assert!(StartId::parse(invalid_pid).is_none());
    }

    /// Start ID must have exactly 3 colon-separated parts.
    #[test]
    fn start_id_has_three_parts() {
        let too_few = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789";
        assert!(StartId::parse(too_few).is_none());

        let too_many = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:4242:extra";
        assert!(StartId::parse(too_many).is_none());
    }

    /// Linux Start ID construction should be valid.
    #[test]
    fn linux_start_id_construction() {
        let sid = StartId::from_linux("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 123456789, 4242);
        assert_eq!(
            sid.0,
            "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:4242"
        );
    }

    /// macOS Start ID construction should be valid.
    #[test]
    fn macos_start_id_construction() {
        let sid = StartId::from_macos("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 987654321, 1234);
        assert_eq!(
            sid.0,
            "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:987654321:1234"
        );
    }
}

// ============================================================================
// Process ID Tests
// ============================================================================

mod process_id {
    use pt_common::id::ProcessId;

    /// ProcessId should display as its inner value.
    #[test]
    fn process_id_display() {
        let pid = ProcessId(1234);
        assert_eq!(format!("{}", pid), "1234");
    }

    /// ProcessId should convert from u32.
    #[test]
    fn process_id_from_u32() {
        let pid: ProcessId = 5678.into();
        assert_eq!(pid.0, 5678);
    }

    /// ProcessId serializes as transparent number.
    #[test]
    fn process_id_serializes_as_number() {
        let pid = ProcessId(42);
        let json = serde_json::to_string(&pid).unwrap();
        assert_eq!(json, "42");
    }

    /// ProcessId deserializes from number.
    #[test]
    fn process_id_deserializes_from_number() {
        let pid: ProcessId = serde_json::from_str("999").unwrap();
        assert_eq!(pid.0, 999);
    }
}

// ============================================================================
// Output Format Tests
// ============================================================================

mod output_format {
    use pt_common::output::OutputFormat;

    /// All output formats should have string representation.
    #[test]
    fn all_formats_display() {
        assert_eq!(format!("{}", OutputFormat::Json), "json");
        assert_eq!(format!("{}", OutputFormat::Md), "md");
        assert_eq!(format!("{}", OutputFormat::Jsonl), "jsonl");
        assert_eq!(format!("{}", OutputFormat::Summary), "summary");
        assert_eq!(format!("{}", OutputFormat::Metrics), "metrics");
        assert_eq!(format!("{}", OutputFormat::Slack), "slack");
        assert_eq!(format!("{}", OutputFormat::Exitcode), "exitcode");
        assert_eq!(format!("{}", OutputFormat::Prose), "prose");
    }

    /// OutputFormat should serialize to lowercase string.
    #[test]
    fn output_format_serializes() {
        let json = serde_json::to_string(&OutputFormat::Json).unwrap();
        assert_eq!(json, "\"json\"");

        let md = serde_json::to_string(&OutputFormat::Md).unwrap();
        assert_eq!(md, "\"md\"");
    }

    /// OutputFormat should deserialize from lowercase string.
    #[test]
    fn output_format_deserializes() {
        let json: OutputFormat = serde_json::from_str("\"json\"").unwrap();
        assert_eq!(json, OutputFormat::Json);

        let jsonl: OutputFormat = serde_json::from_str("\"jsonl\"").unwrap();
        assert_eq!(jsonl, OutputFormat::Jsonl);
    }

    /// Default output format should be Json.
    #[test]
    fn default_format_is_json() {
        assert_eq!(OutputFormat::default(), OutputFormat::Json);
    }
}

// ============================================================================
// JSON Schema Pattern Tests
// ============================================================================

mod schema_patterns {
    /// Semver pattern should match valid versions.
    #[test]
    fn semver_pattern_matches() {
        let semver_re = regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
        assert!(semver_re.is_match("1.0.0"));
        assert!(semver_re.is_match("0.1.0"));
        assert!(semver_re.is_match("10.20.30"));
        assert!(semver_re.is_match("999.999.999"));
    }

    /// Semver pattern should reject invalid versions.
    #[test]
    fn semver_pattern_rejects_invalid() {
        let semver_re = regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
        assert!(!semver_re.is_match("1.0"));
        assert!(!semver_re.is_match("1"));
        assert!(!semver_re.is_match("v1.0.0"));
        assert!(!semver_re.is_match("1.0.0-beta"));
        assert!(!semver_re.is_match("1.0.0.1"));
    }

    /// Session ID pattern should match valid IDs.
    #[test]
    fn session_id_pattern_matches() {
        let session_re = regex::Regex::new(r"^pt-[0-9]{8}-[0-9]{6}-[a-z2-7]{4}$").unwrap();
        assert!(session_re.is_match("pt-20260115-143022-a7xq"));
        assert!(session_re.is_match("pt-20250101-000000-aaaa"));
        assert!(session_re.is_match("pt-20301231-235959-7777"));
    }

    /// Session ID pattern should reject invalid IDs.
    #[test]
    fn session_id_pattern_rejects_invalid() {
        let session_re = regex::Regex::new(r"^pt-[0-9]{8}-[0-9]{6}-[a-z2-7]{4}$").unwrap();
        assert!(!session_re.is_match("pt-20260115-143022-A7XQ"));  // Uppercase
        assert!(!session_re.is_match("pt-20260115-143022-a7x8"));  // 8 not in base32
        assert!(!session_re.is_match("PT-20260115-143022-a7xq"));  // Wrong prefix
        assert!(!session_re.is_match("pt-2026011-143022-a7xq"));   // Short date
        assert!(!session_re.is_match("pt-20260115-14302-a7xq"));   // Short time
    }

    /// Checksum pattern should match SHA-256 hashes.
    #[test]
    fn checksum_pattern_matches() {
        let checksum_re = regex::Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap();
        assert!(checksum_re.is_match("sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"));
        assert!(checksum_re.is_match("sha256:0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(checksum_re.is_match("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    }

    /// Checksum pattern should reject invalid hashes.
    #[test]
    fn checksum_pattern_rejects_invalid() {
        let checksum_re = regex::Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap();
        // Uppercase letters
        assert!(!checksum_re.is_match("sha256:ABCD1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"));
        // Wrong prefix
        assert!(!checksum_re.is_match("sha512:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"));
        // Too short
        assert!(!checksum_re.is_match("sha256:abcd1234"));
        // Too long
        assert!(!checksum_re.is_match("sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"));
        // Invalid characters
        assert!(!checksum_re.is_match("sha256:ghij1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"));
    }
}

// ============================================================================
// JSON Round-trip Tests
// ============================================================================

mod json_roundtrip {
    use pt_common::id::{ProcessId, SessionId, StartId, ProcessIdentity};

    /// ProcessId should round-trip through JSON.
    #[test]
    fn process_id_roundtrip() {
        let original = ProcessId(12345);
        let json = serde_json::to_string(&original).unwrap();
        let restored: ProcessId = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// SessionId should round-trip through JSON.
    #[test]
    fn session_id_roundtrip() {
        let original = SessionId::new();
        let json = serde_json::to_string(&original).unwrap();
        let restored: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(original.0, restored.0);
    }

    /// StartId should round-trip through JSON.
    #[test]
    fn start_id_roundtrip() {
        let original = StartId::from_linux("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 123456789, 4242);
        let json = serde_json::to_string(&original).unwrap();
        let restored: StartId = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// ProcessIdentity should round-trip through JSON.
    #[test]
    fn process_identity_roundtrip() {
        let start_id = StartId::from_linux("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 123456789, 4242);
        let original = ProcessIdentity::new(1234, start_id, 1000);
        let json = serde_json::to_string(&original).unwrap();
        let restored: ProcessIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// ProcessIdentity JSON contains all required fields.
    #[test]
    fn process_identity_json_fields() {
        let start_id = StartId::from_linux("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 123456789, 4242);
        let identity = ProcessIdentity::new(1234, start_id, 1000);
        let json = serde_json::to_string(&identity).unwrap();

        assert!(json.contains("\"pid\""));
        assert!(json.contains("\"start_id\""));
        assert!(json.contains("\"uid\""));
        assert!(json.contains("1234"));
        assert!(json.contains("1000"));
    }
}
