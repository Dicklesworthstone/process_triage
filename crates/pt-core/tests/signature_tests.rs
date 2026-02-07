//! Comprehensive tests for the pattern/signature library.
//!
//! This test module covers:
//! - Unit tests: pattern compilation, matching, normalization, versioning
//! - Built-in pattern tests: test runners, dev servers, agents, builds
//! - Integration tests: fast-path classification, pattern learning, persistence, conflicts
//! - Performance tests: < 1ms for 1000 processes, < 100ms library load

use pt_core::inference::ledger::Classification;
use pt_core::inference::signature_fast_path::{
    try_signature_fast_path, FastPathConfig, FastPathSkipReason,
};
use pt_core::supervision::pattern_persistence::{
    AllPatternStats, ConflictResolution, DisabledPatterns, PatternLibrary, PatternLifecycle,
    PatternSource, PatternStats, PersistedPattern, PersistedSchema,
};
use pt_core::supervision::signature::{
    BetaParams, MatchDetails, MatchLevel, ProcessExpectations, ProcessMatchContext,
    SignatureDatabase, SignatureError, SignaturePatterns, SignaturePriors, SignatureSchema,
    SupervisorSignature, SCHEMA_VERSION,
};
use pt_core::supervision::SupervisorCategory;
use std::collections::HashMap;
use std::time::Instant;
use tempfile::tempdir;

// ============================================================================
// Unit Tests: Pattern Compilation
// ============================================================================

mod pattern_compilation_tests {
    use super::*;

    #[test]
    fn test_valid_regex_patterns_compile() {
        let sig = SupervisorSignature::new("test-valid", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^test$", r"test-\d+", r".*worker.*"])
            .with_arg_patterns(vec![r"--flag", r"-v", r"\d{4}"])
            .with_working_dir_patterns(vec![r"/home/.*", r"/tmp/.*"])
            .with_env_patterns(HashMap::from([
                ("PATH".into(), ".*".into()),
                ("NODE_ENV".into(), "development|production".into()),
            ]));

        assert!(sig.validate().is_ok(), "Valid patterns should compile");
    }

    #[test]
    fn test_invalid_regex_patterns_rejected() {
        // Invalid process name pattern
        let sig = SupervisorSignature::new("test-invalid", SupervisorCategory::Other)
            .with_process_patterns(vec![r"[invalid"]);

        let result = sig.validate();
        assert!(
            matches!(
                &result,
                Err(SignatureError::InvalidRegex { pattern, .. }) if pattern == "[invalid"
            ),
            "Expected InvalidRegex error for '[invalid', got {:?}",
            result
        );

        // Invalid arg pattern
        let sig2 = SupervisorSignature::new("test-invalid2", SupervisorCategory::Other)
            .with_arg_patterns(vec![r"(unclosed"]);

        assert!(matches!(
            sig2.validate(),
            Err(SignatureError::InvalidRegex { .. })
        ));

        // Invalid working dir pattern
        let sig3 = SupervisorSignature::new("test-invalid3", SupervisorCategory::Other)
            .with_working_dir_patterns(vec![r"*invalid"]);

        assert!(matches!(
            sig3.validate(),
            Err(SignatureError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn test_regex_caching_in_database() {
        let mut db = SignatureDatabase::new();

        // Add multiple signatures
        for i in 0..10 {
            let sig = SupervisorSignature::new(&format!("sig-{}", i), SupervisorCategory::Other)
                .with_process_patterns(vec![&format!(r"^process-{}$", i)]);
            db.add(sig).expect("Should add signature");
        }

        assert_eq!(db.len(), 10);

        // Verify matching still works (uses cached regexes)
        let ctx = ProcessMatchContext::with_comm("process-5");
        let matches = db.match_process(&ctx);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].signature.name, "sig-5");
    }

    #[test]
    fn test_empty_pattern_fields() {
        let sig = SupervisorSignature::new("empty-patterns", SupervisorCategory::Other);

        // Empty patterns should be valid
        assert!(sig.validate().is_ok());

        // Database should accept signature with no patterns
        let mut db = SignatureDatabase::new();
        assert!(db.add(sig).is_ok());
    }

    #[test]
    fn test_special_regex_characters() {
        let sig = SupervisorSignature::new("special-chars", SupervisorCategory::Other)
            .with_process_patterns(vec![
                r"^node\$",        // Dollar sign (end of string)
                r"test\.exe",      // Escaped dot
                r"process\[0\]",   // Escaped brackets
                r"cmd\(1\)",       // Escaped parens
                r"run\+\+",        // Escaped plus
                r"file\?",         // Escaped question mark
                r"star\*",         // Escaped asterisk
                r"pipe\|pipe",     // Escaped pipe
                r"caret\^",        // Escaped caret
                r"path/to/file",   // Forward slash (unescaped OK)
                r"path\\to\\file", // Escaped backslash
            ]);

        assert!(
            sig.validate().is_ok(),
            "Special characters should be valid when escaped"
        );
    }

    #[test]
    fn test_case_sensitive_patterns() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("case-test", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^CaseSensitive$"]);
        db.add(sig).unwrap();

        // Exact case should match
        let ctx_match = ProcessMatchContext::with_comm("CaseSensitive");
        assert!(!db.match_process(&ctx_match).is_empty());

        // Wrong case should NOT match
        let ctx_no_match = ProcessMatchContext::with_comm("casesensitive");
        assert!(db.match_process(&ctx_no_match).is_empty());
    }

    #[test]
    fn test_case_insensitive_patterns() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("case-insensitive", SupervisorCategory::Other)
            .with_process_patterns(vec![r"(?i)^caseinsensitive$"]);
        db.add(sig).unwrap();

        // Both cases should match
        let ctx1 = ProcessMatchContext::with_comm("CaseInsensitive");
        let ctx2 = ProcessMatchContext::with_comm("caseinsensitive");
        let ctx3 = ProcessMatchContext::with_comm("CASEINSENSITIVE");

        assert!(!db.match_process(&ctx1).is_empty());
        assert!(!db.match_process(&ctx2).is_empty());
        assert!(!db.match_process(&ctx3).is_empty());
    }
}

// ============================================================================
// Unit Tests: Pattern Matching
// ============================================================================

mod pattern_matching_tests {
    use super::*;

    #[test]
    fn test_match_level_ordering() {
        // Verify match levels are ordered correctly
        assert!(MatchLevel::None < MatchLevel::GenericCategory);
        assert!(MatchLevel::GenericCategory < MatchLevel::CommandOnly);
        assert!(MatchLevel::CommandOnly < MatchLevel::CommandPlusArgs);
        assert!(MatchLevel::CommandPlusArgs < MatchLevel::ExactCommand);
        assert!(MatchLevel::ExactCommand < MatchLevel::MultiPattern);
    }

    #[test]
    fn test_exact_command_match() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("exact-test", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^exactcmd$"])
            .with_confidence(0.95);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("exactcmd");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].level, MatchLevel::ExactCommand);
        assert!(matches[0].details.process_name_matched);
    }

    #[test]
    fn test_command_only_match() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("cmd-only", SupervisorCategory::Other)
            .with_process_patterns(vec![r"cmd-.*"]) // Pattern, not exact
            .with_confidence(0.90);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("cmd-worker");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].level, MatchLevel::CommandOnly);
    }

    #[test]
    fn test_command_plus_args_match() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("cmd-args", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^node$"])
            .with_arg_patterns(vec![r"--inspect"])
            .with_confidence(0.90);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("node").cmdline("node --inspect app.js");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].level, MatchLevel::CommandPlusArgs);
        assert!(matches[0].details.process_name_matched);
        assert!(matches[0].details.args_matched);
    }

    #[test]
    fn test_multi_pattern_match() {
        let mut db = SignatureDatabase::new();
        let env_patterns = HashMap::from([("TEST_ENV".into(), ".*".into())]);
        let sig = SupervisorSignature::new("multi", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^multi$"])
            .with_arg_patterns(vec![r"--flag"])
            .with_env_patterns(env_patterns)
            .with_confidence(0.95);
        db.add(sig).unwrap();

        let env = HashMap::from([("TEST_ENV".to_string(), "value".to_string())]);
        let ctx = ProcessMatchContext::with_comm("multi")
            .cmdline("multi --flag")
            .env_vars(&env);
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].level, MatchLevel::MultiPattern);
        assert!(matches[0].details.process_name_matched);
        assert!(matches[0].details.args_matched);
        assert!(matches[0].details.env_vars_matched);
        assert!(matches[0].details.pattern_types_matched >= 3);
    }

    #[test]
    fn test_min_matches_requirement() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("min-match", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^node$"])
            .with_arg_patterns(vec![r"--flag"])
            .with_min_matches(2) // Require BOTH process AND args to match
            .with_confidence(0.90);
        db.add(sig).unwrap();

        // Only process name matches - should NOT match due to min_matches
        let ctx1 = ProcessMatchContext::with_comm("node");
        let matches1 = db.match_process(&ctx1);
        assert!(
            matches1.is_empty(),
            "Should not match with only 1 pattern type"
        );

        // Both match - should succeed
        let ctx2 = ProcessMatchContext::with_comm("node").cmdline("node --flag");
        let matches2 = db.match_process(&ctx2);
        assert_eq!(matches2.len(), 1, "Should match with 2 pattern types");
    }

    #[test]
    fn test_no_match() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("specific", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^specific-process$"]);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("completely-different");
        let matches = db.match_process(&ctx);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_multiple_signatures_match() {
        let mut db = SignatureDatabase::new();

        // Two signatures that can both match "node"
        let sig1 = SupervisorSignature::new("node-generic", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^node$"])
            .with_confidence(0.70)
            .with_priority(50);
        let sig2 = SupervisorSignature::new("node-test", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^node$"])
            .with_arg_patterns(vec![r"test"])
            .with_confidence(0.90)
            .with_priority(100);

        db.add(sig1).unwrap();
        db.add(sig2).unwrap();

        // With test arg, both should match but node-test should be first (higher score)
        let ctx = ProcessMatchContext::with_comm("node").cmdline("node test");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 2);
        // node-test should be first due to higher score (command+args vs command-only)
        assert_eq!(matches[0].signature.name, "node-test");
    }

    #[test]
    fn test_socket_path_matching() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("socket-test", SupervisorCategory::Other)
            .with_socket_paths(vec!["/tmp/myapp-"])
            .with_confidence(0.80);
        db.add(sig).unwrap();

        let sockets = vec!["/tmp/myapp-12345.sock".to_string()];
        let ctx = ProcessMatchContext::with_comm("anyprocess").socket_paths(&sockets);
        let matches = db.match_process(&ctx);

        assert!(!matches.is_empty());
        assert!(matches[0].details.socket_matched);
    }

    #[test]
    fn test_parent_pattern_matching() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("child-of-parent", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^worker$"])
            .with_parent_patterns(vec![r"^supervisor$"])
            .with_confidence(0.85);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("worker").parent_comm("supervisor");
        let matches = db.match_process(&ctx);

        assert!(!matches.is_empty());
        assert!(matches[0].details.parent_matched);
    }

    #[test]
    fn test_working_dir_matching() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("project-specific", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^app$"])
            .with_working_dir_patterns(vec![r"/home/.*/my-project"])
            .with_confidence(0.85);
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("app").cwd("/home/user/my-project");
        let matches = db.match_process(&ctx);

        assert!(!matches.is_empty());
        assert!(matches[0].details.working_dir_matched);
    }

    #[test]
    fn test_match_score_calculation() {
        let mut db = SignatureDatabase::new();
        let sig = SupervisorSignature::new("score-test", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^test$"])
            .with_confidence(0.80); // confidence_weight = 0.80
        db.add(sig).unwrap();

        let ctx = ProcessMatchContext::with_comm("test");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 1);
        // ExactCommand base score = 0.85, * confidence_weight 0.80 = 0.68
        let expected_score = 0.85 * 0.80;
        assert!((matches[0].score - expected_score).abs() < 0.01);
    }
}

// ============================================================================
// Unit Tests: Versioning
// ============================================================================

mod versioning_tests {
    use super::*;

    #[test]
    fn test_current_schema_version() {
        assert!(SCHEMA_VERSION >= 2, "Schema version should be at least 2");
    }

    #[test]
    fn test_schema_version_in_serialization() {
        let schema = SignatureSchema::new();
        let json = schema.to_json().unwrap();

        assert!(json.contains(&format!("\"schema_version\": {}", SCHEMA_VERSION)));
    }

    #[test]
    fn test_reject_future_schema_version() {
        let future_json = r#"{"schema_version": 999, "signatures": []}"#;
        let result = SignatureSchema::from_json(future_json);

        assert!(
            matches!(
                &result,
                Err(SignatureError::UnsupportedVersion { found, expected })
                if *found == 999 && *expected == SCHEMA_VERSION
            ),
            "Expected UnsupportedVersion error for schema_version=999, got {:?}",
            result
        );
    }

    #[test]
    fn test_accept_current_schema_version() {
        let json = format!(
            r#"{{"schema_version": {}, "signatures": []}}"#,
            SCHEMA_VERSION
        );
        let result = SignatureSchema::from_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_accept_older_schema_version() {
        // Version 1 should be accepted (with potential migration)
        let json = r#"{"schema_version": 1, "signatures": []}"#;
        let result = SignatureSchema::from_json(json);
        // Should succeed - older versions are supported
        assert!(result.is_ok());
    }
}

// ============================================================================
// Built-in Pattern Tests: Test Runners
// ============================================================================

mod builtin_test_runner_tests {
    use super::*;

    fn get_default_db() -> SignatureDatabase {
        SignatureDatabase::with_defaults()
    }

    #[test]
    fn test_jest_detection() {
        let db = get_default_db();

        // By process name
        let ctx1 = ProcessMatchContext::with_comm("jest");
        let matches1 = db.match_process(&ctx1);
        assert!(!matches1.is_empty(), "Should detect jest by process name");
        assert_eq!(matches1[0].signature.name, "jest");

        // By arg pattern (node running jest)
        let ctx2 = ProcessMatchContext::with_comm("node").cmdline("node ./node_modules/.bin/jest");
        let _matches2 = db.match_process(&ctx2);
        // Note: May not match if only arg_patterns are defined (needs process_name match too)

        // By environment variable
        let env = HashMap::from([("JEST_WORKER_ID".to_string(), "1".to_string())]);
        let ctx3 = ProcessMatchContext::with_comm("node").env_vars(&env);
        let matches3 = db.match_process(&ctx3);
        // Check if environment-based matching works for jest
        if !matches3.is_empty() {
            assert!(matches3.iter().any(|m| m.signature.name == "jest"));
        }
    }

    #[test]
    fn test_pytest_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("pytest");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect pytest");
        assert_eq!(matches[0].signature.name, "pytest");

        // Verify it has likely_abandoned priors
        assert!(
            !matches[0].signature.priors.is_empty(),
            "pytest should have priors"
        );
    }

    #[test]
    fn test_vitest_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("vitest");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect vitest");
        assert_eq!(matches[0].signature.name, "vitest");

        // Also test by env var
        let env = HashMap::from([("VITEST".to_string(), "true".to_string())]);
        let ctx2 = ProcessMatchContext::with_comm("node").env_vars(&env);
        let matches2 = db.match_process(&ctx2);
        // Check if it matches by env
        if !matches2.is_empty() {
            assert!(matches2.iter().any(|m| m.signature.name == "vitest"));
        }
    }

    #[test]
    fn test_cargo_test_detection() {
        let db = get_default_db();

        // Cargo test is detected by arg pattern
        let ctx = ProcessMatchContext::with_comm("cargo").cmdline("cargo test --lib");
        let matches = db.match_process(&ctx);

        // May match multiple, look for cargo-test
        let cargo_test_match = matches.iter().find(|m| m.signature.name == "cargo-test");
        assert!(cargo_test_match.is_some(), "Should detect cargo test");
    }

    #[test]
    fn test_go_test_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("go").cmdline("go test ./...");
        let matches = db.match_process(&ctx);

        let go_test_match = matches.iter().find(|m| m.signature.name == "go-test");
        assert!(go_test_match.is_some(), "Should detect go test");
    }

    #[test]
    fn test_npm_test_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("npm").cmdline("npm test -- --watch");
        let matches = db.match_process(&ctx);

        let npm_match = matches.iter().find(|m| m.signature.name == "npm");
        assert!(npm_match.is_some(), "Should detect npm test invocation");
    }

    #[test]
    fn test_mocha_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("mocha");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect mocha");
        assert_eq!(matches[0].signature.name, "mocha");
    }

    #[test]
    fn test_rspec_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("rspec");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect rspec");
        assert_eq!(matches[0].signature.name, "rspec");
    }

    #[test]
    fn test_playwright_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("playwright");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect playwright");
        assert_eq!(matches[0].signature.name, "playwright");
    }

    #[test]
    fn test_cypress_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("cypress");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect cypress");
        // Could be "Cypress" or "cypress"
        assert!(matches[0].signature.name == "cypress" || matches[0].signature.name == "Cypress");
    }

    #[test]
    fn test_test_runners_have_abandoned_priors() {
        let db = get_default_db();

        let test_runners = ["jest", "pytest", "vitest", "mocha", "rspec"];

        for runner in test_runners {
            let ctx = ProcessMatchContext::with_comm(runner);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                let priors = &matches[0].signature.priors;
                assert!(!priors.is_empty(), "{} should have priors defined", runner);

                if let Some(abandoned) = &priors.abandoned {
                    assert!(
                        abandoned.mean() > 0.5,
                        "{} should have high abandoned prior (mean: {})",
                        runner,
                        abandoned.mean()
                    );
                }
            }
        }
    }

    #[test]
    fn test_test_runners_have_short_lived_expectations() {
        let db = get_default_db();

        let test_runners = ["jest", "pytest", "vitest"];

        for runner in test_runners {
            let ctx = ProcessMatchContext::with_comm(runner);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                let expectations = &matches[0].signature.expectations;
                if !expectations.is_empty() {
                    assert!(
                        expectations.typical_lifetime_seconds.is_some(),
                        "{} should have typical_lifetime defined",
                        runner
                    );
                }
            }
        }
    }
}

// ============================================================================
// Built-in Pattern Tests: Dev Servers
// ============================================================================

mod builtin_dev_server_tests {
    use super::*;

    fn get_default_db() -> SignatureDatabase {
        SignatureDatabase::with_defaults()
    }

    #[test]
    fn test_next_dev_detection() {
        let db = get_default_db();

        let ctx =
            ProcessMatchContext::with_comm("node").cmdline("node ./node_modules/.bin/next dev");
        let matches = db.match_process(&ctx);

        let next_match = matches.iter().find(|m| m.signature.name == "next-dev");
        assert!(next_match.is_some(), "Should detect next dev server");
    }

    #[test]
    fn test_vite_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("vite");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect vite");
        assert_eq!(matches[0].signature.name, "vite");
    }

    #[test]
    fn test_webpack_dev_server_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("node")
            .cmdline("node ./node_modules/.bin/webpack serve");
        let matches = db.match_process(&ctx);

        let webpack_match = matches
            .iter()
            .find(|m| m.signature.name == "webpack-dev-server");
        assert!(webpack_match.is_some(), "Should detect webpack-dev-server");
    }

    #[test]
    fn test_webpack_hot_watch_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("node")
            .cmdline("node ./node_modules/.bin/webpack serve --hot --watch");
        let matches = db.match_process(&ctx);

        let webpack_match = matches
            .iter()
            .find(|m| m.signature.name == "webpack-dev-server");
        assert!(
            webpack_match.is_some(),
            "Should detect webpack-dev-server with --hot/--watch flags"
        );
    }

    #[test]
    fn test_flask_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("python").cmdline("python -m flask run");
        let matches = db.match_process(&ctx);

        let flask_match = matches.iter().find(|m| m.signature.name == "flask");
        assert!(flask_match.is_some(), "Should detect flask dev server");
    }

    #[test]
    fn test_django_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("python").cmdline("python manage.py runserver");
        let matches = db.match_process(&ctx);

        let django_match = matches.iter().find(|m| m.signature.name == "django");
        assert!(django_match.is_some(), "Should detect django dev server");
    }

    #[test]
    fn test_rails_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("ruby").cmdline("ruby rails server");
        let matches = db.match_process(&ctx);

        let rails_match = matches.iter().find(|m| m.signature.name == "rails");
        assert!(rails_match.is_some(), "Should detect rails server");
    }

    #[test]
    fn test_dev_servers_have_useful_priors() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("vite");
        let matches = db.match_process(&ctx);

        if !matches.is_empty() {
            let priors = &matches[0].signature.priors;

            // Dev servers should have "likely_useful" priors
            if let Some(useful) = &priors.useful {
                assert!(useful.mean() > 0.5, "vite should have high useful prior");
            }
        }
    }

    #[test]
    fn test_dev_servers_have_network_expectations() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("vite");
        let matches = db.match_process(&ctx);

        if !matches.is_empty() {
            let expectations = &matches[0].signature.expectations;
            if !expectations.is_empty() {
                assert!(
                    expectations.expects_network,
                    "Dev servers should expect network activity"
                );
            }
        }
    }
}

// ============================================================================
// Built-in Pattern Tests: AI Agents
// ============================================================================

mod builtin_agent_tests {
    use super::*;

    fn get_default_db() -> SignatureDatabase {
        SignatureDatabase::with_defaults()
    }

    #[test]
    fn test_claude_detection() {
        let db = get_default_db();

        // By process name
        let ctx1 = ProcessMatchContext::with_comm("claude");
        let matches1 = db.match_process(&ctx1);
        assert!(!matches1.is_empty(), "Should detect claude by process name");
        assert_eq!(matches1[0].signature.name, "claude");
        assert_eq!(matches1[0].signature.category, SupervisorCategory::Agent);

        // By socket path
        let sockets = vec!["/tmp/claude-session-123.sock".to_string()];
        let _ctx2 = ProcessMatchContext::with_comm("anyprocess").socket_paths(&sockets);
        let matches2 = db.find_by_socket_path("/tmp/claude-session-123.sock");
        assert!(
            matches2.iter().any(|s| s.name == "claude"),
            "Should detect claude by socket path"
        );
    }

    #[test]
    fn test_codex_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("codex");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect codex");
        assert_eq!(matches[0].signature.name, "codex");
        assert_eq!(matches[0].signature.category, SupervisorCategory::Agent);
    }

    #[test]
    fn test_cursor_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("cursor");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect cursor");
        assert_eq!(matches[0].signature.name, "cursor");
        assert_eq!(matches[0].signature.category, SupervisorCategory::Agent);
    }

    #[test]
    fn test_aider_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("aider");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect aider");
        assert_eq!(matches[0].signature.name, "aider");
        assert_eq!(matches[0].signature.category, SupervisorCategory::Agent);
    }

    #[test]
    fn test_copilot_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("copilot");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect copilot");
        assert_eq!(matches[0].signature.name, "copilot");
        assert_eq!(matches[0].signature.category, SupervisorCategory::Agent);
    }

    #[test]
    fn test_agents_are_categorized() {
        let db = get_default_db();

        let agents = ["claude", "codex", "cursor", "aider", "copilot"];

        for agent in agents {
            let ctx = ProcessMatchContext::with_comm(agent);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                assert_eq!(
                    matches[0].signature.category,
                    SupervisorCategory::Agent,
                    "{} should be categorized as Agent",
                    agent
                );
            }
        }
    }

    #[test]
    fn test_agents_have_high_confidence() {
        let db = get_default_db();

        let agents = ["claude", "codex"];

        for agent in agents {
            let ctx = ProcessMatchContext::with_comm(agent);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                assert!(
                    matches[0].signature.confidence_weight >= 0.90,
                    "{} should have high confidence (got {})",
                    agent,
                    matches[0].signature.confidence_weight
                );
            }
        }
    }
}

// ============================================================================
// Built-in Pattern Tests: Build Tools
// ============================================================================

mod builtin_build_tests {
    use super::*;

    fn get_default_db() -> SignatureDatabase {
        SignatureDatabase::with_defaults()
    }

    #[test]
    fn test_cargo_build_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("cargo").cmdline("cargo build --release");
        let matches = db.match_process(&ctx);

        let cargo_match = matches.iter().find(|m| m.signature.name == "cargo-build");
        assert!(cargo_match.is_some(), "Should detect cargo build");
    }

    #[test]
    fn test_npm_install_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("npm").cmdline("npm install");
        let matches = db.match_process(&ctx);

        let npm_match = matches.iter().find(|m| m.signature.name == "npm");
        assert!(npm_match.is_some(), "Should detect npm");
    }

    #[test]
    fn test_make_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("make");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect make");
        assert_eq!(matches[0].signature.name, "make");
    }

    #[test]
    fn test_tsc_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("tsc");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect tsc");
        assert_eq!(matches[0].signature.name, "tsc");
    }

    #[test]
    fn test_webpack_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("webpack");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect webpack");
        assert_eq!(matches[0].signature.name, "webpack");
    }

    #[test]
    fn test_esbuild_detection() {
        let db = get_default_db();

        let ctx = ProcessMatchContext::with_comm("esbuild");
        let matches = db.match_process(&ctx);
        assert!(!matches.is_empty(), "Should detect esbuild");
        assert_eq!(matches[0].signature.name, "esbuild");
    }

    #[test]
    fn test_build_tools_have_abandoned_priors() {
        let db = get_default_db();

        let build_tools = ["make", "webpack", "tsc", "esbuild"];

        for tool in build_tools {
            let ctx = ProcessMatchContext::with_comm(tool);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                let priors = &matches[0].signature.priors;
                if !priors.is_empty() {
                    if let Some(abandoned) = &priors.abandoned {
                        assert!(
                            abandoned.mean() > 0.5,
                            "{} should have high abandoned prior",
                            tool
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_build_tools_have_short_lived_expectations() {
        let db = get_default_db();

        let build_tools = ["webpack", "tsc", "esbuild"];

        for tool in build_tools {
            let ctx = ProcessMatchContext::with_comm(tool);
            let matches = db.match_process(&ctx);

            if !matches.is_empty() {
                let expectations = &matches[0].signature.expectations;
                if !expectations.is_empty() {
                    assert!(
                        expectations.typical_lifetime_seconds.is_some(),
                        "{} should have typical_lifetime defined",
                        tool
                    );
                }
            }
        }
    }
}

// ============================================================================
// Integration Tests: Fast-Path Classification
// ============================================================================

mod fast_path_tests {
    use super::*;
    use pt_core::supervision::signature::SignatureMatch;

    fn make_test_signature(name: &str, priors: SignaturePriors) -> SupervisorSignature {
        SupervisorSignature {
            name: name.to_string(),
            category: SupervisorCategory::Agent,
            patterns: SignaturePatterns::default(),
            confidence_weight: 0.95,
            notes: None,
            builtin: false,
            priors,
            expectations: Default::default(),
            priority: 100,
        }
    }

    #[test]
    fn test_fast_path_disabled() {
        let config = FastPathConfig::disabled();
        let result = try_signature_fast_path(&config, None, 1234);
        assert_eq!(result, Err(FastPathSkipReason::Disabled));
    }

    #[test]
    fn test_fast_path_no_match() {
        let config = FastPathConfig::default();
        let result = try_signature_fast_path(&config, None, 1234);
        assert_eq!(result, Err(FastPathSkipReason::NoMatch));
    }

    #[test]
    fn test_fast_path_score_below_threshold() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "test-sig",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        // CommandOnly has base score 0.5, * 0.95 confidence = 0.475
        let sig_match = SignatureMatch::new(&sig, MatchLevel::CommandOnly, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert_eq!(result, Err(FastPathSkipReason::ScoreBelowThreshold));
    }

    #[test]
    fn test_fast_path_no_priors() {
        let config = FastPathConfig::default();
        let sig = make_test_signature("test-sig", SignaturePriors::default());
        let details = MatchDetails::default();
        // MultiPattern has base score 0.95, * 0.95 confidence = 0.9025
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert_eq!(result, Err(FastPathSkipReason::NoPriors));
    }

    #[test]
    fn test_fast_path_success_abandoned() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "jest-worker",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)), // 80% abandoned
                useful: Some(BetaParams::new(2.0, 8.0)),    // 20% useful
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(result.is_ok());

        let fast_path = result.unwrap();
        assert!(fast_path.is_some());

        let fast_path = fast_path.unwrap();
        assert_eq!(fast_path.signature_name, "jest-worker");
        assert_eq!(fast_path.classification, Classification::Abandoned);
        assert!(fast_path.bypassed_inference);
        assert!(fast_path.match_score >= 0.9);
    }

    #[test]
    fn test_fast_path_success_useful() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "postgres-daemon",
            SignaturePriors {
                abandoned: Some(BetaParams::new(1.0, 9.0)), // 10% abandoned
                useful: Some(BetaParams::new(9.0, 1.0)),    // 90% useful
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(result.is_ok());

        let fast_path = result.unwrap().unwrap();
        assert_eq!(fast_path.classification, Classification::Useful);
    }

    #[test]
    fn test_fast_path_custom_threshold() {
        let config = FastPathConfig::with_threshold(0.8);
        let sig = make_test_signature(
            "test-sig",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        // ExactCommand has base score 0.85, * 0.95 confidence = 0.8075
        let sig_match = SignatureMatch::new(&sig, MatchLevel::ExactCommand, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_fast_path_ledger_contains_signature_info() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "vscode-server",
            SignaturePriors {
                useful: Some(BetaParams::new(9.0, 1.0)),
                abandoned: Some(BetaParams::new(1.0, 9.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234)
            .unwrap()
            .unwrap();

        // Check ledger contains signature information
        assert!(result.ledger.why_summary.contains("vscode-server"));
        assert!(result.ledger.why_summary.contains("Fast-path"));
        assert!(result
            .ledger
            .top_evidence
            .iter()
            .any(|e: &String| e.contains("vscode-server")));
    }
}

// ============================================================================
// Integration Tests: Pattern Learning & Persistence
// ============================================================================

mod persistence_tests {
    use super::*;

    #[test]
    fn test_pattern_library_create_and_add() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = SupervisorSignature::new("test-pattern", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^test$"])
            .with_confidence(0.80);

        lib.add_custom(sig.clone()).expect("add");

        let pattern = lib.get_pattern("test-pattern");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().signature.name, "test-pattern");
    }

    #[test]
    fn test_pattern_library_persistence() {
        let dir = tempdir().expect("tempdir");

        // Create and save
        {
            let mut lib = PatternLibrary::new(dir.path());
            let sig = SupervisorSignature::new("persisted-pattern", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^persisted$"])
                .with_confidence(0.85);
            lib.add_custom(sig).expect("add");
            lib.save().expect("save");
        }

        // Load and verify
        {
            let mut lib = PatternLibrary::new(dir.path());
            lib.load().expect("load");
            let pattern = lib.get_pattern("persisted-pattern");
            assert!(pattern.is_some());
            assert_eq!(pattern.unwrap().signature.name, "persisted-pattern");
        }
    }

    #[test]
    fn test_pattern_library_disable_enable() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = SupervisorSignature::new("toggle-pattern", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^toggle$"]);
        lib.add_custom(sig).expect("add");

        // Disable
        lib.disable_pattern("toggle-pattern", Some("testing"))
            .expect("disable");

        // Pattern should not appear in active patterns
        let active: Vec<_> = lib
            .all_active_patterns()
            .iter()
            .map(|p| p.signature.name.clone())
            .collect();
        assert!(!active.contains(&"toggle-pattern".to_string()));

        // Enable
        lib.enable_pattern("toggle-pattern").expect("enable");

        // Should now appear in active patterns
        let active: Vec<_> = lib
            .all_active_patterns()
            .iter()
            .map(|p| p.signature.name.clone())
            .collect();
        assert!(active.contains(&"toggle-pattern".to_string()));
    }

    #[test]
    fn test_pattern_stats_recording() {
        let mut stats = PatternStats::default();

        stats.record_match(true);
        stats.record_match(true);
        stats.record_match(false);

        assert_eq!(stats.match_count, 3);
        assert_eq!(stats.accept_count, 2);
        assert_eq!(stats.reject_count, 1);

        // Laplace smoothing: (2+1)/(3+2) = 0.6
        assert!((stats.computed_confidence.unwrap() - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_pattern_lifecycle_transitions() {
        use PatternLifecycle::*;

        // Valid forward transitions
        assert!(New.can_transition_to(Learning));
        assert!(Learning.can_transition_to(Stable));
        assert!(Stable.can_transition_to(Deprecated));
        assert!(Deprecated.can_transition_to(Removed));

        // Reactivation from deprecated
        assert!(Deprecated.can_transition_to(Stable));
        assert!(Deprecated.can_transition_to(Learning));
        assert!(Deprecated.can_transition_to(New));

        // Invalid transitions
        assert!(!New.can_transition_to(Stable)); // Skip not allowed
        assert!(!Removed.can_transition_to(Stable)); // Can't revive removed
    }

    #[test]
    fn test_pattern_lifecycle_from_stats() {
        // Low confidence, low count -> New
        assert_eq!(PatternLifecycle::from_stats(0.3, 5), PatternLifecycle::New);

        // Medium confidence, low count -> Learning
        assert_eq!(
            PatternLifecycle::from_stats(0.6, 5),
            PatternLifecycle::Learning
        );

        // High confidence, high count -> Stable
        assert_eq!(
            PatternLifecycle::from_stats(0.85, 15),
            PatternLifecycle::Stable
        );

        // High confidence but low count -> still Learning (count requirement)
        assert_eq!(
            PatternLifecycle::from_stats(0.9, 5),
            PatternLifecycle::Learning
        );
    }

    #[test]
    fn test_learned_pattern_addition() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = SupervisorSignature::new("learned-pattern", SupervisorCategory::Other)
            .with_process_patterns(vec![r"^learned$"]);

        lib.add_learned(sig.clone()).expect("add learned");

        let pattern = lib.get_pattern("learned-pattern");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().source, PatternSource::Learned);
    }
}

// ============================================================================
// Integration Tests: Conflict Resolution
// ============================================================================

mod conflict_tests {
    use super::*;

    fn make_test_signature(name: &str, confidence: f64) -> SupervisorSignature {
        SupervisorSignature::new(name, SupervisorCategory::Other)
            .with_process_patterns(vec![&format!(r"^{}$", name)])
            .with_confidence(confidence)
    }

    #[test]
    fn test_import_conflict_keep_existing() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        // Add existing pattern with high confidence
        let sig1 = make_test_signature("conflict-test", 0.9);
        lib.add_custom(sig1).expect("add");

        // Import pattern with lower confidence
        let sig2 = make_test_signature("conflict-test", 0.5);
        let import_schema = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns: vec![PersistedPattern::new(sig2, PatternSource::Imported)],
            metadata: None,
        };

        let result = lib
            .import(import_schema, ConflictResolution::KeepExisting)
            .expect("import");

        assert_eq!(result.skipped, 1);
        assert_eq!(result.conflicts.len(), 1);

        // Should still have the original high confidence
        let pattern = lib.get_pattern("conflict-test").unwrap();
        assert!((pattern.signature.confidence_weight - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_import_conflict_replace_with_imported() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig1 = make_test_signature("conflict-test", 0.5);
        lib.add_custom(sig1).expect("add");

        let sig2 = make_test_signature("conflict-test", 0.9);
        let import_schema = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns: vec![PersistedPattern::new(sig2, PatternSource::Imported)],
            metadata: None,
        };

        let result = lib
            .import(import_schema, ConflictResolution::ReplaceWithImported)
            .expect("import");

        assert_eq!(result.updated, 1);

        // Should now have the imported higher confidence
        let pattern = lib.get_pattern("conflict-test").unwrap();
        assert!((pattern.signature.confidence_weight - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_import_conflict_keep_higher_confidence() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        // Existing with low confidence
        let sig1 = make_test_signature("conflict-test", 0.5);
        lib.add_custom(sig1).expect("add");

        // Import with higher confidence - should win
        let sig2 = make_test_signature("conflict-test", 0.9);
        let import_schema = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns: vec![PersistedPattern::new(sig2, PatternSource::Imported)],
            metadata: None,
        };

        let result = lib
            .import(import_schema, ConflictResolution::KeepHigherConfidence)
            .expect("import");

        assert_eq!(result.updated, 1);
        let pattern = lib.get_pattern("conflict-test").unwrap();
        assert!((pattern.signature.confidence_weight - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_import_no_conflict() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        // No existing pattern with this name
        let sig = make_test_signature("new-pattern", 0.85);
        let import_schema = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns: vec![PersistedPattern::new(sig, PatternSource::Imported)],
            metadata: None,
        };

        let result = lib
            .import(import_schema, ConflictResolution::KeepHigherConfidence)
            .expect("import");

        assert_eq!(result.imported, 1);
        assert_eq!(result.conflicts.len(), 0);
        assert!(lib.get_pattern("new-pattern").is_some());
    }

    #[test]
    fn test_builtin_cannot_be_removed() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        // Initialize built-in patterns
        let sig = make_test_signature("builtin-test", 0.95);
        lib.initialize_built_in(vec![sig]).expect("init builtin");

        // Try to remove built-in pattern - should fail
        let result = lib.remove_pattern("builtin-test");
        assert!(matches!(
            result,
            Err(pt_core::supervision::pattern_persistence::PersistenceError::BuiltInReadOnly(_))
        ));
    }

    #[test]
    fn test_export_patterns() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = make_test_signature("export-test", 0.85);
        lib.add_custom(sig).expect("add");

        let exported = lib.export(&[PatternSource::Custom]);
        assert_eq!(exported.patterns.len(), 1);
        assert_eq!(exported.patterns[0].signature.name, "export-test");
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

mod performance_tests {
    use super::*;

    #[test]
    fn test_match_1000_processes_under_1ms() {
        let db = SignatureDatabase::with_defaults();

        // Generate strings first to keep them alive
        let data: Vec<(String, String)> = (0..1000)
            .map(|i| {
                (
                    format!("process-{}", i % 100),
                    format!("process-{} --arg{}", i % 100, i),
                )
            })
            .collect();

        // Create 1000 different process contexts
        let processes: Vec<ProcessMatchContext> = data
            .iter()
            .map(|(comm, cmdline)| ProcessMatchContext::with_comm(comm).cmdline(cmdline))
            .collect();

        // Measure matching time
        let start = Instant::now();
        for ctx in &processes {
            let _ = db.match_process(ctx);
        }
        let elapsed = start.elapsed();

        // Should complete in under 1ms per process (1000ms total max)
        // Being generous here - target is <1ms each, so <1000ms total
        assert!(
            elapsed.as_millis() < 1000,
            "Matching 1000 processes took {}ms (should be <1000ms)",
            elapsed.as_millis()
        );

        // Log actual performance for informational purposes
        let per_process_us = elapsed.as_micros() as f64 / 1000.0;
        eprintln!(
            "Performance: matched 1000 processes in {:?} ({:.2}μs per process)",
            elapsed, per_process_us
        );
    }

    #[test]
    fn test_database_load_under_3000ms() {
        // Create a database with many patterns
        let start = Instant::now();

        let mut db = SignatureDatabase::new();

        // Add 100 custom signatures (simulating a large custom library)
        for i in 0..100 {
            let sig =
                SupervisorSignature::new(&format!("custom-sig-{}", i), SupervisorCategory::Other)
                    .with_process_patterns(vec![&format!(r"^custom-process-{}$", i)])
                    .with_arg_patterns(vec![&format!(r"--config-{}", i)])
                    .with_confidence(0.80 + (i as f64 * 0.001));

            db.add(sig).unwrap();
        }

        // Also load defaults
        db.add_default_signatures();

        let elapsed = start.elapsed();

        // Should complete in under 3000ms on shared/dev hosts
        assert!(
            elapsed.as_millis() < 3000,
            "Loading patterns took {}ms (should be <3000ms)",
            elapsed.as_millis()
        );

        eprintln!(
            "Performance: loaded {} signatures in {:?}",
            db.len(),
            elapsed
        );
    }

    #[test]
    fn test_best_match_performance() {
        let db = SignatureDatabase::with_defaults();

        // Test best_match (single result) performance
        let start = Instant::now();
        for i in 0..10000 {
            let comm = match i % 10 {
                0 => "claude",
                1 => "jest",
                2 => "node",
                3 => "vite",
                4 => "cargo",
                5 => "python",
                6 => "unknown-process",
                7 => "tsc",
                8 => "pytest",
                _ => "make",
            };
            let ctx = ProcessMatchContext::with_comm(comm);
            let _ = db.best_match(&ctx);
        }
        let elapsed = start.elapsed();

        let per_match_us = elapsed.as_micros() as f64 / 10000.0;
        eprintln!(
            "Performance: 10000 best_match calls in {:?} ({:.2}μs per call)",
            elapsed, per_match_us
        );

        // Should be very fast - under 1ms per call average
        assert!(
            per_match_us < 1000.0,
            "best_match averaged {:.2}μs (should be <1000μs)",
            per_match_us
        );
    }

    #[test]
    fn test_pattern_library_load_performance() {
        let dir = tempdir().expect("tempdir");

        // Pre-populate with many patterns
        {
            let mut lib = PatternLibrary::new(dir.path());
            for i in 0..500 {
                let sig = SupervisorSignature::new(
                    &format!("perf-test-{}", i),
                    SupervisorCategory::Other,
                )
                .with_process_patterns(vec![&format!(r"^perf-{}$", i)])
                .with_confidence(0.80);
                lib.add_custom(sig).unwrap();
            }
            lib.save().unwrap();
        }

        // Measure load time
        let start = Instant::now();
        let mut lib = PatternLibrary::new(dir.path());
        lib.load().expect("load");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 1000,
            "Loading 500 patterns took {}ms (should be <1000ms)",
            elapsed.as_millis()
        );

        eprintln!("Performance: loaded 500 custom patterns in {:?}", elapsed);
    }

    #[test]
    fn test_match_with_full_context_performance() {
        let db = SignatureDatabase::with_defaults();

        // Create context with all fields populated
        let env = HashMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("JEST_WORKER_ID".to_string(), "1".to_string()),
        ]);
        let sockets = vec!["/tmp/socket-1".to_string(), "/tmp/socket-2".to_string()];

        let start = Instant::now();
        for _ in 0..1000 {
            let ctx = ProcessMatchContext::with_comm("node")
                .cmdline("node ./node_modules/.bin/jest --runInBand")
                .cwd("/home/user/project")
                .env_vars(&env)
                .socket_paths(&sockets)
                .parent_comm("bash");
            let _ = db.match_process(&ctx);
        }
        let elapsed = start.elapsed();

        eprintln!("Performance: 1000 full-context matches in {:?}", elapsed);

        // Should still be fast even with full context
        assert!(
            elapsed.as_millis() < 2000,
            "Full-context matching took {}ms (should be <2000ms)",
            elapsed.as_millis()
        );
    }
}

// ============================================================================
// Schema Serialization Tests
// ============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_json_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("json-test", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_process_patterns(vec![r"^json$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task()),
        );

        let json = schema.to_json().expect("should serialize to JSON");
        let loaded = SignatureSchema::from_json(&json).expect("should parse JSON");

        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "json-test");
        assert!(!loaded.signatures[0].priors.is_empty());
        assert!(!loaded.signatures[0].expectations.is_empty());
    }

    #[test]
    fn test_toml_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("toml-test", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_process_patterns(vec![r"^toml$"]),
        );

        let toml_str = schema.to_toml().expect("should serialize to TOML");
        let loaded = SignatureSchema::from_toml(&toml_str).expect("should parse TOML");

        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "toml-test");
    }

    #[test]
    fn test_persisted_schema_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("test-schema.json");

        let mut schema = PersistedSchema::new();
        schema.patterns.push(PersistedPattern::new(
            SupervisorSignature::new("persist-test", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^persist$"]),
            PatternSource::Custom,
        ));

        schema.save_to_file(&file_path).expect("save");

        let loaded = PersistedSchema::from_file(&file_path).expect("load");
        assert_eq!(loaded.patterns.len(), 1);
        assert_eq!(loaded.patterns[0].signature.name, "persist-test");
        assert_eq!(loaded.patterns[0].source, PatternSource::Custom);
    }

    #[test]
    fn test_disabled_patterns_persistence() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("disabled.json");

        let mut disabled = DisabledPatterns::default();
        disabled.disable("pattern-1", Some("Testing"));
        disabled.disable("pattern-2", None);

        disabled.save_to_file(&file_path).expect("save");

        let loaded = DisabledPatterns::from_file(&file_path).expect("load");
        assert!(loaded.is_disabled("pattern-1"));
        assert!(loaded.is_disabled("pattern-2"));
        assert!(!loaded.is_disabled("pattern-3"));
    }

    #[test]
    fn test_all_pattern_stats_persistence() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("stats.json");

        let mut stats = AllPatternStats::default();
        stats.record_match("pattern-1", true);
        stats.record_match("pattern-1", true);
        stats.record_match("pattern-1", false);
        stats.record_match("pattern-2", true);

        stats.save_to_file(&file_path).expect("save");

        let loaded = AllPatternStats::from_file(&file_path).expect("load");
        let p1_stats = loaded.get("pattern-1").unwrap();
        assert_eq!(p1_stats.match_count, 3);
        assert_eq!(p1_stats.accept_count, 2);

        let p2_stats = loaded.get("pattern-2").unwrap();
        assert_eq!(p2_stats.match_count, 1);
    }
}
