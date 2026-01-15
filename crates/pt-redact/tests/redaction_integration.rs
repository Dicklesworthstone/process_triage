//! Integration tests for pt-redact.
//!
//! These tests verify:
//! - Canary strings never leak through any redaction path
//! - Hash consistency across runs with the same key
//! - Redaction policy versioning is tracked
//! - Sensitive patterns are properly detected and redacted

use pt_redact::{
    Action, Canonicalizer, ExportProfile, FieldClass, KeyMaterial, RedactionEngine,
    RedactionPolicy, SecretDetector,
};

/// Canary secrets that must NEVER appear in any output.
/// These cover common secret formats across various providers.
const CANARY_SECRETS: &[&str] = &[
    // AWS
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    // GitHub
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    // OpenAI/Anthropic
    "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    // Generic secrets
    "password123!@#",
    "super_secret_token",
    "api_key_12345678901234567890",
    // Database credentials
    "postgres://admin:secretpass@localhost/db",
    "mysql://root:p4ssw0rd@127.0.0.1:3306/mydb",
    // JWT (truncated for test)
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    // SSH-like patterns
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    // Slack tokens - using obfuscated prefix to avoid GitHub secret scanners
    // The detector matches xox[baprs]- patterns; we concatenate to avoid scanner
    // but the test still verifies the pattern is detected
];

/// Additional sensitive patterns embedded in realistic contexts.
/// Note: These must match patterns that the detector actually recognizes.
const EMBEDDED_SECRETS: &[(&str, &str)] = &[
    // Command line with GitHub token (ghp_ pattern is detected)
    (
        "curl -H 'Authorization: Bearer ghp_realtoken1234567890abcdefghijklmn' https://api.github.com",
        "ghp_realtoken1234567890abcdefghijklmn",
    ),
    // --password= argument (RE_PASSWORD_ARG matches)
    (
        "mysql --password=my_super_secret_password_123",
        "my_super_secret_password_123",
    ),
    // URL with credentials (RE_CONNECTION_STRING matches)
    (
        "postgres://user:password123@api.example.com/db",
        "password123",
    ),
    // --token argument pattern (RE_TOKEN_ARG matches)
    (
        "docker login --token abc123secrettoken456",
        "abc123secrettoken456",
    ),
];

// ============================================================================
// Canary Leak Tests
// ============================================================================

#[test]
fn test_canary_secrets_never_leak_cmdline() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    for canary in CANARY_SECRETS {
        // Test direct value
        let result = engine.redact(canary, FieldClass::CmdlineArg);
        assert!(
            !result.output.contains(canary),
            "Canary '{}' leaked in cmdline output: {}",
            canary,
            result.output
        );

        // Test embedded in --password= pattern (which is detected by RE_PASSWORD_ARG)
        let embedded = format!("--password={}", canary);
        let result = engine.redact(&embedded, FieldClass::CmdlineArg);
        assert!(
            !result.output.contains(canary),
            "Embedded canary '{}' leaked in cmdline output: {}",
            canary,
            result.output
        );

        // Test embedded in --token pattern (which is detected by RE_TOKEN_ARG)
        let embedded = format!("--token {}", canary);
        let result = engine.redact(&embedded, FieldClass::CmdlineArg);
        assert!(
            !result.output.contains(canary),
            "Token-embedded canary '{}' leaked in cmdline output: {}",
            canary,
            result.output
        );
    }
}

#[test]
fn test_canary_secrets_never_leak_env_value() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    for canary in CANARY_SECRETS {
        let (_, value_result) = engine.redact_env("SECRET_VAR", canary);
        assert!(
            !value_result.output.contains(canary),
            "Canary '{}' leaked in env value output: {}",
            canary,
            value_result.output
        );
    }
}

#[test]
fn test_canary_secrets_never_leak_free_text() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    for canary in CANARY_SECRETS {
        let result = engine.redact(canary, FieldClass::FreeText);
        assert!(
            !result.output.contains(canary),
            "Canary '{}' leaked in free text output: {}",
            canary,
            result.output
        );
    }
}

#[test]
fn test_embedded_secrets_detected_and_redacted() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    for (input, secret_part) in EMBEDDED_SECRETS {
        let result = engine.redact(input, FieldClass::CmdlineArg);
        assert!(
            !result.output.contains(secret_part),
            "Secret '{}' leaked from input '{}' in output: {}",
            secret_part,
            input,
            result.output
        );
    }
}

#[test]
fn test_all_export_profiles_block_secrets() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let profiles = [ExportProfile::Minimal, ExportProfile::Safe, ExportProfile::Forensic];

    for profile in profiles {
        for canary in CANARY_SECRETS {
            let result = engine.redact_with_profile(canary, FieldClass::CmdlineArg, profile);
            assert!(
                !result.output.contains(canary),
                "Canary '{}' leaked with profile {:?}: {}",
                canary,
                profile,
                result.output
            );
        }
    }
}

// ============================================================================
// Hash Consistency Tests
// ============================================================================

#[test]
fn test_hash_consistency_same_key() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([42u8; 32], "consistent-key");

    let engine1 = RedactionEngine::with_key(policy.clone(), key.clone());
    let engine2 = RedactionEngine::with_key(policy, key);

    let test_values = [
        "hostname.example.com",
        "/path/to/file",
        "user@domain.com",
        "192.168.1.100",
    ];

    for value in test_values {
        let result1 = engine1.redact(value, FieldClass::Hostname);
        let result2 = engine2.redact(value, FieldClass::Hostname);

        assert_eq!(
            result1.output, result2.output,
            "Hash mismatch for '{}': {} vs {}",
            value, result1.output, result2.output
        );
    }
}

#[test]
fn test_hash_consistency_across_field_classes() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    // Same value hashed multiple times should be consistent
    let value = "test_value_for_hashing";
    let hash1 = engine.redact(value, FieldClass::Hostname);
    let hash2 = engine.redact(value, FieldClass::Hostname);
    let hash3 = engine.redact(value, FieldClass::Hostname);

    assert_eq!(hash1.output, hash2.output);
    assert_eq!(hash2.output, hash3.output);
}

#[test]
fn test_different_keys_produce_different_hashes() {
    let policy = RedactionPolicy::default();

    let key1 = KeyMaterial::from_bytes([1u8; 32], "key1");
    let key2 = KeyMaterial::from_bytes([2u8; 32], "key2");

    let engine1 = RedactionEngine::with_key(policy.clone(), key1);
    let engine2 = RedactionEngine::with_key(policy, key2);

    let value = "same_value";
    let result1 = engine1.redact(value, FieldClass::Hostname);
    let result2 = engine2.redact(value, FieldClass::Hostname);

    assert_ne!(
        result1.output, result2.output,
        "Different keys should produce different hashes"
    );
}

#[test]
fn test_hash_determinism_property() {
    // Property: For any given (key, value), the hash must always be the same
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([99u8; 32], "determinism-test");
    let engine = RedactionEngine::with_key(policy, key);

    // Run multiple times to verify determinism
    let value = "deterministic_test_value_12345";
    let mut hashes = Vec::new();

    for _ in 0..100 {
        let result = engine.redact(value, FieldClass::Hostname);
        hashes.push(result.output);
    }

    let first = &hashes[0];
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(
            first, hash,
            "Hash inconsistency at iteration {}: {} vs {}",
            i, first, hash
        );
    }
}

// ============================================================================
// Redaction Policy Versioning Tests
// ============================================================================

#[test]
fn test_policy_version_is_tracked() {
    let policy = RedactionPolicy::default();
    let engine = RedactionEngine::new(policy).unwrap();

    let version = engine.policy_version();
    assert!(
        !version.is_empty(),
        "Policy version should not be empty"
    );
    assert!(
        version.contains('.'),
        "Policy version should be semver format: {}",
        version
    );
}

#[test]
fn test_key_id_is_tracked() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "tracked-key-id");
    let engine = RedactionEngine::with_key(policy, key);

    assert_eq!(engine.key_id(), "tracked-key-id");
}

#[test]
fn test_policy_version_in_default() {
    let policy = RedactionPolicy::default();
    assert_eq!(policy.schema_version, "1.0.0");
}

// ============================================================================
// Sensitive Pattern Detection Tests
// ============================================================================

#[test]
fn test_detector_finds_aws_keys() {
    let detector = SecretDetector::new();

    assert!(detector.detect("AKIAIOSFODNN7EXAMPLE").is_some());
    assert!(detector.detect("not_an_aws_key").is_none());
}

#[test]
fn test_detector_finds_github_tokens() {
    let detector = SecretDetector::new();

    // Various GitHub token formats
    let tokens = [
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ];

    for token in tokens {
        assert!(
            detector.detect(token).is_some(),
            "Should detect GitHub token: {}",
            token
        );
    }
}

#[test]
fn test_detector_finds_jwt() {
    let detector = SecretDetector::new();

    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(detector.detect(jwt).is_some());
}

#[test]
fn test_detector_finds_private_keys() {
    let detector = SecretDetector::new();

    let patterns = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
    ];

    for pattern in patterns {
        assert!(
            detector.detect(pattern).is_some(),
            "Should detect private key marker: {}",
            pattern
        );
    }
}

#[test]
fn test_detector_finds_database_urls() {
    let detector = SecretDetector::new();

    let urls = [
        "postgres://user:pass@localhost/db",
        "mysql://root:secret@127.0.0.1:3306/mydb",
        "mongodb://admin:password@cluster.mongodb.net/db",
    ];

    for url in urls {
        assert!(
            detector.detect(url).is_some(),
            "Should detect database URL with credentials: {}",
            url
        );
    }
}

#[test]
fn test_detector_finds_slack_tokens() {
    let detector = SecretDetector::new();

    // Construct Slack tokens at runtime to avoid GitHub secret scanner
    // The xox prefix plus b/p/a/r/s indicates Slack tokens
    let slack_prefixes = ["b", "p", "a", "r", "s"];
    for prefix_char in slack_prefixes {
        let token = format!("xox{}-123456789012-1234567890123-abcdefghijklmnopqrst", prefix_char);
        assert!(
            detector.detect(&token).is_some(),
            "Should detect Slack token with prefix: xox{}-",
            prefix_char
        );
    }
}

#[test]
fn test_detector_env_var_secret_names() {
    let detector = SecretDetector::new();

    // Names that indicate secrets
    let secret_names = [
        ("AWS_SECRET_KEY", "any_value"),
        ("DB_PASSWORD", "any_value"),
        ("API_TOKEN", "any_value"),
        ("PRIVATE_KEY", "any_value"),
        ("AUTH_SECRET", "any_value"),
    ];

    for (name, value) in secret_names {
        assert!(
            detector.detect_env(name, value).is_some(),
            "Should detect secret env var name: {}",
            name
        );
    }
}

#[test]
fn test_detector_arg_context_password() {
    let detector = SecretDetector::new();

    // Arguments after these specific flags should be detected
    // Note: Only these exact flags are implemented in detect_arg
    let password_flags = ["--password", "--token", "--api-key", "--apikey", "--secret"];

    for flag in password_flags {
        let result = detector.detect_arg("secret_value", Some(flag));
        assert!(
            result.is_some(),
            "Should detect argument after password flag: {}",
            flag
        );
    }
}

#[test]
fn test_high_entropy_detection() {
    let detector = SecretDetector::new();

    // High entropy strings should be flagged
    // Note: Strings must contain non-alphanumeric/underscore/dash chars AND have entropy > 4.5
    let high_entropy = [
        "aB3$cD4@eF5#gH6!iJ7%kL8^",
        "Xy9@Zw8#Vu7!Ts6$Rq5%Po4&",
        "abc123!@#XYZ789$%^def456",
    ];

    for s in high_entropy {
        assert!(
            detector.is_high_entropy(s),
            "Should detect high entropy string: {} (entropy: {})",
            s,
            detector.entropy(s)
        );
    }
}

#[test]
fn test_low_entropy_allowed() {
    let detector = SecretDetector::new();

    // Low entropy strings should not be flagged
    let low_entropy = [
        "aaaaaaaaaa",
        "1111111111",
        "hello",
        "test",
    ];

    for s in low_entropy {
        assert!(
            !detector.is_high_entropy(s),
            "Should not flag low entropy string: {}",
            s
        );
    }
}

// ============================================================================
// Canonicalization Tests
// ============================================================================

#[test]
fn test_canonicalizer_removes_pids() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("--pid 12345 --name test");
    assert!(!result.contains("12345"), "PID should be removed: {}", result);
    assert!(result.contains("[PID]"), "Should have PID placeholder: {}", result);
}

#[test]
fn test_canonicalizer_removes_ports() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("--port 8080 server start");
    assert!(!result.contains("8080"), "Port should be removed: {}", result);
    assert!(result.contains("[PORT]"), "Should have PORT placeholder: {}", result);
}

#[test]
fn test_canonicalizer_removes_uuids() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("session a1b2c3d4-e5f6-7890-abcd-ef1234567890 started");
    assert!(
        !result.contains("a1b2c3d4"),
        "UUID should be removed: {}",
        result
    );
    assert!(result.contains("[UUID]"), "Should have UUID placeholder: {}", result);
}

#[test]
fn test_canonicalizer_removes_timestamps() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("log at 2026-01-15T10:30:00Z message");
    assert!(
        !result.contains("2026-01-15"),
        "Timestamp should be removed: {}",
        result
    );
    assert!(
        result.contains("[TIMESTAMP]"),
        "Should have TIMESTAMP placeholder: {}",
        result
    );
}

#[test]
fn test_canonicalizer_normalizes_home_dir() {
    let canon = Canonicalizer::with_home_dir("/home/testuser");

    let result = canon.canonicalize("/home/testuser/projects/myapp");
    assert!(
        !result.contains("testuser"),
        "Username should be removed: {}",
        result
    );
    assert!(result.contains("[HOME]"), "Should have HOME placeholder: {}", result);
}

#[test]
fn test_canonicalizer_normalizes_tmp() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("/tmp/pytest-123/test.log");
    assert!(!result.contains("pytest-123"), "Tmp session should be normalized: {}", result);
}

#[test]
fn test_canonicalizer_removes_url_credentials() {
    let canon = Canonicalizer::new();

    let result = canon.canonicalize("https://user:secret@api.example.com/path");
    assert!(!result.contains("secret"), "URL credential should be removed: {}", result);
    assert!(result.contains("[CRED]"), "Should have CRED placeholder: {}", result);
}

// ============================================================================
// Field Class Action Tests
// ============================================================================

#[test]
fn test_system_paths_allowed() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let result = engine.redact("/usr/bin/python3", FieldClass::PathSystem);
    assert_eq!(result.action_applied, Action::Allow);
    assert_eq!(result.output, "/usr/bin/python3");
}

#[test]
fn test_env_values_redacted_by_default() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let (_, value_result) = engine.redact_env("SOME_VAR", "some_value");
    assert_eq!(value_result.output, "[REDACTED]");
}

#[test]
fn test_hostnames_hashed() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let result = engine.redact("myserver.example.com", FieldClass::Hostname);
    assert!(result.output.starts_with("[HASH:"));
    assert!(result.was_modified);
}

#[test]
fn test_tmp_paths_normalized() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let result = engine.redact("/tmp/session-abc/data.log", FieldClass::PathTmp);
    assert_eq!(result.action_applied, Action::Normalize);
}

// ============================================================================
// Integration: Full Workflow Tests
// ============================================================================

#[test]
fn test_full_cmdline_redaction_workflow() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "workflow-test");
    let engine = RedactionEngine::with_key(policy, key);

    // Simulate a realistic command line with mixed content
    let cmdline_parts = [
        "/usr/bin/python3",
        "script.py",
        "--database",
        "postgres://admin:secretpass@localhost/db",
        "--api-key",
        "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "--config",
        "/home/alice/.config/app.json",
        "--verbose",
    ];

    let mut redacted_parts = Vec::new();
    let mut prev_arg: Option<&str> = None;

    for arg in cmdline_parts {
        let result = engine.redact_arg(arg, prev_arg);
        redacted_parts.push(result.output);
        prev_arg = Some(arg);
    }

    let output = redacted_parts.join(" ");

    // Verify no sensitive data leaked
    assert!(!output.contains("secretpass"), "Password leaked: {}", output);
    assert!(!output.contains("sk-proj"), "API key leaked: {}", output);
    // Note: username in path might be redacted depending on HOME detection
}

#[test]
fn test_batch_env_redaction() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "batch-test");
    let engine = RedactionEngine::with_key(policy, key);

    let env_vars = [
        ("PATH", "/usr/bin:/bin"),
        ("HOME", "/home/testuser"),
        ("AWS_SECRET_KEY", "wJalrXUtnFEMI/EXAMPLE"),
        ("DATABASE_URL", "postgres://user:pass@localhost/db"),
        ("DEBUG", "true"),
    ];

    for (name, value) in env_vars {
        let (_, value_result) = engine.redact_env(name, value);

        // All env values should be redacted by default policy
        assert_eq!(
            value_result.output, "[REDACTED]",
            "Env var {} value should be redacted",
            name
        );
    }
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_empty_string_handling() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let result = engine.redact("", FieldClass::FreeText);
    // Empty string should not crash and should produce some output
    assert!(result.output.is_empty() || result.output.starts_with("["));
}

#[test]
fn test_unicode_handling() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    // Unicode content should be handled without panicking
    let unicode_inputs = [
        "日本語テスト",
        "emoji: 🔐🔑",
        "mixed: hello世界",
        "rtl: مرحبا",
    ];

    for input in unicode_inputs {
        let result = engine.redact(input, FieldClass::FreeText);
        // Should not panic and should produce some output
        assert!(!result.output.is_empty() || input.is_empty());
    }
}

#[test]
fn test_very_long_string_handling() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    // Very long string should be handled
    let long_string = "a".repeat(100_000);
    let result = engine.redact(&long_string, FieldClass::FreeText);

    // Should not panic
    assert!(!result.output.is_empty());
}

#[test]
fn test_special_characters_in_values() {
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([0u8; 32], "test");
    let engine = RedactionEngine::with_key(policy, key);

    let special_inputs = [
        "value with\nnewlines\nand\ttabs",
        "null\0byte",
        "backslash\\path",
        "quotes\"and'apostrophes",
        "brackets[and]{braces}(parens)",
    ];

    for input in special_inputs {
        let result = engine.redact(input, FieldClass::FreeText);
        // Should not panic
        let _ = result.output;
    }
}
