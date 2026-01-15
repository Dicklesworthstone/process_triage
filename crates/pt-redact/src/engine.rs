//! Main redaction engine.
//!
//! The RedactionEngine is the central component that applies the redaction policy
//! to values, using canonicalization, hashing, and secret detection.

use crate::{
    Action, Canonicalizer, FieldClass, KeyManager, KeyMaterial, RedactionPolicy,
    Result, SecretDetector,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of a redaction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedValue {
    /// The redacted output string.
    pub output: String,

    /// The action that was applied.
    pub action_applied: Action,

    /// Whether the value was modified.
    pub was_modified: bool,

    /// For forensic reference: hash of the original value (if hashing was used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
}

impl RedactedValue {
    /// Create a new redacted value.
    pub fn new(output: String, action: Action, was_modified: bool) -> Self {
        Self {
            output,
            action_applied: action,
            was_modified,
            original_hash: None,
        }
    }

    /// Create a value that was allowed through unchanged.
    pub fn allowed(value: String) -> Self {
        Self::new(value, Action::Allow, false)
    }

    /// Create a fully redacted value.
    pub fn redacted() -> Self {
        Self::new("[REDACTED]".to_string(), Action::Redact, true)
    }
}

/// The main redaction engine.
pub struct RedactionEngine {
    /// The redaction policy.
    policy: RedactionPolicy,

    /// Key material for hashing.
    key: KeyMaterial,

    /// Canonicalizer for normalization.
    canonicalizer: Canonicalizer,

    /// Secret detector.
    detector: SecretDetector,
}

impl RedactionEngine {
    /// Create a new redaction engine with the given policy.
    ///
    /// Generates a new random key for hashing.
    pub fn new(policy: RedactionPolicy) -> Result<Self> {
        let key = KeyMaterial::generate("k1")?;
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Ok(Self {
            policy,
            key,
            canonicalizer,
            detector,
        })
    }

    /// Create a redaction engine with an existing key manager.
    pub fn with_key_manager(policy: RedactionPolicy, key_manager: &KeyManager) -> Result<Self> {
        let key = key_manager.active_key()?;
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Ok(Self {
            policy,
            key,
            canonicalizer,
            detector,
        })
    }

    /// Create a redaction engine with explicit key material.
    pub fn with_key(policy: RedactionPolicy, key: KeyMaterial) -> Self {
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Self {
            policy,
            key,
            canonicalizer,
            detector,
        }
    }

    /// Load a redaction engine from config files.
    pub fn load<P: AsRef<Path>>(policy_path: P, key_path: P) -> Result<Self> {
        let policy = RedactionPolicy::load(policy_path)?;
        let key_manager = KeyManager::load(key_path)?;
        Self::with_key_manager(policy, &key_manager)
    }

    /// Apply redaction to a value based on its field class.
    pub fn redact(&self, value: &str, field_class: FieldClass) -> RedactedValue {
        // Get the action for this field class
        let mut action = self.policy.action_for(field_class);

        // If action is detect+action, run detection first
        if action == Action::DetectAction {
            action = self.detect_action(value, field_class);
        }

        self.apply_action(value, action)
    }

    /// Apply redaction with a specific export profile.
    pub fn redact_with_profile(
        &self,
        value: &str,
        field_class: FieldClass,
        profile: crate::ExportProfile,
    ) -> RedactedValue {
        let mut action = self.policy.action_for_profile(field_class, profile);

        if action == Action::DetectAction {
            action = self.detect_action(value, field_class);
        }

        self.apply_action(value, action)
    }

    /// Get the current policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy.schema_version
    }

    /// Get the current key ID.
    pub fn key_id(&self) -> &str {
        &self.key.key_id
    }

    /// Get a reference to the policy.
    pub fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Detect what action to apply based on content analysis.
    fn detect_action(&self, value: &str, field_class: FieldClass) -> Action {
        // Skip detection if disabled
        if !self.policy.detection_enabled {
            // Fall back to a safe default
            return Action::Hash;
        }

        // Check for secrets
        if let Some(secret_type) = self.detector.detect(value) {
            return secret_type.recommended_action();
        }

        // Apply field-class-specific defaults
        match field_class {
            FieldClass::CmdlineArg => {
                // Check if it looks like a flag vs value
                if value.starts_with('-') {
                    // Flags are usually safe
                    Action::Allow
                } else if self.detector.is_high_entropy(value) {
                    Action::Redact
                } else {
                    Action::Hash
                }
            }
            FieldClass::FreeText => {
                // Free text: check for secrets, otherwise hash
                Action::Hash
            }
            _ => {
                // Default to the field class's default action
                field_class.default_action()
            }
        }
    }

    /// Apply a specific action to a value.
    fn apply_action(&self, value: &str, action: Action) -> RedactedValue {
        match action {
            Action::Allow => RedactedValue::allowed(value.to_string()),

            Action::Redact => RedactedValue::redacted(),

            Action::Hash => {
                let hash = self.key.hash(value, self.policy.hash_truncation_bytes);
                let mut result = RedactedValue::new(hash.clone(), Action::Hash, true);
                result.original_hash = Some(hash);
                result
            }

            Action::Normalize => {
                let normalized = self.canonicalizer.canonicalize(value);
                RedactedValue::new(normalized, Action::Normalize, true)
            }

            Action::NormalizeHash => {
                let normalized = self.canonicalizer.canonicalize(value);
                let hash = self.key.hash(&normalized, self.policy.hash_truncation_bytes);
                let mut result = RedactedValue::new(hash.clone(), Action::NormalizeHash, true);
                result.original_hash = Some(hash);
                result
            }

            Action::Truncate => {
                let truncated = truncate_value(value, 6);
                RedactedValue::new(truncated, Action::Truncate, true)
            }

            Action::DetectAction => {
                // This should have been resolved before calling apply_action,
                // but fall back to safe hash if we get here
                let hash = self.key.hash(value, self.policy.hash_truncation_bytes);
                RedactedValue::new(hash, Action::Hash, true)
            }
        }
    }

    /// Redact a path value.
    pub fn redact_path(&self, path: &str) -> RedactedValue {
        // Classify the path
        let field_class = classify_path(path);
        self.redact(path, field_class)
    }

    /// Redact an environment variable.
    pub fn redact_env(&self, name: &str, value: &str) -> (RedactedValue, RedactedValue) {
        let name_result = self.redact(name, FieldClass::EnvName);

        // Check if the name suggests a secret
        if let Some(_secret_type) = self.detector.detect_env(name, value) {
            return (name_result, RedactedValue::redacted());
        }

        let value_result = self.redact(value, FieldClass::EnvValue);
        (name_result, value_result)
    }

    /// Redact a command line argument.
    pub fn redact_arg(&self, arg: &str, prev_arg: Option<&str>) -> RedactedValue {
        // Check context-aware detection
        if let Some(secret_type) = self.detector.detect_arg(arg, prev_arg) {
            let action = secret_type.recommended_action();
            return self.apply_action(arg, action);
        }

        self.redact(arg, FieldClass::CmdlineArg)
    }
}

/// Truncate a value, keeping prefix and suffix.
fn truncate_value(value: &str, keep_chars: usize) -> String {
    if value.len() <= keep_chars * 2 {
        return value.to_string();
    }

    let prefix: String = value.chars().take(keep_chars).collect();
    let suffix: String = value.chars().rev().take(keep_chars).collect::<String>().chars().rev().collect();

    format!("{}...{}", prefix, suffix)
}

/// Classify a path into a field class.
fn classify_path(path: &str) -> FieldClass {
    // Check for home directory
    if let Ok(home) = std::env::var("HOME") {
        if path.starts_with(&home) {
            return FieldClass::PathHome;
        }
    }

    // Check for temp directories
    if path.starts_with("/tmp") || path.starts_with("/var/tmp") {
        return FieldClass::PathTmp;
    }

    // Check for system paths
    if path.starts_with("/usr")
        || path.starts_with("/etc")
        || path.starts_with("/bin")
        || path.starts_with("/sbin")
        || path.starts_with("/lib")
    {
        return FieldClass::PathSystem;
    }

    // Default to project path
    FieldClass::PathProject
}

/// Canary test strings that should NEVER appear in output.
pub const CANARY_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "password123!@#",
    "super_secret_token",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> RedactionEngine {
        let policy = RedactionPolicy::default();
        let key = KeyMaterial::from_bytes([0u8; 32], "test");
        RedactionEngine::with_key(policy, key)
    }

    #[test]
    fn test_redact_allow() {
        let engine = test_engine();
        let result = engine.redact("/usr/bin/python3", FieldClass::PathSystem);

        assert_eq!(result.output, "/usr/bin/python3");
        assert_eq!(result.action_applied, Action::Allow);
        assert!(!result.was_modified);
    }

    #[test]
    fn test_redact_redact() {
        let engine = test_engine();
        let result = engine.redact("secret_value", FieldClass::EnvValue);

        assert_eq!(result.output, "[REDACTED]");
        assert_eq!(result.action_applied, Action::Redact);
        assert!(result.was_modified);
    }

    #[test]
    fn test_redact_hash() {
        let engine = test_engine();
        let result = engine.redact("myhost.example.com", FieldClass::Hostname);

        assert!(result.output.starts_with("[HASH:test:"));
        assert!(result.output.ends_with("]"));
        assert_eq!(result.action_applied, Action::Hash);
        assert!(result.was_modified);
    }

    #[test]
    fn test_hash_stability() {
        let engine = test_engine();

        let result1 = engine.redact("same_value", FieldClass::Hostname);
        let result2 = engine.redact("same_value", FieldClass::Hostname);

        assert_eq!(result1.output, result2.output);
    }

    #[test]
    fn test_different_values_different_hashes() {
        let engine = test_engine();

        let result1 = engine.redact("value1", FieldClass::Hostname);
        let result2 = engine.redact("value2", FieldClass::Hostname);

        assert_ne!(result1.output, result2.output);
    }

    #[test]
    fn test_redact_normalize() {
        let engine = test_engine();
        let result = engine.redact("/tmp/pytest-123/test.log", FieldClass::PathTmp);

        // Should be normalized (contains [TMP] or similar)
        assert!(result.was_modified);
        assert_eq!(result.action_applied, Action::Normalize);
    }

    #[test]
    fn test_truncate() {
        let truncated = truncate_value("abcdefghijklmnopqrstuvwxyz", 6);
        assert_eq!(truncated, "abcdef...uvwxyz");
    }

    #[test]
    fn test_truncate_short_value() {
        let truncated = truncate_value("short", 6);
        assert_eq!(truncated, "short");
    }

    #[test]
    fn test_detect_action_secret() {
        let engine = test_engine();
        let result = engine.redact("--token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", FieldClass::CmdlineArg);

        // Should detect the GitHub token and redact
        assert_eq!(result.output, "[REDACTED]");
    }

    #[test]
    fn test_detect_action_flag() {
        let engine = test_engine();
        let result = engine.redact("--verbose", FieldClass::CmdlineArg);

        // Flags starting with - should be allowed
        assert_eq!(result.output, "--verbose");
        assert_eq!(result.action_applied, Action::Allow);
    }

    #[test]
    fn test_canary_never_leaks() {
        let engine = test_engine();

        for canary in CANARY_SECRETS {
            let result = engine.redact(canary, FieldClass::CmdlineArg);
            assert!(
                !result.output.contains(canary),
                "Canary '{}' leaked in output: {}",
                canary,
                result.output
            );
        }
    }

    #[test]
    fn test_env_redaction() {
        let engine = test_engine();

        // Secret env var should be redacted
        let (_name, value) = engine.redact_env("AWS_SECRET_KEY", "my_secret");
        assert_eq!(value.output, "[REDACTED]");

        // Normal env var still redacted by default policy
        let (_name, value) = engine.redact_env("PATH", "/usr/bin");
        assert_eq!(value.output, "[REDACTED]"); // env_value defaults to redact
    }

    #[test]
    fn test_path_classification() {
        assert_eq!(classify_path("/tmp/test"), FieldClass::PathTmp);
        assert_eq!(classify_path("/usr/bin/test"), FieldClass::PathSystem);
        assert_eq!(classify_path("/var/tmp/test"), FieldClass::PathTmp);
    }

    #[test]
    fn test_arg_context_detection() {
        let engine = test_engine();

        // Argument after --password should be redacted
        let result = engine.redact_arg("secret123", Some("--password"));
        assert_eq!(result.output, "[REDACTED]");

        // Normal argument without sensitive context
        let result = engine.redact_arg("value", Some("--config"));
        // Should be hashed, not redacted
        assert!(result.output.starts_with("[HASH:") || result.output == "value");
    }

    #[test]
    fn test_policy_version() {
        let engine = test_engine();
        assert_eq!(engine.policy_version(), "1.0.0");
    }

    #[test]
    fn test_key_id() {
        let engine = test_engine();
        assert_eq!(engine.key_id(), "test");
    }
}
