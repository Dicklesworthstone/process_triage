//! Redaction policy configuration.
//!
//! Defines the policy for how different field classes should be redacted,
//! including custom rules and detection patterns.

use crate::{Action, FieldClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Schema version for the policy file.
pub const POLICY_SCHEMA_VERSION: &str = "1.0.0";

/// Redaction policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Default export profile.
    #[serde(default = "default_profile")]
    pub default_profile: ExportProfile,

    /// Hash truncation bytes (default 8 = 16 hex chars).
    #[serde(default = "default_truncation_bytes")]
    pub hash_truncation_bytes: usize,

    /// Per-field-class rules.
    #[serde(default)]
    pub field_rules: BTreeMap<String, FieldRule>,

    /// Whether secret detection is enabled.
    #[serde(default = "default_true")]
    pub detection_enabled: bool,

    /// Entropy threshold for high-entropy detection.
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Custom detection patterns.
    #[serde(default)]
    pub detection_patterns: Vec<DetectionPattern>,

    /// Custom rules for specific patterns.
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

fn default_schema_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

fn default_profile() -> ExportProfile {
    ExportProfile::Safe
}

fn default_truncation_bytes() -> usize {
    8
}

fn default_true() -> bool {
    true
}

fn default_entropy_threshold() -> f64 {
    4.5
}

/// Export profile for controlling redaction level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExportProfile {
    /// Aggregate stats only - for public sharing.
    Minimal,
    /// Evidence + features, strings redacted/hashed - for team sharing.
    #[default]
    Safe,
    /// Raw evidence with explicit allowlist - for support tickets.
    Forensic,
}

impl ExportProfile {
    /// Parse from string.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(ExportProfile::Minimal),
            "safe" => Some(ExportProfile::Safe),
            "forensic" => Some(ExportProfile::Forensic),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExportProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ExportProfile::Minimal => "minimal",
            ExportProfile::Safe => "safe",
            ExportProfile::Forensic => "forensic",
        };
        write!(f, "{}", s)
    }
}

/// Rule for a specific field class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Action to apply.
    pub action: Action,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Override for specific profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_overrides: Option<BTreeMap<String, Action>>,
}

impl FieldRule {
    /// Create a simple rule with just an action.
    pub fn new(action: Action) -> Self {
        Self {
            action,
            description: None,
            profile_overrides: None,
        }
    }

    /// Get the action for a specific profile.
    pub fn action_for_profile(&self, profile: ExportProfile) -> Action {
        if let Some(ref overrides) = self.profile_overrides {
            let profile_str = profile.to_string();
            if let Some(action) = overrides.get(&profile_str) {
                return *action;
            }
        }
        self.action
    }
}

/// Custom detection pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionPattern {
    /// Name of the pattern.
    pub name: String,

    /// Regex pattern.
    pub pattern: String,

    /// Action to apply when matched.
    pub action: Action,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Custom rule for specific value patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Name of the rule.
    pub name: String,

    /// Field classes this rule applies to.
    #[serde(default)]
    pub field_classes: Vec<String>,

    /// Regex pattern to match.
    pub pattern: String,

    /// Action to apply.
    pub action: Action,

    /// Priority (higher = checked first).
    #[serde(default)]
    pub priority: i32,
}

impl RedactionPolicy {
    /// Create a new policy with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load policy from a file.
    pub fn load<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let policy: RedactionPolicy = serde_json::from_str(&content)?;
        Ok(policy)
    }

    /// Save policy to a file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, content)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Get the action for a field class.
    pub fn action_for(&self, field_class: FieldClass) -> Action {
        self.action_for_profile(field_class, self.default_profile)
    }

    /// Get the action for a field class and profile.
    pub fn action_for_profile(&self, field_class: FieldClass, profile: ExportProfile) -> Action {
        let class_str = field_class.to_string();

        // Check for explicit rule
        if let Some(rule) = self.field_rules.get(&class_str) {
            return rule.action_for_profile(profile);
        }

        // Fall back to default action for the field class
        field_class.default_action()
    }

    /// Set the action for a field class.
    pub fn set_action(&mut self, field_class: FieldClass, action: Action) {
        let class_str = field_class.to_string();
        self.field_rules.insert(class_str, FieldRule::new(action));
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        let mut field_rules = BTreeMap::new();

        // Default rules from spec
        field_rules.insert("cmdline".to_string(), FieldRule::new(Action::NormalizeHash));
        field_rules.insert("cmd".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert(
            "cmdline_arg".to_string(),
            FieldRule::new(Action::DetectAction),
        );
        field_rules.insert("env_name".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert("env_value".to_string(), FieldRule::new(Action::Redact));
        field_rules.insert(
            "path_home".to_string(),
            FieldRule::new(Action::NormalizeHash),
        );
        field_rules.insert("path_tmp".to_string(), FieldRule::new(Action::Normalize));
        field_rules.insert("path_system".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert("path_project".to_string(), FieldRule::new(Action::Hash));
        field_rules.insert("hostname".to_string(), FieldRule::new(Action::Hash));
        field_rules.insert("ip_address".to_string(), FieldRule::new(Action::Hash));
        field_rules.insert("url".to_string(), FieldRule::new(Action::NormalizeHash));
        field_rules.insert("url_host".to_string(), FieldRule::new(Action::Hash));
        field_rules.insert("url_path".to_string(), FieldRule::new(Action::Normalize));
        field_rules.insert(
            "url_credentials".to_string(),
            FieldRule::new(Action::Redact),
        );
        field_rules.insert("username".to_string(), FieldRule::new(Action::Hash));
        field_rules.insert("uid".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert("pid".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert("port".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert("container_id".to_string(), FieldRule::new(Action::Truncate));
        field_rules.insert("systemd_unit".to_string(), FieldRule::new(Action::Allow));
        field_rules.insert(
            "free_text".to_string(),
            FieldRule::new(Action::DetectAction),
        );

        // Explicit local-detail allowlist for forensic exports. Structured
        // export still checks secret values and hard-redacts environment and
        // credential fields before consulting these profile overrides.
        // Full URLs retain their credential-removing action.
        for class in [
            FieldClass::Cmdline,
            FieldClass::PathHome,
            FieldClass::PathTmp,
            FieldClass::PathProject,
            FieldClass::Hostname,
            FieldClass::IpAddress,
            FieldClass::UrlHost,
            FieldClass::UrlPath,
            FieldClass::Username,
            FieldClass::ContainerId,
        ] {
            if let Some(rule) = field_rules.get_mut(&class.to_string()) {
                rule.profile_overrides = Some(BTreeMap::from([(
                    ExportProfile::Forensic.to_string(),
                    Action::Allow,
                )]));
            }
        }

        Self {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            default_profile: ExportProfile::Safe,
            hash_truncation_bytes: 8,
            field_rules,
            detection_enabled: true,
            entropy_threshold: 4.5,
            detection_patterns: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = RedactionPolicy::default();
        assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION);
        assert_eq!(policy.default_profile, ExportProfile::Safe);
        assert_eq!(policy.hash_truncation_bytes, 8);
        assert!(policy.detection_enabled);
    }

    #[test]
    fn independent_default_policies_serialize_identically() {
        let serialized = |policy: &RedactionPolicy| {
            serde_json::to_vec(&serde_json::to_value(policy).unwrap()).unwrap()
        };
        let expected = serialized(&RedactionPolicy::default());
        for _ in 0..8 {
            assert_eq!(serialized(&RedactionPolicy::default()), expected);
        }
    }

    #[test]
    fn equivalent_rule_and_profile_order_preserves_serialized_policy() {
        let left: RedactionPolicy = serde_json::from_str(
            r#"{"field_rules":{"hostname":{"action":"hash","profile_overrides":{"safe":"redact","forensic":"allow"}},"cmd":{"action":"allow"}}}"#,
        )
        .unwrap();
        let mut right: RedactionPolicy = serde_json::from_str(
            r#"{"field_rules":{"cmd":{"action":"allow"},"hostname":{"profile_overrides":{"forensic":"allow","safe":"redact"},"action":"hash"}}}"#,
        )
        .unwrap();
        let serialized = |policy: &RedactionPolicy| {
            serde_json::to_vec(&serde_json::to_value(policy).unwrap()).unwrap()
        };
        assert_eq!(serialized(&left), serialized(&right));
        assert_eq!(
            left.action_for_profile(FieldClass::Hostname, ExportProfile::Safe),
            Action::Redact
        );
        assert_eq!(
            right.action_for_profile(FieldClass::Hostname, ExportProfile::Forensic),
            Action::Allow
        );
        right.set_action(FieldClass::Cmd, Action::Redact);
        assert_ne!(serialized(&left), serialized(&right));
        assert_eq!(right.action_for(FieldClass::Cmd), Action::Redact);
    }

    #[test]
    fn test_action_for_field_class() {
        let policy = RedactionPolicy::default();

        assert_eq!(policy.action_for(FieldClass::Cmd), Action::Allow);
        assert_eq!(policy.action_for(FieldClass::EnvValue), Action::Redact);
        assert_eq!(
            policy.action_for(FieldClass::Cmdline),
            Action::NormalizeHash
        );
        assert_eq!(policy.action_for(FieldClass::Hostname), Action::Hash);
    }

    #[test]
    fn default_forensic_allowlist_preserves_sharing_actions_and_credential_guards() {
        let policy = RedactionPolicy::default();
        for (class, sharing_action) in [
            (FieldClass::Cmdline, Action::NormalizeHash),
            (FieldClass::PathHome, Action::NormalizeHash),
            (FieldClass::PathTmp, Action::Normalize),
            (FieldClass::PathProject, Action::Hash),
            (FieldClass::Hostname, Action::Hash),
            (FieldClass::IpAddress, Action::Hash),
            (FieldClass::UrlHost, Action::Hash),
            (FieldClass::UrlPath, Action::Normalize),
            (FieldClass::Username, Action::Hash),
            (FieldClass::ContainerId, Action::Truncate),
        ] {
            assert_eq!(
                policy.action_for_profile(class, ExportProfile::Forensic),
                Action::Allow,
                "forensic local detail {class}"
            );
            for profile in [ExportProfile::Safe, ExportProfile::Minimal] {
                assert_eq!(
                    policy.action_for_profile(class, profile),
                    sharing_action,
                    "sharing action for {class} in {profile}"
                );
            }
        }
        for profile in [
            ExportProfile::Forensic,
            ExportProfile::Safe,
            ExportProfile::Minimal,
        ] {
            for class in [FieldClass::CmdlineArg, FieldClass::FreeText] {
                assert_eq!(
                    policy.action_for_profile(class, profile),
                    Action::DetectAction
                );
            }
            for class in [FieldClass::EnvValue, FieldClass::UrlCredentials] {
                assert_eq!(policy.action_for_profile(class, profile), Action::Redact);
            }
            assert_eq!(
                policy.action_for_profile(FieldClass::Url, profile),
                Action::NormalizeHash
            );
        }
        assert!(policy.detection_enabled);
    }

    #[test]
    fn default_forensic_structured_export_preserves_matchers_but_redacts_secrets() {
        let engine = crate::RedactionEngine::with_key(
            RedactionPolicy::default(),
            crate::KeyMaterial::from_bytes([0; 32], "test"),
        );
        let input = serde_json::json!({
            "cmd": "python /home/local-user/work.py",
            "cwd": "/home/local-user/project",
            "hostname": "local-worker-host",
            "username": "local-user",
            "cmd_pattern": "^worker-(red|blue)$",
            "patterns": {"process_names": ["^local-worker$"]},
            "args": ["--verbose", "--token=local-secret", "AKIAIOSFODNN7EXAMPLE"],
            "environment": {"HOME": "/home/local-user"},
            "environment_vars": {"PRIVATE_TOKEN": "AKIAIOSFODNN7EXAMPLE"},
            "env_value": "private-environment-value",
            "password": "private-password-value"
        });
        let forensic = engine.redact_json_for_export(&input, ExportProfile::Forensic);
        for field in ["cmd", "cwd", "hostname", "username", "cmd_pattern"] {
            assert_eq!(forensic[field], input[field], "forensic field {field}");
        }
        assert_ne!(forensic["patterns"], input["patterns"]);
        let signatures = serde_json::json!({
            "schema_version": 2,
            "signatures": [{
                "name": "local-worker", "category": "other", "confidence_weight": 0.8,
                "patterns": {
                    "process_names": ["^local-worker$"],
                    "arg_patterns": ["^--verbose$"],
                    "working_dir_patterns": ["^/home/local-user/project$"],
                    "parent_patterns": ["^local-parent$"],
                    "socket_paths": ["/home/local-user/worker.sock"],
                    "pid_files": ["/home/local-user/worker.pid"],
                    "environment_vars": {"PRIVATE_TOKEN": "private-environment-value"}
                },
                "notes": "private note"
            }],
            "metadata": {"description": "private description"}
        });
        let exported = engine.redact_json_for_export(&signatures, ExportProfile::Forensic);
        assert_eq!(
            exported["signatures"][0]["name"],
            signatures["signatures"][0]["name"]
        );
        for field in [
            "process_names",
            "arg_patterns",
            "working_dir_patterns",
            "parent_patterns",
            "socket_paths",
            "pid_files",
        ] {
            assert_eq!(
                exported["signatures"][0]["patterns"][field],
                signatures["signatures"][0]["patterns"][field]
            );
        }
        assert_ne!(
            exported["signatures"][0]["notes"],
            signatures["signatures"][0]["notes"]
        );
        assert_ne!(
            exported["metadata"]["description"],
            signatures["metadata"]["description"]
        );
        assert!(!exported.to_string().contains("private-environment-value"));
        let mut restrictive_policy = RedactionPolicy::default();
        restrictive_policy.set_action(FieldClass::Cmdline, Action::Redact);
        let restrictive = crate::RedactionEngine::with_key(
            restrictive_policy,
            crate::KeyMaterial::from_bytes([0; 32], "test"),
        )
        .redact_json_for_export(&signatures, ExportProfile::Forensic);
        assert_eq!(restrictive["signatures"][0]["name"], "[REDACTED]");
        assert_eq!(
            restrictive["signatures"][0]["patterns"]["process_names"][0],
            "[REDACTED]"
        );
        for matcher in [
            serde_json::json!("opaque-matcher"),
            serde_json::json!([["opaque-matcher"]]),
            serde_json::json!(["opaque-matcher", 1]),
        ] {
            let mut malformed = signatures.clone();
            malformed["signatures"][0]["patterns"]["process_names"] = matcher;
            let exported = engine.redact_json_for_export(&malformed, ExportProfile::Forensic);
            assert!(!exported.to_string().contains("opaque-matcher"));
            assert_ne!(
                exported["signatures"][0]["name"],
                malformed["signatures"][0]["name"]
            );
        }
        for malformed in [
            serde_json::json!({"schema_version": "2", "signatures": signatures["signatures"]}),
            serde_json::json!({"schema_version": 2, "signatures": signatures["signatures"], "extra": 1}),
            serde_json::json!({"summary": signatures}),
        ] {
            let exported = engine.redact_json_for_export(&malformed, ExportProfile::Forensic);
            assert!(!exported.to_string().contains("^local-worker$"));
        }
        let mut malformed = signatures.clone();
        malformed["signatures"][0]["category"] = serde_json::json!("unknown-category");
        let exported = engine.redact_json_for_export(&malformed, ExportProfile::Forensic);
        assert!(!exported.to_string().contains("^local-worker$"));
        assert_eq!(forensic["args"][0], "--verbose");
        assert_eq!(forensic["args"][1], "[REDACTED]");
        assert_eq!(forensic["args"][2], "[REDACTED]");
        assert_eq!(forensic["environment"], "[REDACTED]");
        let environment_vars = forensic["environment_vars"].as_object().unwrap();
        assert_eq!(environment_vars.len(), 1);
        assert!(!environment_vars.contains_key("PRIVATE_TOKEN"));
        assert!(environment_vars.values().all(|value| value == "[REDACTED]"));
        let encoded = forensic.to_string();
        for secret in [
            "AKIAIOSFODNN7EXAMPLE",
            "local-secret",
            "private-environment-value",
            "private-password-value",
        ] {
            assert!(!encoded.contains(secret), "forensic secret {secret}");
        }
        let safe = engine.redact_json_for_export(&input, ExportProfile::Safe);
        for field in ["cmd", "cwd", "hostname", "username", "cmd_pattern"] {
            assert_ne!(safe[field], input[field], "safe field {field}");
        }
        assert_ne!(
            safe["patterns"]["process_names"][0],
            input["patterns"]["process_names"][0]
        );
    }

    #[test]
    fn default_forensic_value_apis_preserve_text_without_bypassing_secret_detection() {
        let engine = crate::RedactionEngine::with_key(
            RedactionPolicy::default(),
            crate::KeyMaterial::from_bytes([0; 32], "test"),
        );
        for (value, class) in [
            ("python /home/local-user/work.py", FieldClass::Cmdline),
            ("--verbose", FieldClass::CmdlineArg),
        ] {
            assert_eq!(
                engine
                    .redact_with_profile(value, class, ExportProfile::Forensic)
                    .output,
                value
            );
        }
        for (value, class) in [
            ("private note", FieldClass::FreeText),
            ("opaque-credential", FieldClass::CmdlineArg),
        ] {
            assert_ne!(
                engine
                    .redact_with_profile(value, class, ExportProfile::Forensic)
                    .output,
                value
            );
        }
        let forensic_policy = RedactionPolicy {
            default_profile: ExportProfile::Forensic,
            ..RedactionPolicy::default()
        };
        let default_forensic = crate::RedactionEngine::with_key(
            forensic_policy,
            crate::KeyMaterial::from_bytes([0; 32], "test"),
        );
        for class in [
            FieldClass::Cmdline,
            FieldClass::CmdlineArg,
            FieldClass::FreeText,
        ] {
            for secret in [
                "AKIAIOSFODNN7EXAMPLE",
                "--token=local-secret",
                "--TOKEN=local-secret",
                "--PASSWORD=local-secret",
                "--API-KEY=local-secret",
                "--SECRET=local-secret",
            ] {
                let explicit = engine.redact_with_profile(secret, class, ExportProfile::Forensic);
                assert!(!explicit.output.contains(secret), "explicit {class} secret");
                let implicit = default_forensic.redact(secret, class);
                assert!(!implicit.output.contains(secret), "default {class} secret");
            }
        }
        let disabled = crate::RedactionEngine::with_key(
            RedactionPolicy {
                detection_enabled: false,
                ..RedactionPolicy::default()
            },
            crate::KeyMaterial::from_bytes([0; 32], "test"),
        );
        for secret in [
            "AKIAIOSFODNN7EXAMPLE",
            "--TOKEN=local-secret",
            "--PASSWORD=local-secret",
            "--API-KEY=local-secret",
            "--SECRET=local-secret",
        ] {
            assert!(!disabled
                .redact_with_profile(secret, FieldClass::Cmdline, ExportProfile::Forensic)
                .output
                .contains(secret));
            let input = serde_json::json!({"command": format!("worker {secret}")});
            assert!(!disabled
                .redact_json_for_export(&input, ExportProfile::Forensic)
                .to_string()
                .contains(secret));
        }
    }

    #[test]
    fn test_set_action() {
        let mut policy = RedactionPolicy::default();

        // Override default
        policy.set_action(FieldClass::Hostname, Action::Redact);
        assert_eq!(policy.action_for(FieldClass::Hostname), Action::Redact);
    }

    #[test]
    fn test_export_profile_parsing() {
        assert_eq!(
            ExportProfile::parse_str("minimal"),
            Some(ExportProfile::Minimal)
        );
        assert_eq!(ExportProfile::parse_str("safe"), Some(ExportProfile::Safe));
        assert_eq!(
            ExportProfile::parse_str("forensic"),
            Some(ExportProfile::Forensic)
        );
        assert_eq!(ExportProfile::parse_str("SAFE"), Some(ExportProfile::Safe));
        assert_eq!(ExportProfile::parse_str("invalid"), None);
    }

    #[test]
    fn test_profile_overrides() {
        let mut policy = RedactionPolicy::default();

        // Create a rule with profile override
        let mut overrides = BTreeMap::new();
        overrides.insert("forensic".to_string(), Action::Allow);

        policy.field_rules.insert(
            "hostname".to_string(),
            FieldRule {
                action: Action::Hash,
                description: None,
                profile_overrides: Some(overrides),
            },
        );

        // Default profile uses base action
        assert_eq!(
            policy.action_for_profile(FieldClass::Hostname, ExportProfile::Safe),
            Action::Hash
        );

        // Forensic uses override
        assert_eq!(
            policy.action_for_profile(FieldClass::Hostname, ExportProfile::Forensic),
            Action::Allow
        );
    }

    #[test]
    fn test_policy_serialization() {
        let policy = RedactionPolicy::default();
        let json = serde_json::to_string_pretty(&policy).unwrap();

        // Should be valid JSON
        let parsed: RedactionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, policy.schema_version);
        assert_eq!(parsed.default_profile, policy.default_profile);
    }
}
