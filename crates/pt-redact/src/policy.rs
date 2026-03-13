//! Redaction policy configuration.
//!
//! Defines the policy for how different field classes should be redacted,
//! including custom rules and detection patterns.

use crate::{Action, FieldClass};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub field_rules: HashMap<String, FieldRule>,

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
    pub profile_overrides: Option<HashMap<String, Action>>,
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
        let mut field_rules = HashMap::new();

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
        let mut overrides = HashMap::new();
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
