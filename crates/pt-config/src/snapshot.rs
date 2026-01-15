//! Configuration snapshots for session telemetry and reproducibility.
//!
//! A snapshot captures the exact configuration state at the start of a session,
//! allowing decisions to be audited and reproduced later.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::resolve::{ConfigPaths, ConfigSource};
use crate::{Policy, Priors};

/// A frozen snapshot of configuration state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// When this snapshot was taken.
    pub timestamp: DateTime<Utc>,

    /// Hostname where snapshot was taken.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Schema version of the configuration.
    pub schema_version: String,

    /// SHA-256 hash of the priors JSON content.
    #[serde(default)]
    pub priors_hash: Option<String>,

    /// Path where priors were loaded from.
    #[serde(default)]
    pub priors_path: Option<String>,

    /// Source of priors configuration.
    pub priors_source: String,

    /// SHA-256 hash of the policy JSON content.
    #[serde(default)]
    pub policy_hash: Option<String>,

    /// Path where policy was loaded from.
    #[serde(default)]
    pub policy_path: Option<String>,

    /// Source of policy configuration.
    pub policy_source: String,

    /// Combined hash of all config files (for quick comparison).
    pub combined_hash: String,

    /// Key configuration values for quick reference.
    pub summary: ConfigSummary,
}

/// Summary of key configuration values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    /// Class prior probabilities.
    pub class_priors: ClassPriorSummary,

    /// Whether robot mode is enabled.
    pub robot_mode_enabled: bool,

    /// Minimum posterior for robot mode.
    pub robot_min_posterior: f64,

    /// FDR control method.
    pub fdr_method: String,

    /// FDR alpha level.
    pub fdr_alpha: f64,

    /// Maximum kills per run.
    pub max_kills_per_run: u32,

    /// Number of protected patterns.
    pub protected_pattern_count: usize,
}

/// Summary of class prior probabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPriorSummary {
    pub useful: f64,
    pub useful_bad: f64,
    pub abandoned: f64,
    pub zombie: f64,
}

impl ConfigSnapshot {
    /// Create a new snapshot from loaded configuration.
    pub fn new(
        priors: Option<&Priors>,
        policy: Option<&Policy>,
        paths: &ConfigPaths,
        priors_json: Option<&str>,
        policy_json: Option<&str>,
    ) -> Self {
        let timestamp = Utc::now();
        let hostname = hostname::get().ok().map(|h| h.to_string_lossy().to_string());

        let priors_hash = priors_json.map(hash_content);
        let policy_hash = policy_json.map(hash_content);

        // Combined hash
        let combined = format!(
            "{}:{}",
            priors_hash.as_deref().unwrap_or("none"),
            policy_hash.as_deref().unwrap_or("none")
        );
        let combined_hash = hash_content(&combined);

        let summary = build_summary(priors, policy);

        ConfigSnapshot {
            timestamp,
            hostname,
            schema_version: crate::CONFIG_SCHEMA_VERSION.to_string(),
            priors_hash,
            priors_path: paths.priors.as_ref().map(|p| p.display().to_string()),
            priors_source: paths.priors_source.to_string(),
            policy_hash,
            policy_path: paths.policy.as_ref().map(|p| p.display().to_string()),
            policy_source: paths.policy_source.to_string(),
            combined_hash,
            summary,
        }
    }

    /// Create a snapshot with only defaults (no config files loaded).
    pub fn defaults_only() -> Self {
        let timestamp = Utc::now();
        let hostname = hostname::get().ok().map(|h| h.to_string_lossy().to_string());

        ConfigSnapshot {
            timestamp,
            hostname,
            schema_version: crate::CONFIG_SCHEMA_VERSION.to_string(),
            priors_hash: None,
            priors_path: None,
            priors_source: ConfigSource::BuiltinDefault.to_string(),
            policy_hash: None,
            policy_path: None,
            policy_source: ConfigSource::BuiltinDefault.to_string(),
            combined_hash: hash_content("none:none"),
            summary: ConfigSummary::defaults(),
        }
    }

    /// Serialize snapshot to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize snapshot from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Check if this snapshot matches another (same config).
    pub fn matches(&self, other: &ConfigSnapshot) -> bool {
        self.combined_hash == other.combined_hash
    }

    /// Get a short identifier for this snapshot (first 12 chars of hash).
    pub fn short_id(&self) -> &str {
        &self.combined_hash[..12.min(self.combined_hash.len())]
    }
}

impl ConfigSummary {
    /// Create a summary with default values.
    pub fn defaults() -> Self {
        ConfigSummary {
            class_priors: ClassPriorSummary {
                useful: 0.7,
                useful_bad: 0.1,
                abandoned: 0.15,
                zombie: 0.05,
            },
            robot_mode_enabled: false,
            robot_min_posterior: 0.99,
            fdr_method: "bh".to_string(),
            fdr_alpha: 0.05,
            max_kills_per_run: 5,
            protected_pattern_count: 0,
        }
    }
}

/// Build summary from loaded configuration.
fn build_summary(priors: Option<&Priors>, policy: Option<&Policy>) -> ConfigSummary {
    let class_priors = priors
        .map(|p| ClassPriorSummary {
            useful: p.classes.useful.prior_prob,
            useful_bad: p.classes.useful_bad.prior_prob,
            abandoned: p.classes.abandoned.prior_prob,
            zombie: p.classes.zombie.prior_prob,
        })
        .unwrap_or(ClassPriorSummary {
            useful: 0.7,
            useful_bad: 0.1,
            abandoned: 0.15,
            zombie: 0.05,
        });

    let (robot_mode_enabled, robot_min_posterior, fdr_method, fdr_alpha, max_kills_per_run, protected_pattern_count) =
        policy
            .map(|p| {
                (
                    p.robot_mode.enabled,
                    p.robot_mode.min_posterior,
                    format!("{:?}", p.fdr_control.method).to_lowercase(),
                    p.fdr_control.alpha,
                    p.guardrails.max_kills_per_run,
                    p.guardrails.protected_patterns.len(),
                )
            })
            .unwrap_or((false, 0.99, "bh".to_string(), 0.05, 5, 0));

    ConfigSummary {
        class_priors,
        robot_mode_enabled,
        robot_min_posterior,
        fdr_method,
        fdr_alpha,
        max_kills_per_run,
        protected_pattern_count,
    }
}

/// Hash content with SHA-256 and return hex string.
fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_snapshot() {
        let snapshot = ConfigSnapshot::defaults_only();
        assert_eq!(snapshot.schema_version, crate::CONFIG_SCHEMA_VERSION);
        assert!(snapshot.priors_hash.is_none());
        assert!(snapshot.policy_hash.is_none());
        assert!(!snapshot.summary.robot_mode_enabled);
    }

    #[test]
    fn test_snapshot_short_id() {
        let snapshot = ConfigSnapshot::defaults_only();
        assert_eq!(snapshot.short_id().len(), 12);
    }

    #[test]
    fn test_snapshot_matches() {
        let s1 = ConfigSnapshot::defaults_only();
        let s2 = ConfigSnapshot::defaults_only();
        // Combined hashes should be the same for defaults
        assert!(s1.matches(&s2));
    }

    #[test]
    fn test_hash_content() {
        let hash1 = hash_content("test");
        let hash2 = hash_content("test");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_snapshot_json_roundtrip() {
        let snapshot = ConfigSnapshot::defaults_only();
        let json = snapshot.to_json().unwrap();
        let restored = ConfigSnapshot::from_json(&json).unwrap();
        assert!(snapshot.matches(&restored));
    }
}
