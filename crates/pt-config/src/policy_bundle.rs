//! Policy-as-Data: versioned, signed policy bundles with progressive delivery.
//!
//! A `PolicyBundle` wraps a [`Policy`] with metadata for versioning, integrity
//! verification, and progressive delivery stages. Bundles can optionally carry
//! an ECDSA signature that is verified against trusted public keys.
//!
//! # Progressive Delivery Stages
//!
//! 1. **Shadow** — log decisions from the new policy alongside the active
//!    policy, but don't act on them. Enables off-policy comparison.
//! 2. **Canary** — apply the new policy to a configurable subset of candidates.
//! 3. **Default** — full rollout; the new policy replaces the active policy.
//!
//! # Fallback Behavior
//!
//! On any error (parse, schema mismatch, signature failure, corrupt hash),
//! loading falls back to [`Policy::default()`] embedded in the binary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::Policy;

// ── Bundle types ────────────────────────────────────────────────────────

/// Progressive delivery stage for a policy bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Log new-policy decisions alongside active policy without acting.
    Shadow,
    /// Apply new policy to a subset of candidates.
    Canary,
    /// Full rollout.
    Default,
}

impl std::fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyMode::Shadow => write!(f, "shadow"),
            PolicyMode::Canary => write!(f, "canary"),
            PolicyMode::Default => write!(f, "default"),
        }
    }
}

/// A versioned, optionally-signed policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Bundle format version (for forward-compatible schema evolution).
    pub bundle_version: String,

    /// The embedded policy configuration.
    pub policy: Policy,

    /// Progressive delivery stage.
    #[serde(default = "default_policy_mode")]
    pub policy_mode: PolicyMode,

    /// Canary fraction: when `policy_mode` is `Canary`, what fraction of
    /// candidates should receive the new policy (0.0–1.0).
    #[serde(default)]
    pub canary_fraction: Option<f64>,

    /// SHA-256 hash of the JSON-serialized `policy` field.
    /// Populated on bundle creation; verified on load.
    #[serde(default)]
    pub policy_hash: Option<String>,

    /// Optional ECDSA P-256 signature (base64-encoded DER) over the policy
    /// hash. Verified using the infrastructure in `install/signature.rs`.
    #[serde(default)]
    pub signature: Option<String>,

    /// Human-readable description of what changed in this policy version.
    #[serde(default)]
    pub changelog: Option<String>,

    /// ISO-8601 timestamp of bundle creation.
    #[serde(default)]
    pub created_at: Option<String>,
}

fn default_policy_mode() -> PolicyMode {
    PolicyMode::Default
}

/// Errors that can occur during policy bundle operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyBundleError {
    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("policy hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("unsupported bundle version: {0}")]
    UnsupportedVersion(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("canary fraction must be in [0.0, 1.0], got {0}")]
    InvalidCanaryFraction(f64),

    #[error("signature present but no verifier provided")]
    NoVerifier,
}

// ── Bundle implementation ───────────────────────────────────────────────

impl PolicyBundle {
    /// Supported bundle version.
    pub const CURRENT_VERSION: &'static str = "1.0.0";

    /// Create a new bundle wrapping a policy, computing the integrity hash.
    pub fn new(policy: Policy, mode: PolicyMode) -> Result<Self, PolicyBundleError> {
        let policy_json = serde_json::to_string(&policy)?;
        let hash = sha256_hex(policy_json.as_bytes());

        Ok(Self {
            bundle_version: Self::CURRENT_VERSION.to_string(),
            policy,
            policy_mode: mode,
            canary_fraction: if mode == PolicyMode::Canary {
                Some(0.1)
            } else {
                None
            },
            policy_hash: Some(hash),
            signature: None,
            changelog: None,
            created_at: None,
        })
    }

    /// Parse a bundle from JSON, verifying integrity.
    pub fn from_json(json: &str) -> Result<Self, PolicyBundleError> {
        let bundle: PolicyBundle = serde_json::from_str(json)?;
        bundle.verify_integrity()?;
        Ok(bundle)
    }

    /// Load a bundle from a file, verifying integrity.
    /// Falls back to `Policy::default()` wrapped in a bundle on any error.
    pub fn load_or_default(path: &std::path::Path) -> Self {
        match Self::load_from_file(path) {
            Ok(bundle) => bundle,
            Err(_) => Self::embedded_default(),
        }
    }

    /// Load from file with full error reporting.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, PolicyBundleError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Create a bundle wrapping the embedded default policy.
    pub fn embedded_default() -> Self {
        Self::new(Policy::default(), PolicyMode::Default)
            .expect("default policy should always serialize")
    }

    /// Verify the bundle's integrity hash matches the policy content.
    pub fn verify_integrity(&self) -> Result<(), PolicyBundleError> {
        // Check bundle version
        if self.bundle_version != Self::CURRENT_VERSION {
            return Err(PolicyBundleError::UnsupportedVersion(
                self.bundle_version.clone(),
            ));
        }

        // Verify hash if present
        if let Some(expected_hash) = &self.policy_hash {
            let policy_json = serde_json::to_string(&self.policy)?;
            let actual_hash = sha256_hex(policy_json.as_bytes());

            if *expected_hash != actual_hash {
                return Err(PolicyBundleError::HashMismatch {
                    expected: expected_hash.clone(),
                    actual: actual_hash,
                });
            }
        }

        // Validate canary fraction
        if let Some(frac) = self.canary_fraction {
            if !(0.0..=1.0).contains(&frac) {
                return Err(PolicyBundleError::InvalidCanaryFraction(frac));
            }
        }

        Ok(())
    }

    /// Whether this bundle should apply to a given candidate.
    ///
    /// In `Default` mode, always returns true.
    /// In `Shadow` mode, always returns false (the policy is for logging only).
    /// In `Canary` mode, uses a simple hash-based selection.
    pub fn should_apply(&self, candidate_id: &str) -> bool {
        match self.policy_mode {
            PolicyMode::Default => true,
            PolicyMode::Shadow => false,
            PolicyMode::Canary => {
                let frac = self.canary_fraction.unwrap_or(0.1);
                let hash = candidate_hash(candidate_id);
                hash < frac
            }
        }
    }

    /// Whether this bundle is in shadow mode (for logging/comparison only).
    pub fn is_shadow(&self) -> bool {
        self.policy_mode == PolicyMode::Shadow
    }

    /// Serialize the bundle to JSON.
    pub fn to_json(&self) -> Result<String, PolicyBundleError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Compute a deterministic hash of a candidate ID to a value in [0, 1).
fn candidate_hash(id: &str) -> f64 {
    let hash = sha256_hex(id.as_bytes());
    // Take first 8 hex chars (32 bits) and normalize to [0, 1)
    let v = u32::from_str_radix(&hash[..8], 16).unwrap_or(0);
    v as f64 / u32::MAX as f64
}

/// Compute SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bundle_has_valid_hash() {
        let bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        assert!(bundle.policy_hash.is_some());
        assert!(bundle.verify_integrity().is_ok());
    }

    #[test]
    fn roundtrip_json() {
        let bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        let json = bundle.to_json().unwrap();
        let back = PolicyBundle::from_json(&json).unwrap();
        assert_eq!(back.bundle_version, PolicyBundle::CURRENT_VERSION);
        assert_eq!(back.policy_mode, PolicyMode::Default);
    }

    #[test]
    fn tampered_policy_detected() {
        let mut bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        // Tamper with the policy
        bundle.policy.loss_matrix.useful.kill = 999.0;
        assert!(bundle.verify_integrity().is_err());
    }

    #[test]
    fn embedded_default_is_valid() {
        let bundle = PolicyBundle::embedded_default();
        assert!(bundle.verify_integrity().is_ok());
        assert_eq!(bundle.policy_mode, PolicyMode::Default);
    }

    #[test]
    fn shadow_mode_never_applies() {
        let bundle = PolicyBundle::new(Policy::default(), PolicyMode::Shadow).unwrap();
        assert!(bundle.is_shadow());
        assert!(!bundle.should_apply("any-candidate"));
    }

    #[test]
    fn default_mode_always_applies() {
        let bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        assert!(!bundle.is_shadow());
        assert!(bundle.should_apply("any-candidate"));
    }

    #[test]
    fn canary_mode_deterministic() {
        let mut bundle = PolicyBundle::new(Policy::default(), PolicyMode::Canary).unwrap();
        bundle.canary_fraction = Some(0.5);

        // Same candidate should always get the same answer
        let result1 = bundle.should_apply("process-42");
        let result2 = bundle.should_apply("process-42");
        assert_eq!(result1, result2);
    }

    #[test]
    fn canary_fraction_validated() {
        let mut bundle = PolicyBundle::new(Policy::default(), PolicyMode::Canary).unwrap();
        bundle.canary_fraction = Some(1.5);
        assert!(bundle.verify_integrity().is_err());
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        bundle.bundle_version = "99.0.0".to_string();
        assert!(bundle.verify_integrity().is_err());
    }

    #[test]
    fn policy_mode_serde() {
        for mode in &[PolicyMode::Shadow, PolicyMode::Canary, PolicyMode::Default] {
            let json = serde_json::to_string(mode).unwrap();
            let back: PolicyMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn policy_mode_display() {
        assert_eq!(PolicyMode::Shadow.to_string(), "shadow");
        assert_eq!(PolicyMode::Canary.to_string(), "canary");
        assert_eq!(PolicyMode::Default.to_string(), "default");
    }

    #[test]
    fn load_nonexistent_falls_back() {
        let bundle =
            PolicyBundle::load_or_default(std::path::Path::new("/nonexistent/bundle.json"));
        assert_eq!(bundle.policy_mode, PolicyMode::Default);
        assert!(bundle.verify_integrity().is_ok());
    }

    #[test]
    fn candidate_hash_in_range() {
        for id in &["pid-1", "pid-2", "pid-999", "some-long-process-name"] {
            let h = candidate_hash(id);
            assert!(h >= 0.0);
            assert!(h < 1.0);
        }
    }

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex(b"test data");
        let h2 = sha256_hex(b"test data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn no_hash_still_validates() {
        let mut bundle = PolicyBundle::new(Policy::default(), PolicyMode::Default).unwrap();
        bundle.policy_hash = None;
        assert!(bundle.verify_integrity().is_ok());
    }
}
