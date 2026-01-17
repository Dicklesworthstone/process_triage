//! Configuration loading and validation for pt-core.
//!
//! This module handles:
//! - Loading priors.json and policy.json files
//! - Config resolution order (CLI > env > XDG > defaults)
//! - Schema validation (shape/type checking via serde)
//! - Semantic validation (probability sums, positive params)
//! - Config snapshot generation for session artifacts

// Re-export types from pt-config
pub use pt_config::policy;
pub use pt_config::priors;

pub use policy::Policy;
pub use priors::Priors;

pub use pt_config::validate::ValidationError;
use pt_config::validate::{validate_policy, validate_priors};

// Re-export preset types
pub use pt_config::preset::{get_preset, list_presets, PresetError, PresetInfo, PresetName};

use std::path::PathBuf;
use thiserror::Error;

/// Schema version for configuration files.
pub const CONFIG_SCHEMA_VERSION: &str = "1.0.0";

/// Default XDG config directory name.
const CONFIG_DIR_NAME: &str = "process_triage";

/// Errors that can occur during config loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    NotFound { path: PathBuf },

    #[error("Invalid JSON in config file {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Schema validation failed for {path}: {message}")]
    SchemaError { path: PathBuf, message: String },

    #[error("Semantic validation failed: {0}")]
    ValidationError(#[from] ValidationError),

    #[error("I/O error reading {path}: {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Schema version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },
}

/// Resolved configuration with provenance information.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// The loaded priors configuration.
    pub priors: Priors,
    /// Path to the priors file (None if using defaults).
    pub priors_path: Option<PathBuf>,
    /// SHA-256 hash of the priors file content (None if using defaults).
    pub priors_hash: Option<String>,

    /// The loaded policy configuration.
    pub policy: Policy,
    /// Path to the policy file (None if using defaults).
    pub policy_path: Option<PathBuf>,
    /// SHA-256 hash of the policy file content (None if using defaults).
    pub policy_hash: Option<String>,

    /// The config directory used for resolution.
    pub config_dir: PathBuf,
}

impl ResolvedConfig {
    /// Create a config snapshot for session artifacts.
    pub fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            priors_path: self.priors_path.clone(),
            priors_hash: self.priors_hash.clone(),
            priors_schema_version: self.priors.schema_version.clone(),
            policy_path: self.policy_path.clone(),
            policy_hash: self.policy_hash.clone(),
            policy_schema_version: self.policy.schema_version.clone(),
            config_dir: self.config_dir.clone(),
        }
    }
}

/// Config snapshot for session artifacts/telemetry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigSnapshot {
    pub priors_path: Option<PathBuf>,
    pub priors_hash: Option<String>,
    pub priors_schema_version: String,
    pub policy_path: Option<PathBuf>,
    pub policy_hash: Option<String>,
    pub policy_schema_version: String,
    pub config_dir: PathBuf,
}

/// Configuration resolution options.
#[derive(Debug, Default)]
pub struct ConfigOptions {
    /// Explicit config directory (highest priority).
    pub config_dir: Option<PathBuf>,
    /// Explicit priors file path.
    pub priors_path: Option<PathBuf>,
    /// Explicit policy file path.
    pub policy_path: Option<PathBuf>,
}

/// Load configuration with the standard resolution order.
///
/// Resolution order (highest to lowest priority):
/// 1. Explicit CLI flags (via ConfigOptions)
/// 2. Environment variables (PROCESS_TRIAGE_CONFIG)
/// 3. XDG config home (~/.config/process_triage/)
/// 4. Built-in defaults
pub fn load_config(options: &ConfigOptions) -> Result<ResolvedConfig, ConfigError> {
    let config_dir = resolve_config_dir(options)?;

    // Load priors
    let (priors, priors_path, priors_hash) = load_priors(&config_dir, &options.priors_path)?;

    // Load policy
    let (policy, policy_path, policy_hash) = load_policy(&config_dir, &options.policy_path)?;

    // Validate the configuration semantically
    validate_priors(&priors)?;
    validate_policy(&policy)?;

    Ok(ResolvedConfig {
        priors,
        priors_path,
        priors_hash,
        policy,
        policy_path,
        policy_hash,
        config_dir,
    })
}

/// Resolve the config directory using the standard resolution order.
fn resolve_config_dir(options: &ConfigOptions) -> Result<PathBuf, ConfigError> {
    // 1. Explicit option
    if let Some(dir) = &options.config_dir {
        return Ok(dir.clone());
    }

    // 2. Environment variable
    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_CONFIG") {
        return Ok(PathBuf::from(dir));
    }

    // 3. XDG config home
    let xdg_config = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        });

    Ok(xdg_config.join(CONFIG_DIR_NAME))
}

/// Load priors configuration.
fn load_priors(
    config_dir: &std::path::Path,
    explicit_path: &Option<PathBuf>,
) -> Result<(Priors, Option<PathBuf>, Option<String>), ConfigError> {
    // Try explicit path first
    if let Some(path) = explicit_path {
        let (priors, hash) = load_priors_from_file(path)?;
        return Ok((priors, Some(path.clone()), Some(hash)));
    }

    // Try config directory
    let default_path = config_dir.join("priors.json");
    if default_path.exists() {
        let (priors, hash) = load_priors_from_file(&default_path)?;
        return Ok((priors, Some(default_path), Some(hash)));
    }

    // Fall back to defaults
    Ok((Priors::default(), None, None))
}

/// Load policy configuration.
fn load_policy(
    config_dir: &std::path::Path,
    explicit_path: &Option<PathBuf>,
) -> Result<(Policy, Option<PathBuf>, Option<String>), ConfigError> {
    // Try explicit path first
    if let Some(path) = explicit_path {
        let (policy, hash) = load_policy_from_file(path)?;
        return Ok((policy, Some(path.clone()), Some(hash)));
    }

    // Try config directory
    let default_path = config_dir.join("policy.json");
    if default_path.exists() {
        let (policy, hash) = load_policy_from_file(&default_path)?;
        return Ok((policy, Some(default_path), Some(hash)));
    }

    // Fall back to defaults
    Ok((Policy::default(), None, None))
}

/// Load priors from a specific file.
fn load_priors_from_file(path: &PathBuf) -> Result<(Priors, String), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
        path: path.clone(),
        source: e,
    })?;

    let hash = compute_hash(&content);

    let priors: Priors = serde_json::from_str(&content).map_err(|e| ConfigError::ParseError {
        path: path.clone(),
        source: e,
    })?;

    // Check schema version
    if priors.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::VersionMismatch {
            expected: CONFIG_SCHEMA_VERSION.to_string(),
            actual: priors.schema_version.clone(),
        });
    }

    Ok((priors, hash))
}

/// Load policy from a specific file.
fn load_policy_from_file(path: &PathBuf) -> Result<(Policy, String), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
        path: path.clone(),
        source: e,
    })?;

    let hash = compute_hash(&content);

    let policy: Policy = serde_json::from_str(&content).map_err(|e| ConfigError::ParseError {
        path: path.clone(),
        source: e,
    })?;

    // Check schema version
    if policy.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::VersionMismatch {
            expected: CONFIG_SCHEMA_VERSION.to_string(),
            actual: policy.schema_version.clone(),
        });
    }

    Ok((policy, hash))
}

/// Compute SHA-256 hash of content (simplified - uses built-in hasher for now).
fn compute_hash(content: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Create ConfigOptions pointing to an empty/nonexistent directory.
    /// This avoids race conditions from modifying environment variables.
    fn empty_config_options() -> ConfigOptions {
        // Use a temp directory that definitely has no config files
        let temp_dir = env::temp_dir().join("pt-core-test-config-nonexistent");
        ConfigOptions {
            config_dir: Some(temp_dir),
            priors_path: None,
            policy_path: None,
        }
    }

    #[test]
    fn test_default_config_loads() {
        // Use explicit config_dir to avoid env var race conditions
        let options = empty_config_options();
        // This should work with defaults when no config files exist
        let result = load_config(&options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_snapshot_serializes() {
        let options = empty_config_options();
        let config = load_config(&options).unwrap();
        let snapshot = config.snapshot();
        let json = serde_json::to_string(&snapshot);
        assert!(json.is_ok());
    }
}
