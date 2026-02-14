//! Plugin manifest format (TOML-based).
//!
//! Each plugin lives in its own directory under `~/.config/process_triage/plugins/`
//! and declares its capabilities via a `plugin.toml` manifest.
//!
//! # Example manifest
//!
//! ```toml
//! [plugin]
//! name = "prometheus-metrics"
//! version = "0.1.0"
//! api_version = "1"
//! description = "Fetch process metrics from Prometheus"
//! command = "./fetch_metrics.sh"
//!
//! [plugin.timeouts]
//! invoke_ms = 5000
//!
//! [plugin.limits]
//! max_output_bytes = 1048576
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Current plugin API version.
pub const PLUGIN_API_VERSION: &str = "1";

/// Default invocation timeout in milliseconds.
pub const DEFAULT_INVOKE_TIMEOUT_MS: u64 = 5000;

/// Default max output bytes (1 MB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default max consecutive failures before disabling.
pub const DEFAULT_MAX_FAILURES: u32 = 3;

/// Errors when loading a plugin manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest not found at {path}")]
    NotFound { path: PathBuf },

    #[error("invalid TOML in {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("I/O error reading {path}: {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported API version: expected {expected}, got {actual}")]
    ApiVersionMismatch { expected: String, actual: String },

    #[error("missing required field: {field}")]
    MissingField { field: String },

    #[error("plugin command not found: {path}")]
    CommandNotFound { path: PathBuf },
}

/// Plugin type (evidence source or action hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Provides additional evidence for inference.
    Evidence,
    /// Executes a custom action (notification, restart via API, etc.).
    Action,
}

/// Timeout configuration for plugin invocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTimeouts {
    /// Maximum time for a single invocation in milliseconds.
    #[serde(default = "default_invoke_timeout")]
    pub invoke_ms: u64,
}

impl Default for PluginTimeouts {
    fn default() -> Self {
        Self {
            invoke_ms: DEFAULT_INVOKE_TIMEOUT_MS,
        }
    }
}

/// Resource limits for plugin execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLimits {
    /// Maximum output size in bytes.
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    /// Maximum consecutive failures before auto-disable.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_failures: DEFAULT_MAX_FAILURES,
        }
    }
}

/// Top-level manifest wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub plugin: PluginManifest,
}

/// The plugin manifest declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Human-readable plugin name (e.g. "prometheus-metrics").
    pub name: String,
    /// SemVer version string.
    pub version: String,
    /// Plugin API version this plugin targets.
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Short description.
    #[serde(default)]
    pub description: String,
    /// Plugin type: evidence or action.
    #[serde(rename = "type", default = "default_plugin_type")]
    pub plugin_type: PluginType,
    /// Command to execute (relative to plugin directory or absolute).
    pub command: String,
    /// Optional fixed arguments to pass before the dynamic input.
    #[serde(default)]
    pub args: Vec<String>,
    /// Timeout settings.
    #[serde(default)]
    pub timeouts: PluginTimeouts,
    /// Resource limits.
    #[serde(default)]
    pub limits: PluginLimits,
    /// Evidence weight (0.0–1.0) controlling how much to trust this plugin's data.
    /// Only meaningful for evidence plugins.
    #[serde(default = "default_weight")]
    pub weight: f64,
}

/// A fully resolved plugin with its directory path.
#[derive(Debug, Clone)]
pub struct ResolvedPlugin {
    /// The parsed manifest.
    pub manifest: PluginManifest,
    /// Directory containing the plugin.
    pub plugin_dir: PathBuf,
    /// Resolved absolute path to the plugin command.
    pub command_path: PathBuf,
}

impl ResolvedPlugin {
    /// Unique identifier for this plugin (its name).
    pub fn id(&self) -> &str {
        &self.manifest.name
    }
}

/// Load and validate a plugin manifest from a directory.
pub fn load_manifest(plugin_dir: &Path) -> Result<ResolvedPlugin, ManifestError> {
    let manifest_path = plugin_dir.join("plugin.toml");

    if !manifest_path.exists() {
        return Err(ManifestError::NotFound {
            path: manifest_path,
        });
    }

    let content = std::fs::read_to_string(&manifest_path).map_err(|e| ManifestError::IoError {
        path: manifest_path.clone(),
        source: e,
    })?;

    let file: ManifestFile = toml::from_str(&content).map_err(|e| ManifestError::ParseError {
        path: manifest_path.clone(),
        source: e,
    })?;

    let manifest = file.plugin;

    // Validate API version
    if manifest.api_version != PLUGIN_API_VERSION {
        return Err(ManifestError::ApiVersionMismatch {
            expected: PLUGIN_API_VERSION.to_string(),
            actual: manifest.api_version.clone(),
        });
    }

    // Validate required fields
    if manifest.name.is_empty() {
        return Err(ManifestError::MissingField {
            field: "name".to_string(),
        });
    }
    if manifest.command.is_empty() {
        return Err(ManifestError::MissingField {
            field: "command".to_string(),
        });
    }

    // Resolve command path
    let command_path = if Path::new(&manifest.command).is_absolute() {
        PathBuf::from(&manifest.command)
    } else {
        plugin_dir.join(&manifest.command)
    };

    // Validate weight is in [0, 1]
    let weight = manifest.weight.clamp(0.0, 1.0);
    let mut manifest = manifest;
    manifest.weight = weight;

    Ok(ResolvedPlugin {
        manifest,
        plugin_dir: plugin_dir.to_path_buf(),
        command_path,
    })
}

fn default_invoke_timeout() -> u64 {
    DEFAULT_INVOKE_TIMEOUT_MS
}
fn default_max_output() -> usize {
    DEFAULT_MAX_OUTPUT_BYTES
}
fn default_max_failures() -> u32 {
    DEFAULT_MAX_FAILURES
}
fn default_api_version() -> String {
    PLUGIN_API_VERSION.to_string()
}
fn default_plugin_type() -> PluginType {
    PluginType::Evidence
}
fn default_weight() -> f64 {
    1.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_manifest(dir: &Path, content: &str) {
        std::fs::write(dir.join("plugin.toml"), content).unwrap();
    }

    #[test]
    fn test_load_valid_manifest() {
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("fetch.sh");
        std::fs::write(&script, "#!/bin/sh\necho ok").unwrap();

        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "test-plugin"
version = "0.1.0"
api_version = "1"
description = "A test plugin"
type = "evidence"
command = "fetch.sh"
weight = 0.8

[plugin.timeouts]
invoke_ms = 3000

[plugin.limits]
max_output_bytes = 512000
max_failures = 5
"#,
        );

        let resolved = load_manifest(dir.path()).unwrap();
        assert_eq!(resolved.manifest.name, "test-plugin");
        assert_eq!(resolved.manifest.version, "0.1.0");
        assert_eq!(resolved.manifest.plugin_type, PluginType::Evidence);
        assert_eq!(resolved.manifest.timeouts.invoke_ms, 3000);
        assert_eq!(resolved.manifest.limits.max_output_bytes, 512000);
        assert!((resolved.manifest.weight - 0.8).abs() < f64::EPSILON);
        assert_eq!(resolved.command_path, dir.path().join("fetch.sh"));
    }

    #[test]
    fn test_load_minimal_manifest() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "minimal"
version = "1.0.0"
command = "/usr/bin/true"
"#,
        );

        let resolved = load_manifest(dir.path()).unwrap();
        assert_eq!(resolved.manifest.name, "minimal");
        assert_eq!(resolved.manifest.api_version, PLUGIN_API_VERSION);
        assert_eq!(resolved.manifest.plugin_type, PluginType::Evidence);
        assert_eq!(
            resolved.manifest.timeouts.invoke_ms,
            DEFAULT_INVOKE_TIMEOUT_MS
        );
        assert!((resolved.manifest.weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_missing_manifest() {
        let dir = TempDir::new().unwrap();
        let result = load_manifest(dir.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::NotFound { .. }
        ));
    }

    #[test]
    fn test_invalid_toml() {
        let dir = TempDir::new().unwrap();
        write_manifest(dir.path(), "not valid {{{{ toml");
        let result = load_manifest(dir.path());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::ParseError { .. }
        ));
    }

    #[test]
    fn test_wrong_api_version() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "future-plugin"
version = "1.0.0"
api_version = "99"
command = "/usr/bin/true"
"#,
        );

        let result = load_manifest(dir.path());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::ApiVersionMismatch { .. }
        ));
    }

    #[test]
    fn test_empty_name_rejected() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = ""
version = "1.0.0"
command = "/usr/bin/true"
"#,
        );

        let result = load_manifest(dir.path());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::MissingField { .. }
        ));
    }

    #[test]
    fn test_weight_clamped() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "heavy"
version = "1.0.0"
command = "/usr/bin/true"
weight = 5.0
"#,
        );

        let resolved = load_manifest(dir.path()).unwrap();
        assert!((resolved.manifest.weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_action_plugin_type() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "slack-notify"
version = "1.0.0"
type = "action"
command = "/usr/bin/true"
"#,
        );

        let resolved = load_manifest(dir.path()).unwrap();
        assert_eq!(resolved.manifest.plugin_type, PluginType::Action);
    }

    #[test]
    fn test_absolute_command_path() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            r#"
[plugin]
name = "abs"
version = "1.0.0"
command = "/usr/bin/python3"
args = ["script.py"]
"#,
        );

        let resolved = load_manifest(dir.path()).unwrap();
        assert_eq!(resolved.command_path, PathBuf::from("/usr/bin/python3"));
        assert_eq!(resolved.manifest.args, vec!["script.py"]);
    }
}
