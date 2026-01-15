//! Configuration resolution and path discovery.
//!
//! Resolution order: CLI arguments → environment variables → XDG paths → defaults.

use std::path::{Path, PathBuf};

/// Discovered configuration file paths.
#[derive(Debug, Clone, Default)]
pub struct ConfigPaths {
    /// Path to priors.json (or None if not found).
    pub priors: Option<PathBuf>,

    /// Path to policy.json (or None if not found).
    pub policy: Option<PathBuf>,

    /// Source of the priors config (for diagnostics).
    pub priors_source: ConfigSource,

    /// Source of the policy config (for diagnostics).
    pub policy_source: ConfigSource,
}

/// Where a configuration file was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ConfigSource {
    /// Explicitly provided via CLI argument.
    CliArgument,

    /// Set via environment variable.
    Environment,

    /// Found in XDG config directory.
    XdgConfig,

    /// Found in /etc/process-triage/.
    SystemConfig,

    /// Using built-in defaults.
    #[default]
    BuiltinDefault,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::CliArgument => write!(f, "CLI argument"),
            ConfigSource::Environment => write!(f, "environment variable"),
            ConfigSource::XdgConfig => write!(f, "XDG config"),
            ConfigSource::SystemConfig => write!(f, "system config"),
            ConfigSource::BuiltinDefault => write!(f, "builtin default"),
        }
    }
}

/// Environment variable names.
const ENV_PRIORS_PATH: &str = "PROCESS_TRIAGE_PRIORS";
const ENV_POLICY_PATH: &str = "PROCESS_TRIAGE_POLICY";
const ENV_CONFIG_DIR: &str = "PROCESS_TRIAGE_CONFIG_DIR";

/// Standard config file names.
const PRIORS_FILENAME: &str = "priors.json";
const POLICY_FILENAME: &str = "policy.json";

/// Application name for XDG directories.
const APP_NAME: &str = "process-triage";

/// Resolve configuration paths using the standard resolution order.
///
/// Resolution order for each config file:
/// 1. Explicit CLI path (if provided)
/// 2. Environment variable (PROCESS_TRIAGE_PRIORS, PROCESS_TRIAGE_POLICY)
/// 3. PROCESS_TRIAGE_CONFIG_DIR environment variable + filename
/// 4. XDG config directory (~/.config/process-triage/)
/// 5. System config (/etc/process-triage/)
/// 6. Built-in defaults (None)
pub fn resolve_config(
    cli_priors: Option<&Path>,
    cli_policy: Option<&Path>,
) -> ConfigPaths {
    let mut paths = ConfigPaths::default();

    // Resolve priors path
    paths.priors = resolve_single_config(
        cli_priors,
        ENV_PRIORS_PATH,
        PRIORS_FILENAME,
        &mut paths.priors_source,
    );

    // Resolve policy path
    paths.policy = resolve_single_config(
        cli_policy,
        ENV_POLICY_PATH,
        POLICY_FILENAME,
        &mut paths.policy_source,
    );

    paths
}

/// Resolve a single configuration file path.
fn resolve_single_config(
    cli_path: Option<&Path>,
    env_var: &str,
    filename: &str,
    source: &mut ConfigSource,
) -> Option<PathBuf> {
    // 1. CLI argument
    if let Some(path) = cli_path {
        if path.exists() {
            *source = ConfigSource::CliArgument;
            return Some(path.to_path_buf());
        }
    }

    // 2. Environment variable (direct path)
    if let Ok(env_path) = std::env::var(env_var) {
        let path = PathBuf::from(env_path);
        if path.exists() {
            *source = ConfigSource::Environment;
            return Some(path);
        }
    }

    // 3. Environment variable (config dir)
    if let Ok(config_dir) = std::env::var(ENV_CONFIG_DIR) {
        let path = PathBuf::from(config_dir).join(filename);
        if path.exists() {
            *source = ConfigSource::Environment;
            return Some(path);
        }
    }

    // 4. XDG config directory
    if let Some(xdg_config) = dirs::config_dir() {
        let path = xdg_config.join(APP_NAME).join(filename);
        if path.exists() {
            *source = ConfigSource::XdgConfig;
            return Some(path);
        }
    }

    // 5. System config
    let system_path = PathBuf::from("/etc").join(APP_NAME).join(filename);
    if system_path.exists() {
        *source = ConfigSource::SystemConfig;
        return Some(system_path);
    }

    // 6. Built-in default (None)
    *source = ConfigSource::BuiltinDefault;
    None
}

/// Get the XDG config directory for process-triage.
pub fn xdg_config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(APP_NAME))
}

/// Get the system config directory.
pub fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc").join(APP_NAME)
}

/// Check if a config directory exists and is readable.
pub fn config_dir_exists(path: &Path) -> bool {
    path.is_dir() && path.read_dir().is_ok()
}

/// List all config files in a directory.
pub fn list_config_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "json" {
                        files.push(path);
                    }
                }
            }
        }
    }

    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_source_display() {
        assert_eq!(format!("{}", ConfigSource::CliArgument), "CLI argument");
        assert_eq!(format!("{}", ConfigSource::Environment), "environment variable");
        assert_eq!(format!("{}", ConfigSource::XdgConfig), "XDG config");
        assert_eq!(format!("{}", ConfigSource::SystemConfig), "system config");
        assert_eq!(format!("{}", ConfigSource::BuiltinDefault), "builtin default");
    }

    #[test]
    fn test_resolve_config_defaults() {
        // With no CLI args and no config files, should return None with BuiltinDefault source
        let paths = resolve_config(None, None);
        assert!(paths.priors.is_none());
        assert!(paths.policy.is_none());
        assert_eq!(paths.priors_source, ConfigSource::BuiltinDefault);
        assert_eq!(paths.policy_source, ConfigSource::BuiltinDefault);
    }

    #[test]
    fn test_xdg_config_dir() {
        let dir = xdg_config_dir();
        // Should return Some on most systems
        if let Some(path) = dir {
            assert!(path.ends_with(APP_NAME));
        }
    }

    #[test]
    fn test_system_config_dir() {
        let dir = system_config_dir();
        assert_eq!(dir, PathBuf::from("/etc/process-triage"));
    }
}
