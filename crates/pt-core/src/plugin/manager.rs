//! Plugin manager: discovery, loading, invocation, and lifecycle.
//!
//! The manager scans the plugin directory for valid manifests, maintains
//! failure counters, and provides methods to invoke evidence and action
//! plugins via subprocess execution.
//!
//! Plugins are sandboxed via subprocess isolation — no dynamic library loading.
//! Each invocation is a fresh process with stdin/stdout JSON protocol.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::plugin::action::{ActionPluginError, ActionPluginInput, ActionPluginOutput};
use crate::plugin::evidence::{EvidencePluginError, EvidencePluginInput, EvidencePluginOutput};
use crate::plugin::manifest::{load_manifest, ManifestError, PluginType, ResolvedPlugin};

use thiserror::Error;

/// Default plugins subdirectory name under the config dir.
const PLUGINS_DIR_NAME: &str = "plugins";

/// Errors from the plugin manager.
#[derive(Debug, Error)]
pub enum PluginManagerError {
    #[error("plugin directory does not exist: {path}")]
    DirNotFound { path: PathBuf },

    #[error("I/O error scanning plugins: {source}")]
    IoError {
        #[source]
        source: std::io::Error,
    },

    #[error("no plugins loaded")]
    NoPlugins,
}

/// Per-plugin runtime state tracked by the manager.
#[derive(Debug)]
struct PluginState {
    /// The resolved plugin manifest.
    plugin: ResolvedPlugin,
    /// Consecutive failure count.
    consecutive_failures: u32,
    /// Whether the plugin has been auto-disabled.
    disabled: bool,
    /// Last invocation duration (for telemetry).
    last_duration: Option<Duration>,
}

impl PluginState {
    fn new(plugin: ResolvedPlugin) -> Self {
        Self {
            plugin,
            consecutive_failures: 0,
            disabled: false,
            last_duration: None,
        }
    }

    fn record_success(&mut self, duration: Duration) {
        self.consecutive_failures = 0;
        self.last_duration = Some(duration);
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        let max = self.plugin.manifest.limits.max_failures;
        if self.consecutive_failures >= max {
            warn!(
                plugin = %self.plugin.manifest.name,
                failures = self.consecutive_failures,
                "auto-disabling plugin after {} consecutive failures",
                self.consecutive_failures,
            );
            self.disabled = true;
        }
    }
}

/// Plugin manager handles discovery, loading, and invocation of plugins.
#[derive(Debug)]
pub struct PluginManager {
    /// Loaded plugins keyed by name.
    plugins: HashMap<String, PluginState>,
    /// Directory where plugins are stored.
    plugins_dir: PathBuf,
}

impl PluginManager {
    /// Discover and load plugins from `config_dir/plugins/`.
    pub fn discover(config_dir: &Path) -> Result<Self, PluginManagerError> {
        let plugins_dir = config_dir.join(PLUGINS_DIR_NAME);
        Self::discover_from(&plugins_dir)
    }

    /// Discover and load plugins from an explicit directory.
    pub fn discover_from(plugins_dir: &Path) -> Result<Self, PluginManagerError> {
        if !plugins_dir.exists() {
            debug!(path = %plugins_dir.display(), "plugins directory does not exist, no plugins loaded");
            return Ok(Self {
                plugins: HashMap::new(),
                plugins_dir: plugins_dir.to_path_buf(),
            });
        }

        let mut plugins = HashMap::new();

        let entries = std::fs::read_dir(plugins_dir)
            .map_err(|e| PluginManagerError::IoError { source: e })?;

        for entry in entries {
            let entry = entry.map_err(|e| PluginManagerError::IoError { source: e })?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            match load_manifest(&path) {
                Ok(resolved) => {
                    info!(
                        plugin = %resolved.manifest.name,
                        version = %resolved.manifest.version,
                        plugin_type = ?resolved.manifest.plugin_type,
                        "loaded plugin"
                    );
                    let name = resolved.manifest.name.clone();
                    plugins.insert(name, PluginState::new(resolved));
                }
                Err(ManifestError::NotFound { .. }) => {
                    debug!(path = %path.display(), "skipping directory without plugin.toml");
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping plugin with invalid manifest");
                }
            }
        }

        debug!(count = plugins.len(), "plugin discovery complete");

        Ok(Self {
            plugins,
            plugins_dir: plugins_dir.to_path_buf(),
        })
    }

    /// Create an empty manager (no plugins).
    pub fn empty() -> Self {
        Self {
            plugins: HashMap::new(),
            plugins_dir: PathBuf::new(),
        }
    }

    /// The plugins directory path.
    pub fn plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }

    /// Number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Number of active (non-disabled) plugins.
    pub fn active_count(&self) -> usize {
        self.plugins.values().filter(|s| !s.disabled).count()
    }

    /// List loaded plugin names.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    /// List evidence plugins (active only).
    pub fn evidence_plugins(&self) -> Vec<&ResolvedPlugin> {
        self.plugins
            .values()
            .filter(|s| !s.disabled && s.plugin.manifest.plugin_type == PluginType::Evidence)
            .map(|s| &s.plugin)
            .collect()
    }

    /// List action plugins (active only).
    pub fn action_plugins(&self) -> Vec<&ResolvedPlugin> {
        self.plugins
            .values()
            .filter(|s| !s.disabled && s.plugin.manifest.plugin_type == PluginType::Action)
            .map(|s| &s.plugin)
            .collect()
    }

    /// Check if a specific plugin is disabled.
    pub fn is_disabled(&self, name: &str) -> bool {
        self.plugins.get(name).map_or(true, |s| s.disabled)
    }

    /// Manually disable a plugin.
    pub fn disable(&mut self, name: &str) {
        if let Some(state) = self.plugins.get_mut(name) {
            state.disabled = true;
        }
    }

    /// Manually re-enable a plugin (resets failure counter).
    pub fn enable(&mut self, name: &str) {
        if let Some(state) = self.plugins.get_mut(name) {
            state.disabled = false;
            state.consecutive_failures = 0;
        }
    }

    /// Invoke an evidence plugin and return its output.
    ///
    /// Returns `Ok(None)` if the plugin is disabled.
    pub fn invoke_evidence(
        &mut self,
        plugin_name: &str,
        input: &EvidencePluginInput,
    ) -> Result<Option<EvidencePluginOutput>, EvidencePluginError> {
        match self.plugins.get(plugin_name) {
            Some(s) if s.disabled => return Ok(None),
            Some(s) if s.plugin.manifest.plugin_type != PluginType::Evidence => {
                return Err(EvidencePluginError::ExecutionFailed {
                    plugin: plugin_name.to_string(),
                    message: "not an evidence plugin".to_string(),
                });
            }
            Some(_) => {}
            None => {
                return Err(EvidencePluginError::ExecutionFailed {
                    plugin: plugin_name.to_string(),
                    message: "plugin not found".to_string(),
                });
            }
        }

        // Get plugin info (need to borrow immutably first, then mutably)
        let state = self.plugins.get(plugin_name).unwrap();
        let command_path = state.plugin.command_path.clone();
        let args = state.plugin.manifest.args.clone();
        let timeout_ms = state.plugin.manifest.timeouts.invoke_ms;
        let max_output = state.plugin.manifest.limits.max_output_bytes;
        let plugin_dir = state.plugin.plugin_dir.clone();

        let input_json =
            serde_json::to_vec(input).map_err(|e| EvidencePluginError::ExecutionFailed {
                plugin: plugin_name.to_string(),
                message: format!("failed to serialize input: {e}"),
            })?;

        match invoke_subprocess(
            &command_path,
            &args,
            &plugin_dir,
            &input_json,
            timeout_ms,
            max_output,
        ) {
            Ok((stdout, duration)) => {
                match crate::plugin::evidence::parse_evidence_output(plugin_name, &stdout) {
                    Ok(output) => {
                        let state = self.plugins.get_mut(plugin_name).unwrap();
                        state.record_success(duration);
                        Ok(Some(output))
                    }
                    Err(e) => {
                        let state = self.plugins.get_mut(plugin_name).unwrap();
                        state.record_failure();
                        Err(e)
                    }
                }
            }
            Err(msg) => {
                let state = self.plugins.get_mut(plugin_name).unwrap();
                state.record_failure();
                if msg.contains("timed out") {
                    Err(EvidencePluginError::Timeout {
                        plugin: plugin_name.to_string(),
                        timeout_ms,
                    })
                } else {
                    Err(EvidencePluginError::ExecutionFailed {
                        plugin: plugin_name.to_string(),
                        message: msg,
                    })
                }
            }
        }
    }

    /// Invoke an action plugin.
    ///
    /// Returns `Ok(None)` if the plugin is disabled.
    pub fn invoke_action(
        &mut self,
        plugin_name: &str,
        input: &ActionPluginInput,
    ) -> Result<Option<ActionPluginOutput>, ActionPluginError> {
        match self.plugins.get(plugin_name) {
            Some(s) if s.disabled => return Ok(None),
            Some(s) if s.plugin.manifest.plugin_type != PluginType::Action => {
                return Err(ActionPluginError::ExecutionFailed {
                    plugin: plugin_name.to_string(),
                    message: "not an action plugin".to_string(),
                });
            }
            Some(_) => {}
            None => {
                return Err(ActionPluginError::ExecutionFailed {
                    plugin: plugin_name.to_string(),
                    message: "plugin not found".to_string(),
                });
            }
        }

        let state = self.plugins.get(plugin_name).unwrap();
        let command_path = state.plugin.command_path.clone();
        let args = state.plugin.manifest.args.clone();
        let timeout_ms = state.plugin.manifest.timeouts.invoke_ms;
        let max_output = state.plugin.manifest.limits.max_output_bytes;
        let plugin_dir = state.plugin.plugin_dir.clone();

        let input_json =
            serde_json::to_vec(input).map_err(|e| ActionPluginError::ExecutionFailed {
                plugin: plugin_name.to_string(),
                message: format!("failed to serialize input: {e}"),
            })?;

        match invoke_subprocess(
            &command_path,
            &args,
            &plugin_dir,
            &input_json,
            timeout_ms,
            max_output,
        ) {
            Ok((stdout, duration)) => {
                match crate::plugin::action::parse_action_output(plugin_name, &stdout) {
                    Ok(output) => {
                        let state = self.plugins.get_mut(plugin_name).unwrap();
                        state.record_success(duration);
                        Ok(Some(output))
                    }
                    Err(e) => {
                        let state = self.plugins.get_mut(plugin_name).unwrap();
                        state.record_failure();
                        Err(e)
                    }
                }
            }
            Err(msg) => {
                let state = self.plugins.get_mut(plugin_name).unwrap();
                state.record_failure();
                if msg.contains("timed out") {
                    Err(ActionPluginError::Timeout {
                        plugin: plugin_name.to_string(),
                        timeout_ms,
                    })
                } else {
                    Err(ActionPluginError::ExecutionFailed {
                        plugin: plugin_name.to_string(),
                        message: msg,
                    })
                }
            }
        }
    }

    /// Invoke all active evidence plugins and collect results.
    ///
    /// Failed/timed-out plugins are logged and skipped (graceful degradation).
    pub fn invoke_all_evidence(
        &mut self,
        input: &EvidencePluginInput,
    ) -> Vec<(String, EvidencePluginOutput)> {
        let names: Vec<String> = self
            .evidence_plugins()
            .iter()
            .map(|p| p.manifest.name.clone())
            .collect();

        let mut results = Vec::new();

        for name in names {
            match self.invoke_evidence(&name, input) {
                Ok(Some(output)) => {
                    debug!(plugin = %name, entries = output.evidence.len(), "evidence plugin succeeded");
                    results.push((name, output));
                }
                Ok(None) => {
                    debug!(plugin = %name, "evidence plugin disabled, skipping");
                }
                Err(e) => {
                    warn!(plugin = %name, error = %e, "evidence plugin failed, skipping");
                }
            }
        }

        results
    }

    /// Invoke all active action plugins for a given action.
    ///
    /// Failed/timed-out plugins are logged and skipped (graceful degradation).
    pub fn invoke_all_actions(
        &mut self,
        input: &ActionPluginInput,
    ) -> Vec<(String, ActionPluginOutput)> {
        let names: Vec<String> = self
            .action_plugins()
            .iter()
            .map(|p| p.manifest.name.clone())
            .collect();

        let mut results = Vec::new();

        for name in names {
            match self.invoke_action(&name, input) {
                Ok(Some(output)) => {
                    debug!(plugin = %name, status = ?output.status, "action plugin succeeded");
                    results.push((name, output));
                }
                Ok(None) => {
                    debug!(plugin = %name, "action plugin disabled, skipping");
                }
                Err(e) => {
                    warn!(plugin = %name, error = %e, "action plugin failed, skipping");
                }
            }
        }

        results
    }
}

/// Execute a plugin subprocess with stdin/stdout JSON protocol.
///
/// Returns the stdout bytes and execution duration on success,
/// or an error message string on failure.
fn invoke_subprocess(
    command: &Path,
    args: &[String],
    working_dir: &Path,
    stdin_data: &[u8],
    timeout_ms: u64,
    max_output: usize,
) -> Result<(Vec<u8>, Duration), String> {
    let start = Instant::now();

    let mut child = Command::new(command)
        .args(args)
        .current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn: {e}"))?;

    // Write stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data)
            .map_err(|e| format!("failed to write stdin: {e}"))?;
        // stdin is dropped here, closing the pipe
    }

    // Wait with timeout
    let timeout = Duration::from_millis(timeout_ms);
    let output = match child.wait_with_output() {
        Ok(output) => {
            let elapsed = start.elapsed();
            if elapsed > timeout {
                return Err(format!("timed out after {}ms", elapsed.as_millis()));
            }
            output
        }
        Err(e) => return Err(format!("wait failed: {e}")),
    };

    let duration = start.elapsed();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        return Err(format!(
            "exited with code {code}: {}",
            stderr.chars().take(500).collect::<String>()
        ));
    }

    let mut stdout = output.stdout;
    if stdout.len() > max_output {
        stdout.truncate(max_output);
        warn!(
            "plugin output truncated from {} to {} bytes",
            stdout.len(),
            max_output
        );
    }

    Ok((stdout, duration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_plugin_dir(parent: &Path, name: &str, plugin_type: &str, script: &str) -> PathBuf {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir).unwrap();

        let script_path = dir.join("run.sh");
        std::fs::write(&script_path, script).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let manifest = format!(
            r#"[plugin]
name = "{name}"
version = "0.1.0"
type = "{plugin_type}"
command = "run.sh"

[plugin.timeouts]
invoke_ms = 5000

[plugin.limits]
max_failures = 2
"#
        );
        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();

        dir
    }

    #[test]
    fn test_discover_empty_dir() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        assert_eq!(mgr.plugin_count(), 0);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_discover_nonexistent_dir() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("nonexistent");

        let mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        assert_eq!(mgr.plugin_count(), 0);
    }

    #[test]
    fn test_discover_with_plugins() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        create_plugin_dir(
            &plugins_dir,
            "evidence-a",
            "evidence",
            "#!/bin/sh\necho '{}'",
        );
        create_plugin_dir(&plugins_dir, "action-b", "action", "#!/bin/sh\necho '{}'");

        let mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        assert_eq!(mgr.plugin_count(), 2);
        assert_eq!(mgr.evidence_plugins().len(), 1);
        assert_eq!(mgr.action_plugins().len(), 1);
    }

    #[test]
    fn test_discover_skips_invalid() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        // Valid plugin
        create_plugin_dir(&plugins_dir, "good", "evidence", "#!/bin/sh\necho ok");

        // Invalid manifest
        let bad_dir = plugins_dir.join("bad");
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(bad_dir.join("plugin.toml"), "not valid toml {{").unwrap();

        // Directory without manifest (skipped silently)
        let no_manifest = plugins_dir.join("empty");
        std::fs::create_dir_all(no_manifest).unwrap();

        let mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.plugin_names().contains(&"good"));
    }

    #[test]
    fn test_disable_enable() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        create_plugin_dir(&plugins_dir, "test", "evidence", "#!/bin/sh\necho ok");

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        assert!(!mgr.is_disabled("test"));
        assert_eq!(mgr.active_count(), 1);

        mgr.disable("test");
        assert!(mgr.is_disabled("test"));
        assert_eq!(mgr.active_count(), 0);

        mgr.enable("test");
        assert!(!mgr.is_disabled("test"));
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_empty_manager() {
        let mgr = PluginManager::empty();
        assert_eq!(mgr.plugin_count(), 0);
        assert_eq!(mgr.active_count(), 0);
        assert!(mgr.evidence_plugins().is_empty());
        assert!(mgr.action_plugins().is_empty());
    }

    #[test]
    fn test_invoke_evidence_real_script() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let script = r#"#!/bin/sh
cat << 'EOF'
{
  "plugin": "test-evidence",
  "version": "0.1.0",
  "evidence": [
    {
      "pid": 42,
      "features": {"custom_metric": 0.5},
      "log_likelihoods": {
        "useful": -0.5,
        "useful_bad": -1.0,
        "abandoned": -0.1,
        "zombie": -0.2
      }
    }
  ]
}
EOF
"#;
        create_plugin_dir(&plugins_dir, "test-evidence", "evidence", script);

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        let input = EvidencePluginInput {
            pids: vec![42],
            scan_id: None,
        };

        let result = mgr.invoke_evidence("test-evidence", &input).unwrap();
        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.evidence.len(), 1);
        assert_eq!(output.evidence[0].pid, 42);
    }

    #[test]
    fn test_invoke_action_real_script() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let script = r#"#!/bin/sh
echo '{"plugin": "test-action", "status": "ok", "message": "notified"}'
"#;
        create_plugin_dir(&plugins_dir, "test-action", "action", script);

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        let input = ActionPluginInput {
            action: "kill".to_string(),
            pid: 1234,
            process_name: "zombie".to_string(),
            classification: "zombie".to_string(),
            confidence: 0.99,
            session_id: None,
        };

        let result = mgr.invoke_action("test-action", &input).unwrap();
        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.message, "notified");
    }

    #[test]
    fn test_invoke_disabled_plugin_returns_none() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        create_plugin_dir(&plugins_dir, "disabled", "evidence", "#!/bin/sh\necho fail");

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        mgr.disable("disabled");

        let input = EvidencePluginInput {
            pids: vec![1],
            scan_id: None,
        };
        let result = mgr.invoke_evidence("disabled", &input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_invoke_nonexistent_plugin() {
        let mut mgr = PluginManager::empty();
        let input = EvidencePluginInput {
            pids: vec![1],
            scan_id: None,
        };
        let result = mgr.invoke_evidence("ghost", &input);
        assert!(result.is_err());
    }

    #[test]
    fn test_failure_tracking_auto_disable() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        // Script that always fails
        create_plugin_dir(&plugins_dir, "flaky", "evidence", "#!/bin/sh\nexit 1");

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        let input = EvidencePluginInput {
            pids: vec![1],
            scan_id: None,
        };

        // max_failures = 2, so after 2 failures it should be disabled
        let _ = mgr.invoke_evidence("flaky", &input);
        assert!(!mgr.is_disabled("flaky"));

        let _ = mgr.invoke_evidence("flaky", &input);
        assert!(mgr.is_disabled("flaky"));

        // Now it returns None instead of error
        let result = mgr.invoke_evidence("flaky", &input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_invoke_all_evidence() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let script = r#"#!/bin/sh
echo '{"plugin":"a","version":"1","evidence":[{"pid":1,"features":{},"log_likelihoods":{"useful":0,"useful_bad":0,"abandoned":-1,"zombie":0}}]}'
"#;
        create_plugin_dir(&plugins_dir, "a", "evidence", script);

        // Action plugin should not be invoked
        create_plugin_dir(&plugins_dir, "b", "action", "#!/bin/sh\necho '{}'");

        let mut mgr = PluginManager::discover_from(&plugins_dir).unwrap();
        let input = EvidencePluginInput {
            pids: vec![1],
            scan_id: None,
        };

        let results = mgr.invoke_all_evidence(&input);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "a");
    }

    #[test]
    fn test_discover_via_config_dir() {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path();
        let plugins_dir = config_dir.join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        create_plugin_dir(&plugins_dir, "via-config", "evidence", "#!/bin/sh\necho ok");

        let mgr = PluginManager::discover(config_dir).unwrap();
        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.plugin_names().contains(&"via-config"));
    }
}
