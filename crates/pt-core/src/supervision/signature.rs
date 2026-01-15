//! Unified supervisor signature database.
//!
//! This module provides a unified signature schema that combines all detection
//! methods (process names, environment variables, sockets, PID files) into a
//! single, versioned, and extensible format.
//!
//! # Schema Version
//!
//! The signature schema is versioned to support future updates without breaking
//! existing configurations. Version 1 is the initial format.
//!
//! # File Formats
//!
//! Signatures can be loaded from:
//! - TOML files (recommended for human editing)
//! - JSON files (for programmatic generation)
//!
//! # Example TOML
//!
//! ```toml
//! schema_version = 1
//!
//! [[signatures]]
//! name = "claude"
//! category = "agent"
//! confidence_weight = 0.95
//! notes = "Anthropic Claude AI agent"
//!
//! [signatures.patterns]
//! process_names = ["^claude$", "^claude-code$", "^claude-cli$"]
//! environment_vars = { CLAUDE_SESSION_ID = ".*", CLAUDE_CODE_SESSION = ".*" }
//! socket_paths = ["/tmp/claude-"]
//! pid_files = []
//! parent_patterns = []
//! ```

use super::types::{SupervisorCategory, SupervisorPattern};
use super::environ::EnvPattern;
use super::ipc::IpcPattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Errors from signature loading.
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(String),

    #[error("Unsupported schema version {found}, expected <= {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },

    #[error("Invalid signature: {0}")]
    Invalid(String),

    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },
}

/// A unified supervisor signature combining all detection patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorSignature {
    /// Human-readable name (e.g., "claude", "vscode").
    pub name: String,

    /// Category of supervisor.
    pub category: SupervisorCategory,

    /// Detection patterns.
    pub patterns: SignaturePatterns,

    /// Overall confidence weight for this signature (0.0 - 1.0).
    #[serde(default = "default_confidence")]
    pub confidence_weight: f64,

    /// Human-readable notes about this supervisor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// Whether this is a built-in signature (vs user-defined).
    #[serde(default, skip_serializing_if = "is_false")]
    pub builtin: bool,
}

fn default_confidence() -> f64 {
    0.80
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Detection patterns for a supervisor signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignaturePatterns {
    /// Regex patterns for process name (comm) matching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,

    /// Environment variable patterns: var_name -> expected value regex.
    /// Use ".*" or empty string to match any value (existence check).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment_vars: HashMap<String, String>,

    /// Path prefixes for IPC socket detection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socket_paths: Vec<String>,

    /// Known PID file locations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pid_files: Vec<String>,

    /// Regex patterns for parent/ancestor process names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_patterns: Vec<String>,
}

impl SupervisorSignature {
    /// Create a new signature with minimal required fields.
    pub fn new(name: impl Into<String>, category: SupervisorCategory) -> Self {
        Self {
            name: name.into(),
            category,
            patterns: SignaturePatterns::default(),
            confidence_weight: default_confidence(),
            notes: None,
            builtin: false,
        }
    }

    /// Set confidence weight.
    pub fn with_confidence(mut self, weight: f64) -> Self {
        self.confidence_weight = weight;
        self
    }

    /// Add notes.
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Add process name patterns.
    pub fn with_process_patterns(mut self, patterns: Vec<&str>) -> Self {
        self.patterns.process_names = patterns.into_iter().map(String::from).collect();
        self
    }

    /// Add environment variable patterns.
    pub fn with_env_patterns(mut self, patterns: HashMap<String, String>) -> Self {
        self.patterns.environment_vars = patterns;
        self
    }

    /// Add socket path prefixes.
    pub fn with_socket_paths(mut self, paths: Vec<&str>) -> Self {
        self.patterns.socket_paths = paths.into_iter().map(String::from).collect();
        self
    }

    /// Add PID file locations.
    pub fn with_pid_files(mut self, paths: Vec<&str>) -> Self {
        self.patterns.pid_files = paths.into_iter().map(String::from).collect();
        self
    }

    /// Mark as builtin.
    pub fn as_builtin(mut self) -> Self {
        self.builtin = true;
        self
    }

    /// Validate the signature.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.name.is_empty() {
            return Err(SignatureError::Invalid("name cannot be empty".into()));
        }

        if self.confidence_weight < 0.0 || self.confidence_weight > 1.0 {
            return Err(SignatureError::Invalid(
                "confidence_weight must be between 0.0 and 1.0".into(),
            ));
        }

        // Validate regex patterns
        for pattern in &self.patterns.process_names {
            regex::Regex::new(pattern).map_err(|e| SignatureError::InvalidRegex {
                pattern: pattern.clone(),
                error: e.to_string(),
            })?;
        }

        for pattern in &self.patterns.parent_patterns {
            regex::Regex::new(pattern).map_err(|e| SignatureError::InvalidRegex {
                pattern: pattern.clone(),
                error: e.to_string(),
            })?;
        }

        for (_, value_pattern) in &self.patterns.environment_vars {
            if !value_pattern.is_empty() {
                regex::Regex::new(value_pattern).map_err(|e| SignatureError::InvalidRegex {
                    pattern: value_pattern.clone(),
                    error: e.to_string(),
                })?;
            }
        }

        Ok(())
    }

    /// Convert to a SupervisorPattern (process name only).
    pub fn to_supervisor_pattern(&self) -> SupervisorPattern {
        SupervisorPattern::new(
            &self.name,
            self.category,
            self.patterns
                .process_names
                .iter()
                .map(|s| s.as_str())
                .collect(),
            self.confidence_weight,
        )
    }

    /// Convert to EnvPatterns (one per env var).
    pub fn to_env_patterns(&self) -> Vec<EnvPattern> {
        self.patterns
            .environment_vars
            .iter()
            .map(|(var_name, value_pattern)| {
                let mut pattern =
                    EnvPattern::new(&self.name, self.category, var_name, self.confidence_weight);
                if !value_pattern.is_empty() && value_pattern != ".*" {
                    pattern = pattern.with_value(value_pattern);
                }
                pattern
            })
            .collect()
    }

    /// Convert to IpcPatterns (one per socket path).
    pub fn to_ipc_patterns(&self) -> Vec<IpcPattern> {
        self.patterns
            .socket_paths
            .iter()
            .map(|path| {
                IpcPattern::path(&self.name, self.category, path, self.confidence_weight)
            })
            .collect()
    }
}

/// Schema wrapper for versioned signature files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSchema {
    /// Schema version number.
    pub schema_version: u32,

    /// Signatures defined in this file.
    #[serde(default)]
    pub signatures: Vec<SupervisorSignature>,

    /// Optional metadata about this signature file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SignatureMetadata>,
}

/// Optional metadata for signature files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureMetadata {
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Author or maintainer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// URL for more information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl SignatureSchema {
    /// Create a new schema with current version.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            signatures: vec![],
            metadata: None,
        }
    }

    /// Add a signature.
    pub fn add(&mut self, signature: SupervisorSignature) {
        self.signatures.push(signature);
    }

    /// Validate the schema and all signatures.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(SignatureError::UnsupportedVersion {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }

        for sig in &self.signatures {
            sig.validate()?;
        }

        Ok(())
    }

    /// Load from JSON string.
    pub fn from_json(json: &str) -> Result<Self, SignatureError> {
        let schema: SignatureSchema = serde_json::from_str(json)?;
        schema.validate()?;
        Ok(schema)
    }

    /// Load from JSON file.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, SignatureError> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Load from TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, SignatureError> {
        let schema: SignatureSchema =
            toml::from_str(toml_str).map_err(|e| SignatureError::Toml(e.to_string()))?;
        schema.validate()?;
        Ok(schema)
    }

    /// Load from TOML file.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, SignatureError> {
        let content = fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Load from file, auto-detecting format by extension.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SignatureError> {
        let path = path.as_ref();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "toml" => Self::from_toml_file(path),
            "json" => Self::from_json_file(path),
            _ => {
                // Try JSON first, then TOML
                let content = fs::read_to_string(path)?;
                Self::from_json(&content).or_else(|_| Self::from_toml(&content))
            }
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, SignatureError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize to TOML.
    pub fn to_toml(&self) -> Result<String, SignatureError> {
        toml::to_string_pretty(self).map_err(|e| SignatureError::Toml(e.to_string()))
    }
}

impl Default for SignatureSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Unified signature database combining all detection methods.
#[derive(Debug, Clone, Default)]
pub struct SignatureDatabase {
    /// All loaded signatures.
    signatures: Vec<SupervisorSignature>,
    /// Compiled regex patterns for process names (cached).
    process_regexes: Vec<(usize, regex::Regex)>, // (signature_index, regex)
    /// Compiled regex patterns for parent processes (cached).
    parent_regexes: Vec<(usize, regex::Regex)>,
}

impl SignatureDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self {
            signatures: vec![],
            process_regexes: vec![],
            parent_regexes: vec![],
        }
    }

    /// Create with default bundled signatures.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.add_default_signatures();
        db
    }

    /// Get all signatures.
    pub fn signatures(&self) -> &[SupervisorSignature] {
        &self.signatures
    }

    /// Get signature count.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if database is empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Add a signature and compile its patterns.
    pub fn add(&mut self, signature: SupervisorSignature) -> Result<(), SignatureError> {
        signature.validate()?;
        let idx = self.signatures.len();

        // Compile process name regexes
        for pattern in &signature.patterns.process_names {
            if let Ok(re) = regex::Regex::new(pattern) {
                self.process_regexes.push((idx, re));
            }
        }

        // Compile parent pattern regexes
        for pattern in &signature.patterns.parent_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                self.parent_regexes.push((idx, re));
            }
        }

        self.signatures.push(signature);
        Ok(())
    }

    /// Load signatures from a schema.
    pub fn load_schema(&mut self, schema: SignatureSchema) -> Result<usize, SignatureError> {
        let mut loaded = 0;
        for sig in schema.signatures {
            self.add(sig)?;
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Load signatures from a file.
    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<usize, SignatureError> {
        let schema = SignatureSchema::from_file(path)?;
        self.load_schema(schema)
    }

    /// Load all signature files from a directory.
    pub fn load_directory(&mut self, dir: impl AsRef<Path>) -> Result<usize, SignatureError> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Ok(0);
        }

        let mut total = 0;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if ext == "toml" || ext == "json" {
                    match self.load_file(&path) {
                        Ok(n) => total += n,
                        Err(e) => {
                            tracing::warn!("Failed to load signature file {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        Ok(total)
    }

    /// Find signatures matching a process name.
    pub fn find_by_process_name(&self, comm: &str) -> Vec<&SupervisorSignature> {
        let mut matches = Vec::new();
        for (idx, re) in &self.process_regexes {
            if re.is_match(comm) {
                matches.push(&self.signatures[*idx]);
            }
        }
        // Deduplicate by signature index
        matches.sort_by_key(|s| s.name.as_str());
        matches.dedup_by_key(|s| s.name.as_str());
        matches
    }

    /// Find signatures matching a parent process name.
    pub fn find_by_parent_name(&self, comm: &str) -> Vec<&SupervisorSignature> {
        let mut matches = Vec::new();
        for (idx, re) in &self.parent_regexes {
            if re.is_match(comm) {
                matches.push(&self.signatures[*idx]);
            }
        }
        matches.sort_by_key(|s| s.name.as_str());
        matches.dedup_by_key(|s| s.name.as_str());
        matches
    }

    /// Find signatures matching an environment variable.
    pub fn find_by_env_var(
        &self,
        var_name: &str,
        var_value: &str,
    ) -> Vec<&SupervisorSignature> {
        self.signatures
            .iter()
            .filter(|sig| {
                if let Some(pattern) = sig.patterns.environment_vars.get(var_name) {
                    if pattern.is_empty() || pattern == ".*" {
                        return true;
                    }
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(var_value))
                        .unwrap_or(false)
                } else {
                    false
                }
            })
            .collect()
    }

    /// Find signatures matching a socket path.
    pub fn find_by_socket_path(&self, path: &str) -> Vec<&SupervisorSignature> {
        self.signatures
            .iter()
            .filter(|sig| {
                sig.patterns
                    .socket_paths
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
            })
            .collect()
    }

    /// Find signatures by PID file path.
    pub fn find_by_pid_file(&self, path: &str) -> Vec<&SupervisorSignature> {
        self.signatures
            .iter()
            .filter(|sig| sig.patterns.pid_files.iter().any(|p| path == p || path.starts_with(p)))
            .collect()
    }

    /// Add all default bundled signatures.
    pub fn add_default_signatures(&mut self) {
        // AI Agents
        let _ = self.add(
            SupervisorSignature::new("claude", SupervisorCategory::Agent)
                .with_confidence(0.95)
                .with_notes("Anthropic Claude AI agent")
                .with_process_patterns(vec![r"^claude$", r"^claude-code$", r"^claude-cli$"])
                .with_env_patterns(HashMap::from([
                    ("CLAUDE_SESSION_ID".into(), ".*".into()),
                    ("CLAUDE_CODE_SESSION".into(), ".*".into()),
                    ("CLAUDE_ENTRYPOINT".into(), ".*".into()),
                ]))
                .with_socket_paths(vec!["/tmp/claude-"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("codex", SupervisorCategory::Agent)
                .with_confidence(0.95)
                .with_notes("OpenAI Codex CLI agent")
                .with_process_patterns(vec![r"^codex$", r"^codex-cli$"])
                .with_env_patterns(HashMap::from([
                    ("CODEX_SESSION_ID".into(), ".*".into()),
                    ("CODEX_CLI_SESSION".into(), ".*".into()),
                ]))
                .with_socket_paths(vec!["/tmp/codex-"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("aider", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_notes("Aider AI pair programming")
                .with_process_patterns(vec![r"^aider$", r"^aider-chat$"])
                .with_env_patterns(HashMap::from([("AIDER_SESSION".into(), ".*".into())]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("cursor", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_notes("Cursor IDE with AI")
                .with_process_patterns(vec![r"^cursor$", r"^Cursor$", r"^cursor-agent$"])
                .with_env_patterns(HashMap::from([
                    ("CURSOR_SESSION".into(), ".*".into()),
                    ("CURSOR_PID".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        // IDEs
        let _ = self.add(
            SupervisorSignature::new("vscode", SupervisorCategory::Ide)
                .with_confidence(0.85)
                .with_notes("Visual Studio Code")
                .with_process_patterns(vec![r"^code$", r"^code-server$", r"^Code$", r"^code-oss$"])
                .with_env_patterns(HashMap::from([
                    ("VSCODE_PID".into(), ".*".into()),
                    ("VSCODE_IPC_HOOK".into(), ".*".into()),
                    ("VSCODE_IPC_HOOK_CLI".into(), ".*".into()),
                    ("TERM_PROGRAM".into(), "vscode".into()),
                ]))
                .with_socket_paths(vec!["/tmp/vscode-", "/run/user/"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("jetbrains", SupervisorCategory::Ide)
                .with_confidence(0.85)
                .with_notes("JetBrains IDEs (IntelliJ, PyCharm, WebStorm, etc.)")
                .with_process_patterns(vec![
                    r"^idea$",
                    r"^pycharm$",
                    r"^webstorm$",
                    r"^goland$",
                    r"^clion$",
                    r"^rider$",
                    r"^rubymine$",
                    r"^phpstorm$",
                ])
                .with_env_patterns(HashMap::from([
                    ("IDEA_VM_OPTIONS".into(), ".*".into()),
                    ("PYCHARM_VM_OPTIONS".into(), ".*".into()),
                ]))
                .with_socket_paths(vec!["/tmp/.java_pid"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("nvim-lsp", SupervisorCategory::Ide)
                .with_confidence(0.60)
                .with_notes("Neovim/Vim with LSP")
                .with_process_patterns(vec![r"^nvim$", r"^vim$"])
                .as_builtin(),
        );

        // CI/CD Systems
        let _ = self.add(
            SupervisorSignature::new("github-actions", SupervisorCategory::Ci)
                .with_confidence(0.95)
                .with_notes("GitHub Actions runner")
                .with_process_patterns(vec![r"^Runner\.Worker$", r"^actions-runner$", r"^runner$"])
                .with_env_patterns(HashMap::from([
                    ("GITHUB_ACTIONS".into(), "true".into()),
                    ("GITHUB_WORKFLOW".into(), ".*".into()),
                    ("GITHUB_RUN_ID".into(), ".*".into()),
                ]))
                .with_pid_files(vec![
                    "/actions-runner/.runner",
                    "~/.actions-runner/.runner",
                ])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("gitlab-runner", SupervisorCategory::Ci)
                .with_confidence(0.95)
                .with_notes("GitLab CI Runner")
                .with_process_patterns(vec![r"^gitlab-runner$", r"^gitlab-ci$"])
                .with_env_patterns(HashMap::from([
                    ("GITLAB_CI".into(), "true".into()),
                    ("CI_PROJECT_ID".into(), ".*".into()),
                    ("CI_PIPELINE_ID".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("jenkins", SupervisorCategory::Ci)
                .with_confidence(0.90)
                .with_notes("Jenkins CI")
                .with_process_patterns(vec![r"^java.*jenkins", r"^jenkins$"])
                .with_env_patterns(HashMap::from([
                    ("JENKINS_URL".into(), ".*".into()),
                    ("BUILD_ID".into(), ".*".into()),
                    ("JOB_NAME".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("circleci", SupervisorCategory::Ci)
                .with_confidence(0.95)
                .with_notes("CircleCI")
                .with_env_patterns(HashMap::from([
                    ("CIRCLECI".into(), "true".into()),
                    ("CIRCLE_BUILD_NUM".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("travis", SupervisorCategory::Ci)
                .with_confidence(0.95)
                .with_notes("Travis CI")
                .with_env_patterns(HashMap::from([
                    ("TRAVIS".into(), "true".into()),
                    ("TRAVIS_BUILD_ID".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("ci-generic", SupervisorCategory::Ci)
                .with_confidence(0.70)
                .with_notes("Generic CI environment")
                .with_env_patterns(HashMap::from([("CI".into(), "true".into())]))
                .as_builtin(),
        );

        // Terminal Multiplexers
        let _ = self.add(
            SupervisorSignature::new("tmux", SupervisorCategory::Terminal)
                .with_confidence(0.70)
                .with_notes("tmux terminal multiplexer")
                .with_process_patterns(vec![r"^tmux: server$", r"^tmux$"])
                .with_env_patterns(HashMap::from([("TMUX".into(), ".*".into())]))
                .with_socket_paths(vec!["/tmp/tmux-"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("screen", SupervisorCategory::Terminal)
                .with_confidence(0.70)
                .with_notes("GNU Screen")
                .with_process_patterns(vec![r"^SCREEN$", r"^screen$"])
                .with_env_patterns(HashMap::from([("STY".into(), ".*".into())]))
                .as_builtin(),
        );

        // Process Orchestrators
        let _ = self.add(
            SupervisorSignature::new("systemd", SupervisorCategory::Orchestrator)
                .with_confidence(0.95)
                .with_notes("systemd init system")
                .with_process_patterns(vec![r"^systemd$", r"^systemd-.*$"])
                .with_pid_files(vec!["/run/systemd/", "/var/run/systemd/"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("launchd", SupervisorCategory::Orchestrator)
                .with_confidence(0.95)
                .with_notes("macOS launchd")
                .with_process_patterns(vec![r"^launchd$"])
                .with_pid_files(vec!["/var/run/launchd/"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("pm2", SupervisorCategory::Orchestrator)
                .with_confidence(0.90)
                .with_notes("PM2 process manager")
                .with_process_patterns(vec![r"^PM2$", r"^pm2$", r"^PM2 v\d"])
                .with_env_patterns(HashMap::from([("PM2_HOME".into(), ".*".into())]))
                .with_pid_files(vec!["~/.pm2/pm2.pid", "/root/.pm2/pm2.pid"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("supervisord", SupervisorCategory::Orchestrator)
                .with_confidence(0.90)
                .with_notes("Supervisor daemon")
                .with_process_patterns(vec![r"^supervisord$", r"^python.*supervisord"])
                .with_pid_files(vec!["/var/run/supervisord.pid", "/tmp/supervisord.pid"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("docker", SupervisorCategory::Orchestrator)
                .with_confidence(0.85)
                .with_notes("Docker container engine")
                .with_process_patterns(vec![r"^dockerd$", r"^containerd$"])
                .with_env_patterns(HashMap::from([
                    ("DOCKER_HOST".into(), ".*".into()),
                ]))
                .with_pid_files(vec!["/var/run/docker.pid", "/run/docker.pid"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("kubernetes", SupervisorCategory::Orchestrator)
                .with_confidence(0.90)
                .with_notes("Kubernetes")
                .with_process_patterns(vec![r"^kubelet$", r"^kube-proxy$"])
                .with_env_patterns(HashMap::from([
                    ("KUBERNETES_SERVICE_HOST".into(), ".*".into()),
                ]))
                .as_builtin(),
        );
    }

    /// Export to the legacy SupervisorDatabase format.
    pub fn to_supervisor_database(&self) -> super::types::SupervisorDatabase {
        let mut db = super::types::SupervisorDatabase::new();
        for sig in &self.signatures {
            if !sig.patterns.process_names.is_empty() {
                db.add(sig.to_supervisor_pattern());
            }
        }
        db
    }

    /// Export to the legacy EnvironDatabase format.
    pub fn to_environ_database(&self) -> super::environ::EnvironDatabase {
        let mut db = super::environ::EnvironDatabase::new();
        for sig in &self.signatures {
            for pattern in sig.to_env_patterns() {
                db.add(pattern);
            }
        }
        db
    }

    /// Export to the legacy IpcDatabase format.
    pub fn to_ipc_database(&self) -> super::ipc::IpcDatabase {
        let mut db = super::ipc::IpcDatabase::new();
        for sig in &self.signatures {
            for pattern in sig.to_ipc_patterns() {
                db.add(pattern);
            }
        }
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_creation() {
        let sig = SupervisorSignature::new("test", SupervisorCategory::Agent)
            .with_confidence(0.90)
            .with_notes("Test signature")
            .with_process_patterns(vec![r"^test$"]);

        assert_eq!(sig.name, "test");
        assert_eq!(sig.category, SupervisorCategory::Agent);
        assert_eq!(sig.confidence_weight, 0.90);
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn test_signature_validation_empty_name() {
        let sig = SupervisorSignature::new("", SupervisorCategory::Agent);
        assert!(matches!(sig.validate(), Err(SignatureError::Invalid(_))));
    }

    #[test]
    fn test_signature_validation_invalid_confidence() {
        let mut sig = SupervisorSignature::new("test", SupervisorCategory::Agent);
        sig.confidence_weight = 1.5;
        assert!(matches!(sig.validate(), Err(SignatureError::Invalid(_))));
    }

    #[test]
    fn test_signature_validation_invalid_regex() {
        let sig = SupervisorSignature::new("test", SupervisorCategory::Agent)
            .with_process_patterns(vec![r"[invalid"]);
        assert!(matches!(sig.validate(), Err(SignatureError::InvalidRegex { .. })));
    }

    #[test]
    fn test_signature_database_defaults() {
        let db = SignatureDatabase::with_defaults();
        assert!(!db.is_empty());

        // Check some key signatures exist
        let claude_matches = db.find_by_process_name("claude");
        assert!(!claude_matches.is_empty());
        assert_eq!(claude_matches[0].name, "claude");
        assert_eq!(claude_matches[0].category, SupervisorCategory::Agent);

        let vscode_matches = db.find_by_process_name("code");
        assert!(!vscode_matches.is_empty());
        assert_eq!(vscode_matches[0].name, "vscode");
    }

    #[test]
    fn test_signature_database_env_var_matching() {
        let db = SignatureDatabase::with_defaults();

        let matches = db.find_by_env_var("GITHUB_ACTIONS", "true");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.name == "github-actions"));

        let matches = db.find_by_env_var("VSCODE_PID", "12345");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.name == "vscode"));
    }

    #[test]
    fn test_signature_database_socket_matching() {
        let db = SignatureDatabase::with_defaults();

        let matches = db.find_by_socket_path("/tmp/claude-session-123");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.name == "claude"));

        let matches = db.find_by_socket_path("/tmp/vscode-ipc-456.sock");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.name == "vscode"));
    }

    #[test]
    fn test_signature_database_pid_file_matching() {
        let db = SignatureDatabase::with_defaults();

        let matches = db.find_by_pid_file("/var/run/supervisord.pid");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.name == "supervisord"));
    }

    #[test]
    fn test_signature_schema_json_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("test", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_process_patterns(vec![r"^test$"]),
        );

        let json = schema.to_json().expect("should serialize to JSON");
        let loaded = SignatureSchema::from_json(&json).expect("should parse JSON");

        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "test");
    }

    #[test]
    fn test_signature_schema_toml_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("test", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_process_patterns(vec![r"^test$"]),
        );

        let toml_str = schema.to_toml().expect("should serialize to TOML");
        let loaded = SignatureSchema::from_toml(&toml_str).expect("should parse TOML");

        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "test");
    }

    #[test]
    fn test_signature_schema_version_check() {
        let json = r#"{"schema_version": 999, "signatures": []}"#;
        let result = SignatureSchema::from_json(json);
        assert!(matches!(result, Err(SignatureError::UnsupportedVersion { .. })));
    }

    #[test]
    fn test_export_to_legacy_databases() {
        let db = SignatureDatabase::with_defaults();

        // Check SupervisorDatabase export (patterns field is public)
        let supervisor_db = db.to_supervisor_database();
        assert!(!supervisor_db.patterns.is_empty());

        // Check EnvironDatabase export via find_matches (patterns field is private)
        let environ_db = db.to_environ_database();
        let mut test_env = std::collections::HashMap::new();
        test_env.insert("GITHUB_ACTIONS".to_string(), "true".to_string());
        let matches = environ_db.find_matches(&test_env);
        assert!(!matches.is_empty(), "EnvironDatabase should have patterns loaded");

        // Check IpcDatabase export via find_matches (patterns field is private)
        let ipc_db = db.to_ipc_database();
        let matches = ipc_db.find_matches("/tmp/vscode-ipc-test");
        assert!(!matches.is_empty(), "IpcDatabase should have patterns loaded");
    }

    #[test]
    fn test_signature_to_env_patterns() {
        let sig = SupervisorSignature::new("test", SupervisorCategory::Agent)
            .with_env_patterns(HashMap::from([
                ("VAR1".into(), ".*".into()),
                ("VAR2".into(), "specific".into()),
            ]));

        let patterns = sig.to_env_patterns();
        assert_eq!(patterns.len(), 2);
    }
}
