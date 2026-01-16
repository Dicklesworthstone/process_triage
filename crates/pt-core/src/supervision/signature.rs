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

use super::environ::EnvPattern;
use super::ipc::IpcPattern;
use super::types::{SupervisorCategory, SupervisorPattern};
pub use crate::config::priors::BetaParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Current schema version.
/// Version 2 adds: priors (Beta distributions), expectations (lifetime/CPU),
/// extended patterns (arg_patterns, working_dir_patterns), and match scoring.
pub const SCHEMA_VERSION: u32 = 2;

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

    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<String> for SignatureError {
    fn from(s: String) -> Self {
        SignatureError::Validation(s)
    }
}

/// Bayesian priors for process state classification.
/// These provide signature-specific overrides for the global priors.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SignaturePriors {
    /// Prior probability that a matched process is abandoned.
    /// Higher alpha relative to beta indicates higher abandonment probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<BetaParams>,

    /// Prior probability that a matched process is useful (actively serving a purpose).
    /// Higher alpha relative to beta indicates higher usefulness probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useful: Option<BetaParams>,

    /// Prior probability that a matched process is in useful_bad state.
    /// (Resource hog but still actively used.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useful_bad: Option<BetaParams>,

    /// Prior probability that a matched process is a zombie.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zombie: Option<BetaParams>,
}

impl SignaturePriors {
    /// Create priors indicating high likelihood of usefulness.
    pub fn likely_useful() -> Self {
        Self {
            useful: Some(BetaParams::new(9.0, 1.0)),    // ~90% useful
            abandoned: Some(BetaParams::new(1.0, 9.0)), // ~10% abandoned
            ..Default::default()
        }
    }

    /// Create priors indicating high likelihood of abandonment.
    pub fn likely_abandoned() -> Self {
        Self {
            useful: Some(BetaParams::new(1.0, 4.0)),    // ~20% useful
            abandoned: Some(BetaParams::new(4.0, 1.0)), // ~80% abandoned
            ..Default::default()
        }
    }

    /// Check if any priors are set.
    pub fn is_empty(&self) -> bool {
        self.abandoned.is_none()
            && self.useful.is_none()
            && self.useful_bad.is_none()
            && self.zombie.is_none()
    }

    /// Validate all set priors.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if let Some(ref p) = self.abandoned {
            p.validate().map_err(SignatureError::Invalid)?;
        }
        if let Some(ref p) = self.useful {
            p.validate().map_err(SignatureError::Invalid)?;
        }
        if let Some(ref p) = self.useful_bad {
            p.validate().map_err(SignatureError::Invalid)?;
        }
        if let Some(ref p) = self.zombie {
            p.validate().map_err(SignatureError::Invalid)?;
        }
        Ok(())
    }
}

/// Expected behavioral characteristics for processes matching this signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProcessExpectations {
    /// Typical runtime in seconds for normal operation.
    /// Processes running much shorter may have failed; much longer may be stuck.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typical_lifetime_seconds: Option<u64>,

    /// Maximum normal lifetime in seconds before the process becomes suspicious.
    /// Beyond this, the process should be flagged for review.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_normal_lifetime_seconds: Option<u64>,

    /// Expected CPU utilization during active work (0.0 - 1.0).
    /// E.g., a build process might expect 0.7-0.9 during compilation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_during_run: Option<f64>,

    /// Whether idle CPU (near 0%) is expected/normal for this process type.
    /// True for daemons waiting for events, false for active computation.
    #[serde(default, skip_serializing_if = "is_false")]
    pub idle_cpu_normal: bool,

    /// Expected memory footprint in bytes (rough order of magnitude).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_memory_bytes: Option<u64>,

    /// Whether network activity is expected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub expects_network: bool,

    /// Whether file I/O activity is expected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub expects_disk_io: bool,
}

impl ProcessExpectations {
    /// Create expectations for a short-lived build/compile task.
    pub fn short_lived_task() -> Self {
        Self {
            typical_lifetime_seconds: Some(300),     // 5 minutes typical
            max_normal_lifetime_seconds: Some(3600), // 1 hour max
            cpu_during_run: Some(0.8),
            idle_cpu_normal: false,
            expects_disk_io: true,
            ..Default::default()
        }
    }

    /// Create expectations for a long-running daemon.
    pub fn daemon() -> Self {
        Self {
            typical_lifetime_seconds: None,    // No typical lifetime
            max_normal_lifetime_seconds: None, // Can run indefinitely
            cpu_during_run: Some(0.05),        // Low CPU when serving
            idle_cpu_normal: true,
            expects_network: true,
            ..Default::default()
        }
    }

    /// Create expectations for an interactive development server.
    pub fn dev_server() -> Self {
        Self {
            typical_lifetime_seconds: Some(3600),     // ~1 hour session
            max_normal_lifetime_seconds: Some(28800), // 8 hours max
            cpu_during_run: Some(0.3),
            idle_cpu_normal: true, // Idle between requests
            expects_network: true,
            expects_disk_io: true, // File watching
            ..Default::default()
        }
    }

    /// Check if any expectations are set.
    pub fn is_empty(&self) -> bool {
        self.typical_lifetime_seconds.is_none()
            && self.max_normal_lifetime_seconds.is_none()
            && self.cpu_during_run.is_none()
            && !self.idle_cpu_normal
            && self.expected_memory_bytes.is_none()
            && !self.expects_network
            && !self.expects_disk_io
    }

    /// Validate expectations.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if let Some(cpu) = self.cpu_during_run {
            if !(0.0..=1.0).contains(&cpu) {
                return Err(SignatureError::Invalid(
                    "cpu_during_run must be between 0.0 and 1.0".into(),
                ));
            }
        }
        if let (Some(typical), Some(max)) = (
            self.typical_lifetime_seconds,
            self.max_normal_lifetime_seconds,
        ) {
            if typical > max {
                return Err(SignatureError::Invalid(
                    "typical_lifetime_seconds cannot exceed max_normal_lifetime_seconds".into(),
                ));
            }
        }
        Ok(())
    }
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

    /// Bayesian priors for process state classification (v2).
    /// Overrides global priors when this signature matches.
    #[serde(default, skip_serializing_if = "SignaturePriors::is_empty")]
    pub priors: SignaturePriors,

    /// Expected behavioral characteristics (v2).
    /// Used to detect anomalies in matched processes.
    #[serde(default, skip_serializing_if = "ProcessExpectations::is_empty")]
    pub expectations: ProcessExpectations,

    /// Match priority for conflict resolution (v2).
    /// Higher priority signatures take precedence. Default is 100.
    #[serde(
        default = "default_priority",
        skip_serializing_if = "is_default_priority"
    )]
    pub priority: u32,
}

fn default_priority() -> u32 {
    100
}

fn is_default_priority(p: &u32) -> bool {
    *p == 100
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

    /// Regex patterns for command-line arguments matching.
    /// All patterns must match for an arg match (AND semantics).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_patterns: Vec<String>,

    /// Environment variable patterns: var_name -> expected value regex.
    /// Use ".*" or empty string to match any value (existence check).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment_vars: HashMap<String, String>,

    /// Regex patterns for working directory matching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub working_dir_patterns: Vec<String>,

    /// Path prefixes for IPC socket detection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socket_paths: Vec<String>,

    /// Known PID file locations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pid_files: Vec<String>,

    /// Regex patterns for parent/ancestor process names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_patterns: Vec<String>,

    /// Minimum number of pattern types that must match (default 1).
    /// E.g., min_matches=2 means both process_name AND arg_patterns must match.
    #[serde(default = "default_min_matches", skip_serializing_if = "is_one")]
    pub min_matches: u32,
}

fn default_min_matches() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
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
            priors: SignaturePriors::default(),
            expectations: ProcessExpectations::default(),
            priority: default_priority(),
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

    /// Add argument patterns.
    pub fn with_arg_patterns(mut self, patterns: Vec<&str>) -> Self {
        self.patterns.arg_patterns = patterns.into_iter().map(String::from).collect();
        self
    }

    /// Add working directory patterns.
    pub fn with_working_dir_patterns(mut self, patterns: Vec<&str>) -> Self {
        self.patterns.working_dir_patterns = patterns.into_iter().map(String::from).collect();
        self
    }

    /// Add parent process patterns.
    pub fn with_parent_patterns(mut self, patterns: Vec<&str>) -> Self {
        self.patterns.parent_patterns = patterns.into_iter().map(String::from).collect();
        self
    }

    /// Set Bayesian priors for state classification.
    pub fn with_priors(mut self, priors: SignaturePriors) -> Self {
        self.priors = priors;
        self
    }

    /// Set expected behavioral characteristics.
    pub fn with_expectations(mut self, expectations: ProcessExpectations) -> Self {
        self.expectations = expectations;
        self
    }

    /// Set match priority (higher = more specific).
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set minimum number of pattern types that must match.
    pub fn with_min_matches(mut self, min: u32) -> Self {
        self.patterns.min_matches = min;
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

        for pattern in &self.patterns.arg_patterns {
            regex::Regex::new(pattern).map_err(|e| SignatureError::InvalidRegex {
                pattern: pattern.clone(),
                error: e.to_string(),
            })?;
        }

        for pattern in &self.patterns.working_dir_patterns {
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

        // Validate priors
        self.priors.validate()?;

        // Validate expectations
        self.expectations.validate()?;

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
            .map(|path| IpcPattern::path(&self.name, self.category, path, self.confidence_weight))
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

/// Match priority levels for scoring.
/// Higher values indicate more specific/confident matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchLevel {
    /// No match at all.
    None = 0,
    /// Generic category fallback.
    GenericCategory = 10,
    /// Command pattern matched only.
    CommandOnly = 20,
    /// Command + args pattern matched.
    CommandPlusArgs = 30,
    /// Exact command match (no regex needed).
    ExactCommand = 40,
    /// Multiple pattern types matched (high confidence).
    MultiPattern = 50,
}

/// Details about which patterns matched.
#[derive(Debug, Clone, Default)]
pub struct MatchDetails {
    /// Whether process_names matched.
    pub process_name_matched: bool,
    /// Whether arg_patterns matched.
    pub args_matched: bool,
    /// Whether working_dir_patterns matched.
    pub working_dir_matched: bool,
    /// Whether environment_vars matched.
    pub env_vars_matched: bool,
    /// Whether socket_paths matched.
    pub socket_matched: bool,
    /// Whether parent_patterns matched.
    pub parent_matched: bool,
    /// Number of distinct pattern types that matched.
    pub pattern_types_matched: u32,
}

impl MatchDetails {
    /// Count how many pattern types matched.
    pub fn count_matches(&self) -> u32 {
        let mut count = 0;
        if self.process_name_matched {
            count += 1;
        }
        if self.args_matched {
            count += 1;
        }
        if self.working_dir_matched {
            count += 1;
        }
        if self.env_vars_matched {
            count += 1;
        }
        if self.socket_matched {
            count += 1;
        }
        if self.parent_matched {
            count += 1;
        }
        count
    }
}

/// Result of matching a process against signatures.
#[derive(Debug, Clone)]
pub struct SignatureMatch<'a> {
    /// The matched signature.
    pub signature: &'a SupervisorSignature,
    /// Match level indicating confidence.
    pub level: MatchLevel,
    /// Computed match score (0.0 - 1.0).
    pub score: f64,
    /// Details about which patterns matched.
    pub details: MatchDetails,
}

impl<'a> SignatureMatch<'a> {
    /// Create a new match result.
    pub fn new(
        signature: &'a SupervisorSignature,
        level: MatchLevel,
        details: MatchDetails,
    ) -> Self {
        let score = Self::compute_score(signature, &level, &details);
        Self {
            signature,
            level,
            score,
            details,
        }
    }

    /// Compute overall match score based on level, details, and signature confidence.
    fn compute_score(
        signature: &SupervisorSignature,
        level: &MatchLevel,
        details: &MatchDetails,
    ) -> f64 {
        // Base score from match level
        let level_score = match level {
            MatchLevel::None => 0.0,
            MatchLevel::GenericCategory => 0.2,
            MatchLevel::CommandOnly => 0.5,
            MatchLevel::CommandPlusArgs => 0.7,
            MatchLevel::ExactCommand => 0.85,
            MatchLevel::MultiPattern => 0.95,
        };

        // Bonus for multiple pattern types matching
        let pattern_bonus = (details.count_matches() as f64 - 1.0).max(0.0) * 0.05;

        // Apply signature confidence weight
        let raw_score = (level_score + pattern_bonus).min(1.0);
        raw_score * signature.confidence_weight
    }
}

/// Context about a process for matching.
#[derive(Debug, Clone, Default)]
pub struct ProcessMatchContext<'a> {
    /// Process name (comm).
    pub comm: &'a str,
    /// Full command line arguments.
    pub cmdline: Option<&'a str>,
    /// Working directory path.
    pub cwd: Option<&'a str>,
    /// Environment variables (name -> value).
    pub env_vars: Option<&'a HashMap<String, String>>,
    /// Socket paths the process has open.
    pub socket_paths: Option<&'a [String]>,
    /// Parent process name.
    pub parent_comm: Option<&'a str>,
}

impl<'a> ProcessMatchContext<'a> {
    /// Create context with just the process name.
    pub fn with_comm(comm: &'a str) -> Self {
        Self {
            comm,
            ..Default::default()
        }
    }

    /// Set command line arguments.
    pub fn cmdline(mut self, cmdline: &'a str) -> Self {
        self.cmdline = Some(cmdline);
        self
    }

    /// Set working directory.
    pub fn cwd(mut self, cwd: &'a str) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Set environment variables.
    pub fn env_vars(mut self, env: &'a HashMap<String, String>) -> Self {
        self.env_vars = Some(env);
        self
    }

    /// Set socket paths.
    pub fn socket_paths(mut self, paths: &'a [String]) -> Self {
        self.socket_paths = Some(paths);
        self
    }

    /// Set parent process name.
    pub fn parent_comm(mut self, parent: &'a str) -> Self {
        self.parent_comm = Some(parent);
        self
    }
}

/// Unified signature database combining all detection methods.
#[derive(Debug, Clone, Default)]
pub struct SignatureDatabase {
    /// All loaded signatures.
    signatures: Vec<SupervisorSignature>,
    /// Compiled regex patterns for process names (cached).
    process_regexes: Vec<Vec<regex::Regex>>,
    /// Compiled regex patterns for arguments (cached).
    arg_regexes: Vec<Vec<regex::Regex>>,
    /// Compiled regex patterns for working directories (cached).
    working_dir_regexes: Vec<Vec<regex::Regex>>,
    /// Compiled regex patterns for parent processes (cached).
    parent_regexes: Vec<Vec<regex::Regex>>,
}

impl SignatureDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self {
            signatures: vec![],
            process_regexes: vec![],
            arg_regexes: vec![],
            working_dir_regexes: vec![],
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
        
        // Compile process name regexes
        let mut proc_res = Vec::new();
        for pattern in &signature.patterns.process_names {
            if let Ok(re) = regex::Regex::new(pattern) {
                proc_res.push(re);
            }
        }
        self.process_regexes.push(proc_res);

        // Compile argument regexes
        let mut arg_res = Vec::new();
        for pattern in &signature.patterns.arg_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                arg_res.push(re);
            }
        }
        self.arg_regexes.push(arg_res);

        // Compile working directory regexes
        let mut wd_res = Vec::new();
        for pattern in &signature.patterns.working_dir_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                wd_res.push(re);
            }
        }
        self.working_dir_regexes.push(wd_res);

        // Compile parent pattern regexes
        let mut parent_res = Vec::new();
        for pattern in &signature.patterns.parent_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                parent_res.push(re);
            }
        }
        self.parent_regexes.push(parent_res);

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
        for (idx, regexes) in self.process_regexes.iter().enumerate() {
            for re in regexes {
                if re.is_match(comm) {
                    matches.push(&self.signatures[idx]);
                    break; // Once per signature is enough
                }
            }
        }
        // Deduplicate by signature index not needed with break, but safe to keep logic simple
        matches
    }

    /// Find signatures matching a parent process name.
    pub fn find_by_parent_name(&self, comm: &str) -> Vec<&SupervisorSignature> {
        let mut matches = Vec::new();
        for (idx, regexes) in self.parent_regexes.iter().enumerate() {
            for re in regexes {
                if re.is_match(comm) {
                    matches.push(&self.signatures[idx]);
                    break;
                }
            }
        }
        matches
    }

    /// Find signatures matching an environment variable.
    pub fn find_by_env_var(&self, var_name: &str, var_value: &str) -> Vec<&SupervisorSignature> {
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
            .filter(|sig| {
                sig.patterns
                    .pid_files
                    .iter()
                    .any(|p| path == p || path.starts_with(p))
            })
            .collect()
    }

    /// Match a process against all signatures with comprehensive scoring.
    ///
    /// Returns all matching signatures sorted by score (best match first).
    /// Uses priority rules:
    /// 1. Exact match on command (highest priority)
    /// 2. Pattern match on command plus args
    /// 3. Pattern match on command only
    /// 4. Fallback to generic category
    ///
    /// Performance target: <10ms for 50+ signatures.
    pub fn match_process<'a>(&'a self, ctx: &ProcessMatchContext<'_>) -> Vec<SignatureMatch<'a>> {
        let mut matches: Vec<SignatureMatch<'a>> = Vec::new();

        // Pre-calculate exact match string to avoid allocation in loop
        let exact_match_target = format!("^{}$", regex::escape(ctx.comm));

        for (sig_idx, sig) in self.signatures.iter().enumerate() {
            let mut details = MatchDetails::default();

            // Check process name patterns
            let process_name_matched = self.process_regexes[sig_idx]
                .iter()
                .any(|re| re.is_match(ctx.comm));
            details.process_name_matched = process_name_matched;

            // Check exact command match (higher priority than pattern)
            let exact_command_match = sig
                .patterns
                .process_names
                .iter()
                .any(|p| p == &exact_match_target);

            // Check argument patterns
            let args_matched = if let Some(cmdline) = ctx.cmdline {
                if sig.patterns.arg_patterns.is_empty() {
                    false
                } else {
                    // All arg patterns must match (AND semantics)
                    // Optimization: check if regex list is empty first
                    let regexes = &self.arg_regexes[sig_idx];
                    if regexes.is_empty() {
                        // Should match sig.patterns.arg_patterns.is_empty(), but for safety:
                        false
                    } else {
                        regexes.iter().all(|re| re.is_match(cmdline))
                    }
                }
            } else {
                false
            };
            details.args_matched = args_matched;

            // Check working directory patterns
            let working_dir_matched = if let Some(cwd) = ctx.cwd {
                self.working_dir_regexes[sig_idx]
                    .iter()
                    .any(|re| re.is_match(cwd))
            } else {
                false
            };
            details.working_dir_matched = working_dir_matched;

            // Check environment variables
            let env_vars_matched = if let Some(env) = ctx.env_vars {
                if sig.patterns.environment_vars.is_empty() {
                    false
                } else {
                    sig.patterns
                        .environment_vars
                        .iter()
                        .any(|(var_name, pattern)| {
                            if let Some(var_value) = env.get(var_name) {
                                if pattern.is_empty() || pattern == ".*" {
                                    true
                                } else {
                                    regex::Regex::new(pattern)
                                        .map(|re| re.is_match(var_value))
                                        .unwrap_or(false)
                                }
                            } else {
                                false
                            }
                        })
                }
            } else {
                false
            };
            details.env_vars_matched = env_vars_matched;

            // Check socket paths
            let socket_matched = if let Some(sockets) = ctx.socket_paths {
                sig.patterns
                    .socket_paths
                    .iter()
                    .any(|prefix| sockets.iter().any(|s| s.starts_with(prefix)))
            } else {
                false
            };
            details.socket_matched = socket_matched;

            // Check parent patterns
            let parent_matched = if let Some(parent) = ctx.parent_comm {
                self.parent_regexes[sig_idx]
                    .iter()
                    .any(|re| re.is_match(parent))
            } else {
                false
            };
            details.parent_matched = parent_matched;

            // Update pattern types matched count
            details.pattern_types_matched = details.count_matches();

            // Determine match level
            let level = if details.pattern_types_matched == 0 {
                continue; // No match, skip this signature
            } else if details.pattern_types_matched >= 2 {
                MatchLevel::MultiPattern
            } else if exact_command_match && process_name_matched {
                MatchLevel::ExactCommand
            } else if process_name_matched && args_matched {
                MatchLevel::CommandPlusArgs
            } else if process_name_matched {
                MatchLevel::CommandOnly
            } else {
                // Matched on something other than process name (env, socket, etc.)
                MatchLevel::GenericCategory
            };

            // Check if min_matches requirement is satisfied
            if details.pattern_types_matched < sig.patterns.min_matches {
                continue;
            }

            matches.push(SignatureMatch::new(sig, level, details));
        }

        // Sort by score (descending), then by priority (descending)
        matches.sort_by(|a, b| {
            // First compare scores
            let score_cmp = b
                .score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal);
            if score_cmp != std::cmp::Ordering::Equal {
                return score_cmp;
            }
            // Then compare priorities
            b.signature.priority.cmp(&a.signature.priority)
        });

        matches
    }

    /// Get the best matching signature for a process, if any.
    pub fn best_match<'a>(&'a self, ctx: &ProcessMatchContext<'_>) -> Option<SignatureMatch<'a>> {
        self.match_process(ctx).into_iter().next()
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
                .with_pid_files(vec!["/actions-runner/.runner", "~/.actions-runner/.runner"])
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
            SupervisorSignature::new("nodemon", SupervisorCategory::Orchestrator)
                .with_confidence(0.85)
                .with_notes("nodemon - Node.js file watcher and auto-restarter")
                .with_process_patterns(vec![r"^nodemon$", r"^node.*nodemon"])
                .with_env_patterns(HashMap::from([("NODEMON_CONFIG".into(), ".*".into())]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("forever", SupervisorCategory::Orchestrator)
                .with_confidence(0.85)
                .with_notes("forever - Node.js process manager")
                .with_process_patterns(vec![r"^forever$", r"^node.*forever"])
                .with_env_patterns(HashMap::from([("FOREVER_ROOT".into(), ".*".into())]))
                .with_pid_files(vec!["~/.forever/pids/", "/var/run/forever/"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("docker", SupervisorCategory::Orchestrator)
                .with_confidence(0.85)
                .with_notes("Docker container engine")
                .with_process_patterns(vec![r"^dockerd$", r"^containerd$"])
                .with_env_patterns(HashMap::from([("DOCKER_HOST".into(), ".*".into())]))
                .with_pid_files(vec!["/var/run/docker.pid", "/run/docker.pid"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("kubernetes", SupervisorCategory::Orchestrator)
                .with_confidence(0.90)
                .with_notes("Kubernetes")
                .with_process_patterns(vec![r"^kubelet$", r"^kube-proxy$"])
                .with_env_patterns(HashMap::from([(
                    "KUBERNETES_SERVICE_HOST".into(),
                    ".*".into(),
                )]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("podman", SupervisorCategory::Orchestrator)
                .with_confidence(0.85)
                .with_notes("Podman container engine")
                .with_process_patterns(vec![r"^podman$", r"^conmon$"])
                .with_env_patterns(HashMap::from([("CONTAINER_HOST".into(), ".*".into())]))
                .as_builtin(),
        );

        // AI Agents (additional)
        let _ = self.add(
            SupervisorSignature::new("copilot", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_notes("GitHub Copilot")
                .with_process_patterns(vec![r"^copilot$", r"^copilot-agent$"])
                .with_env_patterns(HashMap::from([
                    ("GITHUB_COPILOT_TOKEN".into(), ".*".into()),
                ]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("codeium", SupervisorCategory::Agent)
                .with_confidence(0.85)
                .with_notes("Codeium AI coding assistant")
                .with_process_patterns(vec![r"^codeium$", r"^codeium_language_server$"])
                .with_env_patterns(HashMap::from([("CODEIUM_API_KEY".into(), ".*".into())]))
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("tabnine", SupervisorCategory::Agent)
                .with_confidence(0.85)
                .with_notes("Tabnine AI assistant")
                .with_process_patterns(vec![r"^TabNine$", r"^tabnine$"])
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("continue", SupervisorCategory::Agent)
                .with_confidence(0.85)
                .with_notes("Continue AI coding assistant")
                .with_process_patterns(vec![r"^continue$"])
                .with_env_patterns(HashMap::from([("CONTINUE_GLOBAL_DIR".into(), ".*".into())]))
                .as_builtin(),
        );

        // Test Runners
        let _ = self.add(
            SupervisorSignature::new("jest", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Jest JavaScript test runner")
                .with_process_patterns(vec![r"^jest$"])
                .with_arg_patterns(vec![r"jest"])
                .with_env_patterns(HashMap::from([("JEST_WORKER_ID".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("mocha", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Mocha JavaScript test runner")
                .with_process_patterns(vec![r"^mocha$", r"^_mocha$"])
                .with_arg_patterns(vec![r"mocha"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("vitest", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Vitest test runner")
                .with_process_patterns(vec![r"^vitest$"])
                .with_arg_patterns(vec![r"vitest"])
                .with_env_patterns(HashMap::from([("VITEST".into(), "true".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("pytest", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("pytest Python test runner")
                .with_process_patterns(vec![r"^pytest$", r"^py\.test$"])
                .with_arg_patterns(vec![r"pytest", r"py\.test"])
                .with_env_patterns(HashMap::from([("PYTEST_CURRENT_TEST".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("cargo-test", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Cargo test runner for Rust")
                .with_arg_patterns(vec![r"cargo.*test", r"cargo-nextest"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("go-test", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Go test runner")
                .with_arg_patterns(vec![r"go\s+test"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("rspec", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("RSpec Ruby test runner")
                .with_process_patterns(vec![r"^rspec$"])
                .with_arg_patterns(vec![r"rspec"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("phpunit", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("PHPUnit test runner")
                .with_process_patterns(vec![r"^phpunit$"])
                .with_arg_patterns(vec![r"phpunit"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("junit", SupervisorCategory::Other)
                .with_confidence(0.75)
                .with_notes("JUnit Java test runner")
                .with_arg_patterns(vec![r"junit", r"org\.junit"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("playwright", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Playwright E2E test runner")
                .with_process_patterns(vec![r"^playwright$"])
                .with_arg_patterns(vec![r"playwright"])
                .with_env_patterns(HashMap::from([("PLAYWRIGHT_BROWSERS_PATH".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("cypress", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Cypress E2E test runner")
                .with_process_patterns(vec![r"^Cypress$", r"^cypress$"])
                .with_arg_patterns(vec![r"cypress"])
                .with_env_patterns(HashMap::from([("CYPRESS_CACHE_FOLDER".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        // Dev Servers
        let _ = self.add(
            SupervisorSignature::new("next-dev", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Next.js development server")
                .with_arg_patterns(vec![r"next\s+dev", r"next-server"])
                .with_env_patterns(HashMap::from([("NEXT_RUNTIME".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("vite", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Vite development server")
                .with_process_patterns(vec![r"^vite$"])
                .with_arg_patterns(vec![r"vite"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("webpack-dev-server", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Webpack development server")
                .with_arg_patterns(vec![r"webpack-dev-server", r"webpack\s+serve"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("create-react-app", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Create React App dev server")
                .with_arg_patterns(vec![r"react-scripts\s+start"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("flask", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Flask Python web server")
                .with_arg_patterns(vec![r"flask\s+run", r"-m\s+flask"])
                .with_env_patterns(HashMap::from([("FLASK_APP".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("django", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Django Python web server")
                .with_arg_patterns(vec![r"manage\.py\s+runserver", r"django"])
                .with_env_patterns(HashMap::from([("DJANGO_SETTINGS_MODULE".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("rails", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Ruby on Rails server")
                .with_arg_patterns(vec![r"rails\s+server", r"rails\s+s\b"])
                .with_env_patterns(HashMap::from([("RAILS_ENV".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .as_builtin(),
        );

        // Build Tools
        let _ = self.add(
            SupervisorSignature::new("webpack", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Webpack bundler")
                .with_process_patterns(vec![r"^webpack$"])
                .with_arg_patterns(vec![r"webpack"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("esbuild", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("esbuild bundler")
                .with_process_patterns(vec![r"^esbuild$"])
                .with_arg_patterns(vec![r"esbuild"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("rollup", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Rollup bundler")
                .with_process_patterns(vec![r"^rollup$"])
                .with_arg_patterns(vec![r"rollup"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("tsc", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("TypeScript compiler")
                .with_process_patterns(vec![r"^tsc$"])
                .with_arg_patterns(vec![r"tsc\b", r"typescript"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("cargo-build", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Cargo build for Rust")
                .with_arg_patterns(vec![r"cargo\s+build", r"cargo\s+check"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("go-build", SupervisorCategory::Other)
                .with_confidence(0.85)
                .with_notes("Go build")
                .with_arg_patterns(vec![r"go\s+build", r"go\s+install"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("make", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("GNU Make")
                .with_process_patterns(vec![r"^make$", r"^gmake$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("cmake", SupervisorCategory::Other)
                .with_confidence(0.75)
                .with_notes("CMake build system")
                .with_process_patterns(vec![r"^cmake$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("maven", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Apache Maven")
                .with_process_patterns(vec![r"^mvn$"])
                .with_arg_patterns(vec![r"mvn", r"maven"])
                .with_env_patterns(HashMap::from([("MAVEN_HOME".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("gradle", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Gradle build tool")
                .with_process_patterns(vec![r"^gradle$", r"^gradlew$"])
                .with_env_patterns(HashMap::from([("GRADLE_HOME".into(), ".*".into())]))
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        // Databases
        let _ = self.add(
            SupervisorSignature::new("postgres", SupervisorCategory::Other)
                .with_confidence(0.90)
                .with_notes("PostgreSQL database")
                .with_process_patterns(vec![r"^postgres$", r"^postmaster$"])
                .with_pid_files(vec!["/var/run/postgresql/", "/tmp/.s.PGSQL"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("mysql", SupervisorCategory::Other)
                .with_confidence(0.90)
                .with_notes("MySQL database")
                .with_process_patterns(vec![r"^mysqld$", r"^mariadbd?$"])
                .with_pid_files(vec!["/var/run/mysqld/", "/var/lib/mysql/"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("redis", SupervisorCategory::Other)
                .with_confidence(0.90)
                .with_notes("Redis in-memory store")
                .with_process_patterns(vec![r"^redis-server$"])
                .with_pid_files(vec!["/var/run/redis/"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("mongodb", SupervisorCategory::Other)
                .with_confidence(0.90)
                .with_notes("MongoDB database")
                .with_process_patterns(vec![r"^mongod$", r"^mongos$"])
                .with_pid_files(vec!["/var/run/mongodb/"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("sqlite", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("SQLite database CLI")
                .with_process_patterns(vec![r"^sqlite3$"])
                .as_builtin(),
        );

        // Language Servers (LSP)
        let _ = self.add(
            SupervisorSignature::new("rust-analyzer", SupervisorCategory::Ide)
                .with_confidence(0.90)
                .with_notes("Rust language server")
                .with_process_patterns(vec![r"^rust-analyzer$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("gopls", SupervisorCategory::Ide)
                .with_confidence(0.90)
                .with_notes("Go language server")
                .with_process_patterns(vec![r"^gopls$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("typescript-language-server", SupervisorCategory::Ide)
                .with_confidence(0.90)
                .with_notes("TypeScript language server")
                .with_process_patterns(vec![r"^tsserver$", r"^typescript-language-server$"])
                .with_arg_patterns(vec![r"tsserver", r"typescript-language-server"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("pylsp", SupervisorCategory::Ide)
                .with_confidence(0.85)
                .with_notes("Python language server")
                .with_process_patterns(vec![r"^pylsp$", r"^pyls$", r"^python-language-server$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("clangd", SupervisorCategory::Ide)
                .with_confidence(0.90)
                .with_notes("C/C++ language server")
                .with_process_patterns(vec![r"^clangd$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("solargraph", SupervisorCategory::Ide)
                .with_confidence(0.85)
                .with_notes("Ruby language server")
                .with_process_patterns(vec![r"^solargraph$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::daemon())
                .as_builtin(),
        );

        // Package Managers / Installers
        let _ = self.add(
            SupervisorSignature::new("npm", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("npm package manager")
                .with_process_patterns(vec![r"^npm$"])
                .with_arg_patterns(vec![r"npm\s+(install|ci|run)"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("yarn", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("Yarn package manager")
                .with_process_patterns(vec![r"^yarn$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("pnpm", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("pnpm package manager")
                .with_process_patterns(vec![r"^pnpm$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("pip", SupervisorCategory::Other)
                .with_confidence(0.70)
                .with_notes("pip Python package manager")
                .with_process_patterns(vec![r"^pip$", r"^pip3$"])
                .with_arg_patterns(vec![r"pip\s+install"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        // Linters / Formatters
        let _ = self.add(
            SupervisorSignature::new("eslint", SupervisorCategory::Other)
                .with_confidence(0.75)
                .with_notes("ESLint JavaScript linter")
                .with_process_patterns(vec![r"^eslint$"])
                .with_arg_patterns(vec![r"eslint"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("prettier", SupervisorCategory::Other)
                .with_confidence(0.75)
                .with_notes("Prettier code formatter")
                .with_process_patterns(vec![r"^prettier$"])
                .with_arg_patterns(vec![r"prettier"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("black", SupervisorCategory::Other)
                .with_confidence(0.75)
                .with_notes("Black Python formatter")
                .with_process_patterns(vec![r"^black$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("rustfmt", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Rust code formatter")
                .with_process_patterns(vec![r"^rustfmt$"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .as_builtin(),
        );

        let _ = self.add(
            SupervisorSignature::new("clippy", SupervisorCategory::Other)
                .with_confidence(0.80)
                .with_notes("Clippy Rust linter")
                .with_arg_patterns(vec![r"clippy"])
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
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
        assert!(matches!(
            sig.validate(),
            Err(SignatureError::InvalidRegex { .. })
        ));
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
        assert!(matches!(
            result,
            Err(SignatureError::UnsupportedVersion { .. })
        ));
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
        assert!(
            !matches.is_empty(),
            "EnvironDatabase should have patterns loaded"
        );

        // Check IpcDatabase export via find_matches (patterns field is private)
        let ipc_db = db.to_ipc_database();
        let matches = ipc_db.find_matches("/tmp/vscode-ipc-test");
        assert!(
            !matches.is_empty(),
            "IpcDatabase should have patterns loaded"
        );
    }

    #[test]
    fn test_signature_to_env_patterns() {
        let sig = SupervisorSignature::new("test", SupervisorCategory::Agent).with_env_patterns(
            HashMap::from([
                ("VAR1".into(), ".*".into()),
                ("VAR2".into(), "specific".into()),
            ]),
        );

        let patterns = sig.to_env_patterns();
        assert_eq!(patterns.len(), 2);
    }

    // ==================== v2 Feature Tests ====================

    #[test]
    fn test_beta_params_mean() {
        let uniform = BetaParams::uniform();
        assert!((uniform.mean() - 0.5).abs() < 0.001);

        let skewed = BetaParams::new(9.0, 1.0);
        assert!((skewed.mean() - 0.9).abs() < 0.001);

        let opposite = BetaParams::new(1.0, 9.0);
        assert!((opposite.mean() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_beta_params_mode() {
        // Uniform has no mode (alpha == beta == 1)
        let uniform = BetaParams::uniform();
        assert!(uniform.mode().is_none());

        // Weakly informative has mode at 0.5
        let weak = BetaParams::weakly_informative();
        let mode = weak.mode().unwrap();
        assert!((mode - 0.5).abs() < 0.001);

        // Skewed distribution
        let skewed = BetaParams::new(9.0, 2.0);
        let mode = skewed.mode().unwrap();
        // Mode = (9 - 1) / (9 + 2 - 2) = 8 / 9 ≈ 0.889
        assert!((mode - 0.889).abs() < 0.01);
    }

    #[test]
    fn test_beta_params_variance() {
        let uniform = BetaParams::uniform();
        // Variance of Beta(1,1) = 1*1 / (2*2*3) = 1/12 ≈ 0.0833
        assert!((uniform.variance() - 0.0833).abs() < 0.001);

        let concentrated = BetaParams::new(10.0, 10.0);
        // More concentrated around the mean, lower variance
        assert!(concentrated.variance() < uniform.variance());
    }

    #[test]
    fn test_beta_params_validation() {
        // Valid params
        let valid = BetaParams::new(1.0, 1.0);
        assert!(valid.validate().is_ok());

        // Invalid: zero or negative
        let invalid = BetaParams::new(0.0, 1.0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_signature_priors_likely_useful() {
        let priors = SignaturePriors::likely_useful();

        // Should have high usefulness prior
        assert!(priors.useful.is_some());
        let useful = priors.useful.unwrap();
        assert!(useful.mean() > 0.8);

        // Should have low abandonment prior
        assert!(priors.abandoned.is_some());
        let abandoned = priors.abandoned.unwrap();
        assert!(abandoned.mean() < 0.2);
    }

    #[test]
    fn test_signature_priors_likely_abandoned() {
        let priors = SignaturePriors::likely_abandoned();

        // Should have high abandonment prior
        assert!(priors.abandoned.is_some());
        let abandoned = priors.abandoned.unwrap();
        assert!(abandoned.mean() > 0.7);

        // Should have low usefulness prior
        assert!(priors.useful.is_some());
        let useful = priors.useful.unwrap();
        assert!(useful.mean() < 0.3);
    }

    #[test]
    fn test_signature_priors_is_empty() {
        let empty = SignaturePriors::default();
        assert!(empty.is_empty());

        let with_useful = SignaturePriors {
            useful: Some(BetaParams::uniform()),
            ..Default::default()
        };
        assert!(!with_useful.is_empty());
    }

    #[test]
    fn test_signature_priors_validation() {
        // Valid priors
        let valid = SignaturePriors::likely_useful();
        assert!(valid.validate().is_ok());

        // Invalid priors (negative alpha)
        let invalid = SignaturePriors {
            useful: Some(BetaParams::new(-1.0, 1.0)),
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_process_expectations_short_lived_task() {
        let exp = ProcessExpectations::short_lived_task();

        assert!(exp.typical_lifetime_seconds.is_some());
        assert!(exp.max_normal_lifetime_seconds.is_some());
        assert!(!exp.idle_cpu_normal);
        assert!(exp.expects_disk_io);
        assert!(!exp.is_empty());
    }

    #[test]
    fn test_process_expectations_daemon() {
        let exp = ProcessExpectations::daemon();

        // Daemons have no typical lifetime
        assert!(exp.typical_lifetime_seconds.is_none());
        assert!(exp.max_normal_lifetime_seconds.is_none());
        assert!(exp.idle_cpu_normal);
        assert!(exp.expects_network);
        assert!(!exp.is_empty());
    }

    #[test]
    fn test_process_expectations_dev_server() {
        let exp = ProcessExpectations::dev_server();

        assert!(exp.typical_lifetime_seconds.is_some());
        assert!(exp.idle_cpu_normal);
        assert!(exp.expects_network);
        assert!(exp.expects_disk_io);
        assert!(!exp.is_empty());
    }

    #[test]
    fn test_process_expectations_validation() {
        // Valid expectations
        let valid = ProcessExpectations::short_lived_task();
        assert!(valid.validate().is_ok());

        // Invalid: CPU out of range
        let invalid_cpu = ProcessExpectations {
            cpu_during_run: Some(1.5),
            ..Default::default()
        };
        assert!(invalid_cpu.validate().is_err());

        // Invalid: typical > max
        let invalid_lifetime = ProcessExpectations {
            typical_lifetime_seconds: Some(1000),
            max_normal_lifetime_seconds: Some(500),
            ..Default::default()
        };
        assert!(invalid_lifetime.validate().is_err());
    }

    #[test]
    fn test_process_expectations_is_empty() {
        let empty = ProcessExpectations::default();
        assert!(empty.is_empty());

        let with_cpu = ProcessExpectations {
            cpu_during_run: Some(0.5),
            ..Default::default()
        };
        assert!(!with_cpu.is_empty());
    }

    #[test]
    fn test_match_details_count_matches() {
        let empty = MatchDetails::default();
        assert_eq!(empty.count_matches(), 0);

        let one_match = MatchDetails {
            process_name_matched: true,
            ..Default::default()
        };
        assert_eq!(one_match.count_matches(), 1);

        let two_matches = MatchDetails {
            process_name_matched: true,
            args_matched: true,
            ..Default::default()
        };
        assert_eq!(two_matches.count_matches(), 2);

        let all_matches = MatchDetails {
            process_name_matched: true,
            args_matched: true,
            working_dir_matched: true,
            env_vars_matched: true,
            socket_matched: true,
            parent_matched: true,
            pattern_types_matched: 6,
        };
        assert_eq!(all_matches.count_matches(), 6);
    }

    #[test]
    fn test_process_match_context_builder() {
        let env = HashMap::from([("FOO".to_string(), "bar".to_string())]);
        let sockets = vec!["/tmp/sock".to_string()];

        let ctx = ProcessMatchContext::with_comm("test")
            .cmdline("test --arg1 --arg2")
            .cwd("/home/user/project")
            .env_vars(&env)
            .socket_paths(&sockets)
            .parent_comm("parent");

        assert_eq!(ctx.comm, "test");
        assert_eq!(ctx.cmdline, Some("test --arg1 --arg2"));
        assert_eq!(ctx.cwd, Some("/home/user/project"));
        assert!(ctx.env_vars.is_some());
        assert!(ctx.socket_paths.is_some());
        assert_eq!(ctx.parent_comm, Some("parent"));
    }

    #[test]
    fn test_match_process_basic() {
        let db = SignatureDatabase::with_defaults();

        // Test matching claude process
        let ctx = ProcessMatchContext::with_comm("claude");
        let matches = db.match_process(&ctx);

        assert!(!matches.is_empty());
        assert_eq!(matches[0].signature.name, "claude");
        assert!(matches[0].level >= MatchLevel::CommandOnly);
    }

    #[test]
    fn test_match_process_no_match() {
        let db = SignatureDatabase::with_defaults();

        // Non-supervisor process should not match
        let ctx = ProcessMatchContext::with_comm("random_process_xyz");
        let matches = db.match_process(&ctx);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_process_with_env_var() {
        let db = SignatureDatabase::with_defaults();

        let env = HashMap::from([("VSCODE_PID".to_string(), "12345".to_string())]);

        // Even if process name doesn't match, env var should match vscode
        let ctx = ProcessMatchContext::with_comm("some_shell").env_vars(&env);
        let matches = db.match_process(&ctx);

        // Should have a match from environment
        assert!(matches.iter().any(|m| m.signature.name == "vscode"));
    }

    #[test]
    fn test_match_process_with_socket() {
        let db = SignatureDatabase::with_defaults();

        let sockets = vec!["/tmp/claude-session-123".to_string()];

        let ctx = ProcessMatchContext::with_comm("shell").socket_paths(&sockets);
        let matches = db.match_process(&ctx);

        // Should match claude via socket path
        assert!(matches.iter().any(|m| m.signature.name == "claude"));
    }

    #[test]
    fn test_match_process_multi_pattern() {
        let db = SignatureDatabase::with_defaults();

        let env = HashMap::from([("VSCODE_PID".to_string(), "12345".to_string())]);
        let sockets = vec!["/tmp/vscode-ipc-456.sock".to_string()];

        // Match on process name, env var, and socket - should get MultiPattern level
        let ctx = ProcessMatchContext::with_comm("code")
            .env_vars(&env)
            .socket_paths(&sockets);
        let matches = db.match_process(&ctx);

        assert!(!matches.is_empty());
        let vscode_match = matches.iter().find(|m| m.signature.name == "vscode");
        assert!(vscode_match.is_some());

        // Should have MultiPattern level due to multiple pattern types
        let m = vscode_match.unwrap();
        assert_eq!(m.level, MatchLevel::MultiPattern);
        assert!(m.details.pattern_types_matched >= 2);
    }

    #[test]
    fn test_best_match() {
        let db = SignatureDatabase::with_defaults();

        let ctx = ProcessMatchContext::with_comm("claude");
        let best = db.best_match(&ctx);

        assert!(best.is_some());
        assert_eq!(best.unwrap().signature.name, "claude");
    }

    #[test]
    fn test_best_match_none() {
        let db = SignatureDatabase::with_defaults();

        let ctx = ProcessMatchContext::with_comm("nonexistent_process_xyz");
        let best = db.best_match(&ctx);

        assert!(best.is_none());
    }

    #[test]
    fn test_signature_with_priors_and_expectations() {
        let sig = SupervisorSignature::new("test-server", SupervisorCategory::Ide)
            .with_confidence(0.85)
            .with_process_patterns(vec![r"^test-server$"])
            .with_priors(SignaturePriors::likely_useful())
            .with_expectations(ProcessExpectations::dev_server())
            .with_priority(150);

        assert!(sig.validate().is_ok());
        assert!(!sig.priors.is_empty());
        assert!(!sig.expectations.is_empty());
        assert_eq!(sig.priority, 150);
    }

    #[test]
    fn test_signature_priority_affects_sorting() {
        let mut db = SignatureDatabase::new();

        // Add two signatures that both match "node"
        let _ = db.add(
            SupervisorSignature::new("generic-node", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^node$"])
                .with_priority(50), // Lower priority
        );
        let _ = db.add(
            SupervisorSignature::new("specific-node", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^node$"])
                .with_priority(150), // Higher priority
        );

        let ctx = ProcessMatchContext::with_comm("node");
        let matches = db.match_process(&ctx);

        assert_eq!(matches.len(), 2);
        // Higher priority should come first when scores are equal
        assert_eq!(matches[0].signature.name, "specific-node");
        assert_eq!(matches[1].signature.name, "generic-node");
    }

    #[test]
    fn test_min_matches_requirement() {
        let mut db = SignatureDatabase::new();

        // Signature requiring both process name AND arg patterns
        let _ = db.add(
            SupervisorSignature::new("strict-match", SupervisorCategory::Agent)
                .with_process_patterns(vec![r"^myapp$"])
                .with_arg_patterns(vec![r"--special-mode"])
                .with_min_matches(2), // Require both to match
        );

        // Just process name - should NOT match (only 1 pattern type)
        let ctx1 = ProcessMatchContext::with_comm("myapp");
        let matches1 = db.match_process(&ctx1);
        assert!(matches1.is_empty());

        // Process name + args - should match (2 pattern types)
        let ctx2 = ProcessMatchContext::with_comm("myapp").cmdline("myapp --special-mode --other");
        let matches2 = db.match_process(&ctx2);
        assert!(!matches2.is_empty());
    }

    #[test]
    fn test_arg_patterns_matching() {
        let mut db = SignatureDatabase::new();

        let _ = db.add(
            SupervisorSignature::new("jest-watch", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^node$"])
                .with_arg_patterns(vec![r"jest", r"--watch"]),
        );

        // With matching args
        let ctx_match = ProcessMatchContext::with_comm("node")
            .cmdline("node ./node_modules/.bin/jest --watch src/");
        let matches = db.match_process(&ctx_match);
        assert!(matches.iter().any(|m| m.signature.name == "jest-watch"));

        // Without --watch (partial arg match - needs ALL)
        let ctx_partial = ProcessMatchContext::with_comm("node")
            .cmdline("node ./node_modules/.bin/jest src/test.js");
        let matches_partial = db.match_process(&ctx_partial);
        // Should not match because --watch is missing (AND semantics)
        assert!(!matches_partial
            .iter()
            .any(|m| m.signature.name == "jest-watch" && m.details.args_matched));
    }

    #[test]
    fn test_working_dir_patterns_matching() {
        let mut db = SignatureDatabase::new();

        let _ = db.add(
            SupervisorSignature::new("project-dev", SupervisorCategory::Other)
                .with_process_patterns(vec![r"^node$"])
                .with_working_dir_patterns(vec![r"/home/.*/projects/"]),
        );

        let ctx_match = ProcessMatchContext::with_comm("node").cwd("/home/user/projects/myapp");
        let matches = db.match_process(&ctx_match);

        assert!(!matches.is_empty());
        assert!(matches[0].details.working_dir_matched);
    }

    #[test]
    fn test_schema_v2_json_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("test-v2", SupervisorCategory::Agent)
                .with_confidence(0.90)
                .with_process_patterns(vec![r"^test$"])
                .with_priors(SignaturePriors::likely_useful())
                .with_expectations(ProcessExpectations::dev_server())
                .with_priority(200),
        );

        let json = schema.to_json().expect("should serialize to JSON");
        let loaded = SignatureSchema::from_json(&json).expect("should parse JSON");

        assert_eq!(loaded.signatures.len(), 1);
        let sig = &loaded.signatures[0];
        assert_eq!(sig.name, "test-v2");
        assert_eq!(sig.priority, 200);
        assert!(!sig.priors.is_empty());
        assert!(!sig.expectations.is_empty());

        // Verify priors survived roundtrip
        let useful = sig.priors.useful.clone().unwrap();
        assert!(useful.mean() > 0.8);
    }

    #[test]
    fn test_schema_v2_toml_roundtrip() {
        let mut schema = SignatureSchema::new();
        schema.add(
            SupervisorSignature::new("test-v2-toml", SupervisorCategory::Ci)
                .with_confidence(0.85)
                .with_process_patterns(vec![r"^ci-runner$"])
                .with_arg_patterns(vec![r"--pipeline"])
                .with_working_dir_patterns(vec![r"/builds/"])
                .with_min_matches(2)
                .with_priors(SignaturePriors::likely_abandoned())
                .with_expectations(ProcessExpectations::short_lived_task())
                .with_priority(75),
        );

        let toml_str = schema.to_toml().expect("should serialize to TOML");
        let loaded = SignatureSchema::from_toml(&toml_str).expect("should parse TOML");

        assert_eq!(loaded.signatures.len(), 1);
        let sig = &loaded.signatures[0];
        assert_eq!(sig.name, "test-v2-toml");
        assert_eq!(sig.priority, 75);
        assert_eq!(sig.patterns.min_matches, 2);
        assert!(!sig.patterns.arg_patterns.is_empty());
        assert!(!sig.patterns.working_dir_patterns.is_empty());
    }

    #[test]
    fn test_match_score_ordering() {
        // Test that scores are ordered correctly by match level
        let sig = SupervisorSignature::new("test", SupervisorCategory::Agent).with_confidence(1.0); // Use 1.0 for easy score comparison

        let details = MatchDetails {
            process_name_matched: true,
            ..Default::default()
        };

        let command_only = SignatureMatch::new(&sig, MatchLevel::CommandOnly, details.clone());
        let multi = SignatureMatch::new(
            &sig,
            MatchLevel::MultiPattern,
            MatchDetails {
                process_name_matched: true,
                env_vars_matched: true,
                pattern_types_matched: 2,
                ..Default::default()
            },
        );

        assert!(multi.score > command_only.score);
    }
}
