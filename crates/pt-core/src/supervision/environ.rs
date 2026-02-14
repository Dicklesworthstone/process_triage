//! Environment variable supervision detection.
//!
//! Detects supervision through environment variables injected by supervisors
//! into child processes.

use super::types::{EvidenceType, SupervisionEvidence, SupervisorCategory};
use crate::collect::parse_environ_content;
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

/// Errors from environment detection.
#[derive(Debug, Error)]
pub enum EnvironError {
    #[error("I/O error reading /proc/{pid}/environ: {source}")]
    IoError {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),
}

/// A pattern for detecting supervisor environment variables.
#[derive(Debug, Clone)]
pub struct EnvPattern {
    /// Name of the supervisor.
    pub supervisor_name: String,
    /// Category of supervisor.
    pub category: SupervisorCategory,
    /// Variable name to check.
    pub var_name: String,
    /// Expected value pattern (None = just check existence).
    pub value_pattern: Option<String>,
    /// Confidence weight for this detection.
    pub confidence: f64,
}

impl EnvPattern {
    /// Create a new environment pattern.
    pub fn new(
        name: impl Into<String>,
        category: SupervisorCategory,
        var_name: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            supervisor_name: name.into(),
            category,
            var_name: var_name.into(),
            value_pattern: None,
            confidence,
        }
    }

    /// Add a value pattern requirement.
    pub fn with_value(mut self, pattern: impl Into<String>) -> Self {
        self.value_pattern = Some(pattern.into());
        self
    }
}

/// Result of environment-based supervision detection.
#[derive(Debug, Clone)]
pub struct EnvironResult {
    /// Whether supervision was detected via environment.
    pub is_supervised: bool,
    /// Detected supervisor name (if any).
    pub supervisor_name: Option<String>,
    /// Detected supervisor category (if any).
    pub category: Option<SupervisorCategory>,
    /// Confidence score.
    pub confidence: f64,
    /// Evidence found.
    pub evidence: Vec<SupervisionEvidence>,
    /// Environment variables found (for debugging).
    pub matched_vars: Vec<(String, String)>,
}

impl EnvironResult {
    /// Create a result indicating no supervision detected.
    pub fn not_supervised() -> Self {
        Self {
            is_supervised: false,
            supervisor_name: None,
            category: None,
            confidence: 0.0,
            evidence: vec![],
            matched_vars: vec![],
        }
    }

    /// Create a result indicating supervision detected.
    pub fn supervised(
        name: String,
        category: SupervisorCategory,
        confidence: f64,
        evidence: Vec<SupervisionEvidence>,
        matched_vars: Vec<(String, String)>,
    ) -> Self {
        Self {
            is_supervised: true,
            supervisor_name: Some(name),
            category: Some(category),
            confidence,
            evidence,
            matched_vars,
        }
    }
}

/// Database of environment variable patterns for supervision detection.
#[derive(Debug, Clone, Default)]
pub struct EnvironDatabase {
    patterns: Vec<EnvPattern>,
}

impl EnvironDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self { patterns: vec![] }
    }

    /// Create with default patterns.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.add_default_patterns();
        db
    }

    /// Add a pattern.
    pub fn add(&mut self, pattern: EnvPattern) {
        self.patterns.push(pattern);
    }

    /// Add all default patterns.
    pub fn add_default_patterns(&mut self) {
        // VS Code
        self.add(EnvPattern::new(
            "vscode",
            SupervisorCategory::Ide,
            "VSCODE_PID",
            0.95,
        ));
        self.add(EnvPattern::new(
            "vscode",
            SupervisorCategory::Ide,
            "VSCODE_IPC_HOOK",
            0.95,
        ));
        self.add(EnvPattern::new(
            "vscode",
            SupervisorCategory::Ide,
            "VSCODE_IPC_HOOK_CLI",
            0.95,
        ));
        self.add(
            EnvPattern::new("vscode", SupervisorCategory::Ide, "TERM_PROGRAM", 0.80)
                .with_value("vscode"),
        );

        // Claude
        self.add(EnvPattern::new(
            "claude",
            SupervisorCategory::Agent,
            "CLAUDE_SESSION_ID",
            0.95,
        ));
        self.add(EnvPattern::new(
            "claude",
            SupervisorCategory::Agent,
            "CLAUDE_CODE_SESSION",
            0.95,
        ));
        self.add(EnvPattern::new(
            "claude",
            SupervisorCategory::Agent,
            "CLAUDE_ENTRYPOINT",
            0.90,
        ));

        // Codex
        self.add(EnvPattern::new(
            "codex",
            SupervisorCategory::Agent,
            "CODEX_SESSION_ID",
            0.95,
        ));
        self.add(EnvPattern::new(
            "codex",
            SupervisorCategory::Agent,
            "CODEX_CLI_SESSION",
            0.95,
        ));

        // Cursor
        self.add(EnvPattern::new(
            "cursor",
            SupervisorCategory::Agent,
            "CURSOR_SESSION",
            0.95,
        ));
        self.add(EnvPattern::new(
            "cursor",
            SupervisorCategory::Ide,
            "CURSOR_PID",
            0.95,
        ));

        // Aider
        self.add(EnvPattern::new(
            "aider",
            SupervisorCategory::Agent,
            "AIDER_SESSION",
            0.90,
        ));

        // CI/CD environments
        self.add(EnvPattern::new(
            "github-actions",
            SupervisorCategory::Ci,
            "GITHUB_ACTIONS",
            0.95,
        ));
        self.add(EnvPattern::new(
            "github-actions",
            SupervisorCategory::Ci,
            "GITHUB_WORKFLOW",
            0.90,
        ));
        self.add(EnvPattern::new(
            "gitlab-ci",
            SupervisorCategory::Ci,
            "GITLAB_CI",
            0.95,
        ));
        self.add(EnvPattern::new(
            "gitlab-ci",
            SupervisorCategory::Ci,
            "CI_PROJECT_ID",
            0.85,
        ));
        self.add(EnvPattern::new(
            "jenkins",
            SupervisorCategory::Ci,
            "JENKINS_URL",
            0.95,
        ));
        self.add(EnvPattern::new(
            "jenkins",
            SupervisorCategory::Ci,
            "BUILD_ID",
            0.70,
        ));
        self.add(EnvPattern::new(
            "circleci",
            SupervisorCategory::Ci,
            "CIRCLECI",
            0.95,
        ));
        self.add(EnvPattern::new(
            "travis",
            SupervisorCategory::Ci,
            "TRAVIS",
            0.95,
        ));

        // Generic CI indicator
        self.add(
            EnvPattern::new("ci-generic", SupervisorCategory::Ci, "CI", 0.70).with_value("true"),
        );

        // Terminal multiplexers (weaker signal - might host agents)
        self.add(EnvPattern::new(
            "tmux",
            SupervisorCategory::Terminal,
            "TMUX",
            0.30,
        ));
        self.add(EnvPattern::new(
            "screen",
            SupervisorCategory::Terminal,
            "STY",
            0.30,
        ));

        // JetBrains IDEs
        self.add(EnvPattern::new(
            "jetbrains",
            SupervisorCategory::Ide,
            "IDEA_VM_OPTIONS",
            0.85,
        ));
        self.add(EnvPattern::new(
            "jetbrains",
            SupervisorCategory::Ide,
            "PYCHARM_VM_OPTIONS",
            0.85,
        ));

        // macOS launchd (Orchestrator)
        // XPC_SERVICE_NAME is set for XPC services managed by launchd
        self.add(EnvPattern::new(
            "launchd",
            SupervisorCategory::Orchestrator,
            "XPC_SERVICE_NAME",
            0.95,
        ));
        // __CFBundleIdentifier is set for application bundles launched by launchd
        self.add(EnvPattern::new(
            "launchd",
            SupervisorCategory::Orchestrator,
            "__CFBundleIdentifier",
            0.80,
        ));
        // LAUNCH_DAEMON indicates a daemon managed by launchd
        self.add(EnvPattern::new(
            "launchd",
            SupervisorCategory::Orchestrator,
            "LAUNCH_DAEMON",
            0.90,
        ));
    }

    /// Find matching patterns in an environment.
    pub fn find_matches(&self, env: &HashMap<String, String>) -> Vec<(EnvPattern, String)> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if let Some(value) = env.get(&pattern.var_name) {
                // Check value pattern if specified
                if let Some(ref expected) = pattern.value_pattern {
                    if value != expected {
                        continue;
                    }
                }
                matches.push((pattern.clone(), value.clone()));
            }
        }

        matches
    }
}

/// Read environment variables from /proc/\[pid\]/environ.
#[cfg(target_os = "linux")]
pub fn read_environ(pid: u32) -> Result<HashMap<String, String>, EnvironError> {
    let path = format!("/proc/{}/environ", pid);
    let content = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            EnvironError::ProcessNotFound(pid)
        } else {
            EnvironError::IoError { pid, source: e }
        }
    })?;

    Ok(parse_environ_content(&content).unwrap_or_default())
}

#[cfg(not(target_os = "linux"))]
pub fn read_environ(_pid: u32) -> Result<HashMap<String, String>, EnvironError> {
    Ok(HashMap::new())
}

/// Analyzer for environment-based supervision detection.
pub struct EnvironAnalyzer {
    database: EnvironDatabase,
}

impl EnvironAnalyzer {
    /// Create a new analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            database: EnvironDatabase::with_defaults(),
        }
    }

    /// Create an analyzer with a custom database.
    pub fn with_database(database: EnvironDatabase) -> Self {
        Self { database }
    }

    /// Analyze a process for supervision via environment variables.
    pub fn analyze(&self, pid: u32) -> Result<EnvironResult, EnvironError> {
        let env = read_environ(pid)?;
        Ok(self.analyze_env(&env))
    }

    /// Analyze a pre-read environment.
    pub fn analyze_env(&self, env: &HashMap<String, String>) -> EnvironResult {
        let matches = self.database.find_matches(env);

        if matches.is_empty() {
            return EnvironResult::not_supervised();
        }

        // Find the best match (highest confidence)
        let best = matches
            .iter()
            .max_by(|a, b| {
                a.0.confidence
                    .partial_cmp(&b.0.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();

        let evidence: Vec<SupervisionEvidence> = matches
            .iter()
            .map(|(pattern, _value)| SupervisionEvidence {
                evidence_type: EvidenceType::Environment,
                description: format!(
                    "Environment variable {} indicates {} supervision",
                    pattern.var_name, pattern.supervisor_name
                ),
                weight: pattern.confidence,
            })
            .collect();

        let matched_vars: Vec<(String, String)> = matches
            .iter()
            .map(|(p, v)| (p.var_name.clone(), v.clone()))
            .collect();

        EnvironResult::supervised(
            best.0.supervisor_name.clone(),
            best.0.category,
            best.0.confidence,
            evidence,
            matched_vars,
        )
    }
}

impl Default for EnvironAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to check a single process.
pub fn detect_environ_supervision(pid: u32) -> Result<EnvironResult, EnvironError> {
    let analyzer = EnvironAnalyzer::new();
    analyzer.analyze(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_environ() {
        let content = b"KEY1=value1\0KEY2=value2\0EMPTY=\0";
        let env = parse_environ_content(content).unwrap();

        assert_eq!(env.get("KEY1"), Some(&"value1".to_string()));
        assert_eq!(env.get("KEY2"), Some(&"value2".to_string()));
        assert_eq!(env.get("EMPTY"), Some(&"".to_string()));
    }

    #[test]
    fn test_parse_environ_with_equals_in_value() {
        let content = b"PATH=/usr/bin:/bin\0OPTS=--flag=value\0";
        let env = parse_environ_content(content).unwrap();

        assert_eq!(env.get("PATH"), Some(&"/usr/bin:/bin".to_string()));
        assert_eq!(env.get("OPTS"), Some(&"--flag=value".to_string()));
    }

    #[test]
    fn test_environ_database_defaults() {
        let db = EnvironDatabase::with_defaults();
        assert!(!db.patterns.is_empty());

        // Check some patterns exist
        let vscode_patterns: Vec<_> = db
            .patterns
            .iter()
            .filter(|p| p.supervisor_name == "vscode")
            .collect();
        assert!(!vscode_patterns.is_empty());
    }

    #[test]
    fn test_environ_database_find_matches() {
        let db = EnvironDatabase::with_defaults();
        let mut env = HashMap::new();
        env.insert("VSCODE_PID".to_string(), "12345".to_string());

        let matches = db.find_matches(&env);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].0.supervisor_name, "vscode");
    }

    #[test]
    fn test_environ_database_value_pattern() {
        let db = EnvironDatabase::with_defaults();

        // TERM_PROGRAM=vscode should match
        let mut env1 = HashMap::new();
        env1.insert("TERM_PROGRAM".to_string(), "vscode".to_string());
        let matches1 = db.find_matches(&env1);
        assert!(matches1.iter().any(|(p, _)| p.var_name == "TERM_PROGRAM"));

        // TERM_PROGRAM=iterm2 should not match
        let mut env2 = HashMap::new();
        env2.insert("TERM_PROGRAM".to_string(), "iterm2".to_string());
        let matches2 = db.find_matches(&env2);
        assert!(!matches2.iter().any(|(p, _)| p.var_name == "TERM_PROGRAM"));
    }

    #[test]
    fn test_environ_analyzer_no_match() {
        let analyzer = EnvironAnalyzer::new();
        let env = HashMap::new();
        let result = analyzer.analyze_env(&env);

        assert!(!result.is_supervised);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_environ_analyzer_match() {
        let analyzer = EnvironAnalyzer::new();
        let mut env = HashMap::new();
        env.insert("GITHUB_ACTIONS".to_string(), "true".to_string());

        let result = analyzer.analyze_env(&env);
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("github-actions".to_string()));
        assert_eq!(result.category, Some(SupervisorCategory::Ci));
    }

    #[test]
    fn test_environ_result_not_supervised() {
        let result = EnvironResult::not_supervised();
        assert!(!result.is_supervised);
        assert!(result.supervisor_name.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_environ_current_process() {
        let pid = std::process::id();
        let env = read_environ(pid).expect("should read current process environ");

        // Should have at least PATH
        assert!(!env.is_empty());
    }

    #[test]
    fn test_launchd_xpc_service_name_detection() {
        let analyzer = EnvironAnalyzer::new();
        let mut env = HashMap::new();
        env.insert(
            "XPC_SERVICE_NAME".to_string(),
            "com.apple.Spotlight".to_string(),
        );

        let result = analyzer.analyze_env(&env);
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("launchd".to_string()));
        assert_eq!(result.category, Some(SupervisorCategory::Orchestrator));
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_launchd_cfbundle_detection() {
        let analyzer = EnvironAnalyzer::new();
        let mut env = HashMap::new();
        env.insert(
            "__CFBundleIdentifier".to_string(),
            "com.apple.Safari".to_string(),
        );

        let result = analyzer.analyze_env(&env);
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("launchd".to_string()));
        assert_eq!(result.category, Some(SupervisorCategory::Orchestrator));
    }

    #[test]
    fn test_launchd_database_patterns_exist() {
        let db = EnvironDatabase::with_defaults();

        // Verify XPC_SERVICE_NAME pattern exists
        let has_xpc = db
            .patterns
            .iter()
            .any(|p| p.var_name == "XPC_SERVICE_NAME" && p.supervisor_name == "launchd");
        assert!(has_xpc, "should have XPC_SERVICE_NAME pattern for launchd");

        // Verify __CFBundleIdentifier pattern exists
        let has_cfbundle = db
            .patterns
            .iter()
            .any(|p| p.var_name == "__CFBundleIdentifier" && p.supervisor_name == "launchd");
        assert!(
            has_cfbundle,
            "should have __CFBundleIdentifier pattern for launchd"
        );
    }
}
