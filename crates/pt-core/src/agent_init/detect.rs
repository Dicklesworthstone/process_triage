//! Agent detection implementation.
//!
//! Detects installed coding agents by checking:
//! - Configuration directories
//! - Executable availability in PATH
//! - Version information

use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{debug, trace};

/// Errors during agent detection.
#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("home directory not found")]
    NoHomeDir,
}

/// Types of supported coding agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    /// Claude Code - Anthropic's CLI coding assistant
    ClaudeCode,
    /// Codex - OpenAI's coding model CLI
    Codex,
    /// GitHub Copilot CLI
    Copilot,
    /// Cursor - AI-powered code editor
    Cursor,
    /// Windsurf - AI coding assistant
    Windsurf,
}

impl AgentType {
    /// Get display name for the agent.
    pub fn display_name(&self) -> &'static str {
        match self {
            AgentType::ClaudeCode => "Claude Code",
            AgentType::Codex => "Codex",
            AgentType::Copilot => "GitHub Copilot",
            AgentType::Cursor => "Cursor",
            AgentType::Windsurf => "Windsurf",
        }
    }

    /// Get the executable name to search for.
    pub fn executable_name(&self) -> &'static str {
        match self {
            AgentType::ClaudeCode => "claude",
            AgentType::Codex => "codex",
            AgentType::Copilot => "gh",
            AgentType::Cursor => "cursor",
            AgentType::Windsurf => "windsurf",
        }
    }

    /// Get config directory name relative to home.
    pub fn config_dir_name(&self) -> &'static str {
        match self {
            AgentType::ClaudeCode => ".claude",
            AgentType::Codex => ".codex",
            AgentType::Copilot => ".config/gh", // Copilot is a gh extension
            AgentType::Cursor => ".cursor",
            AgentType::Windsurf => ".windsurf",
        }
    }
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Information about a detected agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAgent {
    /// Type of agent.
    pub agent_type: AgentType,

    /// Agent info (version, paths, etc.).
    pub info: AgentInfo,
}

/// Detailed information about an agent installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Path to the executable (if found in PATH).
    pub executable_path: Option<PathBuf>,

    /// Path to the configuration directory.
    pub config_dir: Option<PathBuf>,

    /// Version string (if detectable).
    pub version: Option<String>,

    /// Whether the agent appears to be properly installed.
    pub is_installed: bool,

    /// Additional detection notes.
    pub notes: Vec<String>,
}

/// Result of agent detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Detected agents.
    pub agents: Vec<DetectedAgent>,

    /// Agents that were checked but not found.
    pub not_found: Vec<AgentType>,

    /// Any warnings during detection.
    pub warnings: Vec<String>,
}

/// Detect all supported agents on the system.
pub fn detect_agents() -> Result<DetectionResult, DetectionError> {
    let home = dirs::home_dir().ok_or(DetectionError::NoHomeDir)?;

    let mut result = DetectionResult {
        agents: Vec::new(),
        not_found: Vec::new(),
        warnings: Vec::new(),
    };

    // Check each agent type
    let agent_types = [
        AgentType::ClaudeCode,
        AgentType::Codex,
        AgentType::Copilot,
        AgentType::Cursor,
        AgentType::Windsurf,
    ];

    for agent_type in agent_types {
        debug!(agent = ?agent_type, "Checking for agent");

        match detect_single_agent(&agent_type, &home) {
            Some(agent) => {
                if agent.info.is_installed {
                    debug!(agent = ?agent_type, "Agent detected");
                    result.agents.push(agent);
                } else {
                    trace!(agent = ?agent_type, "Agent not fully installed");
                    result.not_found.push(agent_type);
                }
            }
            None => {
                trace!(agent = ?agent_type, "Agent not found");
                result.not_found.push(agent_type);
            }
        }
    }

    Ok(result)
}

/// Detect a single agent.
fn detect_single_agent(agent_type: &AgentType, home: &Path) -> Option<DetectedAgent> {
    let mut info = AgentInfo {
        executable_path: None,
        config_dir: None,
        version: None,
        is_installed: false,
        notes: Vec::new(),
    };

    // Check for config directory
    let config_dir = home.join(agent_type.config_dir_name());
    if config_dir.exists() && config_dir.is_dir() {
        info.config_dir = Some(config_dir);
    }

    // Check for executable in PATH
    if let Some(exe_path) = find_executable(agent_type.executable_name()) {
        info.executable_path = Some(exe_path);
    }

    // Special handling for Copilot (gh extension)
    if *agent_type == AgentType::Copilot {
        if let Some(copilot_status) = check_copilot_extension() {
            info.notes.push(copilot_status);
            info.is_installed = info.notes.iter().any(|n| n.contains("installed"));
        }
    } else {
        // For other agents, require either config dir or executable
        info.is_installed = info.config_dir.is_some() || info.executable_path.is_some();
    }

    // Try to get version
    if info.executable_path.is_some() {
        info.version = get_agent_version(agent_type);
    }

    if info.is_installed || info.config_dir.is_some() || info.executable_path.is_some() {
        Some(DetectedAgent {
            agent_type: agent_type.clone(),
            info,
        })
    } else {
        None
    }
}

/// Find an executable in PATH.
fn find_executable(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let full_path = dir.join(name);
            if full_path.is_file() && is_executable(&full_path) {
                Some(full_path)
            } else {
                None
            }
        })
    })
}

/// Check if a file is executable.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    // On Windows, check for common executable extensions
    path.extension()
        .map(|ext| {
            let ext = ext.to_string_lossy().to_lowercase();
            ext == "exe" || ext == "cmd" || ext == "bat" || ext == "ps1"
        })
        .unwrap_or(false)
}

/// Check for GitHub Copilot CLI extension.
fn check_copilot_extension() -> Option<String> {
    let output = Command::new("gh")
        .args(["extension", "list"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("copilot") {
            Some("Copilot extension installed".to_string())
        } else {
            Some("gh found but Copilot extension not installed".to_string())
        }
    } else {
        None
    }
}

/// Get version string for an agent.
fn get_agent_version(agent_type: &AgentType) -> Option<String> {
    let (cmd, args): (&str, &[&str]) = match agent_type {
        AgentType::ClaudeCode => ("claude", &["--version"]),
        AgentType::Codex => ("codex", &["--version"]),
        AgentType::Copilot => ("gh", &["copilot", "--version"]),
        AgentType::Cursor => ("cursor", &["--version"]),
        AgentType::Windsurf => ("windsurf", &["--version"]),
    };

    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Take first line, trim whitespace
                stdout.lines().next().map(|l| l.trim().to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_type_display_names() {
        assert_eq!(AgentType::ClaudeCode.display_name(), "Claude Code");
        assert_eq!(AgentType::Codex.display_name(), "Codex");
        assert_eq!(AgentType::Copilot.display_name(), "GitHub Copilot");
        assert_eq!(AgentType::Cursor.display_name(), "Cursor");
        assert_eq!(AgentType::Windsurf.display_name(), "Windsurf");
    }

    #[test]
    fn test_agent_type_executable_names() {
        assert_eq!(AgentType::ClaudeCode.executable_name(), "claude");
        assert_eq!(AgentType::Codex.executable_name(), "codex");
        assert_eq!(AgentType::Copilot.executable_name(), "gh");
    }

    #[test]
    fn test_agent_type_config_dirs() {
        assert_eq!(AgentType::ClaudeCode.config_dir_name(), ".claude");
        assert_eq!(AgentType::Codex.config_dir_name(), ".codex");
        assert_eq!(AgentType::Cursor.config_dir_name(), ".cursor");
    }

    #[test]
    fn test_detection_result_structure() {
        let result = DetectionResult {
            agents: vec![],
            not_found: vec![AgentType::ClaudeCode],
            warnings: vec!["test warning".to_string()],
        };
        assert!(result.agents.is_empty());
        assert_eq!(result.not_found.len(), 1);
        assert_eq!(result.warnings.len(), 1);
    }
}
