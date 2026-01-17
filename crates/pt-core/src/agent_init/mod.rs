//! Agent initialization and auto-configuration.
//!
//! This module provides functionality to detect installed coding agents
//! and configure pt as a tool for them.
//!
//! # Supported Agents
//!
//! - Claude Code: Anthropic's CLI coding assistant
//! - Codex: OpenAI's coding model CLI
//! - GitHub Copilot: GitHub's AI pair programmer
//! - Cursor: AI-powered code editor
//! - Windsurf: AI coding assistant
//!
//! # Usage
//!
//! ```bash
//! # Detect and configure all agents
//! pt agent init
//!
//! # Non-interactive mode
//! pt agent init --yes
//!
//! # Dry run (show what would change)
//! pt agent init --dry-run
//!
//! # Configure specific agent only
//! pt agent init --agent claude
//! ```

mod detect;
mod config;

pub use detect::{
    detect_agents, AgentInfo, AgentType, DetectedAgent, DetectionResult,
};
pub use config::{
    configure_agent, generate_config, ConfigError, ConfigResult,
    AgentConfig, BackupInfo,
};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Errors during agent initialization.
#[derive(Debug, Error)]
pub enum AgentInitError {
    #[error("detection error: {0}")]
    Detection(#[from] detect::DetectionError),

    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no agents found")]
    NoAgentsFound,

    #[error("user cancelled")]
    Cancelled,
}

/// Result of agent initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitResult {
    /// Agents that were detected.
    pub detected: Vec<DetectedAgent>,

    /// Agents that were configured.
    pub configured: Vec<ConfiguredAgent>,

    /// Agents that were skipped.
    pub skipped: Vec<SkippedAgent>,

    /// Backup files created.
    pub backups: Vec<BackupInfo>,
}

/// An agent that was successfully configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredAgent {
    /// Agent type.
    pub agent_type: AgentType,

    /// Configuration file path.
    pub config_path: PathBuf,

    /// What was configured.
    pub changes: Vec<String>,
}

/// An agent that was skipped during configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedAgent {
    /// Agent type.
    pub agent_type: AgentType,

    /// Reason for skipping.
    pub reason: String,
}

/// Options for agent initialization.
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    /// Apply defaults without prompts.
    pub non_interactive: bool,

    /// Show what would change without modifying.
    pub dry_run: bool,

    /// Specific agent to configure (None = all detected).
    pub agent_filter: Option<AgentType>,

    /// Skip creating backups.
    pub skip_backup: bool,
}

/// Initialize pt for detected agents.
pub fn initialize_agents(options: &InitOptions) -> Result<InitResult, AgentInitError> {
    use tracing::{info, debug, warn};

    info!(mode = ?options, "Starting agent initialization");

    // Detect installed agents
    let detection_result = detect_agents()?;

    if detection_result.agents.is_empty() {
        return Err(AgentInitError::NoAgentsFound);
    }

    info!(
        count = detection_result.agents.len(),
        agents = ?detection_result.agents.iter().map(|a| &a.agent_type).collect::<Vec<_>>(),
        "Detected agents"
    );

    // Filter to specific agent if requested
    let agents_to_configure: Vec<_> = if let Some(filter) = &options.agent_filter {
        detection_result
            .agents
            .iter()
            .filter(|a| &a.agent_type == filter)
            .cloned()
            .collect()
    } else {
        detection_result.agents.clone()
    };

    let mut result = InitResult {
        detected: detection_result.agents,
        configured: Vec::new(),
        skipped: Vec::new(),
        backups: Vec::new(),
    };

    // Configure each agent
    for agent in &agents_to_configure {
        debug!(agent = ?agent.agent_type, "Configuring agent");

        match configure_agent(agent, options) {
            Ok(config_result) => {
                result.configured.push(ConfiguredAgent {
                    agent_type: agent.agent_type.clone(),
                    config_path: config_result.config_path,
                    changes: config_result.changes,
                });
                if let Some(backup) = config_result.backup {
                    result.backups.push(backup);
                }
            }
            Err(e) => {
                warn!(agent = ?agent.agent_type, error = %e, "Failed to configure agent");
                result.skipped.push(SkippedAgent {
                    agent_type: agent.agent_type.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    info!(
        configured = result.configured.len(),
        skipped = result.skipped.len(),
        "Agent initialization complete"
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_options_default() {
        let opts = InitOptions::default();
        assert!(!opts.non_interactive);
        assert!(!opts.dry_run);
        assert!(opts.agent_filter.is_none());
        assert!(!opts.skip_backup);
    }
}
