//! Agent configuration generation and application.
//!
//! This module handles generating pt integration configurations
//! for each supported agent type and safely applying them.

use super::{AgentType, DetectedAgent, InitOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info};

/// Errors during configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("no config directory found for agent")]
    NoConfigDir,

    #[error("backup failed: {0}")]
    BackupFailed(String),

    #[error("config file not writable: {0}")]
    NotWritable(PathBuf),

    #[error("dry run - no changes made")]
    DryRun,
}

/// Result of configuring an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResult {
    /// Path to the modified config file.
    pub config_path: PathBuf,

    /// List of changes made.
    pub changes: Vec<String>,

    /// Backup information (if created).
    pub backup: Option<BackupInfo>,
}

/// Information about a backup file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    /// Original file path.
    pub original_path: PathBuf,

    /// Backup file path.
    pub backup_path: PathBuf,

    /// Timestamp of backup.
    pub created_at: String,
}

/// Configuration for pt integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Tool definition for MCP or similar.
    pub tool_definition: Value,

    /// Additional settings.
    pub settings: Value,
}

/// Configure a detected agent to use pt.
pub fn configure_agent(
    agent: &DetectedAgent,
    options: &InitOptions,
) -> Result<ConfigResult, ConfigError> {
    let config_dir = if let Some(dir) = agent.info.config_dir.as_ref() {
        dir.clone()
    } else {
        // Try to create default config dir
        dirs::home_dir()
            .map(|h| h.join(agent.agent_type.config_dir_name()))
            .ok_or(ConfigError::NoConfigDir)?
    };

    // Ensure config directory exists
    if !config_dir.exists() && !options.dry_run {
        fs::create_dir_all(&config_dir)?;
    }

    match agent.agent_type {
        AgentType::ClaudeCode => configure_claude_code(&config_dir, options),
        AgentType::Codex => configure_codex(&config_dir, options),
        AgentType::Copilot => configure_copilot(&config_dir, options),
        AgentType::Cursor => configure_cursor(&config_dir, options),
        AgentType::Windsurf => configure_windsurf(&config_dir, options),
    }
}

/// Generate pt tool configuration.
pub fn generate_config(agent_type: &AgentType) -> AgentConfig {
    let tool_definition = json!({
        "name": "process_triage",
        "description": "Bayesian-inspired zombie/abandoned process detection and cleanup",
        "commands": {
            "scan": "Scan for candidate processes",
            "plan": "Generate action plan",
            "apply": "Execute action plan",
            "verify": "Verify action outcomes"
        },
        "capabilities": {
            "process_management": true,
            "system_monitoring": true,
            "resource_cleanup": true
        }
    });

    let settings = match agent_type {
        AgentType::ClaudeCode => json!({
            "allowedTools": ["process_triage"],
            "mcpServers": {
                "process_triage": {
                    "command": "pt",
                    "args": ["mcp", "serve"],
                    "description": "Process triage MCP server"
                }
            }
        }),
        AgentType::Codex => json!({
            "tools": [{
                "name": "process_triage",
                "type": "mcp",
                "config": {
                    "command": "pt",
                    "args": ["mcp", "serve"]
                }
            }]
        }),
        AgentType::Copilot => json!({
            "aliases": {
                "pt-scan": "pt scan --format json",
                "pt-plan": "pt agent plan --format json",
                "pt-apply": "pt agent apply"
            }
        }),
        AgentType::Cursor | AgentType::Windsurf => json!({
            "extensions": {
                "process_triage": {
                    "enabled": true,
                    "command": "pt"
                }
            }
        }),
    };

    AgentConfig {
        tool_definition,
        settings,
    }
}

/// Configure Claude Code.
fn configure_claude_code(config_dir: &Path, options: &InitOptions) -> Result<ConfigResult, ConfigError> {
    let settings_path = config_dir.join("settings.json");
    let mut changes = Vec::new();

    // Load existing config or create new
    let mut config: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        json!({})
    };

    // Create backup if needed
    let backup = if settings_path.exists() && !options.skip_backup && !options.dry_run {
        Some(create_backup(&settings_path)?)
    } else {
        None
    };

    // Add pt to allowed tools
    let allowed_tools = config
        .get_mut("allowedTools")
        .and_then(|v| v.as_array_mut());

    if let Some(tools) = allowed_tools {
        if !tools.iter().any(|t| t.as_str() == Some("process_triage")) {
            tools.push(json!("process_triage"));
            changes.push("Added process_triage to allowedTools".to_string());
        }
    } else {
        config["allowedTools"] = json!(["process_triage"]);
        changes.push("Created allowedTools with process_triage".to_string());
    }

    // Add MCP server configuration
    if config.get("mcpServers").is_none() {
        config["mcpServers"] = json!({});
    }

    if config["mcpServers"].get("process_triage").is_none() {
        config["mcpServers"]["process_triage"] = json!({
            "command": "pt",
            "args": ["mcp", "serve"],
            "description": "Process triage MCP server for Bayesian process management"
        });
        changes.push("Added process_triage MCP server configuration".to_string());
    }

    // Write config (or log dry run)
    if options.dry_run {
        info!(path = ?settings_path, changes = ?changes, "Dry run - would write config");
        return Err(ConfigError::DryRun);
    }

    write_json_config(&settings_path, &config)?;

    Ok(ConfigResult {
        config_path: settings_path,
        changes,
        backup,
    })
}

/// Configure Codex.
fn configure_codex(config_dir: &Path, options: &InitOptions) -> Result<ConfigResult, ConfigError> {
    let config_path = config_dir.join("config.json");
    let mut changes = Vec::new();

    let mut config: Value = if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        serde_json::from_str(&content)?
    } else {
        json!({})
    };

    let backup = if config_path.exists() && !options.skip_backup && !options.dry_run {
        Some(create_backup(&config_path)?)
    } else {
        None
    };

    // Add tools array if not present
    if config.get("tools").is_none() {
        config["tools"] = json!([]);
    }

    // Check if pt tool already exists
    let tools = config["tools"].as_array_mut().unwrap();
    let has_pt = tools.iter().any(|t| {
        t.get("name").and_then(|n| n.as_str()) == Some("process_triage")
    });

    if !has_pt {
        tools.push(json!({
            "name": "process_triage",
            "type": "mcp",
            "config": {
                "command": "pt",
                "args": ["mcp", "serve"]
            }
        }));
        changes.push("Added process_triage tool to Codex configuration".to_string());
    }

    if options.dry_run {
        info!(path = ?config_path, changes = ?changes, "Dry run - would write config");
        return Err(ConfigError::DryRun);
    }

    write_json_config(&config_path, &config)?;

    Ok(ConfigResult {
        config_path,
        changes,
        backup,
    })
}

/// Configure GitHub Copilot.
fn configure_copilot(config_dir: &Path, options: &InitOptions) -> Result<ConfigResult, ConfigError> {
    // Copilot uses gh CLI extensions/aliases
    // We'll create a suggestion file since direct config modification isn't straightforward
    let suggestion_path = config_dir.join("pt-copilot-setup.md");
    let mut changes = Vec::new();

    let content = r#"# Process Triage + GitHub Copilot Integration

To integrate pt with GitHub Copilot CLI, add these aliases to your shell configuration:

## Bash/Zsh

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Process Triage aliases for Copilot
alias pt-scan='pt scan --format json'
alias pt-plan='pt agent plan --format json'
alias pt-apply='pt agent apply'
alias pt-verify='pt agent verify'
```

## Fish

Add to `~/.config/fish/config.fish`:

```fish
# Process Triage aliases for Copilot
alias pt-scan 'pt scan --format json'
alias pt-plan 'pt agent plan --format json'
alias pt-apply 'pt agent apply'
alias pt-verify 'pt agent verify'
```

## Usage with Copilot

1. Run `pt-scan` to scan for candidate processes
2. Use `gh copilot suggest` to get recommendations
3. Run `pt-plan` to generate an action plan
4. Use `gh copilot explain` on the plan if needed
5. Run `pt-apply --session <id>` to execute
"#;

    if options.dry_run {
        info!(path = ?suggestion_path, "Dry run - would create Copilot setup guide");
        return Err(ConfigError::DryRun);
    }

    fs::write(&suggestion_path, content)?;
    changes.push("Created Copilot integration guide".to_string());

    Ok(ConfigResult {
        config_path: suggestion_path,
        changes,
        backup: None,
    })
}

/// Configure Cursor.
fn configure_cursor(config_dir: &Path, options: &InitOptions) -> Result<ConfigResult, ConfigError> {
    let settings_path = config_dir.join("settings.json");
    let mut changes = Vec::new();

    let mut config: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        json!({})
    };

    let backup = if settings_path.exists() && !options.skip_backup && !options.dry_run {
        Some(create_backup(&settings_path)?)
    } else {
        None
    };

    // Add extensions configuration
    if config.get("extensions").is_none() {
        config["extensions"] = json!({});
    }

    if config["extensions"].get("process_triage").is_none() {
        config["extensions"]["process_triage"] = json!({
            "enabled": true,
            "command": "pt",
            "description": "Bayesian process triage and cleanup"
        });
        changes.push("Added process_triage extension to Cursor".to_string());
    }

    if options.dry_run {
        info!(path = ?settings_path, changes = ?changes, "Dry run - would write config");
        return Err(ConfigError::DryRun);
    }

    write_json_config(&settings_path, &config)?;

    Ok(ConfigResult {
        config_path: settings_path,
        changes,
        backup,
    })
}

/// Configure Windsurf.
fn configure_windsurf(config_dir: &Path, options: &InitOptions) -> Result<ConfigResult, ConfigError> {
    // Windsurf configuration is similar to Cursor
    configure_cursor(config_dir, options)
}

/// Create a backup of a file.
fn create_backup(path: &Path) -> Result<BackupInfo, ConfigError> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let backup_name = format!(
        "{}.{}.bak",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path.parent().unwrap_or(path).join(backup_name);

    fs::copy(path, &backup_path).map_err(|e| ConfigError::BackupFailed(e.to_string()))?;

    debug!(original = ?path, backup = ?backup_path, "Created backup");

    Ok(BackupInfo {
        original_path: path.to_path_buf(),
        backup_path,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Write JSON config with pretty formatting.
fn write_json_config(path: &Path, config: &Value) -> Result<(), ConfigError> {
    let content = serde_json::to_string_pretty(config)?;
    let mut file = fs::File::create(path)?;
    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config_claude() {
        let config = generate_config(&AgentType::ClaudeCode);
        assert!(config.settings.get("mcpServers").is_some());
    }

    #[test]
    fn test_generate_config_codex() {
        let config = generate_config(&AgentType::Codex);
        assert!(config.settings.get("tools").is_some());
    }

    #[test]
    fn test_generate_config_copilot() {
        let config = generate_config(&AgentType::Copilot);
        assert!(config.settings.get("aliases").is_some());
    }
}
