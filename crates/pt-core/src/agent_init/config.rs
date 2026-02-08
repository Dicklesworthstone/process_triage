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
fn configure_claude_code(
    config_dir: &Path,
    options: &InitOptions,
) -> Result<ConfigResult, ConfigError> {
    let settings_path = config_dir.join("settings.json");
    let mut changes = Vec::new();

    // Load existing config or create new
    let mut config: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        json!({})
    };
    if !config.is_object() {
        changes.push("Replaced non-object Claude settings with empty object".to_string());
        config = json!({});
    }

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
    let mcp_servers = match config.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        Some(servers) => servers,
        None => {
            let had_servers = config.get("mcpServers").is_some();
            config["mcpServers"] = json!({});
            if had_servers {
                changes.push(
                    "Replaced invalid mcpServers value with object for Claude configuration"
                        .to_string(),
                );
            } else {
                changes.push("Created mcpServers object for Claude configuration".to_string());
            }
            config
                .get_mut("mcpServers")
                .and_then(|v| v.as_object_mut())
                .expect("mcpServers object should be initialized")
        }
    };

    if !mcp_servers.contains_key("process_triage") {
        mcp_servers.insert(
            "process_triage".to_string(),
            json!({
                "command": "pt",
                "args": ["mcp", "serve"],
                "description": "Process triage MCP server for Bayesian process management"
            }),
        );
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
    if !config.is_object() {
        changes.push("Replaced non-object Codex config with empty object".to_string());
        config = json!({});
    }

    let backup = if config_path.exists() && !options.skip_backup && !options.dry_run {
        Some(create_backup(&config_path)?)
    } else {
        None
    };

    // Add tools array if not present (or if invalid type)
    let tools = match config.get_mut("tools").and_then(|v| v.as_array_mut()) {
        Some(tools) => tools,
        None => {
            let had_tools = config.get("tools").is_some();
            config["tools"] = json!([]);
            if had_tools {
                changes.push(
                    "Replaced invalid tools value with array for Codex configuration".to_string(),
                );
            } else {
                changes.push("Created tools array for Codex configuration".to_string());
            }
            config
                .get_mut("tools")
                .and_then(|v| v.as_array_mut())
                .expect("tools array should be initialized")
        }
    };

    // Check if pt tool already exists
    let has_pt = tools
        .iter()
        .any(|t| t.get("name").and_then(|n| n.as_str()) == Some("process_triage"));

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
fn configure_copilot(
    config_dir: &Path,
    options: &InitOptions,
) -> Result<ConfigResult, ConfigError> {
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
    if !config.is_object() {
        changes.push("Replaced non-object Cursor settings with empty object".to_string());
        config = json!({});
    }

    let backup = if settings_path.exists() && !options.skip_backup && !options.dry_run {
        Some(create_backup(&settings_path)?)
    } else {
        None
    };

    // Add extensions configuration
    let extensions = match config.get_mut("extensions").and_then(|v| v.as_object_mut()) {
        Some(ext) => ext,
        None => {
            let had_extensions = config.get("extensions").is_some();
            config["extensions"] = json!({});
            if had_extensions {
                changes.push(
                    "Replaced invalid extensions value with object for Cursor configuration"
                        .to_string(),
                );
            } else {
                changes.push("Created extensions object for Cursor configuration".to_string());
            }
            config
                .get_mut("extensions")
                .and_then(|v| v.as_object_mut())
                .expect("extensions object should be initialized")
        }
    };

    if !extensions.contains_key("process_triage") {
        extensions.insert(
            "process_triage".to_string(),
            json!({
                "enabled": true,
                "command": "pt",
                "description": "Bayesian process triage and cleanup"
            }),
        );
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
fn configure_windsurf(
    config_dir: &Path,
    options: &InitOptions,
) -> Result<ConfigResult, ConfigError> {
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

    // ── helpers ──────────────────────────────────────────────────────

    use crate::agent_init::AgentInfo;

    fn make_agent(agent_type: AgentType, config_dir: Option<PathBuf>) -> DetectedAgent {
        DetectedAgent {
            agent_type,
            info: AgentInfo {
                executable_path: None,
                config_dir,
                version: None,
                is_installed: false,
                notes: vec![],
            },
        }
    }

    fn make_options(dry_run: bool, skip_backup: bool) -> InitOptions {
        InitOptions {
            non_interactive: true,
            dry_run,
            agent_filter: None,
            skip_backup,
        }
    }

    // ── generate_config ─────────────────────────────────────────────

    #[test]
    fn generate_config_cursor() {
        let config = generate_config(&AgentType::Cursor);
        assert!(config.settings.get("extensions").is_some());
    }

    #[test]
    fn generate_config_windsurf() {
        let config = generate_config(&AgentType::Windsurf);
        // Windsurf same structure as Cursor
        assert!(config.settings.get("extensions").is_some());
    }

    #[test]
    fn generate_config_tool_definition_has_commands() {
        let config = generate_config(&AgentType::ClaudeCode);
        let commands = config.tool_definition.get("commands").unwrap();
        assert!(commands.get("scan").is_some());
        assert!(commands.get("plan").is_some());
        assert!(commands.get("apply").is_some());
        assert!(commands.get("verify").is_some());
    }

    #[test]
    fn generate_config_tool_definition_has_capabilities() {
        let config = generate_config(&AgentType::Codex);
        let caps = config.tool_definition.get("capabilities").unwrap();
        assert_eq!(caps["process_management"], true);
        assert_eq!(caps["system_monitoring"], true);
        assert_eq!(caps["resource_cleanup"], true);
    }

    #[test]
    fn generate_config_claude_has_mcp_server() {
        let config = generate_config(&AgentType::ClaudeCode);
        let mcp = config.settings.get("mcpServers").unwrap();
        let pt = mcp.get("process_triage").unwrap();
        assert_eq!(pt["command"], "pt");
        assert_eq!(pt["args"][0], "mcp");
        assert_eq!(pt["args"][1], "serve");
    }

    #[test]
    fn generate_config_codex_has_tool_entry() {
        let config = generate_config(&AgentType::Codex);
        let tools = config.settings.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "process_triage");
        assert_eq!(tools[0]["type"], "mcp");
    }

    #[test]
    fn generate_config_copilot_has_aliases() {
        let config = generate_config(&AgentType::Copilot);
        let aliases = config.settings.get("aliases").unwrap();
        assert!(aliases.get("pt-scan").is_some());
        assert!(aliases.get("pt-plan").is_some());
        assert!(aliases.get("pt-apply").is_some());
    }

    // ── AgentConfig serde ───────────────────────────────────────────

    #[test]
    fn agent_config_roundtrip() {
        let config = generate_config(&AgentType::ClaudeCode);
        let json = serde_json::to_string(&config).unwrap();
        let deser: AgentConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deser.tool_definition.get("name").unwrap().as_str().unwrap(),
            "process_triage"
        );
    }

    // ── ConfigResult / BackupInfo serde ─────────────────────────────

    #[test]
    fn config_result_serde_roundtrip() {
        let result = ConfigResult {
            config_path: PathBuf::from("/tmp/settings.json"),
            changes: vec!["Added tool".to_string()],
            backup: Some(BackupInfo {
                original_path: PathBuf::from("/tmp/settings.json"),
                backup_path: PathBuf::from("/tmp/settings.json.bak"),
                created_at: "2025-01-01T00:00:00Z".to_string(),
            }),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: ConfigResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.changes.len(), 1);
        assert!(deser.backup.is_some());
    }

    #[test]
    fn config_result_no_backup() {
        let result = ConfigResult {
            config_path: PathBuf::from("/tmp/x.json"),
            changes: vec![],
            backup: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: ConfigResult = serde_json::from_str(&json).unwrap();
        assert!(deser.backup.is_none());
    }

    // ── ConfigError display ─────────────────────────────────────────

    #[test]
    fn config_error_no_config_dir_display() {
        let err = ConfigError::NoConfigDir;
        assert_eq!(err.to_string(), "no config directory found for agent");
    }

    #[test]
    fn config_error_backup_failed_display() {
        let err = ConfigError::BackupFailed("permission denied".to_string());
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn config_error_not_writable_display() {
        let err = ConfigError::NotWritable(PathBuf::from("/etc/config.json"));
        assert!(err.to_string().contains("/etc/config.json"));
    }

    #[test]
    fn config_error_dry_run_display() {
        let err = ConfigError::DryRun;
        assert_eq!(err.to_string(), "dry run - no changes made");
    }

    // ── write_json_config ───────────────────────────────────────────

    #[test]
    fn write_json_config_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.json");
        let val = json!({"key": "value"});
        write_json_config(&path, &val).unwrap();
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"key\""));
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn write_json_config_pretty_formatted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("pretty.json");
        let val = json!({"a": 1, "b": 2});
        write_json_config(&path, &val).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        // Pretty format uses newlines
        assert!(content.contains('\n'));
    }

    // ── create_backup ───────────────────────────────────────────────

    #[test]
    fn create_backup_copies_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let orig = dir.path().join("settings.json");
        fs::write(&orig, "{\"hello\": true}").unwrap();

        let info = create_backup(&orig).unwrap();
        assert!(info.backup_path.exists());
        assert_eq!(info.original_path, orig);

        let backup_content = fs::read_to_string(&info.backup_path).unwrap();
        assert_eq!(backup_content, "{\"hello\": true}");
    }

    #[test]
    fn create_backup_name_has_timestamp() {
        let dir = tempfile::TempDir::new().unwrap();
        let orig = dir.path().join("config.json");
        fs::write(&orig, "{}").unwrap();

        let info = create_backup(&orig).unwrap();
        let name = info.backup_path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("config.json."));
        assert!(name.ends_with(".bak"));
    }

    // ── configure_claude_code ───────────────────────────────────────

    #[test]
    fn configure_claude_code_fresh_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        let result = configure_claude_code(dir.path(), &options).unwrap();
        assert!(result.config_path.exists());
        assert!(!result.changes.is_empty());

        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        assert!(content.get("allowedTools").is_some());
        assert!(content.get("mcpServers").is_some());
        let mcp = content["mcpServers"]["process_triage"].as_object().unwrap();
        assert_eq!(mcp["command"], "pt");
    }

    #[test]
    fn configure_claude_code_existing_config_preserves_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(
            &settings,
            r#"{"theme": "dark", "allowedTools": ["other_tool"]}"#,
        )
        .unwrap();

        let options = make_options(false, true);
        let result = configure_claude_code(dir.path(), &options).unwrap();

        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        assert_eq!(content["theme"], "dark");
        let tools = content["allowedTools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t == "other_tool"));
        assert!(tools.iter().any(|t| t == "process_triage"));
    }

    #[test]
    fn configure_claude_code_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        configure_claude_code(dir.path(), &options).unwrap();
        let result2 = configure_claude_code(dir.path(), &options).unwrap();

        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result2.config_path).unwrap()).unwrap();
        let tools = content["allowedTools"].as_array().unwrap();
        let pt_count = tools
            .iter()
            .filter(|t| t.as_str() == Some("process_triage"))
            .count();
        assert_eq!(pt_count, 1, "process_triage should appear exactly once");
    }

    #[test]
    fn configure_claude_code_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(true, true);
        let err = configure_claude_code(dir.path(), &options).unwrap_err();
        matches!(err, ConfigError::DryRun);
        // File should not be created
        assert!(!dir.path().join("settings.json").exists());
    }

    #[test]
    fn configure_claude_code_with_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(&settings, "{}").unwrap();

        let options = make_options(false, false); // skip_backup = false
        let result = configure_claude_code(dir.path(), &options).unwrap();
        assert!(result.backup.is_some());
    }

    #[test]
    fn configure_claude_code_replaces_non_object_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(&settings, "\"not an object\"").unwrap();

        let options = make_options(false, true);
        let result = configure_claude_code(dir.path(), &options).unwrap();
        assert!(result.changes.iter().any(|c| c.contains("non-object")));
    }

    #[test]
    fn configure_claude_code_replaces_non_object_mcp_servers() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(&settings, r#"{"mcpServers": "invalid"}"#).unwrap();

        let options = make_options(false, true);
        let result = configure_claude_code(dir.path(), &options).unwrap();
        assert!(result
            .changes
            .iter()
            .any(|c| c.contains("Replaced invalid mcpServers")));
    }

    // ── configure_codex ─────────────────────────────────────────────

    #[test]
    fn configure_codex_fresh_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        let result = configure_codex(dir.path(), &options).unwrap();
        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        let tools = content["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "process_triage");
    }

    #[test]
    fn configure_codex_existing_tools_preserved() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, r#"{"tools": [{"name": "other", "type": "mcp"}]}"#).unwrap();

        let options = make_options(false, true);
        let result = configure_codex(dir.path(), &options).unwrap();
        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        let tools = content["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn configure_codex_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        configure_codex(dir.path(), &options).unwrap();
        configure_codex(dir.path(), &options).unwrap();

        let content: Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("config.json")).unwrap())
                .unwrap();
        let tools = content["tools"].as_array().unwrap();
        let pt_count = tools
            .iter()
            .filter(|t| t.get("name").and_then(|n| n.as_str()) == Some("process_triage"))
            .count();
        assert_eq!(pt_count, 1);
    }

    #[test]
    fn configure_codex_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(true, true);
        let err = configure_codex(dir.path(), &options).unwrap_err();
        matches!(err, ConfigError::DryRun);
    }

    #[test]
    fn configure_codex_replaces_non_array_tools() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, r#"{"tools": "invalid"}"#).unwrap();

        let options = make_options(false, true);
        let result = configure_codex(dir.path(), &options).unwrap();
        assert!(result
            .changes
            .iter()
            .any(|c| c.contains("Replaced invalid tools")));
    }

    // ── configure_cursor ────────────────────────────────────────────

    #[test]
    fn configure_cursor_fresh_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        let result = configure_cursor(dir.path(), &options).unwrap();
        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        let ext = content["extensions"]["process_triage"].as_object().unwrap();
        assert_eq!(ext["enabled"], true);
        assert_eq!(ext["command"], "pt");
    }

    #[test]
    fn configure_cursor_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        configure_cursor(dir.path(), &options).unwrap();
        let result = configure_cursor(dir.path(), &options).unwrap();

        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        let exts = content["extensions"].as_object().unwrap();
        assert_eq!(exts.len(), 1);
    }

    #[test]
    fn configure_cursor_replaces_non_object_extensions() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(&settings, r#"{"extensions": 42}"#).unwrap();

        let options = make_options(false, true);
        let result = configure_cursor(dir.path(), &options).unwrap();
        assert!(result
            .changes
            .iter()
            .any(|c| c.contains("Replaced invalid extensions")));
    }

    // ── configure_copilot ───────────────────────────────────────────

    #[test]
    fn configure_copilot_creates_md_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        let result = configure_copilot(dir.path(), &options).unwrap();
        assert!(result.config_path.exists());
        let content = fs::read_to_string(&result.config_path).unwrap();
        assert!(content.contains("Process Triage"));
        assert!(content.contains("pt-scan"));
        assert!(result.backup.is_none());
    }

    #[test]
    fn configure_copilot_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(true, true);
        let err = configure_copilot(dir.path(), &options).unwrap_err();
        matches!(err, ConfigError::DryRun);
    }

    // ── configure_windsurf delegates to cursor ──────────────────────

    #[test]
    fn configure_windsurf_same_as_cursor() {
        let dir = tempfile::TempDir::new().unwrap();
        let options = make_options(false, true);

        let result = configure_windsurf(dir.path(), &options).unwrap();
        let content: Value =
            serde_json::from_str(&fs::read_to_string(&result.config_path).unwrap()).unwrap();
        assert!(content.get("extensions").is_some());
    }

    // ── configure_agent dispatch ────────────────────────────────────

    #[test]
    fn configure_agent_claude() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = make_agent(AgentType::ClaudeCode, Some(dir.path().to_path_buf()));
        let options = make_options(false, true);

        let result = configure_agent(&agent, &options).unwrap();
        assert!(result.config_path.exists());
    }

    #[test]
    fn configure_agent_codex() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = make_agent(AgentType::Codex, Some(dir.path().to_path_buf()));
        let options = make_options(false, true);

        let result = configure_agent(&agent, &options).unwrap();
        assert!(result.config_path.exists());
    }
}
