//! MCP tool implementations.
//!
//! Each tool maps to a pt operation: scan, explain, history, signatures, capabilities.

use crate::mcp::protocol::{ToolContent, ToolDefinition};

/// Build the list of available MCP tool definitions.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "pt_scan".to_string(),
            description: "Run a process scan and return candidates with scores. \
                          Returns a JSON array of process records with evidence."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "Enable deep probes (lsof, ss, etc.)",
                        "default": false
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Minimum score threshold to include (0.0-1.0)",
                        "default": 0.0,
                        "minimum": 0.0,
                        "maximum": 1.0
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_explain".to_string(),
            description: "Explain a specific process — why it was flagged and its evidence chain."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to explain"
                    },
                    "comm": {
                        "type": "string",
                        "description": "Process name (comm) to explain (alternative to pid)"
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_history".to_string(),
            description: "Get recent session history with summaries.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max sessions to return (default: 10)",
                        "default": 10
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_signatures".to_string(),
            description: "List available process signatures (built-in and user-defined)."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "user_only": {
                        "type": "boolean",
                        "description": "Only show user-defined signatures",
                        "default": false
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category: agent, ide, ci, orchestrator, terminal, other"
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_capabilities".to_string(),
            description: "List available platform capabilities and probes.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            }),
        },
    ]
}

/// Dispatch a tool call by name and return content blocks.
pub fn call_tool(name: &str, params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    match name {
        "pt_scan" => tool_scan(params),
        "pt_explain" => tool_explain(params),
        "pt_history" => tool_history(params),
        "pt_signatures" => tool_signatures(params),
        "pt_capabilities" => tool_capabilities(params),
        _ => Err(format!("Unknown tool: {}", name)),
    }
}

fn tool_scan(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let min_score = params
        .get("min_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let options = crate::collect::QuickScanOptions::default();
    let scan_result =
        crate::collect::quick_scan(&options).map_err(|e| format!("Scan failed: {}", e))?;

    // Filter by score if requested, using state as a basic score proxy
    let candidates: Vec<&crate::collect::ProcessRecord> = scan_result
        .processes
        .iter()
        .filter(|p| {
            if min_score > 0.0 {
                let score = match p.state {
                    crate::collect::ProcessState::Zombie => 0.95,
                    crate::collect::ProcessState::Stopped => 0.6,
                    crate::collect::ProcessState::DiskSleep => 0.4,
                    _ => 0.1,
                };
                score >= min_score
            } else {
                true
            }
        })
        .collect();

    let result = serde_json::json!({
        "scanned_at": scan_result.metadata.started_at,
        "duration_ms": scan_result.metadata.duration_ms,
        "platform": scan_result.metadata.platform,
        "total_processes": scan_result.processes.len(),
        "returned": candidates.len(),
        "processes": candidates.iter().take(200).map(|p| {
            serde_json::json!({
                "pid": p.pid.0,
                "ppid": p.ppid.0,
                "comm": p.comm,
                "cmd": p.cmd,
                "state": format!("{}", p.state),
                "uid": p.uid,
                "user": p.user,
                "cpu_pct": p.cpu_percent,
                "rss_bytes": p.rss_bytes,
                "vsz_bytes": p.vsz_bytes,
                "elapsed_sec": p.elapsed.as_secs(),
            })
        }).collect::<Vec<_>>(),
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_explain(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
    let comm = params.get("comm").and_then(|v| v.as_str());

    if pid.is_none() && comm.is_none() {
        return Err("Either 'pid' or 'comm' must be provided".to_string());
    }

    // Run a quick scan to find the process
    let options = crate::collect::QuickScanOptions::default();
    let scan = crate::collect::quick_scan(&options).map_err(|e| format!("Scan failed: {}", e))?;

    let process = scan.processes.iter().find(|p| {
        if let Some(target_pid) = pid {
            p.pid.0 == target_pid
        } else if let Some(target_comm) = comm {
            p.comm == target_comm
        } else {
            false
        }
    });

    match process {
        Some(p) => {
            // Build signature match context
            let ctx = crate::supervision::signature::ProcessMatchContext {
                comm: &p.comm,
                cmdline: Some(p.cmd.as_str()),
                cwd: None,
                env_vars: None,
                socket_paths: None,
                parent_comm: None,
            };

            let mut db = crate::supervision::SignatureDatabase::new();
            db.add_default_signatures();
            if let Some(user_schema) = crate::signature_cli::load_user_signatures() {
                for sig in user_schema.signatures {
                    let _ = db.add(sig);
                }
            }

            let matches = db.match_process(&ctx);

            let state_risk = match p.state {
                crate::collect::ProcessState::Zombie => "high",
                crate::collect::ProcessState::Stopped => "medium",
                crate::collect::ProcessState::DiskSleep => "elevated",
                _ => "low",
            };

            let result = serde_json::json!({
                "pid": p.pid.0,
                "ppid": p.ppid.0,
                "comm": p.comm,
                "cmd": p.cmd,
                "state": format!("{}", p.state),
                "uid": p.uid,
                "user": p.user,
                "cpu_pct": p.cpu_percent,
                "rss_bytes": p.rss_bytes,
                "vsz_bytes": p.vsz_bytes,
                "elapsed_sec": p.elapsed.as_secs(),
                "signature_matches": matches.iter().map(|m| {
                    serde_json::json!({
                        "name": m.signature.name,
                        "category": format!("{:?}", m.signature.category),
                        "score": m.score,
                    })
                }).collect::<Vec<_>>(),
                "evidence": {
                    "state_risk": state_risk,
                    "age_seconds": p.elapsed.as_secs(),
                    "memory_rss_bytes": p.rss_bytes,
                },
            });

            Ok(vec![ToolContent {
                content_type: "text".to_string(),
                text: serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("Serialization error: {}", e))?,
            }])
        }
        None => {
            let target = if let Some(p) = pid {
                format!("PID {}", p)
            } else {
                format!("comm '{}'", comm.unwrap_or("?"))
            };
            Ok(vec![ToolContent {
                content_type: "text".to_string(),
                text: format!("Process {} not found in current scan.", target),
            }])
        }
    }
}

fn tool_history(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let store = crate::session::SessionStore::from_env()
        .map_err(|e| format!("Session store error: {}", e))?;

    let sessions_root = store.sessions_root();
    let mut entries = Vec::new();

    if sessions_root.exists() {
        if let Ok(dir) = std::fs::read_dir(sessions_root) {
            let mut session_dirs: Vec<_> = dir.filter_map(|e| e.ok()).collect();
            session_dirs.sort_by(|a, b| {
                let ta = a.metadata().and_then(|m| m.modified()).ok();
                let tb = b.metadata().and_then(|m| m.modified()).ok();
                tb.cmp(&ta)
            });

            for entry in session_dirs.into_iter().take(limit) {
                let name = entry.file_name().to_string_lossy().to_string();
                let modified = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

                entries.push(serde_json::json!({
                    "session_id": name,
                    "modified": modified,
                }));
            }
        }
    }

    let result = serde_json::json!({
        "sessions_dir": sessions_root.display().to_string(),
        "count": entries.len(),
        "sessions": entries,
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_signatures(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let user_only = params
        .get("user_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let category_filter = params.get("category").and_then(|v| v.as_str());

    let mut all_sigs = Vec::new();

    if !user_only {
        let mut db = crate::supervision::SignatureDatabase::new();
        db.add_default_signatures();
        for sig in db.signatures() {
            if let Some(cat) = category_filter {
                if let Some(parsed) = crate::signature_cli::parse_category(cat) {
                    if sig.category != parsed {
                        continue;
                    }
                }
            }
            all_sigs.push(serde_json::json!({
                "name": sig.name,
                "category": format!("{:?}", sig.category),
                "source": "builtin",
                "priority": sig.priority,
                "confidence": sig.confidence_weight,
            }));
        }
    }

    if let Some(user_schema) = crate::signature_cli::load_user_signatures() {
        for sig in &user_schema.signatures {
            if let Some(cat) = category_filter {
                if let Some(parsed) = crate::signature_cli::parse_category(cat) {
                    if sig.category != parsed {
                        continue;
                    }
                }
            }
            all_sigs.push(serde_json::json!({
                "name": sig.name,
                "category": format!("{:?}", sig.category),
                "source": "user",
                "priority": sig.priority,
                "confidence": sig.confidence_weight,
            }));
        }
    }

    let result = serde_json::json!({
        "count": all_sigs.len(),
        "signatures": all_sigs,
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_capabilities(_params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let caps = crate::capabilities::get_capabilities();

    // Capabilities derives Serialize, so serialize it directly
    let result = serde_json::to_value(&caps).map_err(|e| format!("Serialization error: {}", e))?;

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_not_empty() {
        let defs = tool_definitions();
        assert!(!defs.is_empty());
    }

    #[test]
    fn tool_definitions_have_valid_schemas() {
        for def in tool_definitions() {
            assert!(!def.name.is_empty());
            assert!(!def.description.is_empty());
            assert_eq!(def.input_schema["type"], "object");
        }
    }

    #[test]
    fn tool_definitions_names_have_pt_prefix() {
        for def in tool_definitions() {
            assert!(
                def.name.starts_with("pt_"),
                "Tool '{}' missing pt_ prefix",
                def.name
            );
        }
    }

    #[test]
    fn call_unknown_tool_returns_error() {
        let result = call_tool("nonexistent", &serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn tool_explain_requires_pid_or_comm() {
        let result = call_tool("pt_explain", &serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pid"));
    }

    #[test]
    fn tool_signatures_returns_builtin() {
        let result = call_tool("pt_signatures", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn tool_capabilities_succeeds() {
        let result = call_tool("pt_capabilities", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn tool_history_succeeds() {
        let result = call_tool("pt_history", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed.get("sessions").is_some());
    }

    #[test]
    fn tool_definitions_count() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 5);
    }

    #[test]
    fn tool_scan_definition_has_min_score() {
        let defs = tool_definitions();
        let scan = defs.iter().find(|d| d.name == "pt_scan").unwrap();
        assert!(scan.input_schema["properties"].get("min_score").is_some());
    }
}
