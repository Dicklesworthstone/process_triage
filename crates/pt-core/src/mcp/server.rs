//! MCP server implementation with stdio transport.
//!
//! Reads JSON-RPC 2.0 messages from stdin, dispatches to handlers,
//! and writes responses to stdout.

use crate::mcp::protocol::*;
use crate::mcp::resources;
use crate::mcp::tools;
use std::io::{self, BufRead, Write};

/// MCP server state.
pub struct McpServer {
    initialized: bool,
}

impl McpServer {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Run the stdio event loop: read lines from stdin, dispatch, write to stdout.
    pub fn run_stdio(&mut self) -> io::Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut stdout = stdout.lock();

        for line in stdin.lock().lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let response = self.handle_message(trimmed);

            // Notifications (no id) get no response
            if let Some(resp) = response {
                let json = serde_json::to_string(&resp).unwrap_or_else(|_| {
                    r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Serialization failed"}}"#
                        .to_string()
                });
                writeln!(stdout, "{}", json)?;
                stdout.flush()?;
            }
        }

        Ok(())
    }

    /// Handle a single JSON-RPC message and return a response (or None for notifications).
    pub fn handle_message(&mut self, raw: &str) -> Option<JsonRpcResponse> {
        let request: JsonRpcRequest = match serde_json::from_str(raw) {
            Ok(req) => req,
            Err(_) => {
                return Some(JsonRpcResponse::error(
                    None,
                    PARSE_ERROR,
                    "Parse error: invalid JSON",
                ));
            }
        };

        // Notifications have no id — don't send a response
        if request.id.is_none() {
            self.handle_notification(&request.method);
            return None;
        }

        let id = request.id.clone();

        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request.params),
            "tools/list" => self.handle_tools_list(),
            "tools/call" => self.handle_tools_call(&request.params),
            "resources/list" => self.handle_resources_list(),
            "resources/read" => self.handle_resources_read(&request.params),
            "ping" => Ok(serde_json::json!({})),
            _ => Err((
                METHOD_NOT_FOUND,
                format!("Method not found: {}", request.method),
            )),
        };

        Some(match result {
            Ok(value) => JsonRpcResponse::success(id, value),
            Err((code, msg)) => JsonRpcResponse::error(id, code, msg),
        })
    }

    fn handle_notification(&mut self, method: &str) {
        match method {
            "notifications/initialized" => {
                self.initialized = true;
                eprintln!("[pt-mcp] Client initialized");
            }
            "notifications/cancelled" => {
                eprintln!("[pt-mcp] Request cancelled by client");
            }
            _ => {
                eprintln!("[pt-mcp] Unknown notification: {}", method);
            }
        }
    }

    fn handle_initialize(
        &mut self,
        _params: &serde_json::Value,
    ) -> Result<serde_json::Value, (i32, String)> {
        Ok(serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: None }),
                resources: Some(ResourcesCapability { list_changed: None }),
            },
            "serverInfo": ServerInfo {
                name: "process_triage".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        }))
    }

    fn handle_tools_list(&self) -> Result<serde_json::Value, (i32, String)> {
        let defs = tools::tool_definitions();
        Ok(serde_json::json!({ "tools": defs }))
    }

    fn handle_tools_call(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, (i32, String)> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or((INVALID_PARAMS, "Missing 'name' in tools/call".to_string()))?;

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        match tools::call_tool(name, &arguments) {
            Ok(content) => Ok(serde_json::json!({
                "content": content,
                "isError": false,
            })),
            Err(msg) => Ok(serde_json::json!({
                "content": [ToolContent {
                    content_type: "text".to_string(),
                    text: msg,
                }],
                "isError": true,
            })),
        }
    }

    fn handle_resources_list(&self) -> Result<serde_json::Value, (i32, String)> {
        let defs = resources::resource_definitions();
        Ok(serde_json::json!({ "resources": defs }))
    }

    fn handle_resources_read(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, (i32, String)> {
        let uri = params.get("uri").and_then(|v| v.as_str()).ok_or((
            INVALID_PARAMS,
            "Missing 'uri' in resources/read".to_string(),
        ))?;

        match resources::read_resource(uri) {
            Ok(contents) => Ok(serde_json::json!({ "contents": contents })),
            Err(msg) => Err((INVALID_PARAMS, msg)),
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> McpServer {
        McpServer::new()
    }

    #[test]
    fn handle_parse_error() {
        let mut s = server();
        let resp = s.handle_message("not json").unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn handle_initialize() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#)
            .unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert!(result.get("capabilities").is_some());
        assert!(result.get("serverInfo").is_some());
    }

    #[test]
    fn handle_notification_no_response() {
        let mut s = server();
        let resp = s.handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(resp.is_none());
        assert!(s.initialized);
    }

    #[test]
    fn handle_ping() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#)
            .unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn handle_unknown_method() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":3,"method":"foo/bar"}"#)
            .unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn handle_tools_list() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#)
            .unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
    }

    #[test]
    fn handle_tools_call_missing_name() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}"#)
            .unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handle_tools_call_signatures() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"pt_signatures","arguments":{}}}"#)
            .unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], false);
    }

    #[test]
    fn handle_tools_call_unknown_tool() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}"#)
            .unwrap();
        assert!(resp.error.is_none()); // Returns isError in content, not protocol error
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn handle_resources_list() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":8,"method":"resources/list"}"#)
            .unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
    }

    #[test]
    fn handle_resources_read_missing_uri() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{}}"#)
            .unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn handle_resources_read_version() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":10,"method":"resources/read","params":{"uri":"pt://version"}}"#)
            .unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert!(!contents.is_empty());
    }

    #[test]
    fn handle_resources_read_unknown_uri() {
        let mut s = server();
        let resp = s
            .handle_message(r#"{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"pt://nonexistent"}}"#)
            .unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn server_default_not_initialized() {
        let s = McpServer::default();
        assert!(!s.initialized);
    }

    #[test]
    fn empty_line_skipped() {
        // Verify empty/whitespace input doesn't produce a response
        let mut s = server();
        // Empty string should be filtered by run_stdio, but handle_message treats it as parse error
        let resp = s.handle_message("");
        // Empty string is technically invalid JSON
        assert!(resp.is_some());
    }
}
