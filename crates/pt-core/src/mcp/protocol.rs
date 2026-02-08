//! JSON-RPC 2.0 and MCP protocol types.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// MCP protocol version we implement.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Server info returned in initialize response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Server capabilities advertised in initialize response.
#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Tool definition for tools/list response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Resource definition for resources/list response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Content block returned from tool calls.
#[derive(Debug, Serialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// Resource content block.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_request_deserialize() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn jsonrpc_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc","method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Some(serde_json::json!("abc")));
    }

    #[test]
    fn jsonrpc_request_null_id() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
    }

    #[test]
    fn jsonrpc_response_success_serialize() {
        let resp =
            JsonRpcResponse::success(Some(serde_json::json!(1)), serde_json::json!({"ok": true}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn jsonrpc_response_error_serialize() {
        let resp =
            JsonRpcResponse::error(Some(serde_json::json!(1)), METHOD_NOT_FOUND, "not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"result\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn tool_definition_serialize() {
        let tool = ToolDefinition {
            name: "pt_scan".to_string(),
            description: "Run a process scan".to_string(),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "pt_scan");
        assert_eq!(json["inputSchema"]["type"], "object");
    }

    #[test]
    fn resource_definition_serialize() {
        let res = ResourceDefinition {
            uri: "pt://processes/current".to_string(),
            name: "Current Processes".to_string(),
            description: "Current process snapshot".to_string(),
            mime_type: Some("application/json".to_string()),
        };
        let json = serde_json::to_value(&res).unwrap();
        assert_eq!(json["uri"], "pt://processes/current");
        assert_eq!(json["mimeType"], "application/json");
    }

    #[test]
    fn mcp_protocol_version_is_valid() {
        assert!(!MCP_PROTOCOL_VERSION.is_empty());
        // Should be a date-like string
        assert!(MCP_PROTOCOL_VERSION.contains('-'));
    }

    #[test]
    fn server_capabilities_serialize_with_tools_only() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: None }),
            resources: None,
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("tools").is_some());
        assert!(json.get("resources").is_none());
    }

    #[test]
    fn tool_content_serialize() {
        let content = ToolContent {
            content_type: "text".to_string(),
            text: "hello".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }
}
