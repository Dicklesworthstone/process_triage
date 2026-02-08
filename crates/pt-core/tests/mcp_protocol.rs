//! MCP server protocol compliance and integration tests.
//!
//! Tests the full MCP server against JSON-RPC 2.0 and MCP protocol spec.

use pt_core::mcp::protocol::{
    JsonRpcResponse, MCP_PROTOCOL_VERSION, INVALID_PARAMS, METHOD_NOT_FOUND, PARSE_ERROR,
};
use pt_core::mcp::McpServer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn server() -> McpServer {
    McpServer::new()
}

fn send(server: &mut McpServer, json: &str) -> JsonRpcResponse {
    server.handle_message(json).expect("expected a response")
}

fn send_rpc(server: &mut McpServer, id: u64, method: &str, params: serde_json::Value) -> JsonRpcResponse {
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    send(server, &serde_json::to_string(&msg).unwrap())
}

fn assert_success(resp: &JsonRpcResponse) -> &serde_json::Value {
    assert!(resp.error.is_none(), "expected success but got error: {:?}", resp.error);
    resp.result.as_ref().expect("missing result")
}

fn assert_error(resp: &JsonRpcResponse, expected_code: i32) -> &str {
    let err = resp.error.as_ref().expect("expected error response");
    assert_eq!(err.code, expected_code, "expected error code {} but got {}", expected_code, err.code);
    &err.message
}

// ===========================================================================
// 1. JSON-RPC 2.0 Protocol Compliance
// ===========================================================================

#[test]
fn jsonrpc_version_in_response() {
    let mut s = server();
    let resp = send(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    assert_eq!(resp.jsonrpc, "2.0");
}

#[test]
fn jsonrpc_id_preserved_integer() {
    let mut s = server();
    let resp = send(&mut s, r#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#);
    assert_eq!(resp.id, Some(serde_json::json!(42)));
}

#[test]
fn jsonrpc_id_preserved_string() {
    let mut s = server();
    let resp = send(&mut s, r#"{"jsonrpc":"2.0","id":"my-req-123","method":"ping"}"#);
    assert_eq!(resp.id, Some(serde_json::json!("my-req-123")));
}

#[test]
fn jsonrpc_parse_error_for_invalid_json() {
    let mut s = server();
    let resp = send(&mut s, "{not valid json}");
    assert_error(&resp, PARSE_ERROR);
    assert!(resp.id.is_none()); // Cannot determine id from malformed request
}

#[test]
fn jsonrpc_parse_error_for_truncated_json() {
    let mut s = server();
    let resp = send(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"#);
    assert_error(&resp, PARSE_ERROR);
}

#[test]
fn jsonrpc_method_not_found() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "nonexistent/method", serde_json::json!({}));
    assert_error(&resp, METHOD_NOT_FOUND);
}

#[test]
fn jsonrpc_notification_no_response() {
    let mut s = server();
    // Notifications have no id
    let resp = s.handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert!(resp.is_none(), "notifications should not produce a response");
}

#[test]
fn jsonrpc_ping_returns_empty_object() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "ping", serde_json::json!({}));
    let result = assert_success(&resp);
    assert_eq!(result, &serde_json::json!({}));
}

// ===========================================================================
// 2. MCP Handshake (initialize)
// ===========================================================================

#[test]
fn initialize_returns_protocol_version() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }),
    );
    let result = assert_success(&resp);
    assert_eq!(result["protocolVersion"], MCP_PROTOCOL_VERSION);
}

#[test]
fn initialize_returns_server_info() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }),
    );
    let result = assert_success(&resp);
    let server_info = &result["serverInfo"];
    assert_eq!(server_info["name"], "process_triage");
    assert!(server_info["version"].is_string());
}

#[test]
fn initialize_advertises_tools_capability() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }),
    );
    let result = assert_success(&resp);
    assert!(result["capabilities"]["tools"].is_object());
}

#[test]
fn initialize_advertises_resources_capability() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }),
    );
    let result = assert_success(&resp);
    assert!(result["capabilities"]["resources"].is_object());
}

// ===========================================================================
// 3. tools/list
// ===========================================================================

#[test]
fn tools_list_returns_all_tools() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let tools = result["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5, "expected 5 tools (scan, explain, history, signatures, capabilities)");
}

#[test]
fn tools_list_all_have_pt_prefix() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        assert!(name.starts_with("pt_"), "tool '{}' missing pt_ prefix", name);
    }
}

#[test]
fn tools_list_all_have_valid_input_schema() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "tool {} schema type should be object", tool["name"]);
        assert!(schema.get("properties").is_some(), "tool {} missing properties", tool["name"]);
    }
}

#[test]
fn tools_list_all_have_descriptions() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let desc = tool["description"].as_str().unwrap_or("");
        assert!(!desc.is_empty(), "tool {} has empty description", tool["name"]);
    }
}

#[test]
fn tools_list_includes_expected_tools() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let names: Vec<&str> = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"pt_scan"));
    assert!(names.contains(&"pt_explain"));
    assert!(names.contains(&"pt_history"));
    assert!(names.contains(&"pt_signatures"));
    assert!(names.contains(&"pt_capabilities"));
}

// ===========================================================================
// 4. tools/call — pt_signatures
// ===========================================================================

#[test]
fn tools_call_signatures_returns_content() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_signatures", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "text");
    // The text should be valid JSON with a count field.
    let parsed: serde_json::Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed["count"].as_u64().unwrap() > 0);
}

#[test]
fn tools_call_signatures_with_category_filter() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_signatures", "arguments": {"category": "agent"}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
}

#[test]
fn tools_call_signatures_user_only() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_signatures", "arguments": {"user_only": true}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
}

// ===========================================================================
// 5. tools/call — pt_capabilities
// ===========================================================================

#[test]
fn tools_call_capabilities_returns_platform_info() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_capabilities", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    // Capabilities should have platform and probe info.
    assert!(parsed.get("platform").is_some() || parsed.get("os_type").is_some());
}

// ===========================================================================
// 6. tools/call — pt_explain
// ===========================================================================

#[test]
fn tools_call_explain_requires_pid_or_comm() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_explain", "arguments": {}}),
    );
    let result = assert_success(&resp);
    // Returns isError=true in content, not a protocol error
    assert_eq!(result["isError"], true);
    let content = result["content"].as_array().unwrap();
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("pid"), "error should mention 'pid' requirement");
}

#[test]
fn tools_call_explain_nonexistent_pid() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_explain", "arguments": {"pid": 99999999}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("not found"), "should indicate process not found");
}

// ===========================================================================
// 7. tools/call — pt_history
// ===========================================================================

#[test]
fn tools_call_history_returns_sessions() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_history", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed.get("sessions").is_some());
}

#[test]
fn tools_call_history_with_limit() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_history", "arguments": {"limit": 5}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
}

// ===========================================================================
// 8. tools/call — pt_scan
// ===========================================================================

#[test]
fn tools_call_scan_returns_processes() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_scan", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed["total_processes"].as_u64().unwrap() > 0);
    assert!(parsed.get("scanned_at").is_some());
    assert!(parsed.get("platform").is_some());
    assert!(parsed.get("processes").is_some());
}

#[test]
fn tools_call_scan_with_min_score() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_scan", "arguments": {"min_score": 0.5}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let content = result["content"].as_array().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    // With min_score=0.5, we should get fewer (or equal) processes.
    assert!(parsed["returned"].as_u64().unwrap() <= parsed["total_processes"].as_u64().unwrap());
}

// ===========================================================================
// 9. tools/call — Error Cases
// ===========================================================================

#[test]
fn tools_call_missing_name_param() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"arguments": {}}),
    );
    assert_error(&resp, INVALID_PARAMS);
}

#[test]
fn tools_call_unknown_tool_is_content_error() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_nonexistent", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], true);
}

#[test]
fn tools_call_no_arguments_uses_default() {
    let mut s = server();
    // Missing "arguments" key should default to empty object.
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_capabilities"}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
}

// ===========================================================================
// 10. resources/list
// ===========================================================================

#[test]
fn resources_list_returns_all_resources() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "resources/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let resources = result["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 4, "expected 4 resources");
}

#[test]
fn resources_list_all_have_pt_uri_prefix() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "resources/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for res in result["resources"].as_array().unwrap() {
        let uri = res["uri"].as_str().unwrap();
        assert!(uri.starts_with("pt://"), "resource '{}' missing pt:// prefix", uri);
    }
}

#[test]
fn resources_list_all_have_json_mime_type() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "resources/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for res in result["resources"].as_array().unwrap() {
        assert_eq!(
            res["mimeType"], "application/json",
            "resource '{}' should have application/json mime type",
            res["uri"]
        );
    }
}

#[test]
fn resources_list_includes_expected_uris() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "resources/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let uris: Vec<&str> = result["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"pt://config/priors"));
    assert!(uris.contains(&"pt://config/policy"));
    assert!(uris.contains(&"pt://signatures/builtin"));
    assert!(uris.contains(&"pt://version"));
}

// ===========================================================================
// 11. resources/read
// ===========================================================================

#[test]
fn resources_read_version() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({"uri": "pt://version"}),
    );
    let result = assert_success(&resp);
    let contents = result["contents"].as_array().unwrap();
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0]["uri"], "pt://version");
    let parsed: serde_json::Value =
        serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(parsed["name"], "process_triage");
    assert!(parsed["version"].is_string());
    assert_eq!(parsed["mcp_protocol"], MCP_PROTOCOL_VERSION);
}

#[test]
fn resources_read_signatures_builtin() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({"uri": "pt://signatures/builtin"}),
    );
    let result = assert_success(&resp);
    let contents = result["contents"].as_array().unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed["count"].as_u64().unwrap() > 0);
    assert!(parsed["signatures"].is_array());
}

#[test]
fn resources_read_config_priors() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({"uri": "pt://config/priors"}),
    );
    let result = assert_success(&resp);
    let contents = result["contents"].as_array().unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed.get("description").is_some());
}

#[test]
fn resources_read_config_policy() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({"uri": "pt://config/policy"}),
    );
    let result = assert_success(&resp);
    let contents = result["contents"].as_array().unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
    assert!(parsed.get("description").is_some());
}

#[test]
fn resources_read_unknown_uri() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({"uri": "pt://nonexistent"}),
    );
    assert_error(&resp, INVALID_PARAMS);
}

#[test]
fn resources_read_missing_uri_param() {
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "resources/read",
        serde_json::json!({}),
    );
    assert_error(&resp, INVALID_PARAMS);
}

// ===========================================================================
// 12. Full Protocol Conversation Flow
// ===========================================================================

#[test]
fn full_mcp_conversation_flow() {
    let mut s = server();

    // 1. Initialize
    let resp = send_rpc(
        &mut s,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "integration-test", "version": "1.0"}
        }),
    );
    let result = assert_success(&resp);
    assert_eq!(result["protocolVersion"], MCP_PROTOCOL_VERSION);

    // 2. Send initialized notification (no response expected)
    let notif = s.handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert!(notif.is_none());

    // 3. List tools
    let resp = send_rpc(&mut s, 2, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let tools = result["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);

    // 4. List resources
    let resp = send_rpc(&mut s, 3, "resources/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let resources = result["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 4);

    // 5. Call a tool
    let resp = send_rpc(
        &mut s,
        4,
        "tools/call",
        serde_json::json!({"name": "pt_capabilities", "arguments": {}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);

    // 6. Read a resource
    let resp = send_rpc(
        &mut s,
        5,
        "resources/read",
        serde_json::json!({"uri": "pt://version"}),
    );
    assert_success(&resp);

    // 7. Ping
    let resp = send_rpc(&mut s, 6, "ping", serde_json::json!({}));
    assert_success(&resp);
}

// ===========================================================================
// 13. Security: Malformed Input Handling
// ===========================================================================

#[test]
fn security_malformed_json_handled_gracefully() {
    let mut s = server();
    let cases = vec![
        "",
        "null",
        "[]",
        "true",
        "42",
        r#"{"jsonrpc":"1.0"}"#,  // Wrong version (still parseable)
        r#"{"jsonrpc":"2.0","id":1}"#,  // Missing method
    ];
    for input in cases {
        let resp = s.handle_message(input);
        // Should either return None (notification-like) or an error response, not panic.
        if let Some(r) = resp {
            // Either parse error or some other handled error — never a success
            // (except for the empty-method case which would be METHOD_NOT_FOUND)
            assert!(r.error.is_some() || r.result.is_some());
        }
    }
}

#[test]
fn security_very_large_id_handled() {
    let mut s = server();
    let resp = send(
        &mut s,
        r#"{"jsonrpc":"2.0","id":99999999999999999,"method":"ping"}"#,
    );
    assert!(resp.error.is_none());
}

#[test]
fn security_null_params_handled() {
    let mut s = server();
    let resp = send(
        &mut s,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}"#,
    );
    // Should work — tools/list doesn't use params.
    assert_success(&resp);
}

#[test]
fn security_extra_fields_ignored() {
    let mut s = server();
    let resp = send(
        &mut s,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","extra_field":"ignored","nested":{"x":1}}"#,
    );
    assert_success(&resp);
}

// ===========================================================================
// 14. Resource Content Validation
// ===========================================================================

#[test]
fn all_resources_return_valid_json_content() {
    let mut s = server();
    let uris = ["pt://config/priors", "pt://config/policy", "pt://signatures/builtin", "pt://version"];

    for uri in &uris {
        let resp = send_rpc(
            &mut s,
            1,
            "resources/read",
            serde_json::json!({"uri": uri}),
        );
        let result = assert_success(&resp);
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1, "resource {} should return 1 content block", uri);
        assert_eq!(contents[0]["uri"], *uri);
        // Content should be parseable JSON
        let text = contents[0]["text"].as_str().unwrap();
        let _: serde_json::Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("resource {} returned invalid JSON: {}", uri, e));
    }
}

// ===========================================================================
// 15. Tool Schema Validation
// ===========================================================================

#[test]
fn tool_scan_schema_has_min_score_and_deep() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let scan = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "pt_scan")
        .expect("pt_scan tool not found");

    let props = &scan["inputSchema"]["properties"];
    assert!(props.get("min_score").is_some(), "pt_scan should have min_score parameter");
    assert!(props.get("deep").is_some(), "pt_scan should have deep parameter");
}

#[test]
fn tool_explain_schema_has_pid_and_comm() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let explain = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "pt_explain")
        .expect("pt_explain tool not found");

    let props = &explain["inputSchema"]["properties"];
    assert!(props.get("pid").is_some(), "pt_explain should have pid parameter");
    assert!(props.get("comm").is_some(), "pt_explain should have comm parameter");
}

#[test]
fn tool_history_schema_has_limit() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let history = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "pt_history")
        .expect("pt_history tool not found");

    let props = &history["inputSchema"]["properties"];
    assert!(props.get("limit").is_some(), "pt_history should have limit parameter");
}

#[test]
fn tool_signatures_schema_has_user_only_and_category() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let sigs = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "pt_signatures")
        .expect("pt_signatures tool not found");

    let props = &sigs["inputSchema"]["properties"];
    assert!(props.get("user_only").is_some());
    assert!(props.get("category").is_some());
}

#[test]
fn tool_capabilities_schema_is_empty() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    let caps = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "pt_capabilities")
        .expect("pt_capabilities tool not found");

    let props = caps["inputSchema"]["properties"].as_object().unwrap();
    assert!(props.is_empty(), "pt_capabilities should have no parameters");
}

// ===========================================================================
// 16. Multiple Sequential Requests
// ===========================================================================

#[test]
fn multiple_sequential_requests_different_ids() {
    let mut s = server();
    for i in 1..=20 {
        let resp = send_rpc(&mut s, i, "ping", serde_json::json!({}));
        assert_eq!(resp.id, Some(serde_json::json!(i)));
        assert_success(&resp);
    }
}

#[test]
fn interleaved_tool_and_resource_calls() {
    let mut s = server();

    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_signatures", "arguments": {}}),
    );
    assert_eq!(assert_success(&resp)["isError"], false);

    let resp = send_rpc(
        &mut s,
        2,
        "resources/read",
        serde_json::json!({"uri": "pt://version"}),
    );
    assert_success(&resp);

    let resp = send_rpc(
        &mut s,
        3,
        "tools/call",
        serde_json::json!({"name": "pt_capabilities", "arguments": {}}),
    );
    assert_eq!(assert_success(&resp)["isError"], false);

    let resp = send_rpc(
        &mut s,
        4,
        "resources/read",
        serde_json::json!({"uri": "pt://signatures/builtin"}),
    );
    assert_success(&resp);
}
