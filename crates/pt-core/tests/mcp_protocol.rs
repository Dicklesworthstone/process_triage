//! MCP server protocol compliance and integration tests.
//!
//! Tests the full MCP server against JSON-RPC 2.0 and MCP protocol spec.

use pt_core::mcp::protocol::{
    JsonRpcResponse, INVALID_PARAMS, MCP_PROTOCOL_VERSION, METHOD_NOT_FOUND, PARSE_ERROR,
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

fn send_rpc(
    server: &mut McpServer,
    id: u64,
    method: &str,
    params: serde_json::Value,
) -> JsonRpcResponse {
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    send(server, &serde_json::to_string(&msg).unwrap())
}

fn assert_success(resp: &JsonRpcResponse) -> &serde_json::Value {
    assert!(
        resp.error.is_none(),
        "expected success but got error: {:?}",
        resp.error
    );
    resp.result.as_ref().expect("missing result")
}

fn assert_error(resp: &JsonRpcResponse, expected_code: i32) -> &str {
    let err = resp.error.as_ref().expect("expected error response");
    assert_eq!(
        err.code, expected_code,
        "expected error code {} but got {}",
        expected_code, err.code
    );
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
    let resp = send(
        &mut s,
        r#"{"jsonrpc":"2.0","id":"my-req-123","method":"ping"}"#,
    );
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
    assert!(
        resp.is_none(),
        "notifications should not produce a response"
    );
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
    assert_eq!(
        tools.len(),
        6,
        "expected 6 tools (scan, explain, plan, history, signatures, capabilities)"
    );
}

#[test]
fn tools_list_all_have_pt_prefix() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        assert!(
            name.starts_with("pt_"),
            "tool '{}' missing pt_ prefix",
            name
        );
    }
}

#[test]
fn tools_list_all_have_valid_input_schema() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"], "object",
            "tool {} schema type should be object",
            tool["name"]
        );
        assert!(
            schema.get("properties").is_some(),
            "tool {} missing properties",
            tool["name"]
        );
    }
}

#[test]
fn tools_list_all_have_descriptions() {
    let mut s = server();
    let resp = send_rpc(&mut s, 1, "tools/list", serde_json::json!({}));
    let result = assert_success(&resp);
    for tool in result["tools"].as_array().unwrap() {
        let desc = tool["description"].as_str().unwrap_or("");
        assert!(
            !desc.is_empty(),
            "tool {} has empty description",
            tool["name"]
        );
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
    let parsed: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
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
    let parsed: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
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
    assert!(
        text.contains("pid"),
        "error should mention 'pid' requirement"
    );
}

/// pt_scan scores are pt's posterior P(abandoned or zombie), not an ad-hoc
/// signature+state number; protected processes are marked and listed last.
#[test]
fn tools_call_scan_scores_are_posterior_probabilities() {
    let mut s = server();
    // min_age 0: score every process (a freshly booted CI runner may have none older
    // than the default floor).
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_scan", "arguments": {"min_age": 0}}),
    );
    let result = assert_success(&resp);
    assert_eq!(result["isError"], false);
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    let procs = parsed["processes"].as_array().expect("processes");
    assert!(!procs.is_empty());
    assert_eq!(parsed["window_ms"], 500);
    let mut seen_protected = false;
    for p in procs {
        let activity = &p["activity"];
        assert!(activity.is_object(), "{p}");
        assert_eq!(activity["requested_window_ms"], 500, "{p}");
        assert_eq!(activity["pid"], p["pid"], "{p}");
        assert_eq!(activity["start_id"], p["start_id"], "{p}");
        assert_eq!(activity["uid"], p["uid"], "{p}");
        assert_eq!(p["cpu_pct"], activity["cpu_percent"], "{p}");
        assert_eq!(p["io_activity"], activity["io_active"], "{p}");
        assert!(p["cpu_lifetime_pct"].as_f64().is_some(), "{p}");
        if p["cpu_pct"].is_null() {
            assert!(activity["cpu_error"].is_string(), "{p}");
        }
        let score = p["score"].as_f64().expect("score");
        assert!((0.0..=1.0).contains(&score), "{p}");
        let post = &p["posterior"];
        let ab = post["abandoned"].as_f64().unwrap() + post["zombie"].as_f64().unwrap();
        assert!(
            (score - ab).abs() < 1e-9,
            "score must be P(abandoned+zombie): {p}"
        );
        assert_eq!(
            p["suspicion_score"].as_u64().unwrap(),
            (score * 100.0).round() as u64
        );
        let protected = !p["protected"].is_null();
        assert!(
            !(seen_protected && !protected),
            "unprotected after protected: {p}"
        );
        seen_protected |= protected;
    }
}

/// pt_scan applies agent plan's age floor by default: a process started a moment ago
/// is not scored (it was returned with a suspicion score); `min_age: 0` includes it.
#[test]
fn tools_call_scan_skips_processes_younger_than_the_age_floor() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = u64::from(child.id());
    let scan = |s: &mut McpServer, args: serde_json::Value| {
        let resp = send_rpc(
            s,
            1,
            "tools/call",
            serde_json::json!({"name": "pt_scan", "arguments": args}),
        );
        let result = assert_success(&resp);
        let text = result["content"][0]["text"].as_str().unwrap();
        serde_json::from_str::<serde_json::Value>(text).unwrap()
    };
    let mut s = server();
    let default = scan(&mut s, serde_json::json!({}));
    let all = scan(&mut s, serde_json::json!({"min_age": 0}));
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        default["min_age_seconds"].as_u64().unwrap() > 0,
        "{default}"
    );
    assert!(
        default["younger_than_min_age"].as_u64().unwrap() >= 1,
        "the child is younger than the floor"
    );
    let returned_pids = |v: &serde_json::Value| -> Vec<u64> {
        v["processes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["pid"].as_u64().unwrap())
            .collect()
    };
    assert!(!returned_pids(&default).contains(&pid));
    for p in default["processes"].as_array().unwrap() {
        assert!(
            p["elapsed_sec"].as_u64().unwrap() >= default["min_age_seconds"].as_u64().unwrap(),
            "{p}"
        );
    }

    assert_eq!(all["min_age_seconds"], 0);
    assert_eq!(all["younger_than_min_age"], 0);
}

/// pt_explain reports the posterior and protection for a live process.
#[test]
fn tools_call_explain_reports_posterior_and_protection() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let mut s = server();
    let resp = send_rpc(
        &mut s,
        1,
        "tools/call",
        serde_json::json!({"name": "pt_explain", "arguments": {"pid": child.id()}}),
    );
    let _ = child.kill();
    let _ = child.wait();
    let result = assert_success(&resp);
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    let post = &parsed["posterior"];
    let ab = post["abandoned"].as_f64().unwrap() + post["zombie"].as_f64().unwrap();
    assert!(
        (parsed["score"].as_f64().unwrap() - ab).abs() < 1e-9,
        "{parsed}"
    );
    assert!(parsed.get("protected").is_some(), "{parsed}");
    assert_eq!(parsed["window_ms"], 500);
    let activity = &parsed["activity"];
    assert!(activity.is_object(), "{parsed}");
    assert_eq!(activity["pid"], parsed["pid"], "{parsed}");
    assert_eq!(activity["start_id"], parsed["start_id"], "{parsed}");
    assert_eq!(activity["uid"], parsed["uid"], "{parsed}");
    assert_eq!(activity["requested_window_ms"], 500, "{parsed}");
    assert_eq!(parsed["cpu_pct"], activity["cpu_percent"], "{parsed}");
    assert_eq!(parsed["io_activity"], activity["io_active"], "{parsed}");
    assert!(parsed["cpu_lifetime_pct"].as_f64().is_some(), "{parsed}");
    if parsed["cpu_pct"].is_null() {
        assert!(activity["cpu_error"].is_string(), "{parsed}");
    }
    assert!(
        parsed["evidence"].as_array().is_some_and(|e| !e.is_empty()),
        "{parsed}"
    );
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
    assert!(
        text.contains("not found"),
        "should indicate process not found"
    );
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
    let parsed: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
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
    let parsed: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
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
    let parsed: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
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
        assert!(
            uri.starts_with("pt://"),
            "resource '{}' missing pt:// prefix",
            uri
        );
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
    let resp = send_rpc(&mut s, 1, "resources/read", serde_json::json!({}));
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
    assert_eq!(tools.len(), 6);

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
        r#"{"jsonrpc":"1.0"}"#,        // Wrong version (still parseable)
        r#"{"jsonrpc":"2.0","id":1}"#, // Missing method
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
    let uris = [
        "pt://config/priors",
        "pt://config/policy",
        "pt://signatures/builtin",
        "pt://version",
    ];

    for uri in &uris {
        let resp = send_rpc(&mut s, 1, "resources/read", serde_json::json!({"uri": uri}));
        let result = assert_success(&resp);
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(
            contents.len(),
            1,
            "resource {} should return 1 content block",
            uri
        );
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
    assert!(
        props.get("min_score").is_some(),
        "pt_scan should have min_score parameter"
    );
    assert!(
        props.get("deep").is_some(),
        "pt_scan should have deep parameter"
    );
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
    assert!(
        props.get("pid").is_some(),
        "pt_explain should have pid parameter"
    );
    assert!(
        props.get("comm").is_some(),
        "pt_explain should have comm parameter"
    );
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
    assert!(
        props.get("limit").is_some(),
        "pt_history should have limit parameter"
    );
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
    assert!(
        props.is_empty(),
        "pt_capabilities should have no parameters"
    );
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

#[test]
fn actual_mcp_sampling_windows_are_advertised_and_rejected_before_process_work() {
    use assert_cmd::cargo::cargo_bin_cmd;

    let config = tempfile::tempdir().expect("config directory");
    std::fs::write(config.path().join("policy.json"), b"{")
        .expect("write deliberately invalid config");
    let mut requests = vec![serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    })];
    for name in ["pt_scan", "pt_explain", "pt_plan"] {
        for invalid in [
            serde_json::json!(-1),
            serde_json::json!(60_001),
            serde_json::json!(0.5),
            serde_json::json!("500"),
            serde_json::Value::Null,
        ] {
            requests.push(serde_json::json!({
                "jsonrpc": "2.0",
                "id": requests.len() + 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": {"pid": 1, "window_ms": invalid},
                },
            }));
        }
    }
    let input = requests.iter().map(|request| format!("{request}\n")).collect::<String>();
    let output = cargo_bin_cmd!("pt-core")
        .arg("--config")
        .arg(config.path())
        .arg("mcp")
        .write_stdin(input)
        .timeout(std::time::Duration::from_secs(30))
        .output()
        .expect("run actual MCP window validation");
    assert!(output.status.success(), "{output:?}");
    let responses: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .expect("MCP stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), requests.len(), "{responses:?}");
    let definitions = responses[0]["result"]["tools"].as_array().expect("tool definitions");
    for name in ["pt_scan", "pt_explain", "pt_plan"] {
        let definition = definitions.iter().find(|tool| tool["name"] == name).unwrap();
        let window = &definition["inputSchema"]["properties"]["window_ms"];
        assert_eq!(window["type"], "integer", "{name}");
        assert_eq!(window["default"], 500, "{name}");
        assert_eq!(window["minimum"], 0, "{name}");
        assert_eq!(window["maximum"], 60_000, "{name}");
    }
    for (index, response) in responses.iter().enumerate().skip(1) {
        assert_eq!(response["id"], index + 1, "{response}");
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["isError"], true, "{response}");
        let error = response["result"]["content"][0]["text"].as_str().unwrap();
        // This must reject the interval before loading the deliberately broken
        // policy, scanning /proc, waiting, or spawning the planner child.
        assert!(error.contains("window_ms"), "{error}");
        assert!(error.contains("60000"), "{error}");
        assert!(!error.contains("config"), "{error}");
    }
}

#[test]
fn actual_mcp_plan_child_uses_the_servers_explicit_config() {
    use assert_cmd::cargo::cargo_bin_cmd;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let root = std::env::temp_dir().join(format!("pt-mcp-config-{}", uuid::Uuid::new_v4()));
    let valid = root.join("valid config");
    let invalid = root.join("invalid config");
    std::fs::create_dir_all(&valid).expect("create retained valid config");
    std::fs::create_dir_all(&invalid).expect("create retained invalid config");
    std::fs::write(
        valid.join("policy.json"),
        serde_json::to_vec_pretty(&pt_core::config::Policy::default()).expect("serialize policy"),
    )
    .expect("write valid policy");
    std::fs::write(invalid.join("policy.json"), b"{").expect("write malformed policy");
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 73,
        "method": "tools/call",
        "params": {
            "name": "pt_plan",
            "arguments": {"min_age": u64::MAX}
        }
    });
    std::fs::write(root.join("request.json"), request.to_string()).expect("retain request");
    let mut steps = std::fs::File::create(root.join("steps.jsonl")).expect("retain steps");
    eprintln!("retained MCP config evidence: {}", root.display());

    for (label, explicit, fallback, expected_error) in [
        ("explicit_valid", Some(&valid), &invalid, false),
        ("fallback_invalid", None, &invalid, true),
        ("explicit_invalid", Some(&invalid), &valid, true),
    ] {
        let data = root.join(format!("data-{label}"));
        let mut command = cargo_bin_cmd!("pt-core");
        command
            .timeout(std::time::Duration::from_secs(120))
            .env_remove("PT_CONFIG_DIR")
            .env_remove("PT_SKIP_GLOBAL_LOCK")
            .env("PROCESS_TRIAGE_CONFIG", fallback)
            .env("PROCESS_TRIAGE_DATA", &data)
            .env("PROCESS_TRIAGE_RETENTION", "off");
        if let Some(dir) = explicit {
            command.arg("--config").arg(dir);
        }
        let started = std::time::Instant::now();
        let output = command
            .arg("mcp")
            .write_stdin(format!("{request}\n"))
            .output()
            .expect("execute actual MCP server and planner child");
        std::fs::write(root.join(format!("{label}.stdout")), &output.stdout)
            .expect("retain MCP stdout");
        std::fs::write(root.join(format!("{label}.stderr")), &output.stderr)
            .expect("retain MCP stderr");
        writeln!(
            steps,
            "{}",
            serde_json::json!({
                "step": label,
                "command": "pt-core mcp",
                "explicit_config": explicit,
                "fallback_config": fallback,
                "exit_code": output.status.code(),
                "elapsed_ms": started.elapsed().as_millis(),
                "stdout_sha256": hex::encode(Sha256::digest(&output.stdout)),
                "stderr_sha256": hex::encode(Sha256::digest(&output.stderr))
            })
        )
        .expect("retain MCP step receipt");
        assert!(output.status.success(), "MCP server failed: {output:?}");
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("actual JSON-RPC response");
        assert_eq!(response["id"], 73);
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["isError"], expected_error, "{response}");
        let content = response["result"]["content"][0]["text"]
            .as_str()
            .expect("planner result text");
        if expected_error {
            assert!(content.contains("failed to load config"), "{content}");
        } else {
            let plan: serde_json::Value = serde_json::from_str(content).expect("real plan JSON");
            let executable: pt_core::plan::Plan =
                serde_json::from_value(plan.clone()).expect("real executable Plan");
            assert!(executable.actions.is_empty(), "{plan}");
            assert_eq!(plan["candidates"].as_array().expect("candidates").len(), 0);
            let saved: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    data.join("sessions")
                        .join(&executable.session_id)
                        .join("decision/plan.json"),
                )
                .expect("actual MCP child saved Plan"),
            )
            .expect("saved plan JSON");
            assert_eq!(saved, plan, "MCP returns the genuine persisted Plan");
        }
    }
}

#[test]
fn actual_mcp_scan_and_explain_preserve_config_and_invoker_protection() {
    use assert_cmd::cargo::cargo_bin_cmd;

    let root = std::env::temp_dir().join(format!("pt-mcp-evaluator-{}", uuid::Uuid::new_v4()));
    let valid = root.join("valid config");
    let invalid = root.join("invalid config");
    let invalid_pattern = root.join("invalid protection");
    let invalid_priors = root.join("invalid priors");
    for dir in [&valid, &invalid, &invalid_pattern, &invalid_priors] {
        std::fs::create_dir_all(dir).expect("create retained MCP config");
    }
    let mut policy = pt_core::config::Policy::default();
    // The scan must use this explicit policy, not defaults. No processes need to
    // be scored; explain still evaluates the requested caller below this floor.
    policy.guardrails.min_process_age_seconds = u64::MAX;
    std::fs::write(
        valid.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize valid policy"),
    )
    .expect("write valid policy");
    std::fs::write(invalid.join("policy.json"), b"{").expect("write malformed policy");
    policy.guardrails.protected_patterns[0].pattern = "[".to_string();
    std::fs::write(
        invalid_pattern.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize malformed protection rule"),
    )
    .expect("write invalid protection");
    std::fs::write(invalid_priors.join("priors.json"), b"{").expect("write malformed priors");

    let caller_pid = std::process::id();
    let requests = [
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "pt_scan", "arguments": {}}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "pt_explain", "arguments": {"pid": caller_pid}}
        }),
    ];
    let input = format!("{}\n{}\n", requests[0], requests[1]);
    std::fs::write(root.join("requests.jsonl"), &input).expect("retain MCP requests");
    eprintln!("retained MCP evaluator evidence: {}", root.display());

    for (label, explicit, fallback, expected_error) in [
        ("explicit_valid", Some(&valid), &invalid, false),
        ("fallback_valid", None, &valid, false),
        ("fallback_invalid", None, &invalid, true),
        ("explicit_invalid", Some(&invalid), &valid, true),
        ("invalid_protection", Some(&invalid_pattern), &valid, true),
        ("invalid_priors", Some(&invalid_priors), &valid, true),
    ] {
        let mut command = cargo_bin_cmd!("pt-core");
        command
            .timeout(std::time::Duration::from_secs(120))
            .env_remove("PT_CONFIG_DIR")
            .env_remove("PT_SKIP_GLOBAL_LOCK")
            .env("PROCESS_TRIAGE_CONFIG", fallback)
            .env("PROCESS_TRIAGE_DATA", root.join(format!("data-{label}")))
            .env("PROCESS_TRIAGE_RETENTION", "off");
        if let Some(dir) = explicit {
            command.arg("--config").arg(dir);
        }
        let output = command
            .arg("mcp")
            .write_stdin(input.clone())
            .output()
            .expect("execute actual MCP scan and explain");
        std::fs::write(root.join(format!("{label}.stdout")), &output.stdout)
            .expect("retain MCP stdout");
        std::fs::write(root.join(format!("{label}.stderr")), &output.stderr)
            .expect("retain MCP stderr");
        assert!(output.status.success(), "{label}: {output:?}");
        let responses: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
            .expect("MCP stdout is UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("actual JSON-RPC response"))
            .collect();
        assert_eq!(responses.len(), 2, "{label}: {responses:?}");
        for (index, response) in responses.iter().enumerate() {
            assert_eq!(response["id"], index + 1, "{label}: {response}");
            assert!(response["error"].is_null(), "{label}: {response}");
            assert_eq!(
                response["result"]["isError"], expected_error,
                "{label}: {response}"
            );
            let text = response["result"]["content"][0]["text"]
                .as_str()
                .expect("tool response text");
            if expected_error {
                assert!(
                    text.starts_with("failed to load config:")
                        || text.starts_with("failed to load protection rules:"),
                    "{label}: {text}"
                );
                continue;
            }
            let result: serde_json::Value = serde_json::from_str(text).expect("tool result JSON");
            if index == 0 {
                assert_eq!(result["min_age_seconds"], u64::MAX, "{label}: {result}");
                assert!(result["total_processes"].as_u64().unwrap() > 0);
                assert_eq!(result["returned"], 0);
                assert!(result["processes"].as_array().unwrap().is_empty());
            } else {
                assert_eq!(result["pid"], caller_pid, "{label}: {result}");
                assert_eq!(
                    result["protected"]["rule"], "builtin.invoker_chain",
                    "{label}: the actual MCP server must protect its caller: {result}"
                );
                assert!(result["posterior"].is_object(), "{label}: {result}");
                assert_eq!(result["window_ms"], 500, "{label}: {result}");
                let activity = &result["activity"];
                assert_eq!(activity["pid"], caller_pid, "{label}: {result}");
                assert_eq!(activity["start_id"], result["start_id"], "{label}: {result}");
                assert_eq!(activity["uid"], result["uid"], "{label}: {result}");
                assert_eq!(activity["requested_window_ms"], 500, "{label}: {result}");
                assert_eq!(result["cpu_pct"], activity["cpu_percent"], "{label}: {result}");
                assert_eq!(result["io_activity"], activity["io_active"], "{label}: {result}");
                assert!(result["cpu_lifetime_pct"].as_f64().is_some(), "{label}: {result}");
                if result["cpu_pct"].is_null() {
                    assert!(activity["cpu_error"].is_string(), "{label}: {result}");
                }
            }
        }
    }
}

/// Deep scanning must enrich the canonical snapshot instead of replacing age,
/// CPU and terminal facts with zeroes. Exercise the actual stdin/stdout protocol
/// with a positive policy age floor and an owned, CPU-active terminal process.
#[cfg(target_os = "linux")]
#[test]
fn actual_mcp_deep_scan_preserves_live_snapshot_and_default_age_candidates() {
    use assert_cmd::cargo::cargo_bin_cmd;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty initializes both output descriptors and null inputs request
    // default terminal settings; each successful descriptor is owned below.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: these are distinct descriptors returned by the successful openpty.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    for descriptor in [&master, &slave] {
        // SAFETY: fcntl changes only close-on-exec for this fixture's live FDs.
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
            -1,
            "terminal close-on-exec"
        );
    }
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("owned listener");
    let port = listener.local_addr().unwrap().port();
    let socket: OwnedFd = listener.into();
    let mut command = std::process::Command::new("bash");
    command
        .args([
            "-c",
            "deadline=$((SECONDS+300)); while (( SECONDS < deadline )); do :; done",
        ])
        .stdin(Stdio::from(slave))
        // No output is written: the open listener supplies real deep evidence.
        .stdout(Stdio::from(socket))
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe syscalls run in this child before exec. Its
    // stdin is the owned PTY slave and becomes its controlling terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(command.spawn().expect("spawn owned terminal process"));
    drop(command);
    let pid = child.0.id();
    let deadline = Instant::now() + Duration::from_secs(15);
    let baseline = loop {
        let scan = pt_core::collect::quick_scan(&pt_core::collect::QuickScanOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .expect("observe owned process");
        if let Some(process) = scan.processes.into_iter().find(|process| {
            process.pid.0 == pid
                && process.elapsed.as_secs() >= 1
                && process.cpu_percent > 0.0
                && process.has_tty()
        }) {
            break process;
        }
        assert!(
            Instant::now() < deadline,
            "owned process never became an aged CPU-active TTY fixture"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    let root = std::env::temp_dir().join(format!("pt-mcp-deep-{}", uuid::Uuid::new_v4()));
    let config = root.join("config");
    std::fs::create_dir_all(&config).expect("create retained MCP config");
    eprintln!("retained MCP deep-scan evidence: {}", root.display());
    let mut policy = pt_core::config::Policy::default();
    policy.guardrails.min_process_age_seconds = 1;
    policy.guardrails.builtin_protection = false;
    policy.guardrails.protected_users.clear();
    policy.guardrails.protected_categories.clear();
    policy.guardrails.never_kill_ppid.clear();
    // Keep the owned child first in the bounded scan response on busy CI hosts,
    // and limit deep probes to it. The full snapshot is still used for protection.
    policy.guardrails.never_kill_pid = pt_core::collect::quick_scan(&Default::default())
        .expect("fixture population")
        .processes
        .into_iter()
        .filter(|process| process.pid.0 != pid)
        .map(|process| process.pid.0)
        .collect();
    std::fs::write(
        config.join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .expect("write policy");
    std::fs::write(
        root.join("baseline.json"),
        serde_json::to_vec_pretty(&baseline).unwrap(),
    )
    .expect("retain observed baseline");

    // This regression isolates preservation of quick-snapshot facts. Sampled
    // activity has separate protocol coverage and must not replace this baseline.
    let requests = [
        serde_json::json!({"window_ms": 0}),
        serde_json::json!({"deep": true, "window_ms": 0}),
        serde_json::json!({"deep": true, "min_age": u64::MAX, "window_ms": 0}),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, arguments)| {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": index + 1,
            "method": "tools/call",
            "params": {"name": "pt_scan", "arguments": arguments},
        })
        .to_string()
            + "\n"
    })
    .collect::<String>();
    let output = cargo_bin_cmd!("pt-core")
        .arg("--config")
        .arg(&config)
        .arg("mcp")
        .env("PROCESS_TRIAGE_DATA", root.join("data"))
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .write_stdin(requests)
        .timeout(Duration::from_secs(120))
        .output()
        .expect("run actual MCP deep scan");
    std::fs::write(root.join("stdout.jsonl"), &output.stdout).expect("retain MCP stdout");
    std::fs::write(root.join("stderr.txt"), &output.stderr).expect("retain MCP stderr");
    assert!(output.status.success(), "{output:?}");
    let responses: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .expect("MCP stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), 3, "{responses:?}");
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response["id"], index + 1);
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["isError"], false, "{response}");
        let result: serde_json::Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("scan JSON text"),
        )
        .expect("scan JSON");
        let processes = result["processes"].as_array().expect("processes");
        assert_eq!(result["returned"], processes.len(), "{result}");
        assert_eq!(result["window_ms"], 0, "{result}");
        if index == 2 {
            assert_eq!(result["min_age_seconds"], u64::MAX);
            assert!(processes.is_empty());
            assert_eq!(result["deep_scan"]["status"], "no_eligible_processes");
            assert_eq!(result["deep_scan"]["requested_processes"], 0);
            continue;
        }
        assert_eq!(result["min_age_seconds"], 1, "policy default must be used");
        let process = processes
            .iter()
            .find(|process| process["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap_or_else(|| {
                panic!("scan {index} lost the owned age-eligible process: {result}")
            });
        assert!(process["elapsed_sec"].as_u64().unwrap() >= 1, "{process}");
        assert!(process["cpu_pct"].as_f64().unwrap() > 0.0, "{process}");
        assert_eq!(process["cpu_pct"], process["cpu_lifetime_pct"], "{process}");
        assert!(process["activity"].is_null(), "{process}");
        assert!(process["io_activity"].is_null(), "{process}");
        assert!(process["rss_bytes"].as_u64().unwrap() > 0, "{process}");
        assert_eq!(process["start_id"], baseline.start_id.0);
        assert_eq!(process["start_time_unix"], baseline.start_time_unix);
        assert_eq!(process["tty"].as_str(), baseline.tty.as_deref());
        assert!(process["protected"].is_null(), "{process}");
        if index == 0 {
            assert!(process["deep_evidence"].is_null());
        } else {
            let deep = &process["deep_evidence"];
            assert_eq!(deep["start_id"], baseline.start_id.0);
            assert_eq!(deep["has_network_sockets"], true, "{deep}");
            assert!(
                deep["network"]["listening_ports"]
                    .as_array()
                    .expect("observed listeners")
                    .iter()
                    .any(|listener| listener["port"].as_u64() == Some(u64::from(port))),
                "{deep}"
            );
            assert!(
                deep["io_activity"].is_null(),
                "single counters cannot prove current activity"
            );
            assert!(result["deep_scan"]["matched_processes"].as_u64().unwrap() > 0);
        }
    }
    assert!(child.0.try_wait().expect("fixture status").is_none());
}
