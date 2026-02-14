//! Action plugin interface.
//!
//! Action plugins receive a JSON action request on stdin and return a
//! result on stdout. They are used for notifications and custom actions
//! (e.g. Slack, PagerDuty, Kubernetes restart).
//!
//! **Important**: Action plugins can only _observe_ and _notify_. They cannot
//! perform destructive operations (kill, signal) — those are handled by the
//! core action executor with identity validation.
//!
//! # Plugin protocol (stdin → stdout)
//!
//! **Input** (JSON on stdin):
//! ```json
//! {
//!   "action": "kill",
//!   "pid": 1234,
//!   "process_name": "runaway-worker",
//!   "classification": "zombie",
//!   "confidence": 0.97,
//!   "session_id": "abc-123"
//! }
//! ```
//!
//! **Output** (JSON on stdout):
//! ```json
//! {
//!   "plugin": "slack-notify",
//!   "status": "ok",
//!   "message": "Posted to #ops channel"
//! }
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from action plugin invocation.
#[derive(Debug, Error)]
pub enum ActionPluginError {
    #[error("plugin {plugin} returned invalid JSON: {source}")]
    InvalidOutput {
        plugin: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("plugin {plugin} reported failure: {message}")]
    PluginFailure { plugin: String, message: String },

    #[error("plugin {plugin} failed to execute: {message}")]
    ExecutionFailed { plugin: String, message: String },

    #[error("plugin {plugin} timed out after {timeout_ms}ms")]
    Timeout { plugin: String, timeout_ms: u64 },
}

/// Input sent to an action plugin on stdin.
#[derive(Debug, Clone, Serialize)]
pub struct ActionPluginInput {
    /// The action being taken (keep, kill, pause, etc.).
    pub action: String,
    /// Target process PID.
    pub pid: u32,
    /// Process command name.
    pub process_name: String,
    /// Classified state (useful, useful_bad, abandoned, zombie).
    pub classification: String,
    /// Posterior confidence for the classification.
    pub confidence: f64,
    /// Session identifier for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Status of an action plugin invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Ok,
    Failed,
    Skipped,
}

/// Output from an action plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPluginOutput {
    /// Plugin name.
    pub plugin: String,
    /// Execution status.
    pub status: ActionStatus,
    /// Human-readable message.
    #[serde(default)]
    pub message: String,
}

/// Parse raw stdout from an action plugin.
pub fn parse_action_output(
    plugin_name: &str,
    stdout: &[u8],
) -> Result<ActionPluginOutput, ActionPluginError> {
    let output: ActionPluginOutput =
        serde_json::from_slice(stdout).map_err(|e| ActionPluginError::InvalidOutput {
            plugin: plugin_name.to_string(),
            source: e,
        })?;

    if output.status == ActionStatus::Failed {
        return Err(ActionPluginError::PluginFailure {
            plugin: plugin_name.to_string(),
            message: output.message,
        });
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ok_output() {
        let json = r#"{"plugin": "slack", "status": "ok", "message": "Sent to #ops"}"#;
        let output = parse_action_output("slack", json.as_bytes()).unwrap();
        assert_eq!(output.status, ActionStatus::Ok);
        assert_eq!(output.message, "Sent to #ops");
    }

    #[test]
    fn test_parse_failed_output() {
        let json = r#"{"plugin": "slack", "status": "failed", "message": "auth error"}"#;
        let result = parse_action_output("slack", json.as_bytes());
        assert!(matches!(
            result.unwrap_err(),
            ActionPluginError::PluginFailure { .. }
        ));
    }

    #[test]
    fn test_parse_skipped_output() {
        let json = r#"{"plugin": "pagerduty", "status": "skipped", "message": "not critical"}"#;
        let output = parse_action_output("pagerduty", json.as_bytes()).unwrap();
        assert_eq!(output.status, ActionStatus::Skipped);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_action_output("bad", b"nope");
        assert!(matches!(
            result.unwrap_err(),
            ActionPluginError::InvalidOutput { .. }
        ));
    }

    #[test]
    fn test_action_input_serialization() {
        let input = ActionPluginInput {
            action: "kill".to_string(),
            pid: 1234,
            process_name: "zombie-worker".to_string(),
            classification: "zombie".to_string(),
            confidence: 0.97,
            session_id: Some("sess-1".to_string()),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"action\":\"kill\""));
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"confidence\":0.97"));
    }

    #[test]
    fn test_action_input_no_session() {
        let input = ActionPluginInput {
            action: "pause".to_string(),
            pid: 42,
            process_name: "leak".to_string(),
            classification: "abandoned".to_string(),
            confidence: 0.85,
            session_id: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("session_id"));
    }
}
