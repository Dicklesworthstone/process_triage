//! Structured error handling for agent consumption.
//!
//! Provides machine-readable error codes, recovery suggestions, and
//! partial-success reporting for batch operations.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Structured error code for agent interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    // Permission errors.
    #[serde(rename = "E_PERMISSION_DENIED")]
    PermissionDenied,
    #[serde(rename = "E_SUDO_REQUIRED")]
    SudoRequired,

    // Process errors.
    #[serde(rename = "E_PROCESS_NOT_FOUND")]
    ProcessNotFound,
    #[serde(rename = "E_PROCESS_PROTECTED")]
    ProcessProtected,
    #[serde(rename = "E_PROCESS_CHANGED")]
    ProcessChanged,

    // System errors.
    #[serde(rename = "E_OUT_OF_MEMORY")]
    OutOfMemory,
    #[serde(rename = "E_PROC_UNAVAILABLE")]
    ProcUnavailable,
    #[serde(rename = "E_TIMEOUT")]
    Timeout,

    // Fleet errors.
    #[serde(rename = "E_COORDINATOR_UNREACHABLE")]
    CoordinatorUnreachable,
    #[serde(rename = "E_FDR_BUDGET_EXCEEDED")]
    FdrBudgetExceeded,
    #[serde(rename = "E_QUORUM_LOST")]
    QuorumLost,

    // Generic.
    #[serde(rename = "E_INTERNAL")]
    Internal,
}

/// Error category for grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Permission,
    Process,
    System,
    Fleet,
    Internal,
}

impl ErrorCode {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::PermissionDenied | Self::SudoRequired => ErrorCategory::Permission,
            Self::ProcessNotFound | Self::ProcessProtected | Self::ProcessChanged => {
                ErrorCategory::Process
            }
            Self::OutOfMemory | Self::ProcUnavailable | Self::Timeout => ErrorCategory::System,
            Self::CoordinatorUnreachable | Self::FdrBudgetExceeded | Self::QuorumLost => {
                ErrorCategory::Fleet
            }
            Self::Internal => ErrorCategory::Internal,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::PermissionDenied
                | Self::SudoRequired
                | Self::ProcessNotFound
                | Self::ProcessChanged
                | Self::Timeout
                | Self::CoordinatorUnreachable
                | Self::QuorumLost
        )
    }

    pub fn suggested_action(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "retry_with_sudo",
            Self::SudoRequired => "retry_with_sudo",
            Self::ProcessNotFound => "refresh_scan",
            Self::ProcessProtected => "skip_or_override",
            Self::ProcessChanged => "refresh_scan",
            Self::OutOfMemory => "reduce_scope",
            Self::ProcUnavailable => "check_system",
            Self::Timeout => "retry_with_longer_timeout",
            Self::CoordinatorUnreachable => "retry_later",
            Self::FdrBudgetExceeded => "wait_for_budget_reset",
            Self::QuorumLost => "retry_later",
            Self::Internal => "report_bug",
        }
    }
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

/// Structured error detail for agent consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: ErrorCode,
    pub message: String,
    pub category: ErrorCategory,
    pub recoverable: bool,
    pub suggested_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl AgentError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            category: code.category(),
            recoverable: code.is_recoverable(),
            suggested_action: code.suggested_action().to_string(),
            code,
            message: message.into(),
            context: None,
        }
    }

    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }
}

// ---------------------------------------------------------------------------
// Response envelope
// ---------------------------------------------------------------------------

/// Response envelope with partial success support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_results: Option<PartialResults>,
}

impl<T: Serialize> AgentResponse<T> {
    pub fn ok(result: T) -> Self {
        Self {
            success: true,
            error: None,
            result: Some(result),
            partial_results: None,
        }
    }

    pub fn err(error: AgentError) -> Self {
        Self {
            success: false,
            error: Some(error),
            result: None,
            partial_results: None,
        }
    }

    pub fn partial(error: AgentError, partial: PartialResults) -> Self {
        Self {
            success: false,
            error: Some(error),
            result: None,
            partial_results: Some(partial),
        }
    }
}

/// Partial results for batch operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResults {
    pub successful: Vec<u32>,
    pub failed: Vec<FailedOperation>,
}

/// A single failed operation in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedOperation {
    pub pid: u32,
    pub error: AgentError,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_categories() {
        assert_eq!(
            ErrorCode::PermissionDenied.category(),
            ErrorCategory::Permission
        );
        assert_eq!(
            ErrorCode::ProcessNotFound.category(),
            ErrorCategory::Process
        );
        assert_eq!(ErrorCode::OutOfMemory.category(), ErrorCategory::System);
        assert_eq!(
            ErrorCode::FdrBudgetExceeded.category(),
            ErrorCategory::Fleet
        );
        assert_eq!(ErrorCode::Internal.category(), ErrorCategory::Internal);
    }

    #[test]
    fn test_recoverability() {
        assert!(ErrorCode::PermissionDenied.is_recoverable());
        assert!(ErrorCode::Timeout.is_recoverable());
        assert!(!ErrorCode::ProcessProtected.is_recoverable());
        assert!(!ErrorCode::OutOfMemory.is_recoverable());
        assert!(!ErrorCode::Internal.is_recoverable());
    }

    #[test]
    fn test_suggested_actions() {
        assert_eq!(
            ErrorCode::PermissionDenied.suggested_action(),
            "retry_with_sudo"
        );
        assert_eq!(
            ErrorCode::ProcessNotFound.suggested_action(),
            "refresh_scan"
        );
        assert_eq!(
            ErrorCode::Timeout.suggested_action(),
            "retry_with_longer_timeout"
        );
    }

    #[test]
    fn test_agent_error_new() {
        let err = AgentError::new(ErrorCode::ProcessNotFound, "PID 1234 gone");
        assert_eq!(err.code, ErrorCode::ProcessNotFound);
        assert!(err.recoverable);
        assert_eq!(err.category, ErrorCategory::Process);
        assert_eq!(err.suggested_action, "refresh_scan");
    }

    #[test]
    fn test_agent_error_with_context() {
        let err = AgentError::new(ErrorCode::PermissionDenied, "Cannot kill")
            .with_context(serde_json::json!({"pid": 1234, "owner": "root"}));
        assert!(err.context.is_some());
    }

    #[test]
    fn test_success_response() {
        let resp = AgentResponse::ok("all done");
        assert!(resp.success);
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_error_response() {
        let err = AgentError::new(ErrorCode::Timeout, "scan timed out");
        let resp: AgentResponse<()> = AgentResponse::err(err);
        assert!(!resp.success);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_partial_response() {
        let err = AgentError::new(ErrorCode::PermissionDenied, "some failed");
        let partial = PartialResults {
            successful: vec![100, 200],
            failed: vec![FailedOperation {
                pid: 300,
                error: AgentError::new(ErrorCode::PermissionDenied, "root process"),
            }],
        };
        let resp: AgentResponse<()> = AgentResponse::partial(err, partial);
        assert!(!resp.success);
        assert!(resp.partial_results.is_some());
        let pr = resp.partial_results.unwrap();
        assert_eq!(pr.successful.len(), 2);
        assert_eq!(pr.failed.len(), 1);
    }

    #[test]
    fn test_serialization_success() {
        let resp = AgentResponse::ok(42u32);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"result\":42"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_serialization_error() {
        let err = AgentError::new(ErrorCode::FdrBudgetExceeded, "budget exceeded");
        let resp: AgentResponse<()> = AgentResponse::err(err);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("E_FDR_BUDGET_EXCEEDED"));
        assert!(json.contains("\"recoverable\":false"));
    }

    #[test]
    fn test_error_code_serde_roundtrip() {
        let code = ErrorCode::ProcessChanged;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"E_PROCESS_CHANGED\"");
        let restored: ErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, ErrorCode::ProcessChanged);
    }
}
