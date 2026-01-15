//! Exit codes for pt-core CLI.
//!
//! Exit codes communicate operation outcome without requiring output parsing.
//! These are stable and documented in CLI_SPECIFICATION.md.

/// Exit codes for pt-core operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Clean / nothing to do
    Clean = 0,

    /// Candidates exist (plan produced) but no actions executed
    PlanReady = 1,

    /// Actions executed successfully
    ActionsOk = 2,

    /// Partial failure executing actions
    PartialFail = 3,

    /// Blocked by safety gates / policy
    PolicyBlocked = 4,

    /// Goal not achievable (insufficient candidates)
    GoalUnreachable = 5,

    /// Session interrupted / resumable
    Interrupted = 6,

    /// Configuration error
    ConfigError = 10,

    /// Collection/scan error
    CollectionError = 11,

    /// Inference error
    InferenceError = 12,

    /// I/O error
    IoError = 13,

    /// Internal/unknown error
    InternalError = 99,
}

impl ExitCode {
    /// Convert to i32 for process exit.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Check if this exit code indicates success.
    pub fn is_success(self) -> bool {
        matches!(self, ExitCode::Clean | ExitCode::PlanReady | ExitCode::ActionsOk)
    }

    /// Check if this exit code indicates an error requiring attention.
    pub fn is_error(self) -> bool {
        (self as i32) >= 10
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}
