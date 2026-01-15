//! Exit codes for pt-core CLI.
//!
//! Exit codes communicate operation outcome without requiring output parsing.
//! These are stable and documented in specs/cli-surface.md.
//!
//! Exit code ranges:
//! - 0-6: Success/operational outcomes (parse outcome from code, not output)
//! - 10-19: User/environment errors (recoverable by user action)
//! - 20-29: Internal errors (bugs, should be reported)

/// Exit codes for pt-core operations.
///
/// These codes are a stable contract for automation. Changes require
/// a major version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    // ========================================================================
    // Success / Operational Outcomes (0-6)
    // ========================================================================
    /// Success: nothing to do / clean run
    Clean = 0,

    /// Candidates exist (plan produced) but no actions executed
    PlanReady = 1,

    /// Actions executed successfully
    ActionsOk = 2,

    /// Partial failure: some actions failed
    PartialFail = 3,

    /// Blocked by safety gates or policy
    PolicyBlocked = 4,

    /// Goal not achievable (insufficient candidates)
    GoalUnreachable = 5,

    /// Session interrupted; resumable
    Interrupted = 6,

    // ========================================================================
    // User / Environment Errors (10-19)
    // ========================================================================
    /// Invalid arguments
    ArgsError = 10,

    /// Required capability missing (e.g., lsof not available)
    CapabilityError = 11,

    /// Permission denied
    PermissionError = 12,

    /// Version mismatch (wrapper/core incompatibility)
    VersionError = 13,

    /// Lock contention (another pt instance running)
    LockError = 14,

    /// Session not found or invalid
    SessionError = 15,

    /// Process identity mismatch (PID reused since plan)
    IdentityError = 16,

    // ========================================================================
    // Internal Errors (20-29)
    // ========================================================================
    /// Internal error (bug - please report)
    InternalError = 20,

    /// I/O error
    IoError = 21,

    /// Operation timed out
    TimeoutError = 22,
}

impl ExitCode {
    /// Convert to i32 for process exit.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Check if this exit code indicates success (codes 0-2).
    pub fn is_success(self) -> bool {
        matches!(
            self,
            ExitCode::Clean | ExitCode::PlanReady | ExitCode::ActionsOk
        )
    }

    /// Check if this exit code indicates operational outcome (codes 0-6).
    /// These are not errors - they communicate workflow state.
    pub fn is_operational(self) -> bool {
        (self as i32) < 10
    }

    /// Check if this exit code is a user/environment error (codes 10-19).
    /// These can be resolved by user action.
    pub fn is_user_error(self) -> bool {
        let code = self as i32;
        (10..20).contains(&code)
    }

    /// Check if this exit code is an internal error (codes 20-29).
    /// These indicate bugs and should be reported.
    pub fn is_internal_error(self) -> bool {
        let code = self as i32;
        code >= 20
    }

    /// Check if this exit code indicates any error requiring attention.
    pub fn is_error(self) -> bool {
        (self as i32) >= 10
    }

    /// Get the error code name as a string constant (for JSON output).
    pub fn code_name(&self) -> &'static str {
        match self {
            ExitCode::Clean => "OK_CLEAN",
            ExitCode::PlanReady => "OK_CANDIDATES",
            ExitCode::ActionsOk => "OK_APPLIED",
            ExitCode::PartialFail => "ERR_PARTIAL",
            ExitCode::PolicyBlocked => "ERR_BLOCKED",
            ExitCode::GoalUnreachable => "ERR_GOAL_UNREACHABLE",
            ExitCode::Interrupted => "ERR_INTERRUPTED",
            ExitCode::ArgsError => "ERR_ARGS",
            ExitCode::CapabilityError => "ERR_CAPABILITY",
            ExitCode::PermissionError => "ERR_PERMISSION",
            ExitCode::VersionError => "ERR_VERSION",
            ExitCode::LockError => "ERR_LOCK",
            ExitCode::SessionError => "ERR_SESSION",
            ExitCode::IdentityError => "ERR_IDENTITY",
            ExitCode::InternalError => "ERR_INTERNAL",
            ExitCode::IoError => "ERR_IO",
            ExitCode::TimeoutError => "ERR_TIMEOUT",
        }
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }

}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.code_name(), self.as_i32())
    }
}
