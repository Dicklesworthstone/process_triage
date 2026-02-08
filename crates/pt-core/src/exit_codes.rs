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

#[cfg(test)]
mod tests {
    use super::*;

    // ── as_i32 / From<ExitCode> ─────────────────────────────────

    #[test]
    fn as_i32_clean() {
        assert_eq!(ExitCode::Clean.as_i32(), 0);
    }

    #[test]
    fn as_i32_plan_ready() {
        assert_eq!(ExitCode::PlanReady.as_i32(), 1);
    }

    #[test]
    fn as_i32_actions_ok() {
        assert_eq!(ExitCode::ActionsOk.as_i32(), 2);
    }

    #[test]
    fn as_i32_partial_fail() {
        assert_eq!(ExitCode::PartialFail.as_i32(), 3);
    }

    #[test]
    fn as_i32_policy_blocked() {
        assert_eq!(ExitCode::PolicyBlocked.as_i32(), 4);
    }

    #[test]
    fn as_i32_goal_unreachable() {
        assert_eq!(ExitCode::GoalUnreachable.as_i32(), 5);
    }

    #[test]
    fn as_i32_interrupted() {
        assert_eq!(ExitCode::Interrupted.as_i32(), 6);
    }

    #[test]
    fn as_i32_args_error() {
        assert_eq!(ExitCode::ArgsError.as_i32(), 10);
    }

    #[test]
    fn as_i32_capability_error() {
        assert_eq!(ExitCode::CapabilityError.as_i32(), 11);
    }

    #[test]
    fn as_i32_permission_error() {
        assert_eq!(ExitCode::PermissionError.as_i32(), 12);
    }

    #[test]
    fn as_i32_version_error() {
        assert_eq!(ExitCode::VersionError.as_i32(), 13);
    }

    #[test]
    fn as_i32_lock_error() {
        assert_eq!(ExitCode::LockError.as_i32(), 14);
    }

    #[test]
    fn as_i32_session_error() {
        assert_eq!(ExitCode::SessionError.as_i32(), 15);
    }

    #[test]
    fn as_i32_identity_error() {
        assert_eq!(ExitCode::IdentityError.as_i32(), 16);
    }

    #[test]
    fn as_i32_internal_error() {
        assert_eq!(ExitCode::InternalError.as_i32(), 20);
    }

    #[test]
    fn as_i32_io_error() {
        assert_eq!(ExitCode::IoError.as_i32(), 21);
    }

    #[test]
    fn as_i32_timeout_error() {
        assert_eq!(ExitCode::TimeoutError.as_i32(), 22);
    }

    #[test]
    fn from_i32_trait() {
        let val: i32 = ExitCode::Clean.into();
        assert_eq!(val, 0);
        let val: i32 = ExitCode::InternalError.into();
        assert_eq!(val, 20);
    }

    // ── is_success ──────────────────────────────────────────────

    #[test]
    fn is_success_clean() {
        assert!(ExitCode::Clean.is_success());
    }

    #[test]
    fn is_success_plan_ready() {
        assert!(ExitCode::PlanReady.is_success());
    }

    #[test]
    fn is_success_actions_ok() {
        assert!(ExitCode::ActionsOk.is_success());
    }

    #[test]
    fn is_success_partial_fail_false() {
        assert!(!ExitCode::PartialFail.is_success());
    }

    #[test]
    fn is_success_errors_false() {
        assert!(!ExitCode::ArgsError.is_success());
        assert!(!ExitCode::InternalError.is_success());
    }

    // ── is_operational ──────────────────────────────────────────

    #[test]
    fn is_operational_success_codes() {
        assert!(ExitCode::Clean.is_operational());
        assert!(ExitCode::PlanReady.is_operational());
        assert!(ExitCode::ActionsOk.is_operational());
    }

    #[test]
    fn is_operational_partial_fail() {
        assert!(ExitCode::PartialFail.is_operational());
    }

    #[test]
    fn is_operational_interrupted() {
        assert!(ExitCode::Interrupted.is_operational());
    }

    #[test]
    fn is_operational_errors_false() {
        assert!(!ExitCode::ArgsError.is_operational());
        assert!(!ExitCode::InternalError.is_operational());
    }

    // ── is_user_error ───────────────────────────────────────────

    #[test]
    fn is_user_error_args() {
        assert!(ExitCode::ArgsError.is_user_error());
    }

    #[test]
    fn is_user_error_all_user_codes() {
        assert!(ExitCode::CapabilityError.is_user_error());
        assert!(ExitCode::PermissionError.is_user_error());
        assert!(ExitCode::VersionError.is_user_error());
        assert!(ExitCode::LockError.is_user_error());
        assert!(ExitCode::SessionError.is_user_error());
        assert!(ExitCode::IdentityError.is_user_error());
    }

    #[test]
    fn is_user_error_not_for_operational() {
        assert!(!ExitCode::Clean.is_user_error());
    }

    #[test]
    fn is_user_error_not_for_internal() {
        assert!(!ExitCode::InternalError.is_user_error());
    }

    // ── is_internal_error ───────────────────────────────────────

    #[test]
    fn is_internal_error_internal() {
        assert!(ExitCode::InternalError.is_internal_error());
    }

    #[test]
    fn is_internal_error_io() {
        assert!(ExitCode::IoError.is_internal_error());
    }

    #[test]
    fn is_internal_error_timeout() {
        assert!(ExitCode::TimeoutError.is_internal_error());
    }

    #[test]
    fn is_internal_error_not_for_user() {
        assert!(!ExitCode::ArgsError.is_internal_error());
    }

    #[test]
    fn is_internal_error_not_for_operational() {
        assert!(!ExitCode::Clean.is_internal_error());
    }

    // ── is_error ────────────────────────────────────────────────

    #[test]
    fn is_error_user_codes() {
        assert!(ExitCode::ArgsError.is_error());
        assert!(ExitCode::PermissionError.is_error());
    }

    #[test]
    fn is_error_internal_codes() {
        assert!(ExitCode::InternalError.is_error());
        assert!(ExitCode::IoError.is_error());
    }

    #[test]
    fn is_error_not_for_operational() {
        assert!(!ExitCode::Clean.is_error());
        assert!(!ExitCode::PlanReady.is_error());
        assert!(!ExitCode::Interrupted.is_error());
    }

    // ── code_name ───────────────────────────────────────────────

    #[test]
    fn code_name_all_variants() {
        assert_eq!(ExitCode::Clean.code_name(), "OK_CLEAN");
        assert_eq!(ExitCode::PlanReady.code_name(), "OK_CANDIDATES");
        assert_eq!(ExitCode::ActionsOk.code_name(), "OK_APPLIED");
        assert_eq!(ExitCode::PartialFail.code_name(), "ERR_PARTIAL");
        assert_eq!(ExitCode::PolicyBlocked.code_name(), "ERR_BLOCKED");
        assert_eq!(
            ExitCode::GoalUnreachable.code_name(),
            "ERR_GOAL_UNREACHABLE"
        );
        assert_eq!(ExitCode::Interrupted.code_name(), "ERR_INTERRUPTED");
        assert_eq!(ExitCode::ArgsError.code_name(), "ERR_ARGS");
        assert_eq!(ExitCode::CapabilityError.code_name(), "ERR_CAPABILITY");
        assert_eq!(ExitCode::PermissionError.code_name(), "ERR_PERMISSION");
        assert_eq!(ExitCode::VersionError.code_name(), "ERR_VERSION");
        assert_eq!(ExitCode::LockError.code_name(), "ERR_LOCK");
        assert_eq!(ExitCode::SessionError.code_name(), "ERR_SESSION");
        assert_eq!(ExitCode::IdentityError.code_name(), "ERR_IDENTITY");
        assert_eq!(ExitCode::InternalError.code_name(), "ERR_INTERNAL");
        assert_eq!(ExitCode::IoError.code_name(), "ERR_IO");
        assert_eq!(ExitCode::TimeoutError.code_name(), "ERR_TIMEOUT");
    }

    // ── Display ─────────────────────────────────────────────────

    #[test]
    fn display_format() {
        let s = ExitCode::Clean.to_string();
        assert_eq!(s, "OK_CLEAN (0)");
    }

    #[test]
    fn display_error_format() {
        let s = ExitCode::InternalError.to_string();
        assert_eq!(s, "ERR_INTERNAL (20)");
    }

    // ── PartialEq / Eq ─────────────────────────────────────────

    #[test]
    fn equality() {
        assert_eq!(ExitCode::Clean, ExitCode::Clean);
        assert_ne!(ExitCode::Clean, ExitCode::PlanReady);
    }

    #[test]
    fn clone() {
        let a = ExitCode::InternalError;
        let b = a;
        assert_eq!(a, b);
    }
}
