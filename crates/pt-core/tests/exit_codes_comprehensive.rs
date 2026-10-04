//! Comprehensive exit code tests for pt-core.
//!
//! These tests validate that all exit codes match the CLI specification
//! and that helper methods behave correctly.

use pt_core::exit_codes::ExitCode;

#[test]
fn cli_usage_errors_follow_the_agent_exit_contract() {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;

    for args in [
        vec!["agent", "apply", "--definitely-not-a-flag"],
        vec!["nonexistent-command"],
        vec!["config", "export-preset"],
        vec!["agent", "apply", "--pids", "not-a-pid"],
    ] {
        cargo_bin_cmd!("pt-core")
            .args(args)
            .assert()
            .code(ExitCode::ArgsError.as_i32())
            .stderr(predicate::str::contains("error:"));
    }
}

#[test]
fn cli_help_and_version_remain_successful_without_actions() {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;

    for args in [vec!["--help"], vec!["agent", "plan", "--help"]] {
        cargo_bin_cmd!("pt-core")
            .args(args)
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"));
    }
    cargo_bin_cmd!("pt-core")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("pt-core"));
}

// ============================================================================
// Exit Code Value Tests
// ============================================================================

mod exit_code_values {
    use super::*;

    #[test]
    fn operational_codes_are_0_to_6() {
        assert_eq!(ExitCode::Clean.as_i32(), 0);
        assert_eq!(ExitCode::PlanReady.as_i32(), 1);
        assert_eq!(ExitCode::ActionsOk.as_i32(), 2);
        assert_eq!(ExitCode::PartialFail.as_i32(), 3);
        assert_eq!(ExitCode::PolicyBlocked.as_i32(), 4);
        assert_eq!(ExitCode::GoalUnreachable.as_i32(), 5);
        assert_eq!(ExitCode::Interrupted.as_i32(), 6);
    }

    #[test]
    fn user_error_codes_are_10_to_19() {
        assert_eq!(ExitCode::ArgsError.as_i32(), 10);
        assert_eq!(ExitCode::CapabilityError.as_i32(), 11);
        assert_eq!(ExitCode::PermissionError.as_i32(), 12);
        assert_eq!(ExitCode::VersionError.as_i32(), 13);
        assert_eq!(ExitCode::LockError.as_i32(), 14);
        assert_eq!(ExitCode::SessionError.as_i32(), 15);
        assert_eq!(ExitCode::IdentityError.as_i32(), 16);
    }

    #[test]
    fn internal_error_codes_are_20_plus() {
        assert_eq!(ExitCode::InternalError.as_i32(), 20);
        assert_eq!(ExitCode::IoError.as_i32(), 21);
        assert_eq!(ExitCode::TimeoutError.as_i32(), 22);
    }

    #[test]
    fn from_trait_matches_as_i32() {
        let codes = [
            ExitCode::Clean,
            ExitCode::PlanReady,
            ExitCode::ActionsOk,
            ExitCode::PartialFail,
            ExitCode::PolicyBlocked,
            ExitCode::GoalUnreachable,
            ExitCode::Interrupted,
            ExitCode::ArgsError,
            ExitCode::CapabilityError,
            ExitCode::PermissionError,
            ExitCode::VersionError,
            ExitCode::LockError,
            ExitCode::SessionError,
            ExitCode::IdentityError,
            ExitCode::InternalError,
            ExitCode::IoError,
            ExitCode::TimeoutError,
        ];

        for code in codes {
            let via_as = code.as_i32();
            let via_from: i32 = code.into();
            assert_eq!(via_as, via_from, "Mismatch for {:?}", code);
        }
    }
}

// ============================================================================
// is_success() Tests
// ============================================================================

mod is_success {
    use super::*;

    #[test]
    fn clean_is_success() {
        assert!(ExitCode::Clean.is_success());
    }

    #[test]
    fn plan_ready_is_success() {
        assert!(ExitCode::PlanReady.is_success());
    }

    #[test]
    fn actions_ok_is_success() {
        assert!(ExitCode::ActionsOk.is_success());
    }

    #[test]
    fn partial_fail_is_not_success() {
        assert!(!ExitCode::PartialFail.is_success());
    }

    #[test]
    fn policy_blocked_is_not_success() {
        assert!(!ExitCode::PolicyBlocked.is_success());
    }

    #[test]
    fn goal_unreachable_is_not_success() {
        assert!(!ExitCode::GoalUnreachable.is_success());
    }

    #[test]
    fn interrupted_is_not_success() {
        assert!(!ExitCode::Interrupted.is_success());
    }

    #[test]
    fn user_errors_are_not_success() {
        assert!(!ExitCode::ArgsError.is_success());
        assert!(!ExitCode::CapabilityError.is_success());
        assert!(!ExitCode::PermissionError.is_success());
        assert!(!ExitCode::VersionError.is_success());
        assert!(!ExitCode::LockError.is_success());
        assert!(!ExitCode::SessionError.is_success());
        assert!(!ExitCode::IdentityError.is_success());
    }

    #[test]
    fn internal_errors_are_not_success() {
        assert!(!ExitCode::InternalError.is_success());
        assert!(!ExitCode::IoError.is_success());
        assert!(!ExitCode::TimeoutError.is_success());
    }
}

// ============================================================================
// is_operational() Tests
// ============================================================================

mod is_operational {
    use super::*;

    #[test]
    fn codes_0_to_6_are_operational() {
        assert!(ExitCode::Clean.is_operational());
        assert!(ExitCode::PlanReady.is_operational());
        assert!(ExitCode::ActionsOk.is_operational());
        assert!(ExitCode::PartialFail.is_operational());
        assert!(ExitCode::PolicyBlocked.is_operational());
        assert!(ExitCode::GoalUnreachable.is_operational());
        assert!(ExitCode::Interrupted.is_operational());
    }

    #[test]
    fn user_errors_are_not_operational() {
        assert!(!ExitCode::ArgsError.is_operational());
        assert!(!ExitCode::CapabilityError.is_operational());
        assert!(!ExitCode::PermissionError.is_operational());
        assert!(!ExitCode::VersionError.is_operational());
        assert!(!ExitCode::LockError.is_operational());
        assert!(!ExitCode::SessionError.is_operational());
        assert!(!ExitCode::IdentityError.is_operational());
    }

    #[test]
    fn internal_errors_are_not_operational() {
        assert!(!ExitCode::InternalError.is_operational());
        assert!(!ExitCode::IoError.is_operational());
        assert!(!ExitCode::TimeoutError.is_operational());
    }
}

// ============================================================================
// is_user_error() Tests
// ============================================================================

mod is_user_error {
    use super::*;

    #[test]
    fn operational_codes_are_not_user_errors() {
        assert!(!ExitCode::Clean.is_user_error());
        assert!(!ExitCode::PlanReady.is_user_error());
        assert!(!ExitCode::ActionsOk.is_user_error());
        assert!(!ExitCode::PartialFail.is_user_error());
        assert!(!ExitCode::PolicyBlocked.is_user_error());
        assert!(!ExitCode::GoalUnreachable.is_user_error());
        assert!(!ExitCode::Interrupted.is_user_error());
    }

    #[test]
    fn codes_10_to_19_are_user_errors() {
        assert!(ExitCode::ArgsError.is_user_error());
        assert!(ExitCode::CapabilityError.is_user_error());
        assert!(ExitCode::PermissionError.is_user_error());
        assert!(ExitCode::VersionError.is_user_error());
        assert!(ExitCode::LockError.is_user_error());
        assert!(ExitCode::SessionError.is_user_error());
        assert!(ExitCode::IdentityError.is_user_error());
    }

    #[test]
    fn internal_errors_are_not_user_errors() {
        assert!(!ExitCode::InternalError.is_user_error());
        assert!(!ExitCode::IoError.is_user_error());
        assert!(!ExitCode::TimeoutError.is_user_error());
    }
}

// ============================================================================
// is_internal_error() Tests
// ============================================================================

mod is_internal_error {
    use super::*;

    #[test]
    fn operational_codes_are_not_internal_errors() {
        assert!(!ExitCode::Clean.is_internal_error());
        assert!(!ExitCode::PlanReady.is_internal_error());
        assert!(!ExitCode::ActionsOk.is_internal_error());
        assert!(!ExitCode::PartialFail.is_internal_error());
        assert!(!ExitCode::PolicyBlocked.is_internal_error());
        assert!(!ExitCode::GoalUnreachable.is_internal_error());
        assert!(!ExitCode::Interrupted.is_internal_error());
    }

    #[test]
    fn user_errors_are_not_internal_errors() {
        assert!(!ExitCode::ArgsError.is_internal_error());
        assert!(!ExitCode::CapabilityError.is_internal_error());
        assert!(!ExitCode::PermissionError.is_internal_error());
        assert!(!ExitCode::VersionError.is_internal_error());
        assert!(!ExitCode::LockError.is_internal_error());
        assert!(!ExitCode::SessionError.is_internal_error());
        assert!(!ExitCode::IdentityError.is_internal_error());
    }

    #[test]
    fn codes_20_plus_are_internal_errors() {
        assert!(ExitCode::InternalError.is_internal_error());
        assert!(ExitCode::IoError.is_internal_error());
        assert!(ExitCode::TimeoutError.is_internal_error());
    }
}

// ============================================================================
// is_error() Tests
// ============================================================================

mod is_error {
    use super::*;

    #[test]
    fn operational_codes_are_not_errors() {
        assert!(!ExitCode::Clean.is_error());
        assert!(!ExitCode::PlanReady.is_error());
        assert!(!ExitCode::ActionsOk.is_error());
        assert!(!ExitCode::PartialFail.is_error());
        assert!(!ExitCode::PolicyBlocked.is_error());
        assert!(!ExitCode::GoalUnreachable.is_error());
        assert!(!ExitCode::Interrupted.is_error());
    }

    #[test]
    fn user_errors_are_errors() {
        assert!(ExitCode::ArgsError.is_error());
        assert!(ExitCode::CapabilityError.is_error());
        assert!(ExitCode::PermissionError.is_error());
        assert!(ExitCode::VersionError.is_error());
        assert!(ExitCode::LockError.is_error());
        assert!(ExitCode::SessionError.is_error());
        assert!(ExitCode::IdentityError.is_error());
    }

    #[test]
    fn internal_errors_are_errors() {
        assert!(ExitCode::InternalError.is_error());
        assert!(ExitCode::IoError.is_error());
        assert!(ExitCode::TimeoutError.is_error());
    }
}

// ============================================================================
// code_name() Tests
// ============================================================================

mod code_name {
    use super::*;

    #[test]
    fn operational_code_names() {
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
    }

    #[test]
    fn user_error_code_names() {
        assert_eq!(ExitCode::ArgsError.code_name(), "ERR_ARGS");
        assert_eq!(ExitCode::CapabilityError.code_name(), "ERR_CAPABILITY");
        assert_eq!(ExitCode::PermissionError.code_name(), "ERR_PERMISSION");
        assert_eq!(ExitCode::VersionError.code_name(), "ERR_VERSION");
        assert_eq!(ExitCode::LockError.code_name(), "ERR_LOCK");
        assert_eq!(ExitCode::SessionError.code_name(), "ERR_SESSION");
        assert_eq!(ExitCode::IdentityError.code_name(), "ERR_IDENTITY");
    }

    #[test]
    fn internal_error_code_names() {
        assert_eq!(ExitCode::InternalError.code_name(), "ERR_INTERNAL");
        assert_eq!(ExitCode::IoError.code_name(), "ERR_IO");
        assert_eq!(ExitCode::TimeoutError.code_name(), "ERR_TIMEOUT");
    }

    #[test]
    fn success_codes_start_with_ok() {
        assert!(ExitCode::Clean.code_name().starts_with("OK_"));
        assert!(ExitCode::PlanReady.code_name().starts_with("OK_"));
        assert!(ExitCode::ActionsOk.code_name().starts_with("OK_"));
    }

    #[test]
    fn non_success_operational_codes_start_with_err() {
        assert!(ExitCode::PartialFail.code_name().starts_with("ERR_"));
        assert!(ExitCode::PolicyBlocked.code_name().starts_with("ERR_"));
        assert!(ExitCode::GoalUnreachable.code_name().starts_with("ERR_"));
        assert!(ExitCode::Interrupted.code_name().starts_with("ERR_"));
    }
}

// ============================================================================
// Display Implementation Tests
// ============================================================================

mod display {
    use super::*;

    #[test]
    fn display_format_includes_name_and_code() {
        let display = format!("{}", ExitCode::Clean);
        assert!(display.contains("OK_CLEAN"));
        assert!(display.contains("0"));
    }

    #[test]
    fn display_format_for_all_codes() {
        let codes_and_expected = [
            (ExitCode::Clean, "OK_CLEAN (0)"),
            (ExitCode::PlanReady, "OK_CANDIDATES (1)"),
            (ExitCode::ActionsOk, "OK_APPLIED (2)"),
            (ExitCode::PartialFail, "ERR_PARTIAL (3)"),
            (ExitCode::PolicyBlocked, "ERR_BLOCKED (4)"),
            (ExitCode::GoalUnreachable, "ERR_GOAL_UNREACHABLE (5)"),
            (ExitCode::Interrupted, "ERR_INTERRUPTED (6)"),
            (ExitCode::ArgsError, "ERR_ARGS (10)"),
            (ExitCode::CapabilityError, "ERR_CAPABILITY (11)"),
            (ExitCode::PermissionError, "ERR_PERMISSION (12)"),
            (ExitCode::VersionError, "ERR_VERSION (13)"),
            (ExitCode::LockError, "ERR_LOCK (14)"),
            (ExitCode::SessionError, "ERR_SESSION (15)"),
            (ExitCode::IdentityError, "ERR_IDENTITY (16)"),
            (ExitCode::InternalError, "ERR_INTERNAL (20)"),
            (ExitCode::IoError, "ERR_IO (21)"),
            (ExitCode::TimeoutError, "ERR_TIMEOUT (22)"),
        ];

        for (code, expected) in codes_and_expected {
            assert_eq!(
                format!("{}", code),
                expected,
                "Display mismatch for {:?}",
                code
            );
        }
    }
}

// ============================================================================
// Trait Implementation Tests
// ============================================================================

mod traits {
    use super::*;

    #[test]
    fn exit_code_is_copy() {
        let code = ExitCode::Clean;
        let copy = code;
        assert_eq!(code, copy);
    }

    #[test]
    fn exit_code_is_clone() {
        let code = ExitCode::Clean;
        let cloned = code;
        assert_eq!(code, cloned);
    }

    #[test]
    fn exit_code_is_eq() {
        assert_eq!(ExitCode::Clean, ExitCode::Clean);
        assert_ne!(ExitCode::Clean, ExitCode::PlanReady);
    }

    #[test]
    fn exit_code_is_debug() {
        let debug = format!("{:?}", ExitCode::Clean);
        assert!(debug.contains("Clean"));
    }
}

// ============================================================================
// Semantic Tests (Higher-level behavior)
// ============================================================================

mod semantics {
    use super::*;

    #[test]
    fn success_implies_operational() {
        let success_codes = [ExitCode::Clean, ExitCode::PlanReady, ExitCode::ActionsOk];
        for code in success_codes {
            assert!(
                code.is_operational(),
                "{:?} is success but not operational",
                code
            );
        }
    }

    #[test]
    fn error_codes_are_disjoint_from_operational() {
        let all_codes = [
            ExitCode::Clean,
            ExitCode::PlanReady,
            ExitCode::ActionsOk,
            ExitCode::PartialFail,
            ExitCode::PolicyBlocked,
            ExitCode::GoalUnreachable,
            ExitCode::Interrupted,
            ExitCode::ArgsError,
            ExitCode::CapabilityError,
            ExitCode::PermissionError,
            ExitCode::VersionError,
            ExitCode::LockError,
            ExitCode::SessionError,
            ExitCode::IdentityError,
            ExitCode::InternalError,
            ExitCode::IoError,
            ExitCode::TimeoutError,
        ];

        for code in all_codes {
            // A code cannot be both operational and an error
            assert!(
                !(code.is_operational() && code.is_error()),
                "{:?} is both operational and error",
                code
            );
            // A code must be one or the other
            assert!(
                code.is_operational() || code.is_error(),
                "{:?} is neither operational nor error",
                code
            );
        }
    }

    #[test]
    fn user_and_internal_errors_are_disjoint() {
        let all_codes = [
            ExitCode::ArgsError,
            ExitCode::CapabilityError,
            ExitCode::PermissionError,
            ExitCode::VersionError,
            ExitCode::LockError,
            ExitCode::SessionError,
            ExitCode::IdentityError,
            ExitCode::InternalError,
            ExitCode::IoError,
            ExitCode::TimeoutError,
        ];

        for code in all_codes {
            // An error code is either user error or internal, not both
            let is_user = code.is_user_error();
            let is_internal = code.is_internal_error();
            assert!(
                is_user ^ is_internal,
                "{:?}: is_user_error={}, is_internal_error={}",
                code,
                is_user,
                is_internal
            );
        }
    }

    #[test]
    fn all_error_codes_are_classified() {
        let error_codes = [
            ExitCode::ArgsError,
            ExitCode::CapabilityError,
            ExitCode::PermissionError,
            ExitCode::VersionError,
            ExitCode::LockError,
            ExitCode::SessionError,
            ExitCode::IdentityError,
            ExitCode::InternalError,
            ExitCode::IoError,
            ExitCode::TimeoutError,
        ];

        for code in error_codes {
            assert!(code.is_error(), "{:?} should be an error", code);
            assert!(
                code.is_user_error() || code.is_internal_error(),
                "{:?} should be classified as user or internal",
                code
            );
        }
    }
}

// ============================================================================
// Stability Tests (Contract guarantees)
// ============================================================================

mod stability {
    use super::*;

    /// These values are part of the stable CLI contract.
    /// Changing them requires a major version bump.
    #[test]
    fn exit_codes_match_specification() {
        // Success / Operational (0-6)
        assert_eq!(ExitCode::Clean.as_i32(), 0, "Clean must be 0");
        assert_eq!(ExitCode::PlanReady.as_i32(), 1, "PlanReady must be 1");
        assert_eq!(ExitCode::ActionsOk.as_i32(), 2, "ActionsOk must be 2");
        assert_eq!(ExitCode::PartialFail.as_i32(), 3, "PartialFail must be 3");
        assert_eq!(
            ExitCode::PolicyBlocked.as_i32(),
            4,
            "PolicyBlocked must be 4"
        );
        assert_eq!(
            ExitCode::GoalUnreachable.as_i32(),
            5,
            "GoalUnreachable must be 5"
        );
        assert_eq!(ExitCode::Interrupted.as_i32(), 6, "Interrupted must be 6");

        // User / Environment Errors (10-19)
        assert_eq!(ExitCode::ArgsError.as_i32(), 10, "ArgsError must be 10");
        assert_eq!(
            ExitCode::CapabilityError.as_i32(),
            11,
            "CapabilityError must be 11"
        );
        assert_eq!(
            ExitCode::PermissionError.as_i32(),
            12,
            "PermissionError must be 12"
        );
        assert_eq!(
            ExitCode::VersionError.as_i32(),
            13,
            "VersionError must be 13"
        );
        assert_eq!(ExitCode::LockError.as_i32(), 14, "LockError must be 14");
        assert_eq!(
            ExitCode::SessionError.as_i32(),
            15,
            "SessionError must be 15"
        );
        assert_eq!(
            ExitCode::IdentityError.as_i32(),
            16,
            "IdentityError must be 16"
        );

        // Internal Errors (20-29)
        assert_eq!(
            ExitCode::InternalError.as_i32(),
            20,
            "InternalError must be 20"
        );
        assert_eq!(ExitCode::IoError.as_i32(), 21, "IoError must be 21");
        assert_eq!(
            ExitCode::TimeoutError.as_i32(),
            22,
            "TimeoutError must be 22"
        );
    }

    /// Code names are used in JSON output and must remain stable.
    #[test]
    fn code_names_match_specification() {
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
}
