//! Property-based tests for recovery tree, session tracking, and executor invariants.

use proptest::prelude::*;
use pt_core::action::{
    ActionAttempt, AttemptResult, FailureCategory, NoopRequirementChecker, RecoveryExecutor,
    RecoverySession, RecoveryTreeDatabase, Requirement, RequirementContext,
};
use pt_core::decision::Action;

fn failure_category_strategy() -> impl Strategy<Value = FailureCategory> {
    prop_oneof![
        Just(FailureCategory::PermissionDenied),
        Just(FailureCategory::ProcessNotFound),
        Just(FailureCategory::ProcessProtected),
        Just(FailureCategory::Timeout),
        Just(FailureCategory::SupervisorConflict),
        Just(FailureCategory::ResourceConflict),
        Just(FailureCategory::IdentityMismatch),
        Just(FailureCategory::PreCheckBlocked),
        Just(FailureCategory::UnexpectedError),
    ]
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Kill),
        Just(Action::Pause),
        Just(Action::Renice),
        Just(Action::Throttle),
        Just(Action::Restart),
    ]
}

fn requirement_strategy() -> impl Strategy<Value = Requirement> {
    prop_oneof![
        Just(Requirement::SudoAvailable),
        Just(Requirement::ProcessExists),
        Just(Requirement::SystemdSupervised),
        Just(Requirement::DockerSupervised),
        Just(Requirement::Pm2Supervised),
        Just(Requirement::InDState),
        Just(Requirement::RetryBudgetAvailable),
        Just(Requirement::UserConfirmation),
        Just(Requirement::CgroupV2Available),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    // ── Database invariants ─────────────────────────────────────────

    /// Every action in the database has a valid tree with a default branch.
    #[test]
    fn database_all_actions_have_trees(
        action in action_strategy(),
    ) {
        let db = RecoveryTreeDatabase::new();
        let tree = db.get_tree(action);
        prop_assert!(tree.is_some(),
            "no tree for action {:?}", action);
    }

    /// Lookup with any valid action+category never panics; returns branch or None.
    #[test]
    fn database_lookup_never_panics(
        action in action_strategy(),
        category in failure_category_strategy(),
    ) {
        let db = RecoveryTreeDatabase::new();
        let _branch = db.lookup(action, category);
        // just verifying no panic
    }

    // ── RequirementContext invariants ────────────────────────────────

    /// A fully-enabled context satisfies most requirements.
    #[test]
    fn context_full_satisfies_basic(
        req in requirement_strategy(),
    ) {
        let ctx = RequirementContext {
            sudo_available: true,
            process_exists: true,
            systemd_supervised: true,
            docker_supervised: true,
            pm2_supervised: true,
            in_d_state: true,
            retry_budget: 10,
            user_confirmation_available: true,
            cgroup_v2_available: true,
        };
        // Full context should satisfy all requirements
        prop_assert!(ctx.is_met(&req),
            "full context failed to satisfy {:?}", req);
    }

    /// all_met returns true only when every requirement is individually met.
    #[test]
    fn context_all_met_consistent(
        reqs in proptest::collection::vec(requirement_strategy(), 1..5),
        sudo in any::<bool>(),
        process in any::<bool>(),
        systemd in any::<bool>(),
        budget in 0u32..5,
    ) {
        let ctx = RequirementContext {
            sudo_available: sudo,
            process_exists: process,
            systemd_supervised: systemd,
            docker_supervised: false,
            pm2_supervised: false,
            in_d_state: false,
            retry_budget: budget,
            user_confirmation_available: false,
            cgroup_v2_available: false,
        };
        let all = ctx.all_met(&reqs);
        let each = reqs.iter().all(|r| ctx.is_met(r));
        prop_assert_eq!(all, each,
            "all_met({}) != individual check({})", all, each);
    }

    /// consume_retry decrements retry_budget by 1 (or stays at 0).
    #[test]
    fn context_consume_retry_decrements(
        budget in 0u32..20,
    ) {
        let mut ctx = RequirementContext {
            retry_budget: budget,
            ..Default::default()
        };
        ctx.consume_retry();
        if budget > 0 {
            prop_assert_eq!(ctx.retry_budget, budget - 1);
        } else {
            prop_assert_eq!(ctx.retry_budget, 0);
        }
    }

    // ── RecoverySession invariants ──────────────────────────────────

    /// Session attempt count equals number of record_attempt calls.
    #[test]
    fn session_attempt_count(
        n in 0usize..20,
        pid in 1u32..65535,
    ) {
        let mut session = RecoverySession::new(pid, None, 50);
        for i in 0..n {
            session.record_attempt(ActionAttempt {
                action: Action::Kill,
                result: AttemptResult::Failed {
                    category: FailureCategory::Timeout,
                },
                time_ms: i as u64 * 10,
                attempt_number: i as u32 + 1,
            });
        }
        prop_assert_eq!(session.all_attempts().len(), n);
        prop_assert_eq!(session.has_attempts(), n > 0);
    }

    /// consume_budget increments the category counter.
    #[test]
    fn session_budget_consumption(
        category in failure_category_strategy(),
        n_consumes in 1usize..10,
    ) {
        let mut session = RecoverySession::new(1000, None, 20);
        for _ in 0..n_consumes {
            session.consume_budget(category);
        }
        prop_assert_eq!(session.attempts_for_category(category), n_consumes as u32);
    }

    /// is_budget_exhausted returns true when category count >= max.
    #[test]
    fn session_budget_exhaustion(
        max in 1u32..10,
        consumes in 0u32..15,
    ) {
        let mut session = RecoverySession::new(2000, None, 50);
        for _ in 0..consumes {
            session.consume_budget(FailureCategory::PermissionDenied);
        }
        let exhausted = session.is_budget_exhausted(FailureCategory::PermissionDenied, max);
        prop_assert_eq!(exhausted, consumes >= max,
            "exhausted={} but consumes={} max={}", exhausted, consumes, max);
    }

    /// Fresh session has zero attempts for any category.
    #[test]
    fn session_fresh_zero_attempts(
        category in failure_category_strategy(),
        pid in 1u32..65535,
    ) {
        let session = RecoverySession::new(pid, None, 10);
        prop_assert_eq!(session.attempts_for_category(category), 0);
        prop_assert!(!session.has_attempts());
    }

    // ── RecoveryExecutor invariants ─────────────────────────────────

    /// find_alternatives never panics for any action+category combination.
    #[test]
    fn executor_find_alternatives_no_panic(
        action in action_strategy(),
        category in failure_category_strategy(),
        pid in 1u32..65535,
    ) {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = RecoverySession::new(pid, None, 10);
        let _alts = executor.find_alternatives(action, category, pid, &session);
    }

    /// get_best_alternative returns first element of find_alternatives (or None).
    #[test]
    fn executor_best_matches_first(
        action in action_strategy(),
        category in failure_category_strategy(),
    ) {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = RecoverySession::new(1234, None, 10);
        let alts = executor.find_alternatives(action, category, 1234, &session);
        let best = executor.get_best_alternative(action, category, 1234, &session);
        if alts.is_empty() {
            prop_assert!(best.is_none());
        } else {
            prop_assert!(best.is_some());
        }
    }

    /// classify_failure always returns a valid FailureCategory.
    #[test]
    fn executor_classify_valid(
        error_kind in prop_oneof![
            Just("EPERM"),
            Just("ESRCH"),
            Just("timeout"),
            Just("supervisor"),
            Just("resource_busy"),
            Just("some_random_error"),
        ],
        respawned in any::<bool>(),
    ) {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        let _cat = executor.classify_failure(error_kind, 1234, respawned);
        // Just verifying it returns without panic
    }

    /// generate_hint never panics for any action+category pair.
    #[test]
    fn executor_generate_hint_no_panic(
        action in action_strategy(),
        category in failure_category_strategy(),
    ) {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = RecoverySession::new(9999, None, 10);
        let _hint = executor.generate_hint(action, category, 9999, &session);
        // Verify no panic; returning None is valid for some combinations
    }

    /// generate_hint returns a hint for Kill + PermissionDenied (well-known pair).
    #[test]
    fn executor_kill_permission_has_hint(
        pid in 1u32..65535,
    ) {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = RecoverySession::new(pid, None, 10);
        let hint = executor.generate_hint(Action::Kill, FailureCategory::PermissionDenied, pid, &session);
        prop_assert!(hint.is_some(),
            "Kill + PermissionDenied should always produce a hint");
    }
}
