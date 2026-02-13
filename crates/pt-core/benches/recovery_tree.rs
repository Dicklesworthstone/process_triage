//! Criterion benchmarks for recovery tree traversal, session tracking, and
//! failure classification.
//!
//! Benchmarks `RecoveryTreeDatabase` (construction/lookup), `RecoverySession`
//! (budget tracking/attempt recording), `RecoveryExecutor` (find_alternatives/
//! classify_failure/generate_hint), and `RequirementContext` (is_met/all_met)
//! — recovery-engine hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::action::{
    ActionAttempt, AttemptResult, FailureCategory, NoopRequirementChecker, RecoveryExecutor,
    RecoverySession, RecoveryTreeDatabase, Requirement, RequirementContext,
};
use pt_core::decision::Action;

// ── Helpers ──────────────────────────────────────────────────────────

fn all_failure_categories() -> Vec<FailureCategory> {
    vec![
        FailureCategory::PermissionDenied,
        FailureCategory::ProcessNotFound,
        FailureCategory::ProcessProtected,
        FailureCategory::Timeout,
        FailureCategory::SupervisorConflict,
        FailureCategory::ResourceConflict,
        FailureCategory::IdentityMismatch,
        FailureCategory::PreCheckBlocked,
        FailureCategory::UnexpectedError,
    ]
}

fn all_actions() -> Vec<Action> {
    vec![
        Action::Kill,
        Action::Pause,
        Action::Renice,
        Action::Throttle,
        Action::Restart,
    ]
}

fn make_session_with_attempts(n: usize) -> RecoverySession {
    let mut session = RecoverySession::new(1234, Some("start-id".to_string()), 20);
    let categories = all_failure_categories();
    for i in 0..n {
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Failed {
                category: categories[i % categories.len()],
            },
            time_ms: 50 + i as u64 * 10,
            attempt_number: i as u32 + 1,
        });
        session.consume_budget(categories[i % categories.len()]);
    }
    session
}

fn make_requirement_context(full: bool) -> RequirementContext {
    if full {
        RequirementContext {
            sudo_available: true,
            process_exists: true,
            systemd_supervised: true,
            docker_supervised: false,
            pm2_supervised: false,
            in_d_state: false,
            retry_budget: 5,
            user_confirmation_available: true,
            cgroup_v2_available: true,
        }
    } else {
        RequirementContext {
            sudo_available: false,
            process_exists: true,
            systemd_supervised: false,
            docker_supervised: false,
            pm2_supervised: false,
            in_d_state: false,
            retry_budget: 0,
            user_confirmation_available: false,
            cgroup_v2_available: false,
        }
    }
}

// ── Database construction and lookup benchmarks ─────────────────────

fn bench_database_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/database");

    group.bench_function("new", |b| {
        b.iter(|| {
            let db = RecoveryTreeDatabase::new();
            black_box(db);
        })
    });

    group.finish();
}

fn bench_database_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/lookup");
    let db = RecoveryTreeDatabase::new();

    // Lookup for each action type
    for action in all_actions() {
        group.bench_function(BenchmarkId::new("get_tree", format!("{:?}", action)), |b| {
            b.iter(|| {
                let tree = db.get_tree(black_box(action));
                black_box(tree.is_some());
            })
        });
    }

    // Full lookup: action + failure category
    for category in [
        FailureCategory::PermissionDenied,
        FailureCategory::Timeout,
        FailureCategory::SupervisorConflict,
        FailureCategory::UnexpectedError,
    ] {
        group.bench_function(
            BenchmarkId::new("lookup", format!("kill_{:?}", category)),
            |b| {
                b.iter(|| {
                    let branch = db.lookup(black_box(Action::Kill), black_box(category));
                    black_box(branch.is_some());
                })
            },
        );
    }

    // Sweep: all actions × all categories
    group.bench_function("sweep_all", |b| {
        let actions = all_actions();
        let categories = all_failure_categories();
        b.iter(|| {
            let mut count = 0usize;
            for &action in &actions {
                for &cat in &categories {
                    if db.lookup(action, cat).is_some() {
                        count += 1;
                    }
                }
            }
            black_box(count);
        })
    });

    group.finish();
}

// ── RequirementContext benchmarks ────────────────────────────────────

fn bench_requirement_context(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/requirement_context");

    let ctx_full = make_requirement_context(true);
    let ctx_minimal = make_requirement_context(false);

    let all_reqs = vec![
        Requirement::SudoAvailable,
        Requirement::ProcessExists,
        Requirement::SystemdSupervised,
        Requirement::DockerSupervised,
        Requirement::Pm2Supervised,
        Requirement::InDState,
        Requirement::RetryBudgetAvailable,
        Requirement::UserConfirmation,
        Requirement::CgroupV2Available,
    ];

    // Single requirement check
    for req in &all_reqs {
        group.bench_function(BenchmarkId::new("is_met", format!("{:?}", req)), |b| {
            b.iter(|| {
                let met = ctx_full.is_met(black_box(req));
                black_box(met);
            })
        });
    }

    // all_met with varying requirement counts
    for n in [1, 3, 5, 9] {
        let reqs: Vec<_> = all_reqs.iter().take(n).cloned().collect();
        group.bench_function(BenchmarkId::new("all_met_full", n), |b| {
            b.iter(|| {
                let met = ctx_full.all_met(black_box(&reqs));
                black_box(met);
            })
        });

        group.bench_function(BenchmarkId::new("all_met_minimal", n), |b| {
            b.iter(|| {
                let met = ctx_minimal.all_met(black_box(&reqs));
                black_box(met);
            })
        });
    }

    group.finish();
}

// ── RecoverySession benchmarks ──────────────────────────────────────

fn bench_session_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/session");

    // Session creation
    group.bench_function("new", |b| {
        b.iter(|| {
            let session = RecoverySession::new(
                black_box(5678),
                black_box(Some("start-abc".to_string())),
                black_box(10),
            );
            black_box(session.has_attempts());
        })
    });

    // Record attempts
    for n in [1, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("record_attempts", n), |b| {
            b.iter(|| {
                let session = make_session_with_attempts(n);
                black_box(session.all_attempts().len());
            })
        });
    }

    // Budget exhaustion check
    for n in [0, 3, 10] {
        group.bench_function(BenchmarkId::new("budget_check", n), |b| {
            let session = make_session_with_attempts(n);
            b.iter(|| {
                let exhausted = session.is_budget_exhausted(
                    black_box(FailureCategory::PermissionDenied),
                    black_box(3),
                );
                black_box(exhausted);
            })
        });
    }

    // Category count lookup
    group.bench_function("attempts_for_category", |b| {
        let session = make_session_with_attempts(15);
        b.iter(|| {
            let count = session.attempts_for_category(black_box(FailureCategory::Timeout));
            black_box(count);
        })
    });

    group.finish();
}

// ── RecoveryExecutor benchmarks ─────────────────────────────────────

fn bench_executor_find_alternatives(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/find_alternatives");
    let db = RecoveryTreeDatabase::new();
    let checker = NoopRequirementChecker::default();
    let executor = RecoveryExecutor::new(&db, &checker);

    // Fresh session — no prior attempts
    for action in [Action::Kill, Action::Pause, Action::Renice] {
        for category in [
            FailureCategory::PermissionDenied,
            FailureCategory::Timeout,
            FailureCategory::SupervisorConflict,
        ] {
            let session = RecoverySession::new(1234, None, 10);
            group.bench_function(
                BenchmarkId::new("fresh", format!("{:?}_{:?}", action, category)),
                |b| {
                    b.iter(|| {
                        let alts = executor.find_alternatives(
                            black_box(action),
                            black_box(category),
                            black_box(1234),
                            black_box(&session),
                        );
                        black_box(alts.len());
                    })
                },
            );
        }
    }

    // With prior attempts (budget partially consumed)
    for n_prior in [3, 8] {
        let session = make_session_with_attempts(n_prior);
        group.bench_function(BenchmarkId::new("with_attempts", n_prior), |b| {
            b.iter(|| {
                let alts = executor.find_alternatives(
                    black_box(Action::Kill),
                    black_box(FailureCategory::PermissionDenied),
                    black_box(1234),
                    black_box(&session),
                );
                black_box(alts.len());
            })
        });
    }

    group.finish();
}

fn bench_executor_classify_failure(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/classify_failure");
    let db = RecoveryTreeDatabase::new();
    let checker = NoopRequirementChecker::default();
    let executor = RecoveryExecutor::new(&db, &checker);

    let error_kinds: Vec<(&str, bool, &str)> = vec![
        ("EPERM", false, "EPERM"),
        ("ESRCH", false, "ESRCH"),
        ("timeout", false, "timeout"),
        ("supervisor", false, "supervisor"),
        ("unknown_error", false, "unknown"),
        ("ESRCH", true, "ESRCH_respawn"),
    ];

    for (kind, respawned, label) in &error_kinds {
        group.bench_function(BenchmarkId::new("error", *label), |b| {
            b.iter(|| {
                let cat = executor.classify_failure(
                    black_box(kind),
                    black_box(1234),
                    black_box(*respawned),
                );
                black_box(cat);
            })
        });
    }

    group.finish();
}

fn bench_executor_generate_hint(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery_tree/generate_hint");
    let db = RecoveryTreeDatabase::new();
    let checker = NoopRequirementChecker::default();
    let executor = RecoveryExecutor::new(&db, &checker);

    for action in [Action::Kill, Action::Pause, Action::Throttle] {
        let session = RecoverySession::new(9999, None, 10);
        group.bench_function(BenchmarkId::new("action", format!("{:?}", action)), |b| {
            b.iter(|| {
                let hint = executor.generate_hint(
                    black_box(action),
                    black_box(FailureCategory::PermissionDenied),
                    black_box(9999),
                    black_box(&session),
                );
                black_box(hint.is_some());
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_database_new,
    bench_database_lookup,
    bench_requirement_context,
    bench_session_tracking,
    bench_executor_find_alternatives,
    bench_executor_classify_failure,
    bench_executor_generate_hint
);
criterion_main!(benches);
