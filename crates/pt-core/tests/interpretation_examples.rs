//! Interpretation examples from Plan §9.
//!
//! These tests encode the expected behavior for real developer-machine process
//! snapshots, ensuring the inference and decision engines behave correctly for
//! common scenarios.
//!
//! The examples are:
//! 1. `bun test --filter=gateway` - high CPU test runner (should be KEEP/REVIEW, not KILL)
//! 2. `gemini --yolo` workers - agent workers at moderate CPU (should be KEEP unless abandoned signals)
//! 3. `gunicorn` workers - production server at 45-50% CPU (should always be KEEP)
//! 4. `claude` processes - agent at 35-112% CPU (should be KEEP unless orphaned+stalled)
//!
//! These tests protect against over-indexing on simplistic signals and ensure
//! the system respects category-conditioned priors.

use pt_common::categories::CommandCategory;
use pt_core::config::policy::Policy;
use pt_core::config::priors::Priors;
use pt_core::decision::expected_loss::Action;
use pt_core::decision::{decide_action, ActionFeasibility};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence};

/// Action tier for test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionTier {
    /// Process should be kept (no action recommended)
    Keep,
    /// Process should be reviewed (reversible action like pause/renice)
    Review,
    /// Process should be acted upon (kill recommended)
    Act,
}

/// Get the action tier from a decision outcome.
fn get_action_tier(action: Action) -> ActionTier {
    match action {
        Action::Keep => ActionTier::Keep,
        Action::Pause | Action::Renice | Action::Throttle | Action::Freeze | Action::Quarantine => {
            ActionTier::Review
        }
        Action::Kill | Action::Restart => ActionTier::Act,
        Action::Resume | Action::Unfreeze | Action::Unquarantine => ActionTier::Keep,
    }
}

/// Helper to get command category index.
fn category_index(cat: CommandCategory) -> usize {
    CommandCategory::all()
        .iter()
        .position(|c| *c == cat)
        .unwrap_or(CommandCategory::all().len() - 1)
}

// =============================================================================
// Example 1: bun test --filter=gateway (~91% CPU for ~18 minutes)
// =============================================================================
//
// Intended interpretation:
// - Category: test
// - Short runtime + high CPU is consistent with useful or useful_bad, not abandoned
// - Default: KEEP or REVIEW, never KILL based on CPU+runtime alone

#[test]
fn example_1_bun_test_high_cpu_short_runtime() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: bun test at 91% CPU for 18 minutes
    // Has TTY (interactive), has network (test server), doing I/O
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.91 }),
        runtime_seconds: Some(18.0 * 60.0), // 18 minutes
        orphan: Some(false),                // Not orphaned
        tty: Some(true),                    // Has TTY
        net: Some(true),                    // Has network
        io_active: Some(true),              // Active I/O
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Test)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // Useful + useful_bad should dominate abandoned
    let useful_total = posterior.useful + posterior.useful_bad;
    assert!(
        useful_total > posterior.abandoned,
        "High-CPU test runner with TTY should be more likely useful than abandoned. \
         Got useful+useful_bad={:.3} vs abandoned={:.3}",
        useful_total,
        posterior.abandoned
    );

    // Should NOT be classified as zombie
    assert!(
        posterior.zombie < 0.01,
        "Active test runner should not be zombie. Got zombie={:.3}",
        posterior.zombie
    );

    // Decision should be KEEP or REVIEW, never ACT (kill)
    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    assert!(
        tier != ActionTier::Act,
        "High-CPU test runner with interactive TTY should not trigger kill. \
         Got action={:?}, posterior.abandoned={:.3}",
        decision.optimal_action,
        posterior.abandoned
    );
}

#[test]
fn example_1_bun_test_stalled_signals_shift_posterior() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Same test runner, but now showing abandonment signals:
    // - No TTY (detached)
    // - No I/O progress
    // - Much longer runtime (4 hours instead of 18 minutes)
    // - LOW CPU (stalled processes don't consume CPU; high CPU would indicate useful_bad)
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.02 }),
        runtime_seconds: Some(4.0 * 3600.0), // 4 hours
        orphan: Some(true),                  // Now orphaned
        tty: Some(false),                    // No TTY
        net: Some(false),                    // No network
        io_active: Some(false),              // No I/O
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Test)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // With stalled signals, abandoned should now be more likely
    // (but we still shouldn't auto-kill without explicit confirmation)
    assert!(
        posterior.abandoned > posterior.useful,
        "Stalled test runner (orphaned, no TTY, no IO) should lean abandoned. \
         Got abandoned={:.3} vs useful={:.3}",
        posterior.abandoned,
        posterior.useful
    );

    // Decision can be ACT for stalled tests
    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // For stalled processes, we expect REVIEW or ACT (reversible action first)
    assert!(
        tier != ActionTier::Keep,
        "Stalled test runner should trigger some action. Got action={:?}",
        decision.optimal_action
    );
}

// =============================================================================
// Example 2: gemini --yolo workers (25m to 4h46m)
// =============================================================================
//
// Intended interpretation:
// - Category: agent
// - Moderate CPU and runtime alone should not trigger kill
// - If orphaned + no TTY + stalled progress, posterior can shift

#[test]
fn example_2_gemini_worker_moderate_cpu_normal_runtime() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: gemini worker at moderate CPU for 2 hours
    // Has TTY (launched from terminal), has network, doing I/O
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.45 }),
        runtime_seconds: Some(2.0 * 3600.0), // 2 hours
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // Should be mostly useful
    assert!(
        posterior.useful > 0.5,
        "Active agent worker should be likely useful. Got useful={:.3}",
        posterior.useful
    );

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    assert_eq!(
        tier,
        ActionTier::Keep,
        "Active agent worker should be kept. Got action={:?}",
        decision.optimal_action
    );
}

#[test]
fn example_2_gemini_worker_long_runtime_but_active() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: gemini worker running for 4h46m but still active
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.30 }),
        runtime_seconds: Some(4.0 * 3600.0 + 46.0 * 60.0), // 4h46m
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // Long-running but active agent should still be kept
    assert!(
        tier == ActionTier::Keep || tier == ActionTier::Review,
        "Long-running but active agent should be kept or reviewed. Got action={:?}",
        decision.optimal_action
    );
}

// =============================================================================
// Example 3: gunicorn (2 workers) at 45-50% CPU for ~1 hour
// =============================================================================
//
// Intended interpretation:
// - Category: server
// - Likely useful; false-kill cost is HIGH
// - Recommendations should bias toward KEEP unless strong abandonment evidence
// - Even then, prefer reversible mitigation

#[test]
fn example_3_gunicorn_server_normal_operation() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: gunicorn server at 47% CPU for 1 hour
    // No TTY (daemon), has network (serving requests), active I/O
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.47 }),
        runtime_seconds: Some(3600.0), // 1 hour
        orphan: Some(false),           // Managed by supervisor
        tty: Some(false),              // Daemon, no TTY
        net: Some(true),               // Serving network requests
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Server)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // Server should be overwhelmingly useful
    assert!(
        posterior.useful > 0.6,
        "Production server should be very likely useful. Got useful={:.3}",
        posterior.useful
    );

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    assert_eq!(
        tier,
        ActionTier::Keep,
        "Production server should always be kept. Got action={:?}",
        decision.optimal_action
    );
}

#[test]
fn example_3_gunicorn_server_even_with_ambiguous_signals() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: gunicorn server with some ambiguous signals
    // Still has network but low I/O (maybe idle period)
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.10 }),
        runtime_seconds: Some(24.0 * 3600.0), // 24 hours
        orphan: Some(true),                   // Orphaned (supervisor died?)
        tty: Some(false),
        net: Some(true), // Still has network connections
        io_active: Some(false),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Server)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // Even with ambiguous signals, server category should prevent kill
    // At most, we might suggest review (reversible action)
    assert!(
        tier != ActionTier::Act,
        "Server with ambiguous signals should not be killed. \
         Got action={:?}, abandoned={:.3}, useful={:.3}",
        decision.optimal_action,
        posterior.abandoned,
        posterior.useful
    );
}

// =============================================================================
// Example 4: claude processes at 35-112% CPU
// =============================================================================
//
// Intended interpretation:
// - Category: agent
// - Often useful unless orphaned + no TTY + stalled

#[test]
fn example_4_claude_process_normal_operation() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: claude at 85% CPU for 30 minutes
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.85 }),
        runtime_seconds: Some(30.0 * 60.0), // 30 minutes
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    assert!(
        posterior.useful > 0.5,
        "Active claude process should be useful. Got useful={:.3}",
        posterior.useful
    );

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // Allow Keep or Review (mild interventions like Renice are acceptable for high CPU)
    assert!(
        tier == ActionTier::Keep || tier == ActionTier::Review,
        "Active claude process should be kept or reviewed (not killed). Got action={:?}",
        decision.optimal_action
    );
}

#[test]
fn example_4_claude_process_very_high_cpu() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: claude at >100% CPU (multi-core) but still active
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 1.0 }), // Clamped at 1.0
        runtime_seconds: Some(15.0 * 60.0),                  // 15 minutes
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // High CPU alone should NOT make it abandoned
    assert!(
        posterior.abandoned < 0.3,
        "High CPU alone should not indicate abandonment. Got abandoned={:.3}",
        posterior.abandoned
    );

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // High CPU is more likely useful_bad than abandoned
    assert!(
        tier != ActionTier::Act,
        "High CPU agent should not be killed. Got action={:?}",
        decision.optimal_action
    );
}

// Fixed: Prior tuning complete - adjusted runtime_gamma and command_category weights
// to properly identify stalled agents. Prior issue: zombie class with Beta(1,100) for
// cpu_beta was absorbing probability from abandoned class.
#[test]
fn example_4_claude_process_stalled() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: claude at low CPU, orphaned, no TTY, stalled
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.01 }),
        runtime_seconds: Some(12.0 * 3600.0), // 12 hours
        orphan: Some(true),
        tty: Some(false),
        net: Some(false),
        io_active: Some(false),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // Stalled agent should be classified as abandoned
    assert!(
        posterior.abandoned > 0.5,
        "Stalled agent should be likely abandoned. Got abandoned={:.3}",
        posterior.abandoned
    );

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // Stalled agent can be acted upon
    assert!(
        tier != ActionTier::Keep,
        "Stalled agent should trigger action. Got action={:?}",
        decision.optimal_action
    );
}

// =============================================================================
// Additional regression tests for edge cases
// =============================================================================

#[test]
fn regression_ppid1_alone_is_weak_signal() {
    let priors = Priors::default();

    // Scenario: Process with PPID=1 but otherwise healthy
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.50 }),
        runtime_seconds: Some(3600.0),
        orphan: Some(true), // PPID=1
        tty: Some(true),    // But has TTY
        net: Some(true),    // Has network
        io_active: Some(true),
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Agent)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // PPID=1 alone should not dominate other signals
    assert!(
        posterior.useful > 0.3,
        "PPID=1 with active signals should still have significant useful probability. \
         Got useful={:.3}, abandoned={:.3}",
        posterior.useful,
        posterior.abandoned
    );
}

#[test]
fn regression_high_cpu_is_not_abandoned() {
    let priors = Priors::default();

    // Scenario: Very high CPU is more consistent with useful_bad than abandoned
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.99 }),
        runtime_seconds: Some(600.0), // 10 minutes
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: None,
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    // High CPU should correlate with useful or useful_bad, not abandoned
    assert!(
        posterior.useful + posterior.useful_bad > posterior.abandoned,
        "High CPU should indicate useful/useful_bad, not abandoned. \
         useful={:.3}, useful_bad={:.3}, abandoned={:.3}",
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned
    );
}

// Fixed: Daemon category weights now provide strong protection. Prior issue: zombie
// class with Beta(1,100) for cpu_beta was absorbing probability. With corrected priors
// and command_categories Dirichlet, daemon category provides appropriate protection.
#[test]
fn regression_daemon_category_protects_against_kill() {
    let priors = Priors::default();
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    // Scenario: Daemon process (like systemd service) with some ambiguous signals
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.02 }),
        runtime_seconds: Some(7.0 * 24.0 * 3600.0), // 1 week
        orphan: Some(true),                         // PPID=1 is normal for daemons
        tty: Some(false),                           // No TTY is normal for daemons
        net: Some(false),                           // Might not have network
        io_active: Some(false),                     // Might be idle
        state_flag: None,
        command_category: Some(category_index(CommandCategory::Daemon)),
        queue_saturated: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    let decision =
        decide_action(&posterior, &policy, &feasibility).expect("decision computation failed");
    let tier = get_action_tier(decision.optimal_action);

    // Daemon category should provide strong protection
    assert!(
        tier != ActionTier::Act,
        "Daemon process should never be killed based on ambiguous signals. \
         Got action={:?}, abandoned={:.3}",
        decision.optimal_action,
        posterior.abandoned
    );
}
