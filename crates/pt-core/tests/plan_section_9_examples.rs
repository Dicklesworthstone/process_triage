//! Plan §9 Applied Interpretation Examples
//!
//! These tests encode the intended behavior for specific real-world scenarios
//! described in Plan §9. They serve as regression tests to ensure the inference
//! engine and decision layer produce sensible results for common developer
//! machine process patterns.
//!
//! Scenarios:
//! 1) `bun test --filter=gateway` ~91% CPU for ~18m
//! 2) `gemini --yolo` workers (25m to 4h46m)
//! 3) `gunicorn` (2 workers) at 45–50% CPU for ~1h
//! 4) `claude` processes at 35–112% CPU

use pt_core::config::policy::Policy;
use pt_core::config::priors::Priors;
use pt_core::decision::{decide_action, ActionFeasibility};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence};

/// Helper to check that a class probability is above a threshold.
fn assert_class_above(
    name: &str,
    scenario: &str,
    value: f64,
    threshold: f64,
) {
    assert!(
        value >= threshold,
        "{}: expected {} >= {} but got {}",
        scenario,
        name,
        threshold,
        value
    );
}

/// Helper to check that a class probability is below a threshold.
fn assert_class_below(
    name: &str,
    scenario: &str,
    value: f64,
    threshold: f64,
) {
    assert!(
        value <= threshold,
        "{}: expected {} <= {} but got {}",
        scenario,
        name,
        threshold,
        value
    );
}

/// Scenario 1: `bun test --filter=gateway` ~91% CPU for ~18m
///
/// Intended interpretation from Plan §9:
/// - Category: test
/// - Short runtime + high CPU is consistent with **useful** or **useful_bad**, not abandoned.
/// - The posterior should NOT heavily favor abandoned without additional evidence
///   (no TTY, no IO progress, change-point indicates stall).
#[test]
fn scenario_1_bun_test_high_cpu_18min_is_not_abandoned() {
    let priors = Priors::default();

    // Test runner: 91% CPU, 18 minutes runtime, has TTY, IO active
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.91 }),
        runtime_seconds: Some(18.0 * 60.0), // 18 minutes
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(false),
        state_flag: None,
        command_category: None, // Would be "test" if categories were configured
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // With high CPU + short runtime + TTY + IO active, this should look useful
    // P(useful) + P(useful_bad) should dominate P(abandoned) + P(zombie)
    let useful_like = posterior.useful + posterior.useful_bad;
    let suspicious_like = posterior.abandoned + posterior.zombie;

    assert!(
        useful_like > suspicious_like,
        "Scenario 1 (bun test): useful-like ({:.4}) should exceed suspicious-like ({:.4})",
        useful_like,
        suspicious_like
    );

    // Abandoned should not be the dominant class
    assert_class_below(
        "abandoned",
        "Scenario 1 (bun test)",
        posterior.abandoned,
        0.3, // Should be well below 30%
    );
}

/// Scenario 1b: Same bun test but WITHOUT TTY and WITHOUT IO (stalled)
///
/// This demonstrates that additional abandonment evidence can shift the posterior.
#[test]
fn scenario_1b_bun_test_stalled_shifts_toward_abandoned() {
    let priors = Priors::default();

    // Same test runner but: no TTY, no IO, orphaned
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.91 }),
        runtime_seconds: Some(18.0 * 60.0), // 18 minutes
        orphan: Some(true),    // Orphaned
        tty: Some(false),      // No TTY
        io_active: Some(false), // No IO activity
        net: Some(false),
        state_flag: None,
        command_category: None,
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // With abandonment signals (orphaned + no TTY + no IO), abandoned should increase
    // relative to scenario 1
    let baseline_evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.91 }),
        runtime_seconds: Some(18.0 * 60.0),
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(false),
        state_flag: None,
        command_category: None,
    };
    let baseline = compute_posterior(&priors, &baseline_evidence)
        .expect("baseline computation should succeed")
        .posterior;

    assert!(
        posterior.abandoned > baseline.abandoned,
        "Stalled evidence should increase P(abandoned): {:.4} vs baseline {:.4}",
        posterior.abandoned,
        baseline.abandoned
    );
}

/// Scenario 2: `gemini --yolo` workers (25m to 4h46m runtime)
///
/// Intended interpretation from Plan §9:
/// - Category: agent
/// - Moderate CPU and runtime alone should NOT trigger kill.
/// - Only if orphaned + no TTY + stalled progress signals should posterior shift.
#[test]
fn scenario_2_gemini_agent_moderate_runtime_not_abandoned() {
    let priors = Priors::default();

    // Agent process: moderate CPU (40%), 2 hours runtime, has TTY
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.40 }),
        runtime_seconds: Some(2.0 * 3600.0), // 2 hours
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(true), // Likely has network activity
        state_flag: None,
        command_category: None, // Would be "agent" if configured
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // Agent with TTY + IO + network should look useful
    assert_class_above(
        "useful",
        "Scenario 2 (gemini agent)",
        posterior.useful,
        0.3, // Should have meaningful useful probability
    );

    // Should not be flagged as abandoned just due to runtime
    assert_class_below(
        "abandoned",
        "Scenario 2 (gemini agent)",
        posterior.abandoned,
        0.35,
    );
}

/// Scenario 2b: Gemini agent at 4h46m, orphaned, no TTY, no IO
///
/// This variant should shift toward abandoned.
#[test]
fn scenario_2b_gemini_agent_long_orphaned_shifts_toward_abandoned() {
    let priors = Priors::default();

    // Agent at 4h46m, orphaned, no TTY, stalled
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.05 }), // Low CPU
        runtime_seconds: Some(4.0 * 3600.0 + 46.0 * 60.0), // 4h46m
        orphan: Some(true),
        tty: Some(false),
        io_active: Some(false),
        net: Some(false),
        state_flag: None,
        command_category: None,
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // With all the abandonment signals, abandoned should be elevated
    assert!(
        posterior.abandoned > 0.15,
        "Orphaned stalled agent should have elevated P(abandoned): {:.4}",
        posterior.abandoned
    );
}

/// Scenario 3: `gunicorn` (2 workers) at 45–50% CPU for ~1h
///
/// Intended interpretation from Plan §9:
/// - Category: server
/// - Likely useful; false-kill cost is high.
/// - Recommendations should bias toward KEEP unless strong abandonment evidence exists.
#[test]
fn scenario_3_gunicorn_server_is_useful() {
    let priors = Priors::default();

    // Web server: steady CPU, 1 hour runtime
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.47 }),
        runtime_seconds: Some(3600.0), // 1 hour
        orphan: Some(false), // Managed by systemd typically
        tty: Some(false),    // Servers often don't have TTY
        io_active: Some(true),
        net: Some(true),     // Serving web requests
        state_flag: None,
        command_category: None, // Would be "server" if configured
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // Server with network + IO should be useful
    let useful_like = posterior.useful + posterior.useful_bad;
    assert!(
        useful_like > 0.5,
        "Scenario 3 (gunicorn): useful-like should be dominant: {:.4}",
        useful_like
    );

    // Test decision: should recommend KEEP (observe) not KILL
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let decision = decide_action(&posterior, &policy, &feasibility)
        .expect("decision should succeed");

    // The optimal action should NOT be Kill for a likely-useful server
    assert!(
        !format!("{:?}", decision.optimal_action).contains("Kill"),
        "Scenario 3 (gunicorn): server should not be recommended for kill, got {:?}",
        decision.optimal_action
    );
}

/// Scenario 4: `claude` processes at 35–112% CPU
///
/// Intended interpretation from Plan §9:
/// - Category: agent
/// - Often useful unless orphaned + no TTY + stalled.
#[test]
fn scenario_4_claude_agent_high_cpu_is_useful() {
    let priors = Priors::default();

    // Claude process: high CPU (112% = 1.12 on multi-core), has TTY
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 1.0 }), // 100%+ normalized to 1.0
        runtime_seconds: Some(30.0 * 60.0), // 30 minutes
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(true), // Making API calls
        state_flag: None,
        command_category: None, // Would be "agent" if configured
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // Interactive agent with TTY + IO + network = useful
    assert_class_above(
        "useful",
        "Scenario 4 (claude)",
        posterior.useful,
        0.25,
    );

    // Should not flag as abandoned
    assert_class_below(
        "abandoned",
        "Scenario 4 (claude)",
        posterior.abandoned,
        0.3,
    );
}

/// Scenario 4b: Claude process at moderate CPU, orphaned, no TTY
///
/// Should shift toward abandoned.
#[test]
fn scenario_4b_claude_orphaned_no_tty_shifts_toward_abandoned() {
    let priors = Priors::default();

    // Claude process: orphaned, no TTY, no IO
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.35 }),
        runtime_seconds: Some(2.0 * 3600.0), // 2 hours
        orphan: Some(true),
        tty: Some(false),
        io_active: Some(false),
        net: Some(false),
        state_flag: None,
        command_category: None,
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // Baseline: active claude
    let baseline_evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.35 }),
        runtime_seconds: Some(2.0 * 3600.0),
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(true),
        state_flag: None,
        command_category: None,
    };
    let baseline = compute_posterior(&priors, &baseline_evidence)
        .expect("baseline should succeed")
        .posterior;

    assert!(
        posterior.abandoned > baseline.abandoned,
        "Orphaned no-TTY claude should have higher P(abandoned): {:.4} vs {:.4}",
        posterior.abandoned,
        baseline.abandoned
    );
}

/// Invariant: PPID=1 (orphan) alone should not dominate the decision.
///
/// From Plan §9: "PPID=1 is a weak signal and must be conditioned on
/// platform/supervision context."
#[test]
fn orphan_alone_is_weak_signal() {
    let priors = Priors::default();

    // Process with orphan=true but everything else looks healthy
    let orphan_evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.5 }),
        runtime_seconds: Some(3600.0),
        orphan: Some(true),
        tty: Some(true),
        io_active: Some(true),
        net: Some(true),
        state_flag: None,
        command_category: None,
    };

    // Same process but not orphaned
    let non_orphan_evidence = Evidence {
        orphan: Some(false),
        ..orphan_evidence.clone()
    };

    let orphan_result = compute_posterior(&priors, &orphan_evidence)
        .expect("orphan computation should succeed");
    let non_orphan_result = compute_posterior(&priors, &non_orphan_evidence)
        .expect("non-orphan computation should succeed");

    // Orphan should increase abandoned probability, but not massively
    let delta = orphan_result.posterior.abandoned - non_orphan_result.posterior.abandoned;

    assert!(
        delta < 0.3,
        "Orphan alone should not cause >30% swing in abandoned probability: delta={:.4}",
        delta
    );

    // Both should still favor useful
    assert!(
        orphan_result.posterior.useful > 0.3,
        "Orphan with positive signals should still have meaningful P(useful): {:.4}",
        orphan_result.posterior.useful
    );
}

/// Invariant: High CPU alone should not mean "abandoned".
///
/// From Plan §9: "High CPU alone is not 'abandoned'; it may be useful_bad."
#[test]
fn high_cpu_alone_is_not_abandoned() {
    let priors = Priors::default();

    // High CPU, everything else neutral/positive
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.95 }),
        runtime_seconds: Some(1800.0), // 30 minutes
        orphan: Some(false),
        tty: Some(true),
        io_active: Some(true),
        net: Some(false),
        state_flag: None,
        command_category: None,
    };

    let result = compute_posterior(&priors, &evidence)
        .expect("posterior computation should succeed");

    let posterior = result.posterior;

    // High CPU should not push toward abandoned
    assert_class_below(
        "abandoned",
        "high CPU alone",
        posterior.abandoned,
        0.2,
    );

    // Might be useful_bad if very high, but should still be useful-like
    let useful_like = posterior.useful + posterior.useful_bad;
    assert!(
        useful_like > 0.5,
        "High CPU should be useful or useful_bad, not abandoned: useful_like={:.4}",
        useful_like
    );
}
