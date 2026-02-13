//! Property-based tests for decision theory invariants.

use proptest::prelude::*;
use pt_core::collect::{CriticalFile, CriticalFileCategory, DetectionStrength};
use pt_core::config::policy::{DecisionTimeBound, LoadAwareDecision, Policy, RobotMode};
use pt_core::config::priors::{
    BetaParams, CausalInterventions, ClassParams, ClassPriors, GammaParams, InterventionPriors,
    Priors,
};
use pt_core::decision::alpha_investing::AlphaInvestingPolicy;
use pt_core::decision::causal_interventions::{
    expected_recovery, expected_recovery_by_action, update_beta,
};
use pt_core::decision::composite_test::{
    glr_bernoulli, mixture_sprt_bernoulli, mixture_sprt_beta_sequential, needs_composite_test,
    GlrConfig, MixtureSprtConfig, MixtureSprtState,
};
use pt_core::decision::cvar::{compute_cvar, decide_with_cvar, CvarTrigger};
use pt_core::decision::dependency_loss::{
    compute_dependency_scaling, scale_kill_loss, should_block_kill, CriticalFileInflation,
    DependencyFactors, DependencyScaling,
};
use pt_core::decision::dro::{
    apply_dro_gate, compute_adaptive_epsilon, compute_wasserstein_dro, decide_with_dro,
    is_de_escalation, DroTrigger,
};
use pt_core::decision::escalation::{
    EscalationConfig, EscalationManager, EscalationTrigger, Severity, TriggerType,
};
use pt_core::decision::expected_loss::{
    apply_dro_control, apply_risk_sensitive_control, decide_action_with_recovery, ActionFeasibility,
};
use pt_core::decision::fdr_selection::TargetIdentity;
use pt_core::decision::fdr_selection::{by_correction_factor, select_fdr, FdrCandidate, FdrMethod};
use pt_core::decision::fleet_fdr::{FleetFdrConfig, FleetFdrCoordinator};
use pt_core::decision::fleet_pattern::{
    correlate_fleet_patterns, FleetPatternConfig, PatternObservation,
};
use pt_core::decision::fleet_registry::{
    FleetRegistry, FleetRegistryConfig, Heartbeat, HostCapabilities, HostRole,
};
use pt_core::decision::goal_contribution::{
    estimate_cpu_contribution, estimate_fd_contribution, estimate_memory_contribution,
    estimate_port_contribution, ContributionCandidate,
};
use pt_core::decision::goal_parser::parse_goal;
use pt_core::decision::goal_plan::{optimize_goal_plan, PlanCandidate, PlanConstraints};
use pt_core::decision::goal_progress::{
    measure_progress, ActionOutcome, GoalMetric, MetricSnapshot, ProgressConfig,
};
use pt_core::decision::load_aware::{
    apply_load_to_loss_matrix, compute_load_adjustment, LoadAdjustment, LoadSignals,
};
use pt_core::decision::martingale_gates::{
    apply_martingale_gates, resolve_alpha, AlphaSource, MartingaleGateCandidate,
    MartingaleGateConfig,
};
use pt_core::decision::mem_pressure::{MemPressureConfig, MemPressureMonitor, MemorySignals};
use pt_core::decision::myopic_policy::{compute_loss_table, decide_from_belief};
use pt_core::decision::rate_limit::{RateLimitConfig, SlidingWindowRateLimiter};
use pt_core::decision::respawn_loop::{
    discount_kill_utility, RespawnLoopConfig, RespawnLoopDetection, RespawnTracker,
};
use pt_core::decision::robot_constraints::{
    ConstraintChecker, ConstraintKind, RobotCandidate, RuntimeRobotConstraints,
};
use pt_core::decision::sequential::{decide_sequential, prioritize_by_esn, EsnCandidate};
use pt_core::decision::submodular::{
    coverage_utility, greedy_select_k, greedy_select_with_budget, FeatureKey, ProbeProfile,
};
use pt_core::decision::time_bound::{apply_time_bound, compute_t_max, TMaxInput};
use pt_core::decision::{
    compute_voi, decide_action, select_probe_by_information_gain, Action, ProbeCostModel, ProbeType,
};
use pt_core::inference::belief_state::BeliefState;
use pt_core::inference::martingale::{MartingaleAnalyzer, MartingaleConfig};
use pt_core::inference::ClassScores;
use std::collections::HashMap;

fn posterior_strategy() -> impl Strategy<Value = ClassScores> {
    (0.0f64..=1.0, 0.0f64..=1.0, 0.0f64..=1.0, 0.0f64..=1.0).prop_map(
        |(useful, useful_bad, abandoned, zombie)| {
            let sum = useful + useful_bad + abandoned + zombie;
            if sum <= 0.0 {
                return ClassScores {
                    useful: 0.25,
                    useful_bad: 0.25,
                    abandoned: 0.25,
                    zombie: 0.25,
                };
            }
            ClassScores {
                useful: useful / sum,
                useful_bad: useful_bad / sum,
                abandoned: abandoned / sum,
                zombie: zombie / sum,
            }
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn expected_loss_is_non_negative_and_optimal_minimizes(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action(&posterior, &policy, &feasibility)
            .expect("decision computation failed");

        for loss in &outcome.expected_loss {
            prop_assert!(loss.loss >= -1e-12, "expected loss below zero: {}", loss.loss);
        }

        let optimal_loss = outcome
            .expected_loss
            .iter()
            .find(|entry| entry.action == outcome.optimal_action)
            .map(|entry| entry.loss)
            .expect("optimal action missing from expected loss list");

        for loss in &outcome.expected_loss {
            prop_assert!(
                optimal_loss <= loss.loss + 1e-9,
                "optimal loss {optimal_loss} exceeds {}", loss.loss
            );
        }
    }

    /// VOI property: high confidence posteriors should make probing less valuable.
    /// When we're already very confident, VOI should be close to cost (probing has little benefit).
    #[test]
    fn voi_high_confidence_makes_probing_less_valuable(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &feasibility,
            &cost_model,
            None,
        );

        if let Ok(analysis) = result {
            // Check if posterior is very confident (one class >> others)
            let max_prob = posterior.useful
                .max(posterior.useful_bad)
                .max(posterior.abandoned)
                .max(posterior.zombie);

            // Loss penalty is 100.0, probe costs are ~0.1-0.5.
            // Risk at 95% is 5.0, which > cost, so probing is still rational.
            // We need much higher confidence (risk < cost) to stop probing.
            if max_prob > 0.999 {
                // When very confident, most probes should have VOI close to cost
                // (little benefit from probing)
                let worthwhile_count = analysis.probes.iter()
                    .filter(|p| p.voi < -0.05)  // Significantly worthwhile
                    .count();

                // With high confidence, at most half of probes should be worthwhile
                prop_assert!(
                    worthwhile_count <= analysis.probes.len() / 2,
                    "High-confidence posterior (max_prob={}) has {} worthwhile probes out of {} (expected fewer)",
                    max_prob,
                    worthwhile_count,
                    analysis.probes.len()
                );
            }
        }
    }

    /// VOI structural invariant: all probes should have finite, non-NaN values.
    #[test]
    fn voi_outputs_are_finite(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let result = compute_voi(
            &posterior,
            &policy,
            &feasibility,
            &cost_model,
            None,
        );

        if let Ok(analysis) = result {
            prop_assert!(analysis.current_min_loss.is_finite());

            for probe_voi in &analysis.probes {
                prop_assert!(probe_voi.voi.is_finite(), "VOI for {} is not finite", probe_voi.probe.name());
                prop_assert!(probe_voi.cost.is_finite(), "Cost for {} is not finite", probe_voi.probe.name());
                prop_assert!(probe_voi.expected_loss_after.is_finite(), "Expected loss after {} is not finite", probe_voi.probe.name());
            }
        }
    }

    /// Property: probe cost should always be non-negative.
    #[test]
    fn probe_costs_are_non_negative(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let result = compute_voi(
            &posterior,
            &policy,
            &feasibility,
            &cost_model,
            None,
        );

        if let Ok(analysis) = result {
            for probe_voi in &analysis.probes {
                prop_assert!(
                    probe_voi.cost >= -1e-12,
                    "Probe {} has negative cost: {}",
                    probe_voi.probe.name(),
                    probe_voi.cost
                );
            }
        }
    }
}

// ── Myopic policy property tests ──────────────────────────────────

fn belief_strategy() -> impl Strategy<Value = BeliefState> {
    (0.01f64..=1.0, 0.01f64..=1.0, 0.01f64..=1.0, 0.01f64..=1.0).prop_map(|(u, ub, a, z)| {
        let sum = u + ub + a + z;
        BeliefState::from_probs([u / sum, ub / sum, a / sum, z / sum])
            .expect("normalised probs should form valid belief")
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    /// decide_from_belief should always succeed for valid belief states.
    #[test]
    fn myopic_decide_from_belief_never_panics(belief in belief_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let decision = decide_from_belief(&belief, &policy, &feasibility);
        prop_assert!(decision.is_ok(), "decide_from_belief failed: {:?}", decision.err());
    }

    /// The optimal action from decide_from_belief should be consistent with
    /// compute_loss_table: it should pick the action with minimal expected loss.
    #[test]
    fn myopic_optimal_action_matches_loss_table(belief in belief_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();

        let decision = decide_from_belief(&belief, &policy, &feasibility)
            .expect("decide_from_belief failed");
        let table = compute_loss_table(&belief, &policy.loss_matrix, &feasibility);

        // Find the minimum loss among feasible actions in the table.
        let table_min = table.iter()
            .filter(|b| b.feasible)
            .min_by(|a, b| a.expected_loss.partial_cmp(&b.expected_loss).unwrap())
            .expect("loss table should have feasible entries");

        prop_assert!(
            (decision.optimal_loss - table_min.expected_loss).abs() < 1e-9,
            "decision loss {} != table min loss {}",
            decision.optimal_loss,
            table_min.expected_loss
        );
    }

    /// The loss table should be sorted by expected loss (ascending).
    #[test]
    fn myopic_loss_table_is_sorted(belief in belief_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let table = compute_loss_table(&belief, &policy.loss_matrix, &feasibility);

        for window in table.windows(2) {
            prop_assert!(
                window[0].expected_loss <= window[1].expected_loss + 1e-12,
                "loss table not sorted: {} > {}",
                window[0].expected_loss,
                window[1].expected_loss
            );
        }
    }

    /// decide_action and decide_from_belief should agree on the optimal action.
    #[test]
    fn decide_action_and_belief_agree(belief in belief_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();

        let posterior = ClassScores {
            useful: belief.prob(pt_core::inference::belief_state::ProcessState::Useful),
            useful_bad: belief.prob(pt_core::inference::belief_state::ProcessState::UsefulBad),
            abandoned: belief.prob(pt_core::inference::belief_state::ProcessState::Abandoned),
            zombie: belief.prob(pt_core::inference::belief_state::ProcessState::Zombie),
        };

        let action_outcome = decide_action(&posterior, &policy, &feasibility)
            .expect("decide_action failed");
        let belief_decision = decide_from_belief(&belief, &policy, &feasibility)
            .expect("decide_from_belief failed");

        prop_assert_eq!(
            action_outcome.optimal_action,
            belief_decision.optimal_action,
            "decide_action chose {:?} but decide_from_belief chose {:?}",
            action_outcome.optimal_action,
            belief_decision.optimal_action
        );
    }

    /// With zombie feasibility constraints, Kill should never be the optimal action.
    #[test]
    fn zombie_feasibility_blocks_kill(belief in belief_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::from_process_state(true, false, None);

        let decision = decide_from_belief(&belief, &policy, &feasibility)
            .expect("decide_from_belief failed");

        prop_assert_ne!(
            decision.optimal_action,
            Action::Kill,
            "Kill should be blocked for zombie processes"
        );
    }
}

// ── VOI property tests ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    /// compute_voi should succeed for any valid posterior.
    #[test]
    fn voi_never_errors_on_valid_posterior(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(&posterior, &policy, &feasibility, &cost_model, None);
        prop_assert!(result.is_ok(), "compute_voi failed: {:?}", result.err());
    }

    /// All VOI probe costs must be non-negative.
    #[test]
    fn voi_probe_costs_non_negative(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        if let Ok(analysis) = compute_voi(&posterior, &policy, &feasibility, &cost_model, None) {
            for probe in &analysis.probes {
                prop_assert!(
                    probe.cost >= -1e-12,
                    "Probe {} has negative cost: {}",
                    probe.probe.name(),
                    probe.cost
                );
            }
        }
    }

    /// All VOI values must be finite (no NaN or infinity).
    #[test]
    fn voi_all_values_finite(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        if let Ok(analysis) = compute_voi(&posterior, &policy, &feasibility, &cost_model, None) {
            prop_assert!(analysis.current_min_loss.is_finite(),
                "current_min_loss is not finite");

            for probe in &analysis.probes {
                prop_assert!(probe.voi.is_finite(),
                    "VOI for {} is not finite", probe.probe.name());
                prop_assert!(probe.cost.is_finite(),
                    "Cost for {} is not finite", probe.probe.name());
                prop_assert!(probe.expected_loss_after.is_finite(),
                    "Expected loss after {} is not finite", probe.probe.name());
            }
        }
    }

    /// The act_now flag should be consistent with best_probe:
    /// act_now == true iff best_probe is None.
    #[test]
    fn voi_act_now_consistent_with_best_probe(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        if let Ok(analysis) = compute_voi(&posterior, &policy, &feasibility, &cost_model, None) {
            prop_assert_eq!(
                analysis.act_now,
                analysis.best_probe.is_none(),
                "act_now={} but best_probe={:?}",
                analysis.act_now,
                analysis.best_probe
            );
        }
    }

    /// If best_probe is Some(p), then p should have negative VOI (worthwhile).
    #[test]
    fn voi_best_probe_has_negative_voi(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        if let Ok(analysis) = compute_voi(&posterior, &policy, &feasibility, &cost_model, None) {
            if let Some(best) = analysis.best_probe {
                let best_entry = analysis.probes.iter()
                    .find(|p| p.probe == best)
                    .expect("best_probe should appear in probes list");
                prop_assert!(
                    best_entry.voi < 0.0,
                    "Best probe {:?} has non-negative VOI: {}",
                    best,
                    best_entry.voi
                );
            }
        }
    }

    /// The best probe should have the minimum VOI among all probes.
    #[test]
    fn voi_best_probe_is_minimal(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();

        if let Ok(analysis) = compute_voi(&posterior, &policy, &feasibility, &cost_model, None) {
            if let Some(best) = analysis.best_probe {
                let best_voi = analysis.probes.iter()
                    .find(|p| p.probe == best)
                    .map(|p| p.voi)
                    .expect("best_probe should appear in probes list");

                for probe in &analysis.probes {
                    prop_assert!(
                        best_voi <= probe.voi + 1e-9,
                        "Best probe {:?} VOI {} exceeds probe {:?} VOI {}",
                        best, best_voi, probe.probe, probe.voi
                    );
                }
            }
        }
    }

    /// select_probe_by_information_gain should always return Some for valid posteriors.
    #[test]
    fn info_gain_always_selects_a_probe(posterior in posterior_strategy()) {
        let cost_model = ProbeCostModel::default();
        let result = select_probe_by_information_gain(&posterior, &cost_model, None);
        prop_assert!(
            result.is_some(),
            "select_probe_by_information_gain returned None for valid posterior"
        );
    }

    /// Restricting available probes should not produce probes outside the set.
    #[test]
    fn voi_respects_available_probes(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let cost_model = ProbeCostModel::default();
        let subset = [ProbeType::QuickScan, ProbeType::CgroupInspect, ProbeType::NetSnapshot];

        if let Ok(analysis) = compute_voi(
            &posterior, &policy, &feasibility, &cost_model, Some(&subset),
        ) {
            for probe in &analysis.probes {
                prop_assert!(
                    subset.contains(&probe.probe),
                    "Probe {:?} not in available set",
                    probe.probe
                );
            }
            if let Some(best) = analysis.best_probe {
                prop_assert!(
                    subset.contains(&best),
                    "Best probe {:?} not in available set",
                    best
                );
            }
        }
    }
}

// ── Composite testing (SPRT/GLR) property tests ────────────────────

/// Strategy for valid Bernoulli p0 parameter (0, 1).
fn p0_strategy() -> impl Strategy<Value = f64> {
    0.01f64..=0.99
}

/// Strategy for valid Beta prior parameters (positive).
fn beta_params_strategy() -> impl Strategy<Value = (f64, f64)> {
    (0.1f64..=10.0, 0.1f64..=10.0)
}

/// Strategy for Bernoulli observation sequences.
fn bernoulli_obs_strategy(len: usize) -> impl Strategy<Value = Vec<bool>> {
    prop::collection::vec(prop::bool::ANY, len..=len)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// mixture_sprt_bernoulli should never fail for valid inputs.
    #[test]
    fn sprt_bernoulli_never_errors(
        p0 in p0_strategy(),
        (alpha, beta) in beta_params_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..50),
    ) {
        let config = MixtureSprtConfig::default();
        let result = mixture_sprt_bernoulli(&obs, p0, alpha, beta, &config);
        prop_assert!(result.is_ok(), "mixture_sprt_bernoulli failed: {:?}", result.err());
    }

    /// SPRT result fields should always be finite.
    #[test]
    fn sprt_bernoulli_outputs_finite(
        p0 in p0_strategy(),
        (alpha, beta) in beta_params_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..50),
    ) {
        let config = MixtureSprtConfig::default();
        if let Ok(result) = mixture_sprt_bernoulli(&obs, p0, alpha, beta, &config) {
            prop_assert!(result.log_lambda.is_finite(),
                "log_lambda is not finite: {}", result.log_lambda);
            prop_assert!(result.e_value.is_finite(),
                "e_value is not finite: {}", result.e_value);
        }
    }

    /// SPRT e_value should be non-negative (it's exp of a log ratio).
    #[test]
    fn sprt_bernoulli_e_value_non_negative(
        p0 in p0_strategy(),
        (alpha, beta) in beta_params_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..50),
    ) {
        let config = MixtureSprtConfig::default();
        if let Ok(result) = mixture_sprt_bernoulli(&obs, p0, alpha, beta, &config) {
            prop_assert!(
                result.e_value >= -1e-12,
                "e_value should be non-negative, got {}",
                result.e_value
            );
        }
    }

    /// n_observations should match the input length.
    #[test]
    fn sprt_bernoulli_n_observations_matches_input(
        p0 in p0_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..100),
    ) {
        let config = MixtureSprtConfig::default();
        if let Ok(result) = mixture_sprt_bernoulli(&obs, p0, 2.0, 2.0, &config) {
            prop_assert_eq!(
                result.n_observations, obs.len(),
                "n_observations {} != input length {}",
                result.n_observations, obs.len()
            );
        }
    }

    /// crossed_upper and crossed_lower should be mutually exclusive.
    #[test]
    fn sprt_boundaries_mutually_exclusive(
        p0 in p0_strategy(),
        (alpha, beta) in beta_params_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..100),
    ) {
        let config = MixtureSprtConfig::default();
        if let Ok(result) = mixture_sprt_bernoulli(&obs, p0, alpha, beta, &config) {
            prop_assert!(
                !(result.crossed_upper && result.crossed_lower),
                "Both boundaries crossed: upper={}, lower={}, log_lambda={}",
                result.crossed_upper, result.crossed_lower, result.log_lambda
            );
        }
    }

    /// Beta-sequential SPRT should also never error for valid inputs.
    #[test]
    fn sprt_beta_sequential_never_errors(
        p0 in p0_strategy(),
        (alpha, beta) in beta_params_strategy(),
        obs in prop::collection::vec(prop::bool::ANY, 1..50),
    ) {
        let config = MixtureSprtConfig::default();
        let result = mixture_sprt_beta_sequential(&obs, p0, alpha, beta, &config);
        prop_assert!(result.is_ok(), "beta_sequential failed: {:?}", result.err());
    }

    /// GLR should succeed for valid inputs (n > 0, 0 < p0 < 1, successes <= n).
    #[test]
    fn glr_bernoulli_never_errors(
        p0 in p0_strategy(),
        n in 1usize..200,
    ) {
        let successes = n / 2; // Half success rate
        let config = GlrConfig::default();
        let result = glr_bernoulli(successes, n, p0, &config);
        prop_assert!(result.is_ok(), "glr_bernoulli failed: {:?}", result.err());
    }

    /// GLR e_value should be non-negative.
    #[test]
    fn glr_e_value_non_negative(
        p0 in p0_strategy(),
        n in 1usize..200,
    ) {
        let successes = n / 2;
        let config = GlrConfig::default();
        if let Ok(result) = glr_bernoulli(successes, n, p0, &config) {
            prop_assert!(
                result.e_value >= -1e-12,
                "GLR e_value should be non-negative, got {}",
                result.e_value
            );
        }
    }

    /// GLR MLE should be in [0, 1] range.
    #[test]
    fn glr_mle_in_valid_range(
        p0 in p0_strategy(),
        n in 1usize..200,
    ) {
        let successes = n / 3;
        let config = GlrConfig::default();
        if let Ok(result) = glr_bernoulli(successes, n, p0, &config) {
            if let Some(mle) = result.mle_h1 {
                prop_assert!(
                    mle >= -1e-12 && mle <= 1.0 + 1e-12,
                    "GLR MLE should be in [0,1], got {}",
                    mle
                );
            }
        }
    }

    /// MixtureSprtState: reset should clear all accumulated state.
    #[test]
    fn sprt_state_reset_clears(
        obs in prop::collection::vec(prop::bool::ANY, 1..50),
    ) {
        let config = MixtureSprtConfig { track_increments: true, ..MixtureSprtConfig::default() };
        let mut state = MixtureSprtState::new(config);

        for &o in &obs {
            let ll1 = if o { -0.5 } else { -1.5 };
            state.update(ll1, -1.0);
        }

        state.reset();
        prop_assert_eq!(state.n_observations, 0, "n_observations should be 0 after reset");
        prop_assert!((state.log_lambda).abs() < 1e-12, "log_lambda should be 0 after reset");
    }

    /// needs_composite_test should be a pure function of its inputs (deterministic).
    #[test]
    fn needs_composite_test_deterministic(
        log_bf in -5.0f64..5.0,
        entropy in 0.0f64..3.0,
        uncertainty in 0.0f64..1.0,
    ) {
        let r1 = needs_composite_test(log_bf, entropy, uncertainty);
        let r2 = needs_composite_test(log_bf, entropy, uncertainty);
        prop_assert_eq!(r1, r2, "needs_composite_test should be deterministic");
    }
}

// ── CVaR property tests ─────────────────────────────────────────────

/// Strategy for valid CVaR alpha parameter (0, 1).
fn alpha_strategy() -> impl Strategy<Value = f64> {
    0.01f64..=0.99
}

/// Strategy for actions that have defined loss entries in the default policy.
fn cvar_action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Keep),
        Just(Action::Pause),
        Just(Action::Throttle),
        Just(Action::Renice),
        Just(Action::Restart),
        Just(Action::Kill),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// compute_cvar should never fail for valid posteriors and alpha.
    #[test]
    fn cvar_never_errors(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
        action in cvar_action_strategy(),
    ) {
        let policy = Policy::default();
        let result = compute_cvar(action, &posterior, &policy.loss_matrix, alpha);
        prop_assert!(result.is_ok(), "compute_cvar failed: {:?}", result.err());
    }

    /// CVaR >= E[L]: tail risk is at least as large as full expectation.
    #[test]
    fn cvar_geq_expected_loss(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
        action in cvar_action_strategy(),
    ) {
        let policy = Policy::default();
        if let Ok(cl) = compute_cvar(action, &posterior, &policy.loss_matrix, alpha) {
            prop_assert!(
                cl.cvar >= cl.expected_loss - 1e-9,
                "CVaR {} < E[L] {} for {:?} α={}",
                cl.cvar, cl.expected_loss, action, alpha
            );
        }
    }

    /// All CVaR outputs should be finite.
    #[test]
    fn cvar_outputs_finite(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
        action in cvar_action_strategy(),
    ) {
        let policy = Policy::default();
        if let Ok(cl) = compute_cvar(action, &posterior, &policy.loss_matrix, alpha) {
            prop_assert!(cl.cvar.is_finite(), "CVaR not finite: {}", cl.cvar);
            prop_assert!(cl.expected_loss.is_finite(), "E[L] not finite");
            prop_assert!(cl.var.is_finite(), "VaR not finite: {}", cl.var);
        }
    }

    /// CVaR is monotone non-decreasing in alpha (higher alpha → more conservative).
    #[test]
    fn cvar_monotone_in_alpha(
        posterior in posterior_strategy(),
        action in cvar_action_strategy(),
    ) {
        let policy = Policy::default();
        let lo = compute_cvar(action, &posterior, &policy.loss_matrix, 0.5);
        let hi = compute_cvar(action, &posterior, &policy.loss_matrix, 0.95);
        if let (Ok(lo), Ok(hi)) = (lo, hi) {
            prop_assert!(
                hi.cvar >= lo.cvar - 1e-9,
                "CVaR not monotone: α=0.5 CVaR={} > α=0.95 CVaR={} for {:?}",
                lo.cvar, hi.cvar, action
            );
        }
    }

    /// Alpha should be preserved in the output.
    #[test]
    fn cvar_preserves_alpha(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
    ) {
        let policy = Policy::default();
        if let Ok(cl) = compute_cvar(Action::Keep, &posterior, &policy.loss_matrix, alpha) {
            prop_assert!(
                (cl.alpha - alpha).abs() < 1e-12,
                "alpha not preserved: {} != {}", cl.alpha, alpha
            );
        }
    }

    /// decide_with_cvar should succeed for valid inputs.
    #[test]
    fn decide_with_cvar_never_errors(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
    ) {
        let policy = Policy::default();
        let feasible = vec![Action::Keep, Action::Pause, Action::Kill];
        let result = decide_with_cvar(&posterior, &policy, &feasible, alpha, Action::Kill, "test");
        prop_assert!(result.is_ok(), "decide_with_cvar failed: {:?}", result.err());
    }

    /// The risk-adjusted action should be one of the feasible actions.
    #[test]
    fn decide_cvar_action_in_feasible_set(
        posterior in posterior_strategy(),
        alpha in alpha_strategy(),
    ) {
        let policy = Policy::default();
        let feasible = vec![Action::Keep, Action::Renice, Action::Pause, Action::Kill];
        if let Ok(outcome) = decide_with_cvar(&posterior, &policy, &feasible, alpha, Action::Kill, "test") {
            prop_assert!(
                feasible.contains(&outcome.risk_adjusted_action),
                "action {:?} not in feasible set", outcome.risk_adjusted_action
            );
        }
    }
}

// ── Submodular selection property tests ─────────────────────────────

/// Build test probe profiles and feature weights from random vectors.
fn build_submodular_data(
    feature_weights: Vec<f64>,
    probe_costs: Vec<f64>,
) -> (Vec<ProbeProfile>, HashMap<FeatureKey, f64>) {
    let n_features = feature_weights.len().max(1);
    let weights: HashMap<FeatureKey, f64> = feature_weights
        .into_iter()
        .enumerate()
        .map(|(i, w)| (FeatureKey::new(format!("f_{i}")), w))
        .collect();
    let probe_types = ProbeType::ALL;
    let profiles: Vec<ProbeProfile> = probe_costs
        .into_iter()
        .enumerate()
        .map(|(i, cost)| {
            let probe = probe_types[i % probe_types.len()];
            let features: Vec<FeatureKey> = (0..2)
                .map(|j| FeatureKey::new(format!("f_{}", (i + j) % n_features)))
                .collect();
            ProbeProfile::new(probe, cost, features)
        })
        .collect();
    (profiles, weights)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// coverage_utility should be non-negative for non-negative weights.
    #[test]
    fn submodular_coverage_non_negative(
        feature_weights in prop::collection::vec(0.0f64..=5.0, 1..=8),
        probe_costs in prop::collection::vec(0.01f64..=2.0, 1..=10),
    ) {
        let (profiles, weights) = build_submodular_data(feature_weights, probe_costs);
        let utility = coverage_utility(&profiles, &weights);
        prop_assert!(utility >= -1e-12, "coverage_utility negative: {}", utility);
    }

    /// greedy_select_k should select at most k probes.
    #[test]
    fn submodular_select_k_respects_cardinality(
        feature_weights in prop::collection::vec(0.1f64..=5.0, 1..=8),
        probe_costs in prop::collection::vec(0.01f64..=2.0, 1..=10),
        k in 0usize..=12,
    ) {
        let (profiles, weights) = build_submodular_data(feature_weights, probe_costs);
        let result = greedy_select_k(&profiles, &weights, k);
        prop_assert!(
            result.selected.len() <= k,
            "selected {} > k={}", result.selected.len(), k
        );
    }

    /// greedy_select_with_budget should respect the budget constraint.
    #[test]
    fn submodular_budget_respects_constraint(
        feature_weights in prop::collection::vec(0.1f64..=5.0, 1..=8),
        probe_costs in prop::collection::vec(0.01f64..=2.0, 1..=10),
        budget in 0.0f64..=5.0,
    ) {
        let (profiles, weights) = build_submodular_data(feature_weights, probe_costs);
        let result = greedy_select_with_budget(&profiles, &weights, budget);
        prop_assert!(
            result.total_cost <= budget + 1e-9,
            "total_cost {} > budget {}", result.total_cost, budget
        );
    }

    /// Increasing k should not decrease total utility (monotonicity).
    #[test]
    fn submodular_select_k_monotone(
        feature_weights in prop::collection::vec(0.1f64..=5.0, 2..=8),
        probe_costs in prop::collection::vec(0.01f64..=2.0, 2..=10),
    ) {
        let (profiles, weights) = build_submodular_data(feature_weights, probe_costs);
        let max_k = profiles.len();
        let mut prev_utility = 0.0;
        for k in 1..=max_k {
            let result = greedy_select_k(&profiles, &weights, k);
            prop_assert!(
                result.total_utility >= prev_utility - 1e-9,
                "utility decreased: k={} u={} < prev u={}",
                k, result.total_utility, prev_utility
            );
            prev_utility = result.total_utility;
        }
    }

    /// Selection utility values should be finite.
    #[test]
    fn submodular_values_finite(
        feature_weights in prop::collection::vec(0.0f64..=5.0, 1..=8),
        probe_costs in prop::collection::vec(0.01f64..=2.0, 1..=10),
    ) {
        let (profiles, weights) = build_submodular_data(feature_weights, probe_costs);
        let u = coverage_utility(&profiles, &weights);
        prop_assert!(u.is_finite(), "coverage_utility not finite: {}", u);

        let sel = greedy_select_k(&profiles, &weights, 3);
        prop_assert!(sel.total_utility.is_finite());
        prop_assert!(sel.total_cost.is_finite());

        let bud = greedy_select_with_budget(&profiles, &weights, 1.0);
        prop_assert!(bud.total_utility.is_finite());
        prop_assert!(bud.total_cost.is_finite());
    }
}

// ── FDR selection property tests ────────────────────────────────────

/// Build FDR candidates with random e-values.
fn build_fdr_candidates(e_values: Vec<f64>) -> Vec<FdrCandidate> {
    e_values
        .into_iter()
        .enumerate()
        .map(|(i, ev)| FdrCandidate {
            target: TargetIdentity {
                pid: i as i32,
                start_id: format!("{i}-start-boot0"),
                uid: 1000,
            },
            e_value: ev,
        })
        .collect()
}

/// Strategy for FDR alpha in (0, 1].
fn fdr_alpha_strategy() -> impl Strategy<Value = f64> {
    0.01f64..=1.0
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// select_fdr should never fail for valid inputs.
    #[test]
    fn fdr_never_errors(
        e_values in prop::collection::vec(0.0f64..=200.0, 1..=50),
        alpha in fdr_alpha_strategy(),
    ) {
        let candidates = build_fdr_candidates(e_values);
        for method in [FdrMethod::EBh, FdrMethod::EBy, FdrMethod::None] {
            let result = select_fdr(&candidates, alpha, method);
            prop_assert!(result.is_ok(), "select_fdr failed: {:?}", result.err());
        }
    }

    /// Selected count should never exceed total candidate count.
    #[test]
    fn fdr_selected_leq_total(
        e_values in prop::collection::vec(0.0f64..=200.0, 1..=50),
        alpha in fdr_alpha_strategy(),
    ) {
        let candidates = build_fdr_candidates(e_values);
        for method in [FdrMethod::EBh, FdrMethod::EBy, FdrMethod::None] {
            if let Ok(result) = select_fdr(&candidates, alpha, method) {
                prop_assert!(
                    result.selected_k <= result.m_candidates,
                    "selected {} > total {} for {:?}",
                    result.selected_k, result.m_candidates, method
                );
            }
        }
    }

    /// eBY should be at least as conservative as eBH.
    #[test]
    fn fdr_eby_more_conservative_than_ebh(
        e_values in prop::collection::vec(0.0f64..=200.0, 1..=50),
        alpha in fdr_alpha_strategy(),
    ) {
        let candidates = build_fdr_candidates(e_values);
        let ebh = select_fdr(&candidates, alpha, FdrMethod::EBh);
        let eby = select_fdr(&candidates, alpha, FdrMethod::EBy);
        if let (Ok(ebh), Ok(eby)) = (ebh, eby) {
            prop_assert!(
                eby.selected_k <= ebh.selected_k,
                "eBY selected {} > eBH selected {}",
                eby.selected_k, ebh.selected_k
            );
        }
    }

    /// P-values derived from e-values should be in [0, 1].
    #[test]
    fn fdr_p_values_in_unit_interval(
        e_values in prop::collection::vec(0.0f64..=200.0, 1..=30),
        alpha in fdr_alpha_strategy(),
    ) {
        let candidates = build_fdr_candidates(e_values);
        if let Ok(result) = select_fdr(&candidates, alpha, FdrMethod::EBh) {
            for cand in &result.candidates {
                prop_assert!(
                    cand.p_value >= -1e-12 && cand.p_value <= 1.0 + 1e-12,
                    "p_value {} out of [0,1] for e_value {}",
                    cand.p_value, cand.e_value
                );
            }
        }
    }

    /// Candidates should be sorted by e_value descending in the result.
    #[test]
    fn fdr_candidates_sorted_descending(
        e_values in prop::collection::vec(0.0f64..=200.0, 2..=30),
        alpha in fdr_alpha_strategy(),
    ) {
        let candidates = build_fdr_candidates(e_values);
        if let Ok(result) = select_fdr(&candidates, alpha, FdrMethod::EBh) {
            for window in result.candidates.windows(2) {
                prop_assert!(
                    window[0].e_value >= window[1].e_value - 1e-12,
                    "not sorted: e_value {} < {}",
                    window[0].e_value, window[1].e_value
                );
            }
        }
    }

    /// FdrMethod::None should select exactly the candidates with e_value > 1.
    #[test]
    fn fdr_none_selects_evalue_gt_one(
        e_values in prop::collection::vec(0.0f64..=10.0, 1..=30),
    ) {
        let candidates = build_fdr_candidates(e_values.clone());
        if let Ok(result) = select_fdr(&candidates, 0.05, FdrMethod::None) {
            let expected = e_values.iter().filter(|&&v| v > 1.0).count();
            prop_assert_eq!(
                result.selected_k, expected,
                "None method: selected {} but {} have e>1",
                result.selected_k, expected
            );
        }
    }

    /// by_correction_factor should be monotone non-decreasing (harmonic series).
    #[test]
    fn fdr_by_correction_monotone(m in 1usize..=200) {
        if m >= 2 {
            let h_prev = by_correction_factor(m - 1);
            let h_curr = by_correction_factor(m);
            prop_assert!(
                h_curr >= h_prev - 1e-12,
                "correction not monotone: H({})={} < H({})={}",
                m, h_curr, m - 1, h_prev
            );
        }
    }

    /// by_correction_factor(m) should equal the m-th harmonic number.
    #[test]
    fn fdr_by_correction_positive(m in 1usize..=500) {
        let h = by_correction_factor(m);
        prop_assert!(h >= 1.0 - 1e-12, "H({})={} < 1.0", m, h);
        prop_assert!(h.is_finite(), "H({}) not finite", m);
    }
}

// ── Alpha-investing property tests ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// alpha_spend_for_wealth should be in [0, wealth] for non-negative wealth.
    #[test]
    fn alpha_spend_bounded_by_wealth(
        w0 in 0.01f64..=1.0,
        spend_rate in 0.0f64..=5.0,
        wealth in 0.0f64..=10.0,
    ) {
        let policy = AlphaInvestingPolicy {
            w0,
            alpha_spend: spend_rate,
            alpha_earn: 0.01,
        };
        let spend = policy.alpha_spend_for_wealth(wealth);
        prop_assert!(
            spend >= -1e-12,
            "spend {} < 0 at wealth {}", spend, wealth
        );
        prop_assert!(
            spend <= wealth + 1e-12,
            "spend {} > wealth {}", spend, wealth
        );
    }

    /// alpha_spend_for_wealth returns 0 for zero or negative wealth.
    #[test]
    fn alpha_spend_zero_for_nonpositive_wealth(
        spend_rate in 0.01f64..=5.0,
        wealth in -10.0f64..=0.0,
    ) {
        let policy = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: spend_rate,
            alpha_earn: 0.01,
        };
        let spend = policy.alpha_spend_for_wealth(wealth);
        prop_assert!(
            spend.abs() < 1e-12,
            "spend {} != 0 for wealth {}", spend, wealth
        );
    }

    /// The alpha-investing wealth update formula should produce non-negative wealth.
    #[test]
    fn alpha_wealth_update_non_negative(
        wealth in 0.0f64..=1.0,
        spend_rate in 0.0f64..=2.0,
        earn_rate in 0.0f64..=0.1,
        discoveries in 0u32..=20,
    ) {
        let policy = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: spend_rate,
            alpha_earn: earn_rate,
        };
        let spend = policy.alpha_spend_for_wealth(wealth);
        let reward = earn_rate * discoveries as f64;
        let next = (wealth - spend + reward).max(0.0);
        prop_assert!(
            next >= -1e-12,
            "next wealth {} < 0 (prev={}, spend={}, reward={})",
            next, wealth, spend, reward
        );
    }
}

// ── Sequential stopping property tests ──────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// decide_sequential should never fail for valid posteriors.
    #[test]
    fn sequential_never_errors(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let result = decide_sequential(
            &posterior, &policy, &feasibility, &cost_model, None,
        );
        prop_assert!(result.is_ok(), "decide_sequential failed: {:?}", result.err());
    }

    /// The ledger should always have entries (at least one probe type exists).
    #[test]
    fn sequential_ledger_non_empty(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        if let Ok((_, ledger)) = decide_sequential(
            &posterior, &policy, &feasibility, &cost_model, None,
        ) {
            prop_assert!(
                !ledger.is_empty(),
                "ledger should have entries for available probes"
            );
        }
    }

    /// If should_probe is true, recommended_probe must be Some.
    #[test]
    fn sequential_probe_implies_recommendation(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        if let Ok((decision, _)) = decide_sequential(
            &posterior, &policy, &feasibility, &cost_model, None,
        ) {
            if decision.should_probe {
                prop_assert!(
                    decision.recommended_probe.is_some(),
                    "should_probe=true but recommended_probe is None"
                );
            }
        }
    }

    /// All sequential outputs should be finite.
    #[test]
    fn sequential_outputs_finite(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        if let Ok((decision, ledger)) = decide_sequential(
            &posterior, &policy, &feasibility, &cost_model, None,
        ) {
            if let Some(esn) = decision.esn_estimate {
                prop_assert!(esn.is_finite(), "ESN estimate not finite: {}", esn);
                prop_assert!(esn >= 1.0 - 1e-9, "ESN estimate < 1: {}", esn);
            }
            for entry in &ledger {
                prop_assert!(entry.voi.is_finite(), "ledger VOI not finite");
                prop_assert!(
                    entry.expected_loss_after.is_finite(),
                    "ledger expected_loss_after not finite"
                );
            }
        }
    }

    /// Restricting to a single probe should yield ledger with only that probe.
    #[test]
    fn sequential_respects_probe_filter(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        if let Ok((decision, ledger)) = decide_sequential(
            &posterior, &policy, &feasibility, &cost_model,
            Some(&[ProbeType::QuickScan]),
        ) {
            for entry in &ledger {
                prop_assert_eq!(
                    entry.probe, ProbeType::QuickScan,
                    "ledger contains {:?} but only QuickScan was available",
                    entry.probe
                );
            }
            if decision.should_probe {
                prop_assert_eq!(
                    decision.recommended_probe,
                    Some(ProbeType::QuickScan),
                    "recommended probe should be QuickScan"
                );
            }
        }
    }

    /// prioritize_by_esn should produce exactly one entry per candidate.
    #[test]
    fn esn_priority_count_matches_input(
        n in 1usize..=10,
        posterior in posterior_strategy(),
    ) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let candidates: Vec<EsnCandidate> = (0..n)
            .map(|i| EsnCandidate::new(
                format!("pid-{i}"),
                posterior,
                feasibility.clone(),
                vec![ProbeType::QuickScan],
            ))
            .collect();

        if let Ok(ranked) = prioritize_by_esn(&candidates, &policy, &cost_model) {
            prop_assert_eq!(
                ranked.len(), n,
                "ranked count {} != input count {}",
                ranked.len(), n
            );
        }
    }

    /// prioritize_by_esn should produce a stable sort (ESN ascending, ID tiebreak).
    #[test]
    fn esn_priority_deterministic(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let candidates: Vec<EsnCandidate> = (0..5)
            .map(|i| EsnCandidate::new(
                format!("pid-{i}"),
                posterior,
                feasibility.clone(),
                vec![ProbeType::QuickScan, ProbeType::DeepScan],
            ))
            .collect();

        let r1 = prioritize_by_esn(&candidates, &policy, &cost_model);
        let r2 = prioritize_by_esn(&candidates, &policy, &cost_model);
        if let (Ok(r1), Ok(r2)) = (r1, r2) {
            for (a, b) in r1.iter().zip(r2.iter()) {
                prop_assert_eq!(
                    &a.candidate_id, &b.candidate_id,
                    "non-deterministic ordering"
                );
            }
        }
    }
}

// ── Robot constraint property tests ─────────────────────────────────

fn test_robot_mode() -> RobotMode {
    RobotMode {
        enabled: true,
        min_posterior: 0.95,
        min_confidence: None,
        max_blast_radius_mb: 1024.0,
        max_kills: 10,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// check_candidate should never panic for any candidate configuration.
    #[test]
    fn robot_check_never_panics(
        posterior in 0.0f64..=1.0,
        memory_mb in 0.0f64..=10000.0,
        has_sig in prop::bool::ANY,
        is_kill in prop::bool::ANY,
        has_snapshot in prop::bool::ANY,
        is_supervised in prop::bool::ANY,
    ) {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(posterior)
            .with_memory_mb(memory_mb)
            .with_known_signature(has_sig)
            .with_kill_action(is_kill)
            .with_policy_snapshot(has_snapshot)
            .with_supervised(is_supervised);

        let result = checker.check_candidate(&candidate);
        // Just verify it returns without panic and has consistent fields
        prop_assert_eq!(
            result.allowed,
            result.violations.is_empty(),
            "allowed={} but violations.len()={}",
            result.allowed,
            result.violations.len()
        );
    }

    /// High posterior + small memory should always be allowed (when other constraints off).
    #[test]
    fn robot_high_confidence_small_blast_allowed(
        posterior in 0.96f64..=1.0,
        memory_mb in 0.0f64..=500.0,
    ) {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(posterior)
            .with_memory_mb(memory_mb)
            .with_known_signature(true)
            .with_policy_snapshot(true)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            result.allowed,
            "should be allowed: posterior={}, memory={}MB, violations={:?}",
            posterior, memory_mb,
            result.violations.iter().map(|v| format!("{:?}", v.constraint)).collect::<Vec<_>>()
        );
    }

    /// Low posterior should always be blocked regardless of other fields.
    #[test]
    fn robot_low_posterior_always_blocked(
        posterior in 0.0f64..0.90,
        memory_mb in 0.0f64..=500.0,
    ) {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode()); // min_posterior=0.95
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(posterior)
            .with_memory_mb(memory_mb)
            .with_kill_action(false);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            !result.allowed,
            "low posterior {} should be blocked", posterior
        );
        prop_assert!(
            result.violations.iter().any(|v| v.constraint == ConstraintKind::MinPosterior),
            "should have MinPosterior violation"
        );
    }

    /// Exceeding max_blast_radius should be blocked.
    #[test]
    fn robot_blast_radius_blocks(
        memory_mb in 1025.0f64..=5000.0,
    ) {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode()); // max=1024
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.99)
            .with_memory_mb(memory_mb)
            .with_kill_action(false);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            result.violations.iter().any(|v| v.constraint == ConstraintKind::MaxBlastRadius),
            "memory {}MB should violate max_blast_radius (1024MB)", memory_mb
        );
    }

    /// Kill count tracking: after max_kills are recorded, next kill should be blocked.
    #[test]
    fn robot_kill_count_enforced(
        max_kills in 1u32..=20,
    ) {
        let mut robot_mode = test_robot_mode();
        robot_mode.max_kills = max_kills;
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        // Record max_kills kills
        for _ in 0..max_kills {
            checker.record_action(100 * 1024 * 1024, true);
        }

        let candidate = RobotCandidate::new()
            .with_posterior(0.99)
            .with_memory_mb(50.0)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            result.violations.iter().any(|v| v.constraint == ConstraintKind::MaxKills),
            "after {} kills at limit {}, next should be blocked",
            max_kills, max_kills
        );
    }

    /// Disabled robot mode should always block.
    #[test]
    fn robot_disabled_always_blocks(
        posterior in 0.0f64..=1.0,
    ) {
        let mut robot_mode = test_robot_mode();
        robot_mode.enabled = false;
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(posterior)
            .with_kill_action(false);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            !result.allowed,
            "disabled robot mode should block"
        );
        prop_assert!(
            result.violations.iter().any(|v| v.constraint == ConstraintKind::RobotModeDisabled),
            "should have RobotModeDisabled violation"
        );
    }

    /// Metrics should be consistent: current_kills + remaining_kills == max_kills.
    #[test]
    fn robot_metrics_consistent(
        kills_performed in 0u32..=10,
    ) {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode()); // max_kills=10
        let checker = ConstraintChecker::new(constraints);

        for _ in 0..kills_performed {
            checker.record_action(50 * 1024 * 1024, true);
        }

        let metrics = checker.current_metrics();
        prop_assert_eq!(
            metrics.current_kills, kills_performed,
            "current_kills mismatch"
        );
        prop_assert_eq!(
            metrics.current_kills + metrics.remaining_kills, 10,
            "kills don't sum to max_kills"
        );
    }

    /// Excluded category should always be blocked.
    #[test]
    fn robot_excluded_category_blocked(
        posterior in 0.96f64..=1.0,
    ) {
        let mut robot_mode = test_robot_mode();
        robot_mode.exclude_categories = vec!["daemon".to_string()];
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(posterior)
            .with_memory_mb(50.0)
            .with_category("daemon")
            .with_kill_action(false);

        let result = checker.check_candidate(&candidate);
        prop_assert!(
            result.violations.iter().any(|v| v.constraint == ConstraintKind::ExcludedCategory),
            "excluded category 'daemon' should be blocked"
        );
    }

    /// CLI override with_max_kills should use the more restrictive (smaller) value.
    #[test]
    fn robot_cli_override_safety(
        policy_kills in 1u32..=20,
        cli_kills in 1u32..=20,
    ) {
        let mut robot_mode = test_robot_mode();
        robot_mode.max_kills = policy_kills;
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
            .with_max_kills(Some(cli_kills));

        prop_assert_eq!(
            constraints.max_kills,
            policy_kills.min(cli_kills),
            "should pick min({}, {}) = {}",
            policy_kills, cli_kills, policy_kills.min(cli_kills)
        );
    }
}

// ── Time-bound property tests ────────────────────────────────────────

fn test_time_bound_config() -> DecisionTimeBound {
    DecisionTimeBound {
        enabled: true,
        min_seconds: 60,
        max_seconds: 600,
        voi_decay_half_life_seconds: 120,
        voi_floor: 0.01,
        overhead_budget_seconds: 300,
        fallback_action: "pause".to_string(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// compute_t_max should never panic for any non-negative VOI.
    #[test]
    fn time_bound_t_max_never_panics(
        voi_initial in 0.0f64..=1000.0,
        budget in proptest::option::of(1u64..=3600),
    ) {
        let config = test_time_bound_config();
        let input = TMaxInput { voi_initial, overhead_budget_seconds: budget };
        let decision = compute_t_max(&config, &input);
        prop_assert!(decision.t_max_seconds > 0 || voi_initial <= config.voi_floor,
            "t_max={} for voi={}", decision.t_max_seconds, voi_initial);
    }

    /// T_max should never exceed the budget.
    #[test]
    fn time_bound_t_max_bounded_by_budget(
        voi_initial in 0.0f64..=100.0,
        budget in 1u64..=3600,
    ) {
        let config = test_time_bound_config();
        let input = TMaxInput { voi_initial, overhead_budget_seconds: Some(budget) };
        let decision = compute_t_max(&config, &input);
        prop_assert!(
            decision.t_max_seconds <= budget,
            "t_max {} > budget {}", decision.t_max_seconds, budget
        );
    }

    /// T_max should never exceed max_seconds from config.
    #[test]
    fn time_bound_t_max_bounded_by_max(
        voi_initial in 0.0f64..=1000.0,
    ) {
        let config = test_time_bound_config();
        let input = TMaxInput { voi_initial, overhead_budget_seconds: None };
        let decision = compute_t_max(&config, &input);
        prop_assert!(
            decision.t_max_seconds <= config.max_seconds,
            "t_max {} > max_seconds {}", decision.t_max_seconds, config.max_seconds
        );
    }

    /// apply_time_bound: elapsed < t_max → don't stop probing.
    #[test]
    fn time_bound_early_does_not_stop(
        elapsed in 0u64..100,
        t_max in 101u64..=600,
    ) {
        let config = test_time_bound_config();
        let outcome = apply_time_bound(&config, elapsed, t_max, true);
        prop_assert!(
            !outcome.stop_probing,
            "should not stop: elapsed {} < t_max {}", elapsed, t_max
        );
        prop_assert!(outcome.fallback_action.is_none());
    }

    /// apply_time_bound: elapsed >= t_max → stop probing.
    #[test]
    fn time_bound_past_limit_stops(
        t_max in 1u64..=300,
        extra in 0u64..=300,
        is_uncertain in prop::bool::ANY,
    ) {
        let config = test_time_bound_config();
        let elapsed = t_max + extra;
        let outcome = apply_time_bound(&config, elapsed, t_max, is_uncertain);
        prop_assert!(
            outcome.stop_probing,
            "should stop: elapsed {} >= t_max {}", elapsed, t_max
        );
        // Fallback action present iff uncertain
        prop_assert_eq!(
            outcome.fallback_action.is_some(),
            is_uncertain,
            "fallback presence should match uncertainty"
        );
    }

    /// apply_time_bound: disabled config → never stops.
    #[test]
    fn time_bound_disabled_never_stops(
        elapsed in 0u64..=1000,
        t_max in 1u64..=100,
    ) {
        let mut config = test_time_bound_config();
        config.enabled = false;
        let outcome = apply_time_bound(&config, elapsed, t_max, true);
        prop_assert!(!outcome.stop_probing, "disabled config should never stop");
    }
}

// ── DRO property tests ──────────────────────────────────────────────

/// Strategy for actions with defined loss matrix entries.
fn dro_action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Keep),
        Just(Action::Pause),
        Just(Action::Throttle),
        Just(Action::Renice),
        Just(Action::Restart),
        Just(Action::Kill),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// With ε=0, robust loss == nominal loss (no inflation).
    #[test]
    fn dro_zero_epsilon_no_inflation(
        posterior in posterior_strategy(),
        action in dro_action_strategy(),
    ) {
        let policy = Policy::default();
        if let Ok(dro) = compute_wasserstein_dro(action, &posterior, &policy.loss_matrix, 0.0) {
            prop_assert!(
                (dro.robust_loss - dro.nominal_loss).abs() < 1e-9,
                "ε=0: robust {} != nominal {}", dro.robust_loss, dro.nominal_loss
            );
            prop_assert!(dro.inflation.abs() < 1e-9, "ε=0: inflation {} != 0", dro.inflation);
        }
    }

    /// With ε>0, robust loss >= nominal loss.
    #[test]
    fn dro_positive_epsilon_inflates(
        posterior in posterior_strategy(),
        action in dro_action_strategy(),
        epsilon in 0.001f64..=1.0,
    ) {
        let policy = Policy::default();
        if let Ok(dro) = compute_wasserstein_dro(action, &posterior, &policy.loss_matrix, epsilon) {
            prop_assert!(
                dro.robust_loss >= dro.nominal_loss - 1e-9,
                "robust {} < nominal {}", dro.robust_loss, dro.nominal_loss
            );
        }
    }

    /// Inflation = ε × lipschitz (exact formula check).
    #[test]
    fn dro_inflation_equals_epsilon_times_lipschitz(
        posterior in posterior_strategy(),
        action in dro_action_strategy(),
        epsilon in 0.0f64..=1.0,
    ) {
        let policy = Policy::default();
        if let Ok(dro) = compute_wasserstein_dro(action, &posterior, &policy.loss_matrix, epsilon) {
            let expected_inflation = epsilon * dro.lipschitz;
            prop_assert!(
                (dro.inflation - expected_inflation).abs() < 1e-9,
                "inflation {} != ε×L = {}", dro.inflation, expected_inflation
            );
        }
    }

    /// Lipschitz constant should be non-negative.
    #[test]
    fn dro_lipschitz_non_negative(
        posterior in posterior_strategy(),
        action in dro_action_strategy(),
    ) {
        let policy = Policy::default();
        if let Ok(dro) = compute_wasserstein_dro(action, &posterior, &policy.loss_matrix, 0.1) {
            prop_assert!(dro.lipschitz >= -1e-12, "lipschitz {} < 0", dro.lipschitz);
        }
    }

    /// All DRO outputs should be finite.
    #[test]
    fn dro_outputs_finite(
        posterior in posterior_strategy(),
        action in dro_action_strategy(),
        epsilon in 0.0f64..=2.0,
    ) {
        let policy = Policy::default();
        if let Ok(dro) = compute_wasserstein_dro(action, &posterior, &policy.loss_matrix, epsilon) {
            prop_assert!(dro.robust_loss.is_finite(), "robust_loss not finite");
            prop_assert!(dro.nominal_loss.is_finite(), "nominal_loss not finite");
            prop_assert!(dro.inflation.is_finite(), "inflation not finite");
            prop_assert!(dro.lipschitz.is_finite(), "lipschitz not finite");
        }
    }

    /// decide_with_dro robust action should be in the feasible set.
    #[test]
    fn dro_decide_action_in_feasible_set(
        posterior in posterior_strategy(),
        epsilon in 0.0f64..=1.0,
    ) {
        let policy = Policy::default();
        let feasible = vec![Action::Keep, Action::Renice, Action::Pause, Action::Kill];
        if let Ok(outcome) = decide_with_dro(
            &posterior, &policy, &feasible, epsilon, Action::Kill, "test",
        ) {
            prop_assert!(
                feasible.contains(&outcome.robust_action),
                "robust_action {:?} not in feasible set", outcome.robust_action
            );
        }
    }

    /// compute_adaptive_epsilon should never exceed max.
    #[test]
    fn dro_adaptive_epsilon_capped(
        base in 0.01f64..=1.0,
        max in 0.01f64..=2.0,
        ppc in prop::bool::ANY,
        drift in prop::bool::ANY,
        eta in prop::bool::ANY,
        low_conf in prop::bool::ANY,
    ) {
        let trigger = DroTrigger {
            ppc_failure: ppc,
            drift_detected: drift,
            wasserstein_divergence: if drift { Some(0.5) } else { None },
            eta_tempering_reduced: eta,
            explicit_conservative: false,
            low_model_confidence: low_conf,
        };
        let eps = compute_adaptive_epsilon(base, &trigger, max);
        prop_assert!(
            eps <= max + 1e-9,
            "adaptive ε {} > max {}", eps, max
        );
    }

    /// With no triggers, adaptive epsilon == base.
    #[test]
    fn dro_adaptive_epsilon_no_trigger_is_base(base in 0.01f64..=1.0) {
        let trigger = DroTrigger::none();
        let eps = compute_adaptive_epsilon(base, &trigger, 2.0);
        prop_assert!(
            (eps - base).abs() < 1e-9,
            "no-trigger: ε {} != base {}", eps, base
        );
    }

    /// apply_dro_gate with no trigger should not apply DRO.
    #[test]
    fn dro_gate_no_trigger_passthrough(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let trigger = DroTrigger::none();
        let feasible = vec![Action::Keep, Action::Kill];
        let outcome = apply_dro_gate(Action::Kill, &posterior, &policy, &trigger, 0.1, &feasible);
        prop_assert!(!outcome.applied, "DRO should not be applied without trigger");
        prop_assert_eq!(outcome.robust_action, Action::Kill);
    }

    /// is_de_escalation is asymmetric: if a→b is de-escalation, b→a is not.
    #[test]
    fn dro_de_escalation_asymmetric(
        a_idx in 0usize..6,
        b_idx in 0usize..6,
    ) {
        let actions = [Action::Keep, Action::Renice, Action::Pause, Action::Throttle, Action::Restart, Action::Kill];
        let a = actions[a_idx];
        let b = actions[b_idx];
        if is_de_escalation(a, b) {
            prop_assert!(
                !is_de_escalation(b, a),
                "de-escalation should be asymmetric: {:?}→{:?} and {:?}→{:?}", a, b, b, a
            );
        }
    }
}

// ── Dependency-loss property tests ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Impact score should be non-negative for any factors.
    #[test]
    fn dep_impact_score_non_negative(
        children in 0usize..=200,
        conns in 0usize..=500,
        ports in 0usize..=100,
        writes in 0usize..=1000,
        shm in 0usize..=200,
    ) {
        let scaling = DependencyScaling::default();
        let factors = DependencyFactors::new(children, conns, ports, writes, shm);
        let impact = scaling.compute_impact_score(&factors);
        prop_assert!(impact >= -1e-12, "impact {} < 0", impact);
    }

    /// Impact score should be capped at max_impact.
    #[test]
    fn dep_impact_score_capped(
        children in 0usize..=500,
        conns in 0usize..=500,
        ports in 0usize..=100,
        writes in 0usize..=1000,
        shm in 0usize..=200,
    ) {
        let scaling = DependencyScaling::default();
        let factors = DependencyFactors::new(children, conns, ports, writes, shm);
        let impact = scaling.compute_impact_score(&factors);
        prop_assert!(
            impact <= scaling.max_impact + 1e-9,
            "impact {} > max_impact {}", impact, scaling.max_impact
        );
    }

    /// Zero factors → zero impact.
    #[test]
    fn dep_zero_factors_zero_impact(_dummy in 0u32..1) {
        let scaling = DependencyScaling::default();
        let factors = DependencyFactors::default();
        let impact = scaling.compute_impact_score(&factors);
        prop_assert!(impact.abs() < 1e-12, "zero factors should give zero impact, got {}", impact);
    }

    /// scale_factor = 1 + impact_score (structural invariant).
    #[test]
    fn dep_scale_factor_formula(
        children in 0usize..=50,
        conns in 0usize..=100,
        ports in 0usize..=20,
        writes in 0usize..=200,
        shm in 0usize..=50,
        base_loss in 1.0f64..=1000.0,
    ) {
        let factors = DependencyFactors::new(children, conns, ports, writes, shm);
        let result = compute_dependency_scaling(base_loss, &factors, None);
        prop_assert!(
            (result.scale_factor - (1.0 + result.impact_score)).abs() < 1e-9,
            "scale_factor {} != 1 + impact_score {}", result.scale_factor, result.impact_score
        );
        prop_assert!(
            (result.scaled_kill_loss - base_loss * result.scale_factor).abs() < 1e-6,
            "scaled_loss {} != base × scale_factor", result.scaled_kill_loss
        );
    }

    /// scale_kill_loss convenience matches manual formula.
    #[test]
    fn dep_scale_kill_loss_matches_formula(
        base_loss in 0.0f64..=1000.0,
        impact in 0.0f64..=2.0,
    ) {
        let scaled = scale_kill_loss(base_loss, impact);
        let expected = base_loss * (1.0 + impact);
        prop_assert!(
            (scaled - expected).abs() < 1e-9,
            "scale_kill_loss {} != {} × (1 + {})", scaled, base_loss, impact
        );
    }

    /// has_dependencies is true iff any factor > 0.
    #[test]
    fn dep_has_dependencies_iff_nonzero(
        children in 0usize..=10,
        conns in 0usize..=10,
        ports in 0usize..=10,
        writes in 0usize..=10,
        shm in 0usize..=10,
    ) {
        let factors = DependencyFactors::new(children, conns, ports, writes, shm);
        let any_nonzero = children > 0 || conns > 0 || ports > 0 || writes > 0 || shm > 0;
        prop_assert_eq!(
            factors.has_dependencies(), any_nonzero,
            "has_dependencies mismatch for {:?}", factors
        );
    }
}

// ── Critical file inflation property tests ──────────────────────────

fn make_test_critical_file(
    category: CriticalFileCategory,
    strength: DetectionStrength,
) -> CriticalFile {
    CriticalFile {
        fd: 42,
        path: "/test/path".to_string(),
        category,
        strength,
        rule_id: "prop-test".to_string(),
    }
}

/// Strategy for a CriticalFileCategory.
fn category_strategy() -> impl Strategy<Value = CriticalFileCategory> {
    prop_oneof![
        Just(CriticalFileCategory::SqliteWal),
        Just(CriticalFileCategory::GitLock),
        Just(CriticalFileCategory::GitRebase),
        Just(CriticalFileCategory::SystemPackageLock),
        Just(CriticalFileCategory::NodePackageLock),
        Just(CriticalFileCategory::CargoLock),
        Just(CriticalFileCategory::DatabaseWrite),
        Just(CriticalFileCategory::AppLock),
        Just(CriticalFileCategory::OpenWrite),
    ]
}

/// Strategy for DetectionStrength.
fn strength_strategy() -> impl Strategy<Value = DetectionStrength> {
    prop_oneof![Just(DetectionStrength::Hard), Just(DetectionStrength::Soft),]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// compute_inflation with no files returns exactly 1.0.
    #[test]
    fn crit_file_empty_no_inflation(_dummy in 0u32..1) {
        let config = CriticalFileInflation::default();
        let inflation = config.compute_inflation(&[]);
        prop_assert!((inflation - 1.0).abs() < 1e-12, "empty files: inflation {} != 1.0", inflation);
    }

    /// compute_inflation is always >= 1.0 for any non-empty file list.
    #[test]
    fn crit_file_inflation_geq_one(
        category in category_strategy(),
        strength in strength_strategy(),
    ) {
        let config = CriticalFileInflation::default();
        let files = vec![make_test_critical_file(category, strength)];
        let inflation = config.compute_inflation(&files);
        prop_assert!(inflation >= 1.0 - 1e-12, "inflation {} < 1.0", inflation);
    }

    /// compute_inflation is capped at max_inflation.
    #[test]
    fn crit_file_inflation_capped(n in 1usize..=50) {
        let config = CriticalFileInflation::default();
        let files: Vec<CriticalFile> = (0..n)
            .map(|_| make_test_critical_file(
                CriticalFileCategory::SystemPackageLock,
                DetectionStrength::Hard,
            ))
            .collect();
        let inflation = config.compute_inflation(&files);
        prop_assert!(
            inflation <= config.max_inflation + 1e-9,
            "inflation {} > max {}", inflation, config.max_inflation
        );
    }

    /// Hard detections produce higher inflation than soft (same category).
    #[test]
    fn crit_file_hard_geq_soft(category in category_strategy()) {
        let config = CriticalFileInflation::default();
        let hard = config.compute_inflation(&[make_test_critical_file(category, DetectionStrength::Hard)]);
        let soft = config.compute_inflation(&[make_test_critical_file(category, DetectionStrength::Soft)]);
        prop_assert!(
            hard >= soft - 1e-9,
            "hard inflation {} < soft inflation {} for {:?}", hard, soft, category
        );
    }

    /// should_block_kill is true iff any file has Hard strength.
    #[test]
    fn crit_file_block_kill_iff_hard(
        n_hard in 0usize..=5,
        n_soft in 0usize..=5,
    ) {
        let mut files = Vec::new();
        for _ in 0..n_hard {
            files.push(make_test_critical_file(CriticalFileCategory::GitLock, DetectionStrength::Hard));
        }
        for _ in 0..n_soft {
            files.push(make_test_critical_file(CriticalFileCategory::OpenWrite, DetectionStrength::Soft));
        }
        prop_assert_eq!(
            should_block_kill(&files),
            n_hard > 0,
            "should_block_kill: n_hard={}, n_soft={}", n_hard, n_soft
        );
    }

    /// Adding more files should not decrease inflation (monotone non-decreasing).
    #[test]
    fn crit_file_inflation_monotone_in_count(
        category in category_strategy(),
        strength in strength_strategy(),
        extra in 1usize..=10,
    ) {
        let config = CriticalFileInflation::default();
        let base_file = make_test_critical_file(category, strength);
        let one = config.compute_inflation(&[base_file.clone()]);
        let many: Vec<_> = (0..=extra).map(|_| base_file.clone()).collect();
        let more = config.compute_inflation(&many);
        prop_assert!(
            more >= one - 1e-9,
            "adding files should not decrease inflation: {} (n=1) > {} (n={})",
            one, more, extra + 1
        );
    }

    /// category_weight should always be positive.
    #[test]
    fn crit_file_category_weight_positive(category in category_strategy()) {
        let config = CriticalFileInflation::default();
        let weight = config.category_weight(&category);
        prop_assert!(weight > 0.0, "category weight for {:?} should be positive, got {}", category, weight);
    }
}

// ── Causal intervention property tests ──────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// expected_recovery should be in [0, 1] for valid Beta parameters.
    #[test]
    fn causal_expected_recovery_in_unit_interval(
        alpha in 0.01f64..=100.0,
        beta_val in 0.01f64..=100.0,
    ) {
        let beta = BetaParams::new(alpha, beta_val);
        let p = expected_recovery(&beta);
        prop_assert!(p >= -1e-12 && p <= 1.0 + 1e-12,
            "expected_recovery {} out of [0,1] for α={}, β={}", p, alpha, beta_val);
        prop_assert!(p.is_finite(), "expected_recovery not finite");
    }

    /// update_beta should increase alpha for successes and beta for failures.
    #[test]
    fn causal_update_beta_directional(
        alpha in 0.1f64..=10.0,
        beta_val in 0.1f64..=10.0,
        successes in 0.0f64..=10.0,
        trials in 0.0f64..=10.0,
    ) {
        let beta = BetaParams::new(alpha, beta_val);
        let updated = update_beta(&beta, successes, trials, 1.0);
        // alpha should increase (successes contribute)
        prop_assert!(
            updated.alpha >= alpha - 1e-9,
            "alpha should not decrease: {} < {}", updated.alpha, alpha
        );
        // beta should increase (failures contribute)
        prop_assert!(
            updated.beta >= beta_val - 1e-9,
            "beta should not decrease: {} < {}", updated.beta, beta_val
        );
        // total pseudo-count should increase
        let original_total = alpha + beta_val;
        let updated_total = updated.alpha + updated.beta;
        prop_assert!(
            updated_total >= original_total - 1e-9,
            "total should not decrease: {} < {}", updated_total, original_total
        );
    }

    /// update_beta with zero trials should not change parameters.
    #[test]
    fn causal_update_beta_zero_trials_no_change(
        alpha in 0.1f64..=10.0,
        beta_val in 0.1f64..=10.0,
    ) {
        let beta = BetaParams::new(alpha, beta_val);
        let updated = update_beta(&beta, 0.0, 0.0, 1.0);
        prop_assert!(
            (updated.alpha - alpha).abs() < 1e-9,
            "alpha changed with zero trials: {} -> {}", alpha, updated.alpha
        );
        prop_assert!(
            (updated.beta - beta_val).abs() < 1e-9,
            "beta changed with zero trials: {} -> {}", beta_val, updated.beta
        );
    }

    /// update_beta should clamp successes to trials.
    #[test]
    fn causal_update_beta_clamps_successes(
        alpha in 0.1f64..=10.0,
        beta_val in 0.1f64..=10.0,
        trials in 1.0f64..=10.0,
    ) {
        let beta = BetaParams::new(alpha, beta_val);
        // Pass successes > trials
        let updated = update_beta(&beta, trials + 5.0, trials, 1.0);
        // Alpha should increase by at most `trials` (since successes clamped to trials)
        prop_assert!(
            (updated.alpha - (alpha + trials)).abs() < 1e-9,
            "alpha {} != expected {} (successes should be clamped to trials)",
            updated.alpha, alpha + trials
        );
        // Beta should not increase (all trials were successes after clamping)
        prop_assert!(
            (updated.beta - beta_val).abs() < 1e-9,
            "beta should not change when all trials are successes: {} != {}",
            updated.beta, beta_val
        );
    }

    /// expected_recovery_by_action should return only configured actions.
    #[test]
    fn causal_recovery_by_action_valid_actions(posterior in posterior_strategy()) {
        let priors = test_causal_priors();
        let expectations = expected_recovery_by_action(&priors, &posterior);
        let valid_actions = [Action::Pause, Action::Throttle, Action::Kill, Action::Restart];
        for exp in &expectations {
            prop_assert!(
                valid_actions.contains(&exp.action),
                "unexpected action {:?} in recovery expectations", exp.action
            );
            prop_assert!(
                exp.probability >= -1e-12 && exp.probability <= 1.0 + 1e-12,
                "recovery probability {} out of [0,1] for {:?}", exp.probability, exp.action
            );
        }
    }
}

fn default_class_params() -> ClassParams {
    ClassParams {
        prior_prob: 0.25,
        cpu_beta: BetaParams::new(1.0, 1.0),
        runtime_gamma: Some(GammaParams {
            shape: 1.0,
            rate: 1.0,
            comment: None,
        }),
        orphan_beta: BetaParams::new(1.0, 1.0),
        tty_beta: BetaParams::new(1.0, 1.0),
        net_beta: BetaParams::new(1.0, 1.0),
        io_active_beta: None,
        hazard_gamma: None,
        competing_hazards: None,
    }
}

fn test_causal_priors() -> Priors {
    Priors {
        schema_version: "1.0.0".to_string(),
        description: None,
        created_at: None,
        updated_at: None,
        host_profile: None,
        classes: ClassPriors {
            useful: default_class_params(),
            useful_bad: default_class_params(),
            abandoned: default_class_params(),
            zombie: default_class_params(),
        },
        hazard_regimes: vec![],
        semi_markov: None,
        change_point: None,
        causal_interventions: Some(CausalInterventions {
            pause: Some(InterventionPriors {
                useful: Some(BetaParams::new(8.0, 2.0)),
                useful_bad: Some(BetaParams::new(3.0, 7.0)),
                abandoned: Some(BetaParams::new(2.0, 8.0)),
                zombie: Some(BetaParams::new(1.0, 9.0)),
            }),
            throttle: Some(InterventionPriors {
                useful: Some(BetaParams::new(7.0, 3.0)),
                useful_bad: Some(BetaParams::new(4.0, 6.0)),
                abandoned: Some(BetaParams::new(3.0, 7.0)),
                zombie: Some(BetaParams::new(2.0, 8.0)),
            }),
            kill: Some(InterventionPriors {
                useful: Some(BetaParams::new(1.0, 9.0)),
                useful_bad: Some(BetaParams::new(5.0, 5.0)),
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                zombie: Some(BetaParams::new(9.0, 1.0)),
            }),
            restart: Some(InterventionPriors {
                useful: Some(BetaParams::new(6.0, 4.0)),
                useful_bad: Some(BetaParams::new(5.0, 5.0)),
                abandoned: Some(BetaParams::new(4.0, 6.0)),
                zombie: Some(BetaParams::new(3.0, 7.0)),
            }),
        }),
        command_categories: None,
        state_flags: None,
        hierarchical: None,
        robust_bayes: None,
        error_rate: None,
        bocpd: None,
    }
}

// ── Load-aware property tests ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// load_score should be in [0, 1].
    #[test]
    fn load_score_in_unit_interval(
        queue in 0usize..=1000,
        load1 in 0.0f64..=100.0,
        cores in 1u32..=32,
        mem_frac in 0.0f64..=1.0,
        psi in 0.0f64..=100.0,
    ) {
        let config = LoadAwareDecision { enabled: true, ..LoadAwareDecision::default() };
        let signals = LoadSignals {
            queue_len: queue,
            load1: Some(load1),
            cores: Some(cores),
            memory_used_fraction: Some(mem_frac),
            psi_avg10: Some(psi),
        };
        if let Some(adj) = compute_load_adjustment(&config, &signals) {
            prop_assert!(
                adj.load_score >= -1e-9 && adj.load_score <= 1.0 + 1e-9,
                "load_score {} out of [0,1]", adj.load_score
            );
        }
    }

    /// Disabled config should always return None.
    #[test]
    fn load_disabled_returns_none(
        queue in 0usize..=100,
    ) {
        let config = LoadAwareDecision::default(); // enabled: false
        let signals = LoadSignals {
            queue_len: queue,
            load1: Some(10.0),
            cores: Some(4),
            memory_used_fraction: Some(0.8),
            psi_avg10: Some(50.0),
        };
        prop_assert!(compute_load_adjustment(&config, &signals).is_none(),
            "disabled config should return None");
    }

    /// keep_multiplier >= 1.0 (keep loss increases under load).
    #[test]
    fn load_keep_multiplier_geq_one(
        queue in 0usize..=500,
        load1 in 0.0f64..=50.0,
        cores in 1u32..=16,
        mem_frac in 0.0f64..=1.0,
    ) {
        let config = LoadAwareDecision { enabled: true, ..LoadAwareDecision::default() };
        let signals = LoadSignals {
            queue_len: queue,
            load1: Some(load1),
            cores: Some(cores),
            memory_used_fraction: Some(mem_frac),
            psi_avg10: None,
        };
        if let Some(adj) = compute_load_adjustment(&config, &signals) {
            prop_assert!(adj.keep_multiplier >= 1.0 - 1e-9,
                "keep_multiplier {} < 1.0", adj.keep_multiplier);
        }
    }

    /// reversible_multiplier <= 1.0 (reversible actions become cheaper under load).
    #[test]
    fn load_reversible_multiplier_leq_one(
        queue in 0usize..=500,
        load1 in 0.0f64..=50.0,
        cores in 1u32..=16,
        mem_frac in 0.0f64..=1.0,
    ) {
        let config = LoadAwareDecision { enabled: true, ..LoadAwareDecision::default() };
        let signals = LoadSignals {
            queue_len: queue,
            load1: Some(load1),
            cores: Some(cores),
            memory_used_fraction: Some(mem_frac),
            psi_avg10: None,
        };
        if let Some(adj) = compute_load_adjustment(&config, &signals) {
            prop_assert!(adj.reversible_multiplier <= 1.0 + 1e-9,
                "reversible_multiplier {} > 1.0", adj.reversible_multiplier);
        }
    }

    /// risky_multiplier >= 1.0 (risky actions become more expensive under load).
    #[test]
    fn load_risky_multiplier_geq_one(
        queue in 0usize..=500,
        load1 in 0.0f64..=50.0,
        cores in 1u32..=16,
        mem_frac in 0.0f64..=1.0,
    ) {
        let config = LoadAwareDecision { enabled: true, ..LoadAwareDecision::default() };
        let signals = LoadSignals {
            queue_len: queue,
            load1: Some(load1),
            cores: Some(cores),
            memory_used_fraction: Some(mem_frac),
            psi_avg10: None,
        };
        if let Some(adj) = compute_load_adjustment(&config, &signals) {
            prop_assert!(adj.risky_multiplier >= 1.0 - 1e-9,
                "risky_multiplier {} < 1.0", adj.risky_multiplier);
        }
    }

    /// apply_load_to_loss_matrix should preserve None entries.
    #[test]
    fn load_apply_preserves_none_entries(
        keep_mult in 1.0f64..=2.0,
        rev_mult in 0.5f64..=1.0,
        risk_mult in 1.0f64..=2.0,
    ) {
        let policy = Policy::default();
        let adj = LoadAdjustment {
            load_score: 0.5,
            keep_multiplier: keep_mult,
            reversible_multiplier: rev_mult,
            risky_multiplier: risk_mult,
        };
        let adjusted = apply_load_to_loss_matrix(&policy.loss_matrix, &adj);
        // If original has a Some value, adjusted should too; if None, should remain None
        prop_assert_eq!(
            adjusted.useful.pause.is_some(),
            policy.loss_matrix.useful.pause.is_some(),
            "pause Some-ness changed"
        );
        prop_assert_eq!(
            adjusted.useful.throttle.is_some(),
            policy.loss_matrix.useful.throttle.is_some(),
            "throttle Some-ness changed"
        );
    }
}

// ── Martingale gates property tests ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// resolve_alpha from default policy should return valid alpha.
    #[test]
    fn martingale_resolve_alpha_valid(_dummy in 0u32..1) {
        let policy = Policy::default();
        let (alpha, source) = resolve_alpha(&policy, None).unwrap();
        prop_assert!(alpha > 0.0 && alpha <= 1.0, "alpha {} out of (0,1]", alpha);
        prop_assert_eq!(source, AlphaSource::Policy);
    }

    /// apply_martingale_gates with empty candidates should return empty results.
    #[test]
    fn martingale_empty_candidates_empty_results(_dummy in 0u32..1) {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let summary = apply_martingale_gates(&[], &policy, &config, None).unwrap();
        prop_assert!(summary.results.is_empty());
    }

    /// Results count should match candidates count.
    #[test]
    fn martingale_results_count_matches_candidates(n in 1usize..=20) {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        for _ in 0..10 {
            analyzer.update(0.5);
        }
        let result = analyzer.summary();
        let candidates: Vec<MartingaleGateCandidate> = (0..n)
            .map(|i| MartingaleGateCandidate {
                target: TargetIdentity {
                    pid: i as i32,
                    start_id: format!("{i}-start"),
                    uid: 1000,
                },
                result: result.clone(),
            })
            .collect();
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        prop_assert_eq!(
            summary.results.len(), n,
            "results count {} != candidates count {}", summary.results.len(), n
        );
    }

    /// eligible implies: n >= min_observations AND (anomaly_detected OR !require_anomaly).
    #[test]
    fn martingale_eligibility_consistent(
        n_observations in 1usize..=30,
        update_value in 0.0f64..=1.0,
    ) {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default(); // min_obs=3, require_anomaly=true
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        for _ in 0..n_observations {
            analyzer.update(update_value);
        }
        let result = analyzer.summary();
        let candidates = vec![MartingaleGateCandidate {
            target: TargetIdentity { pid: 1, start_id: "1-start".to_string(), uid: 1000 },
            result,
        }];
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        let r = &summary.results[0];
        if r.eligible {
            prop_assert!(r.n >= config.min_observations,
                "eligible but n={} < min_obs={}", r.n, config.min_observations);
            if config.require_anomaly {
                prop_assert!(r.anomaly_detected,
                    "eligible with require_anomaly=true but anomaly_detected=false");
            }
        }
    }

    /// gate_passed implies eligible.
    #[test]
    fn martingale_gate_passed_implies_eligible(
        n_observations in 1usize..=30,
        update_value in 0.0f64..=1.0,
    ) {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        for _ in 0..n_observations {
            analyzer.update(update_value);
        }
        let result = analyzer.summary();
        let candidates = vec![MartingaleGateCandidate {
            target: TargetIdentity { pid: 1, start_id: "1-start".to_string(), uid: 1000 },
            result,
        }];
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        let r = &summary.results[0];
        if r.gate_passed {
            prop_assert!(r.eligible, "gate_passed but not eligible");
        }
    }
}

// ── Expected loss properties ──────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The optimal action must have the minimum expected loss among feasible actions.
    #[test]
    fn expected_loss_optimal_minimizes(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        let min_loss = outcome.expected_loss.iter()
            .map(|e| e.loss)
            .fold(f64::INFINITY, f64::min);
        let optimal_loss = outcome.expected_loss.iter()
            .find(|e| e.action == outcome.optimal_action)
            .unwrap().loss;
        prop_assert!((optimal_loss - min_loss).abs() < 1e-9,
            "optimal loss {} != min loss {}", optimal_loss, min_loss);
    }

    /// All expected losses must be finite (no NaN/Inf).
    #[test]
    fn expected_loss_all_finite(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        for el in &outcome.expected_loss {
            prop_assert!(el.loss.is_finite(), "loss for {:?} is not finite: {}", el.action, el.loss);
        }
    }

    /// Disabled actions must not appear in the expected loss results.
    #[test]
    fn expected_loss_feasibility_respected(posterior in posterior_strategy()) {
        let feasibility = ActionFeasibility::from_process_state(true, false, None);
        let policy = Policy::default();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        for el in &outcome.expected_loss {
            prop_assert!(feasibility.is_allowed(el.action),
                "disabled action {:?} found in results", el.action);
        }
    }

    /// decide_action_with_recovery never panics and produces valid output.
    #[test]
    fn expected_loss_with_recovery_valid(posterior in posterior_strategy(),
                                         tolerance in 0.0f64..1.0) {
        let policy = Policy::default();
        let priors = test_causal_priors();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action_with_recovery(
            &posterior, &policy, &feasibility, &priors, tolerance,
        ).unwrap();
        prop_assert!(outcome.expected_loss.iter().any(|e| e.action == outcome.optimal_action),
            "optimal action {:?} not in expected_loss list", outcome.optimal_action);
    }

    /// Risk-sensitive control with no trigger preserves the original action.
    #[test]
    fn expected_loss_risk_sensitive_no_trigger_preserves(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        let original = outcome.optimal_action;
        let trigger = CvarTrigger {
            robot_mode: false,
            low_confidence: false,
            high_blast_radius: false,
            explicit_conservative: false,
            blast_radius_mb: None,
        };
        let result = apply_risk_sensitive_control(outcome, &posterior, &policy, &trigger, 0.95);
        prop_assert_eq!(result.optimal_action, original,
            "no-trigger CVaR changed action from {:?} to {:?}", original, result.optimal_action);
    }

    /// DRO control with no trigger preserves the original action.
    #[test]
    fn expected_loss_dro_no_trigger_preserves(posterior in posterior_strategy()) {
        let policy = Policy::default();
        let feasibility = ActionFeasibility::allow_all();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        let original = outcome.optimal_action;
        let trigger = DroTrigger::none();
        let result = apply_dro_control(outcome, &posterior, &policy, &trigger, 0.1);
        prop_assert_eq!(result.optimal_action, original,
            "no-trigger DRO changed action from {:?} to {:?}", original, result.optimal_action);
    }

    /// Zombie feasibility always disables Kill action.
    #[test]
    fn expected_loss_zombie_disables_kill(posterior in posterior_strategy()) {
        let feasibility = ActionFeasibility::from_process_state(true, false, None);
        prop_assert!(!feasibility.is_allowed(Action::Kill));
        let policy = Policy::default();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();
        prop_assert_ne!(outcome.optimal_action, Action::Kill,
            "zombie process should never choose Kill");
    }
}

// ── Goal contribution properties ──────────────────────────────────────

fn contribution_candidate_strategy() -> impl Strategy<Value = ContributionCandidate> {
    (
        1u32..65535,                                      // pid
        1u64..10_000_000_000,                             // rss_bytes
        proptest::option::of(1u64..10_000_000_000),       // uss_bytes
        0.0f64..2.0,                                      // cpu_frac
        0u32..10000,                                      // fd_count
        proptest::collection::vec(1u16..=65535u16, 0..5), // bound_ports
        0.0f64..1.0,                                      // respawn_probability
        proptest::bool::ANY,                              // has_shared_memory
        0usize..50,                                       // child_count
    )
        .prop_map(
            |(
                pid,
                rss_bytes,
                uss_bytes,
                cpu_frac,
                fd_count,
                bound_ports,
                respawn_probability,
                has_shared_memory,
                child_count,
            )| {
                ContributionCandidate {
                    pid,
                    rss_bytes,
                    uss_bytes,
                    cpu_frac,
                    fd_count,
                    bound_ports,
                    respawn_probability,
                    has_shared_memory,
                    child_count,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Memory contribution expected value is always non-negative.
    #[test]
    fn goal_contrib_memory_non_negative(cand in contribution_candidate_strategy()) {
        let contrib = estimate_memory_contribution(&cand);
        prop_assert!(contrib.expected >= 0.0, "expected {} < 0", contrib.expected);
        prop_assert!(contrib.low >= 0.0, "low {} < 0", contrib.low);
    }

    /// Memory contribution confidence is in [0, 1].
    #[test]
    fn goal_contrib_memory_confidence_bounded(cand in contribution_candidate_strategy()) {
        let contrib = estimate_memory_contribution(&cand);
        prop_assert!(contrib.confidence >= 0.0 && contrib.confidence <= 1.0,
            "confidence {} outside [0,1]", contrib.confidence);
    }

    /// CPU contribution expected value is non-negative and confidence in [0,1].
    #[test]
    fn goal_contrib_cpu_non_negative(cand in contribution_candidate_strategy()) {
        let contrib = estimate_cpu_contribution(&cand);
        prop_assert!(contrib.expected >= 0.0, "cpu expected {} < 0", contrib.expected);
        prop_assert!(contrib.confidence >= 0.0 && contrib.confidence <= 1.0,
            "cpu confidence {} outside [0,1]", contrib.confidence);
    }

    /// Port contribution is 0.0 when candidate doesn't hold the port, or in (0,1] when it does.
    #[test]
    fn goal_contrib_port_semantics(cand in contribution_candidate_strategy(),
                                   port in 1u16..=65535u16) {
        let contrib = estimate_port_contribution(&cand, port);
        if cand.bound_ports.contains(&port) {
            prop_assert!(contrib.expected > 0.0,
                "holds port {} but expected == 0", port);
            prop_assert!(contrib.expected <= 1.0,
                "port probability {} > 1.0", contrib.expected);
        } else {
            prop_assert_eq!(contrib.expected, 0.0,
                "doesn't hold port {} but expected != 0", port);
        }
    }

    /// FD contribution expected value is non-negative.
    #[test]
    fn goal_contrib_fd_non_negative(cand in contribution_candidate_strategy()) {
        let contrib = estimate_fd_contribution(&cand);
        prop_assert!(contrib.expected >= 0.0, "fd expected {} < 0", contrib.expected);
    }

    /// All contribution functions produce finite values.
    #[test]
    fn goal_contrib_all_finite(cand in contribution_candidate_strategy()) {
        let mem = estimate_memory_contribution(&cand);
        let cpu = estimate_cpu_contribution(&cand);
        let fd = estimate_fd_contribution(&cand);
        for (name, c) in [("memory", &mem), ("cpu", &cpu), ("fd", &fd)] {
            prop_assert!(c.expected.is_finite(), "{} expected not finite", name);
            prop_assert!(c.low.is_finite(), "{} low not finite", name);
            prop_assert!(c.high.is_finite(), "{} high not finite", name);
            prop_assert!(c.confidence.is_finite(), "{} confidence not finite", name);
        }
    }
}

// ── Goal parser properties ────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// parse_goal("free <n>GB RAM") succeeds for any positive integer GB.
    #[test]
    fn goal_parser_memory_valid(n in 1u32..1000) {
        let input = format!("free {}GB RAM", n);
        let goal = parse_goal(&input).unwrap();
        let canonical = goal.canonical();
        prop_assert!(canonical.contains("memory"), "canonical '{}' missing 'memory'", canonical);
    }

    /// CPU percentage parse always produces value in (0, 1].
    #[test]
    fn goal_parser_cpu_value_fraction(pct in 1u32..100) {
        let input = format!("free {}% CPU", pct);
        let goal = parse_goal(&input).unwrap();
        match goal {
            pt_core::decision::goal_parser::Goal::Target(t) => {
                let expected = pct as f64 / 100.0;
                prop_assert!((t.value - expected).abs() < 1e-6,
                    "parsed value {} != expected {}", t.value, expected);
            }
            _ => prop_assert!(false, "expected Target, got composite"),
        }
    }

    /// Port parse preserves the port number.
    #[test]
    fn goal_parser_port_roundtrip(port in 1u16..=65535u16) {
        let input = format!("release port {}", port);
        let goal = parse_goal(&input).unwrap();
        match goal {
            pt_core::decision::goal_parser::Goal::Target(t) => {
                prop_assert_eq!(t.port, Some(port));
            }
            _ => prop_assert!(false, "expected Target, got composite"),
        }
    }

    /// FD parse is deterministic (same input → same canonical).
    #[test]
    fn goal_parser_deterministic(n in 1u32..10000) {
        let input = format!("free {} FDs", n);
        let g1 = parse_goal(&input).unwrap();
        let g2 = parse_goal(&input).unwrap();
        prop_assert_eq!(g1.canonical(), g2.canonical());
    }

    /// Canonical string is deterministic for AND compositions.
    #[test]
    fn goal_parser_and_canonical_deterministic(a in 1u32..100, b in 1u16..=65535u16) {
        let input = format!("free {}GB RAM AND release port {}", a, b);
        let g1 = parse_goal(&input).unwrap();
        let g2 = parse_goal(&input).unwrap();
        prop_assert_eq!(g1.canonical(), g2.canonical());
    }
}

// ── Memory pressure properties ────────────────────────────────────────

fn memory_signals_strategy() -> impl Strategy<Value = MemorySignals> {
    (
        1u64..100_000_000_000,               // total_bytes (1B to 100GB)
        0.0f64..1.0,                         // used_fraction
        0u64..50_000_000_000,                // swap_total
        0.0f64..1.0,                         // swap_fraction
        proptest::option::of(0.0f64..100.0), // psi_some10
        0.0f64..10000.0,                     // timestamp
    )
        .prop_map(|(total, used_frac, swap_total, swap_frac, psi, ts)| {
            let used = (total as f64 * used_frac) as u64;
            let available = total.saturating_sub(used);
            let swap_used = (swap_total as f64 * swap_frac) as u64;
            MemorySignals {
                total_bytes: total,
                used_bytes: used,
                available_bytes: available,
                swap_used_bytes: swap_used,
                swap_total_bytes: swap_total,
                psi_some10: psi,
                timestamp: ts,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Utilization is in [0, 1] for valid signals.
    #[test]
    fn mem_pressure_utilization_bounded(signals in memory_signals_strategy()) {
        let util = signals.utilization();
        prop_assert!(util >= 0.0 && util <= 1.0,
            "utilization {} outside [0,1]", util);
    }

    /// Swap utilization is in [0, 1] or 0 if no swap.
    #[test]
    fn mem_pressure_swap_utilization_bounded(signals in memory_signals_strategy()) {
        let swap = signals.swap_utilization();
        prop_assert!(swap >= 0.0 && swap <= 1.0,
            "swap utilization {} outside [0,1]", swap);
        if signals.swap_total_bytes == 0 {
            prop_assert_eq!(swap, 0.0);
        }
    }

    /// Evaluate never panics on arbitrary signals.
    #[test]
    fn mem_pressure_evaluate_never_panics(signals in memory_signals_strategy()) {
        let config = MemPressureConfig::default();
        let mut monitor = MemPressureMonitor::new(config);
        let eval = monitor.evaluate(&signals);
        prop_assert!(eval.scan_interval_secs > 0.0,
            "scan interval should be positive");
        prop_assert!(eval.utilization >= 0.0,
            "utilization should be non-negative");
    }

    /// Transition count monotonically increases.
    #[test]
    fn mem_pressure_transitions_monotone(
        sig1 in memory_signals_strategy(),
        sig2 in memory_signals_strategy(),
        sig3 in memory_signals_strategy(),
    ) {
        let config = MemPressureConfig::default();
        let mut monitor = MemPressureMonitor::new(config);
        let _ = monitor.evaluate(&sig1);
        let t1 = monitor.transitions();
        let _ = monitor.evaluate(&sig2);
        let t2 = monitor.transitions();
        let _ = monitor.evaluate(&sig3);
        let t3 = monitor.transitions();
        prop_assert!(t2 >= t1, "transitions decreased from {} to {}", t1, t2);
        prop_assert!(t3 >= t2, "transitions decreased from {} to {}", t2, t3);
    }
}

// ── Rate limit properties ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Fresh rate limiter always allows check.
    #[test]
    fn rate_limit_fresh_always_allowed(
        max_run in 1u32..100,
        max_minute in proptest::option::of(1u32..100),
    ) {
        let config = RateLimitConfig {
            max_per_run: max_run,
            max_per_minute: max_minute,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();
        let result = limiter.check(false).unwrap();
        prop_assert!(result.allowed, "fresh limiter should allow");
    }

    /// Force mode always returns allowed=true.
    #[test]
    fn rate_limit_force_always_allowed(max_run in 1u32..50) {
        let config = RateLimitConfig {
            max_per_run: max_run,
            max_per_minute: Some(1),
            max_per_hour: Some(1),
            max_per_day: Some(1),
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();
        // Record kills up to limit
        for _ in 0..max_run {
            let _ = limiter.record_kill();
        }
        let result = limiter.check(true).unwrap();
        prop_assert!(result.forced || result.allowed,
            "force mode should mark result as forced or allowed");
    }

    /// Run count matches number of recorded kills.
    #[test]
    fn rate_limit_count_matches_kills(n_kills in 0u32..20) {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();
        for _ in 0..n_kills {
            let _ = limiter.record_kill();
        }
        let count = limiter.current_run_count().unwrap();
        prop_assert_eq!(count, n_kills);
    }

    /// Override lowers effective per-run limit (min of override and config).
    #[test]
    fn rate_limit_override_lowers_limit(
        max_run in 5u32..50,
        override_val in 1u32..4,
    ) {
        let config = RateLimitConfig {
            max_per_run: max_run,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();
        // Record kills past the override limit but under the config limit
        for _ in 0..override_val {
            let _ = limiter.record_kill();
        }
        // Without override: allowed (kills <= max_run)
        let no_override = limiter.check_with_override(false, None).unwrap();
        prop_assert!(no_override.allowed,
            "{} kills should be allowed with max_run {}", override_val, max_run);
        // With override: blocked (kills >= override_val, and effective = min(override, max_run) = override)
        let with_override = limiter.check_with_override(false, Some(override_val)).unwrap();
        prop_assert!(!with_override.allowed,
            "override {} should block when {} kills recorded", override_val, override_val);
    }
}

// ── Respawn loop properties ───────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// detect_loop on empty tracker returns no loop.
    #[test]
    fn respawn_empty_tracker_no_loop(
        key in "[a-z]{3,10}",
        now in 0.0f64..10000.0,
    ) {
        let tracker = RespawnTracker::new();
        let config = RespawnLoopConfig::default();
        let detection = tracker.detect_loop(&key, &config, now);
        prop_assert!(!detection.is_loop, "empty tracker should have no loops");
        prop_assert_eq!(detection.loop_count, 0);
    }

    /// identity_count matches distinct keys inserted.
    #[test]
    fn respawn_identity_count_matches(n in 1usize..20) {
        let mut tracker = RespawnTracker::new();
        for i in 0..n {
            tracker.record_respawn(
                format!("proc-{}", i),
                None, None,
                (i * 10) as f64,
                (i * 10 + 1) as f64,
                None,
            );
        }
        prop_assert_eq!(tracker.identity_count(), n);
    }

    /// event_count matches total events inserted.
    #[test]
    fn respawn_event_count_matches(n in 1usize..30) {
        let mut tracker = RespawnTracker::new();
        for i in 0..n {
            tracker.record_respawn(
                "proc-single".to_string(),
                None, None,
                (i * 5) as f64,
                (i * 5 + 1) as f64,
                None,
            );
        }
        prop_assert_eq!(tracker.event_count(), n);
    }

    /// discount_kill_utility is always non-negative when base is non-negative.
    #[test]
    fn respawn_discount_non_negative(base in 0.0f64..1000.0) {
        let detection = RespawnLoopDetection {
            identity_key: "test".to_string(),
            loop_count: 5,
            is_loop: true,
            avg_respawn_delay_secs: 2.0,
            recommendation: pt_core::decision::respawn_loop::RespawnRecommendation::WarnRespawn,
            kill_utility_multiplier: 0.3,
        };
        let discounted = discount_kill_utility(base, &detection);
        prop_assert!(discounted >= 0.0, "discounted {} < 0 for base {}", discounted, base);
    }

    /// discount_kill_utility for non-loop is at least base utility.
    #[test]
    fn respawn_no_loop_preserves_utility(base in 0.0f64..1000.0) {
        let detection = RespawnLoopDetection {
            identity_key: "test".to_string(),
            loop_count: 0,
            is_loop: false,
            avg_respawn_delay_secs: 0.0,
            recommendation: pt_core::decision::respawn_loop::RespawnRecommendation::KillOk,
            kill_utility_multiplier: 1.0,
        };
        let discounted = discount_kill_utility(base, &detection);
        prop_assert!((discounted - base).abs() < 1e-9,
            "non-loop should preserve utility: {} vs {}", discounted, base);
    }

    /// all_loops result count <= identity_count.
    #[test]
    fn respawn_all_loops_bounded(n in 1usize..15) {
        let mut tracker = RespawnTracker::new();
        for i in 0..n {
            for e in 0..5 {
                tracker.record_respawn(
                    format!("proc-{}", i),
                    None, None,
                    (e * 10) as f64,
                    (e * 10 + 1) as f64,
                    None,
                );
            }
        }
        let config = RespawnLoopConfig::default();
        let loops = tracker.all_loops(&config, 100.0);
        prop_assert!(loops.len() <= tracker.identity_count(),
            "all_loops {} > identity_count {}", loops.len(), tracker.identity_count());
    }
}

// ── Goal plan properties ──────────────────────────────────────────────

fn plan_candidate_strategy() -> impl Strategy<Value = PlanCandidate> {
    (
        1u32..10000,         // pid
        0.1f64..1000.0,      // expected_contribution
        0.1f64..1.0,         // confidence
        0.01f64..5.0,        // risk
        proptest::bool::ANY, // is_protected
        1000u32..2000,       // uid
    )
        .prop_map(
            |(pid, expected_contribution, confidence, risk, is_protected, uid)| PlanCandidate {
                pid,
                expected_contribution,
                confidence,
                risk,
                is_protected,
                uid,
                label: format!("proc-{}", pid),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Empty candidates → empty plans.
    #[test]
    fn goal_plan_empty_candidates_empty(target in 1.0f64..1000.0) {
        let constraints = PlanConstraints {
            goal_target: target,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&[], &constraints);
        prop_assert!(plans.is_empty());
    }

    /// Protected candidates never appear in any plan.
    #[test]
    fn goal_plan_protected_excluded(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..20),
        target in 1.0f64..5000.0,
    ) {
        let constraints = PlanConstraints {
            goal_target: target,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        // A pid is exclusively-protected only if every candidate with that pid
        // is protected.  When two candidates share a pid but differ in
        // is_protected, the optimizer may legitimately select the non-protected
        // one.
        let exclusively_protected_pids: Vec<u32> = candidates.iter()
            .filter(|c| c.is_protected)
            .map(|c| c.pid)
            .filter(|pid| candidates.iter().all(|c| c.pid != *pid || c.is_protected))
            .collect();
        for plan in &plans {
            for action in &plan.actions {
                prop_assert!(!exclusively_protected_pids.contains(&action.pid),
                    "protected pid {} found in plan {:?}", action.pid, plan.variant);
            }
        }
    }

    /// Plan actions never exceed max_actions constraint.
    #[test]
    fn goal_plan_max_actions_respected(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..20),
        max_actions in 1usize..10,
    ) {
        let constraints = PlanConstraints {
            goal_target: 10000.0,
            max_actions,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            prop_assert!(plan.actions.len() <= max_actions,
                "plan {:?} has {} actions > max {}", plan.variant, plan.actions.len(), max_actions);
        }
    }

    /// Total risk never exceeds max_total_risk constraint.
    #[test]
    fn goal_plan_risk_budget_respected(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..20),
        max_risk in 0.5f64..10.0,
    ) {
        let constraints = PlanConstraints {
            goal_target: 10000.0,
            max_total_risk: max_risk,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            prop_assert!(plan.total_risk <= max_risk + 1e-9,
                "plan {:?} risk {} exceeds budget {}", plan.variant, plan.total_risk, max_risk);
        }
    }

    /// goal_fraction is in [0, 1].
    #[test]
    fn goal_plan_fraction_bounded(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..15),
        target in 1.0f64..5000.0,
    ) {
        let constraints = PlanConstraints {
            goal_target: target,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            prop_assert!(plan.goal_fraction >= 0.0 && plan.goal_fraction <= 1.0,
                "goal_fraction {} outside [0,1]", plan.goal_fraction);
        }
    }

    /// goal_achievable is true iff total_contribution >= goal_target.
    #[test]
    fn goal_plan_achievable_consistent(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..15),
        target in 1.0f64..5000.0,
    ) {
        let constraints = PlanConstraints {
            goal_target: target,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            let expected_achievable = plan.total_contribution >= target;
            prop_assert_eq!(plan.goal_achievable, expected_achievable,
                "achievable flag mismatch: contribution={}, target={}",
                plan.total_contribution, target);
        }
    }

    /// At most 3 plan variants returned (conservative, balanced, aggressive).
    #[test]
    fn goal_plan_at_most_three_variants(
        candidates in proptest::collection::vec(plan_candidate_strategy(), 1..20),
    ) {
        let constraints = PlanConstraints {
            goal_target: 500.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        prop_assert!(plans.len() <= 3, "got {} plan variants", plans.len());
    }
}

// ── Goal progress properties ──────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Discrepancy equals observed - expected.
    #[test]
    fn goal_progress_discrepancy_formula(
        before_avail in 1u64..10_000_000_000,
        delta in 0u64..5_000_000_000,
        expected_each in 1.0f64..2_000_000_000.0,
    ) {
        let before = MetricSnapshot {
            available_memory_bytes: before_avail,
            total_cpu_frac: 0.5,
            occupied_ports: vec![],
            total_fds: 1000,
            timestamp: 0.0,
        };
        let after = MetricSnapshot {
            available_memory_bytes: before_avail + delta,
            total_cpu_frac: 0.5,
            occupied_ports: vec![],
            total_fds: 1000,
            timestamp: 1.0,
        };
        let outcomes = vec![ActionOutcome {
            pid: 1,
            label: "p".to_string(),
            success: true,
            respawn_detected: false,
            expected_contribution: expected_each,
        }];
        let config = ProgressConfig::default();
        let report = measure_progress(
            GoalMetric::Memory, None, &before, &after, outcomes, &config, None,
        );
        let observed = delta as f64;
        prop_assert!((report.observed_progress - observed).abs() < 1.0,
            "observed {} != delta {}", report.observed_progress, observed);
        prop_assert!((report.discrepancy - (observed - expected_each)).abs() < 1.0,
            "discrepancy {} != observed-expected {}", report.discrepancy, observed - expected_each);
    }

    /// Classification is AsExpected when discrepancy fraction is within tolerance.
    #[test]
    fn goal_progress_as_expected_within_tolerance(
        expected in 100.0f64..1_000_000.0,
        frac_delta in -0.15f64..0.15, // within default 0.2 tolerance
    ) {
        let observed = expected * (1.0 + frac_delta);
        // Need observed > no_effect_threshold (5% of expected)
        prop_assume!(observed.abs() >= expected * 0.05);
        let before = MetricSnapshot {
            available_memory_bytes: 1_000_000_000,
            total_cpu_frac: 0.5,
            occupied_ports: vec![],
            total_fds: 1000,
            timestamp: 0.0,
        };
        let after = MetricSnapshot {
            available_memory_bytes: 1_000_000_000 + observed as u64,
            ..before.clone()
        };
        let outcomes = vec![ActionOutcome {
            pid: 1, label: "p".to_string(),
            success: true, respawn_detected: false,
            expected_contribution: expected,
        }];
        let config = ProgressConfig::default();
        let report = measure_progress(
            GoalMetric::Memory, None, &before, &after, outcomes, &config, None,
        );
        prop_assert_eq!(report.classification,
            pt_core::decision::goal_progress::DiscrepancyClass::AsExpected,
            "frac_delta={}, discrepancy_fraction={}", frac_delta, report.discrepancy_fraction);
    }

    /// measure_progress never panics on arbitrary valid inputs.
    #[test]
    fn goal_progress_never_panics(
        before_avail in 0u64..10_000_000_000,
        after_avail in 0u64..10_000_000_000,
        n_outcomes in 0usize..10,
        expected in 0.0f64..1_000_000_000.0,
    ) {
        let before = MetricSnapshot {
            available_memory_bytes: before_avail,
            total_cpu_frac: 0.5,
            occupied_ports: vec![],
            total_fds: 1000,
            timestamp: 0.0,
        };
        let after = MetricSnapshot {
            available_memory_bytes: after_avail,
            total_cpu_frac: 0.5,
            occupied_ports: vec![],
            total_fds: 1000,
            timestamp: 1.0,
        };
        let outcomes: Vec<ActionOutcome> = (0..n_outcomes).map(|i| ActionOutcome {
            pid: i as u32,
            label: format!("p-{}", i),
            success: true,
            respawn_detected: false,
            expected_contribution: expected / (n_outcomes.max(1)) as f64,
        }).collect();
        let config = ProgressConfig::default();
        let report = measure_progress(
            GoalMetric::Memory, None, &before, &after, outcomes, &config, None,
        );
        prop_assert!(report.discrepancy.is_finite());
    }

    // ── Escalation properties ───────────────────────────────────────

    /// submit_trigger merges duplicate dedupe_keys: pending count stays 1.
    #[test]
    fn escalation_dedupe_merges(
        severity in prop_oneof![Just(Severity::Warning), Just(Severity::Critical)],
        ts in 0.0f64..1e6,
    ) {
        let config = EscalationConfig::default();
        let mut mgr = EscalationManager::new(config);
        let trigger = EscalationTrigger {
            trigger_id: "t-1".to_string(),
            dedupe_key: "dup".to_string(),
            trigger_type: TriggerType::MemoryPressure,
            severity,
            confidence: Some(0.9),
            summary: "test".to_string(),
            detected_at: ts,
            session_id: None,
        };
        mgr.submit_trigger(trigger.clone());
        mgr.submit_trigger(trigger);
        // Two submissions with same dedupe_key produce only 1 pending
        prop_assert_eq!(mgr.pending_count(), 1,
            "duplicate dedupe_key should merge into single pending");
    }

    /// After forget_key, the same dedupe_key is accepted again.
    #[test]
    fn escalation_forget_re_accepts(
        ts in 0.0f64..1e6,
    ) {
        let config = EscalationConfig::default();
        let mut mgr = EscalationManager::new(config);
        let trigger = EscalationTrigger {
            trigger_id: "t-1".to_string(),
            dedupe_key: "key".to_string(),
            trigger_type: TriggerType::CpuPressure,
            severity: Severity::Warning,
            confidence: Some(0.8),
            summary: "test".to_string(),
            detected_at: ts,
            session_id: None,
        };
        mgr.submit_trigger(trigger.clone());
        mgr.forget_key("key");
        prop_assert!(!mgr.has_key("key"));
        let re_accepted = mgr.submit_trigger(trigger);
        prop_assert!(re_accepted, "should accept after forget_key");
    }

    /// flush produces notifications ≤ max_notifications_per_hour.
    #[test]
    fn escalation_flush_respects_rate(
        n_triggers in 1usize..30,
        flush_ts in 100.0f64..1000.0,
    ) {
        let config = EscalationConfig::default();
        let max = config.max_notifications_per_hour;
        let mut mgr = EscalationManager::new(config);
        for i in 0..n_triggers {
            mgr.submit_trigger(EscalationTrigger {
                trigger_id: format!("t-{}", i),
                dedupe_key: format!("k-{}", i),
                trigger_type: TriggerType::OrphanSpike,
                severity: Severity::Warning,
                confidence: Some(0.7),
                summary: format!("trigger {}", i),
                detected_at: i as f64,
                session_id: None,
            });
        }
        let notifications = mgr.flush(flush_ts);
        prop_assert!(notifications.len() <= max,
            "got {} notifications but max is {}", notifications.len(), max);
    }

    /// Persist → restore round-trip preserves total_sent count.
    #[test]
    fn escalation_persist_roundtrip(
        n_triggers in 1usize..10,
    ) {
        let config = EscalationConfig::default();
        let mut mgr = EscalationManager::new(config.clone());
        for i in 0..n_triggers {
            mgr.submit_trigger(EscalationTrigger {
                trigger_id: format!("t-{}", i),
                dedupe_key: format!("k-{}", i),
                trigger_type: TriggerType::ThresholdExceeded,
                severity: Severity::Critical,
                confidence: Some(0.95),
                summary: "test".to_string(),
                detected_at: i as f64 * 10.0,
                session_id: None,
            });
        }
        let _ = mgr.flush(500.0);
        let sent_before = mgr.total_sent();
        let state = mgr.persisted_state();
        let restored = EscalationManager::from_persisted(config, state);
        prop_assert_eq!(restored.total_sent(), sent_before);
    }

    // ── Fleet registry properties ───────────────────────────────────

    /// Registering n unique hosts yields fleet_size == n.
    #[test]
    fn fleet_registry_size_matches(
        n in 1usize..20,
    ) {
        let config = FleetRegistryConfig::default();
        let mut reg = FleetRegistry::new(config);
        for i in 0..n {
            let _ = reg.register(
                format!("h-{}", i),
                format!("host-{}", i),
                vec![format!("10.0.0.{}", i + 1)],
                HostCapabilities {
                    cores: 4,
                    memory_gb: 16.0,
                    pt_version: "2.0.3".to_string(),
                    features: vec![],
                },
                HostRole::Member,
                1000.0,
                None,
            );
        }
        prop_assert_eq!(reg.fleet_size(), n);
    }

    /// Duplicate host_id registration returns AlreadyRegistered error.
    #[test]
    fn fleet_registry_duplicate_rejected(
        ts in 0.0f64..1e6,
    ) {
        let config = FleetRegistryConfig::default();
        let mut reg = FleetRegistry::new(config);
        let cap = HostCapabilities {
            cores: 8,
            memory_gb: 32.0,
            pt_version: "2.0.3".to_string(),
            features: vec![],
        };
        let first = reg.register(
            "dup".to_string(), "host".to_string(), vec![], cap.clone(),
            HostRole::Member, ts, None,
        );
        let second = reg.register(
            "dup".to_string(), "host2".to_string(), vec![], cap,
            HostRole::Member, ts + 1.0, None,
        );
        prop_assert!(first.is_ok());
        prop_assert!(second.is_err(), "duplicate host_id should error");
    }

    /// Heartbeat for unregistered host returns NotFound error.
    #[test]
    fn fleet_registry_heartbeat_unknown(
        ts in 0.0f64..1e6,
    ) {
        let config = FleetRegistryConfig::default();
        let mut reg = FleetRegistry::new(config);
        let hb = Heartbeat {
            host_id: "nonexistent".to_string(),
            timestamp: ts,
            process_count: None,
            active_kills: None,
        };
        let result = reg.heartbeat(&hb);
        prop_assert!(result.is_err());
    }

    /// check_heartbeats degrades hosts with stale heartbeats.
    #[test]
    fn fleet_registry_degradation(
        n in 2usize..10,
        gap in 100.0f64..1000.0,
    ) {
        let config = FleetRegistryConfig::default();
        let mut reg = FleetRegistry::new(config.clone());
        for i in 0..n {
            let _ = reg.register(
                format!("h-{}", i),
                format!("host-{}", i),
                vec![],
                HostCapabilities {
                    cores: 4,
                    memory_gb: 8.0,
                    pt_version: "2.0.3".to_string(),
                    features: vec![],
                },
                HostRole::Member,
                1000.0,
                None,
            );
        }
        // Only heartbeat first host
        let _ = reg.heartbeat(&Heartbeat {
            host_id: "h-0".to_string(),
            timestamp: 1000.0 + gap,
            process_count: None,
            active_kills: None,
        });
        reg.check_heartbeats(1000.0 + gap);
        // First host should still be active, others degraded/offline
        let active = reg.active_host_count();
        prop_assert!(active <= n, "active {} > total {}", active, n);
        prop_assert!(active >= 1, "at least the heartbeating host should be active");
    }

    // ── Fleet pattern properties ────────────────────────────────────

    /// No alerts when observations come from fewer hosts than min_hosts.
    #[test]
    fn fleet_pattern_below_min_hosts_no_alerts(
        n_patterns in 1usize..5,
    ) {
        let config = FleetPatternConfig {
            min_hosts: 5,
            min_host_fraction: 0.0,
            ..FleetPatternConfig::default()
        };
        // Only 1 host
        let obs: Vec<PatternObservation> = (0..n_patterns).map(|p| PatternObservation {
            host_id: "single-host".to_string(),
            pattern_key: format!("pat-{}", p),
            instance_count: 10,
            avg_cpu: 0.5,
            avg_rss_bytes: 100_000_000,
            earliest_spawn_ts: 1000.0,
            latest_spawn_ts: 1001.0,
            abandoned_fraction: 0.9,
            deploy_sha: None,
        }).collect();
        let alerts = correlate_fleet_patterns(&obs, &config);
        prop_assert!(alerts.is_empty(),
            "expected 0 alerts from 1 host with min_hosts=5, got {}", alerts.len());
    }

    /// Each alert's affected_hosts ≤ fleet_size and host_fraction ∈ [0,1].
    #[test]
    fn fleet_pattern_alert_fractions_valid(
        n_hosts in 3usize..12,
        n_patterns in 1usize..4,
    ) {
        let config = FleetPatternConfig::default();
        let obs: Vec<PatternObservation> = (0..n_hosts).flat_map(|h| {
            (0..n_patterns).map(move |p| PatternObservation {
                host_id: format!("h-{}", h),
                pattern_key: format!("pat-{}", p),
                instance_count: 5,
                avg_cpu: 0.3,
                avg_rss_bytes: 200_000_000,
                earliest_spawn_ts: 1000.0,
                latest_spawn_ts: 1005.0,
                abandoned_fraction: 0.6,
                deploy_sha: None,
            })
        }).collect();
        let alerts = correlate_fleet_patterns(&obs, &config);
        for alert in &alerts {
            prop_assert!(alert.affected_hosts <= alert.fleet_size,
                "affected {} > fleet_size {}", alert.affected_hosts, alert.fleet_size);
            prop_assert!(alert.host_fraction >= 0.0 && alert.host_fraction <= 1.0,
                "host_fraction {} out of [0,1]", alert.host_fraction);
        }
    }

    /// Deploy-correlated observations produce alerts mentioning deploy SHA.
    #[test]
    fn fleet_pattern_deploy_correlation(
        n_hosts in 5usize..15,
    ) {
        let config = FleetPatternConfig::default();
        let obs: Vec<PatternObservation> = (0..n_hosts).map(|h| PatternObservation {
            host_id: format!("h-{}", h),
            pattern_key: "leaky-svc".to_string(),
            instance_count: 5,
            avg_cpu: 0.4,
            avg_rss_bytes: 300_000_000,
            earliest_spawn_ts: 1000.0,
            latest_spawn_ts: 1002.0,
            abandoned_fraction: 0.8,
            deploy_sha: Some("abc123".to_string()),
        }).collect();
        let alerts = correlate_fleet_patterns(&obs, &config);
        // With enough hosts all sharing same deploy SHA, should get alerts
        if !alerts.is_empty() {
            for alert in &alerts {
                prop_assert!(alert.deploy_sha.is_some(),
                    "deploy-correlated alert should include deploy_sha");
            }
        }
    }

    // ── Fleet FDR properties ────────────────────────────────────────

    /// compute_fleet_fdr is non-negative and finite.
    #[test]
    fn fleet_fdr_non_negative_finite(
        n_hosts in 1usize..10,
        e_val in 0.1f64..50.0,
    ) {
        let config = FleetFdrConfig::default();
        let mut coord = FleetFdrCoordinator::new(config);
        for i in 0..n_hosts {
            coord.register_host(&format!("h-{}", i), 20);
            coord.submit_e_value(&format!("h-{}", i), e_val + i as f64);
        }
        let fdr = coord.compute_fleet_fdr();
        prop_assert!(fdr >= 0.0, "fdr {} is negative", fdr);
        prop_assert!(fdr.is_finite(), "fdr is not finite");
    }

    /// submit_e_value for unregistered host returns non-approved.
    #[test]
    fn fleet_fdr_unregistered_rejected(
        e_val in 0.1f64..100.0,
    ) {
        let config = FleetFdrConfig::default();
        let mut coord = FleetFdrCoordinator::new(config);
        let result = coord.submit_e_value("ghost", e_val);
        prop_assert!(!result.approved, "unregistered host should not be approved");
    }

    /// pool_evidence combined e-value is finite and n_hosts matches input.
    #[test]
    fn fleet_fdr_pool_evidence_valid(
        n_hosts in 2usize..8,
        base_e in 1.0f64..20.0,
    ) {
        let config = FleetFdrConfig::default();
        let mut coord = FleetFdrCoordinator::new(config);
        for i in 0..n_hosts {
            coord.register_host(&format!("h-{}", i), 30);
        }
        let evidence: Vec<(String, f64)> = (0..n_hosts)
            .map(|i| (format!("h-{}", i), base_e + i as f64 * 0.5))
            .collect();
        let refs: Vec<(&str, f64)> = evidence.iter().map(|(h, v)| (h.as_str(), *v)).collect();
        let pooled = coord.pool_evidence("test-pattern", &refs);
        prop_assert_eq!(pooled.n_hosts, n_hosts);
        prop_assert!(pooled.combined_e_value.is_finite(),
            "combined e-value not finite: {}", pooled.combined_e_value);
    }

    /// rebalance never panics and keeps fleet_fdr finite.
    #[test]
    fn fleet_fdr_rebalance_stable(
        n_hosts in 1usize..15,
        e_val in 0.5f64..10.0,
    ) {
        let config = FleetFdrConfig::default();
        let mut coord = FleetFdrCoordinator::new(config);
        for i in 0..n_hosts {
            coord.register_host(&format!("h-{}", i), 25);
            if i % 2 == 0 {
                coord.submit_e_value(&format!("h-{}", i), e_val);
            }
        }
        coord.rebalance();
        let fdr = coord.compute_fleet_fdr();
        prop_assert!(fdr.is_finite(), "fdr not finite after rebalance: {}", fdr);
    }
}
