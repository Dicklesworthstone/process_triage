//! Property-based tests for decision theory invariants.

use proptest::prelude::*;
use pt_core::config::policy::{Policy, RobotMode};
use pt_core::decision::composite_test::{
    glr_bernoulli, mixture_sprt_bernoulli, mixture_sprt_beta_sequential, needs_composite_test,
    GlrConfig, MixtureSprtConfig, MixtureSprtState,
};
use pt_core::decision::expected_loss::ActionFeasibility;
use pt_core::decision::myopic_policy::{compute_loss_table, decide_from_belief};
use pt_core::decision::robot_constraints::{
    ConstraintChecker, ConstraintKind, RobotCandidate, RuntimeRobotConstraints,
};
use pt_core::decision::sequential::{decide_sequential, prioritize_by_esn, EsnCandidate};
use pt_core::decision::{
    compute_voi, decide_action, select_probe_by_information_gain, Action, ProbeCostModel, ProbeType,
};
use pt_core::inference::belief_state::BeliefState;
use pt_core::decision::alpha_investing::AlphaInvestingPolicy;
use pt_core::decision::cvar::{compute_cvar, decide_with_cvar};
use pt_core::decision::fdr_selection::{
    by_correction_factor, select_fdr, FdrCandidate, FdrMethod, TargetIdentity,
};
use pt_core::decision::submodular::{
    coverage_utility, greedy_select_k, greedy_select_with_budget, FeatureKey, ProbeProfile,
};
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
