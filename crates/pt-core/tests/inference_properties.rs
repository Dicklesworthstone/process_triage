//! Property-based tests for inference engine invariants.

use proptest::prelude::*;
use pt_core::config::priors::Priors;
use pt_core::inference::compound_poisson::{
    BurstEvent, CompoundPoissonAnalyzer, CompoundPoissonConfig,
};
use pt_core::inference::hsmm::{HsmmAnalyzer, HsmmConfig, HsmmState};
use pt_core::inference::robust::{CredalSet, MinimaxConfig, MinimaxGate, RobustConfig, RobustGate};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence};

fn cpu_evidence_strategy() -> impl Strategy<Value = CpuEvidence> {
    prop_oneof![
        (0.0f64..=1.0).prop_map(|occupancy| CpuEvidence::Fraction { occupancy }),
        (1u32..=10_000u32, 0u32..=10_000u32).prop_map(|(n, k)| {
            let k = k.min(n);
            CpuEvidence::Binomial {
                k: k as f64,
                n: n as f64,
                eta: None,
            }
        }),
    ]
}

fn evidence_strategy() -> impl Strategy<Value = Evidence> {
    let cpu = prop::option::of(cpu_evidence_strategy());
    let runtime = prop::option::of(0.1f64..=10_000_000.0f64);
    let orphan = prop::option::of(any::<bool>());
    let tty = prop::option::of(any::<bool>());
    let net = prop::option::of(any::<bool>());
    let io_active = prop::option::of(any::<bool>());

    (cpu, runtime, orphan, tty, net, io_active).prop_map(
        |(cpu, runtime_seconds, orphan, tty, net, io_active)| Evidence {
            cpu,
            runtime_seconds,
            orphan,
            tty,
            net,
            io_active,
            state_flag: None,
            command_category: None,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn posterior_probabilities_are_valid(evidence in evidence_strategy()) {
        let priors = Priors::default();
        let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
        let posterior = result.posterior;

        let sum = posterior.useful
            + posterior.useful_bad
            + posterior.abandoned
            + posterior.zombie;

        prop_assert!(sum.is_finite());
        prop_assert!((sum - 1.0).abs() < 1e-9, "sum={sum}");

        for value in [
            posterior.useful,
            posterior.useful_bad,
            posterior.abandoned,
            posterior.zombie,
        ] {
            prop_assert!(value >= -1e-12, "probability below zero: {value}");
            prop_assert!(value <= 1.0 + 1e-12, "probability above one: {value}");
        }

        let log_posterior = result.log_posterior;
        for value in [
            log_posterior.useful,
            log_posterior.useful_bad,
            log_posterior.abandoned,
            log_posterior.zombie,
        ] {
            prop_assert!(value.is_finite());
            prop_assert!(value <= 1e-9, "log posterior should be <= 0, got {value}");
        }
    }
}

#[test]
fn empty_evidence_equals_prior() {
    let priors = Priors::default();
    let evidence = Evidence::default();
    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");

    let posterior = result.posterior;
    let expected = [
        priors.classes.useful.prior_prob,
        priors.classes.useful_bad.prior_prob,
        priors.classes.abandoned.prior_prob,
        priors.classes.zombie.prior_prob,
    ];

    let actual = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];

    for (idx, (got, exp)) in actual.iter().zip(expected.iter()).enumerate() {
        let delta = (got - exp).abs();
        assert!(
            delta < 1e-9,
            "posterior mismatch at index {idx}: got {got}, expected {exp}"
        );
    }
}

/// Numerical stability test: extreme runtimes should not cause NaN or Inf.
#[test]
fn extreme_runtime_is_stable() {
    let priors = Priors::default();

    // Test very small runtime
    let evidence_small = Evidence {
        runtime_seconds: Some(0.001),
        ..Default::default()
    };
    let result_small = compute_posterior(&priors, &evidence_small).expect("small runtime failed");
    assert!(result_small.posterior.useful.is_finite());
    assert!(result_small.posterior.abandoned.is_finite());

    // Test very large runtime (31 days in seconds)
    let evidence_large = Evidence {
        runtime_seconds: Some(31.0 * 24.0 * 3600.0),
        ..Default::default()
    };
    let result_large = compute_posterior(&priors, &evidence_large).expect("large runtime failed");
    assert!(result_large.posterior.useful.is_finite());
    assert!(result_large.posterior.abandoned.is_finite());

    // Test extreme runtime (1 year)
    let evidence_extreme = Evidence {
        runtime_seconds: Some(365.0 * 24.0 * 3600.0),
        ..Default::default()
    };
    let result_extreme =
        compute_posterior(&priors, &evidence_extreme).expect("extreme runtime failed");
    assert!(result_extreme.posterior.useful.is_finite());
    assert!(result_extreme.posterior.abandoned.is_finite());
}

/// Numerical stability: CPU occupancy boundary values.
#[test]
fn cpu_boundary_values_are_stable() {
    let priors = Priors::default();

    // CPU at 0%
    let evidence_zero = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.0 }),
        ..Default::default()
    };
    let result_zero = compute_posterior(&priors, &evidence_zero).expect("zero CPU failed");
    assert!(result_zero.posterior.useful.is_finite());

    // CPU at 100%
    let evidence_full = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 1.0 }),
        ..Default::default()
    };
    let result_full = compute_posterior(&priors, &evidence_full).expect("full CPU failed");
    assert!(result_full.posterior.useful.is_finite());

    // CPU at tiny epsilon
    let evidence_tiny = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 1e-10 }),
        ..Default::default()
    };
    let result_tiny = compute_posterior(&priors, &evidence_tiny).expect("tiny CPU failed");
    assert!(result_tiny.posterior.useful.is_finite());
}

/// Property: Consistent boolean evidence should shift posterior in expected direction.
#[test]
fn consistent_evidence_increases_confidence() {
    let priors = Priors::default();

    // Orphan = true, tty = false, io_active = false, net = false
    // These all suggest "abandoned"
    let abandoned_evidence = Evidence {
        orphan: Some(true),
        tty: Some(false),
        io_active: Some(false),
        net: Some(false),
        ..Default::default()
    };

    let result =
        compute_posterior(&priors, &abandoned_evidence).expect("abandoned evidence failed");

    // With strong abandoned-like evidence, posterior should favor abandoned over useful
    // (This is a directional test, not exact equality)
    assert!(
        result.posterior.abandoned > priors.classes.abandoned.prior_prob,
        "Abandoned-like evidence should increase abandoned posterior"
    );
}

/// Binomial CPU evidence with extreme values should be stable.
#[test]
fn binomial_cpu_extreme_values_stable() {
    let priors = Priors::default();

    // k = n (100% active)
    let evidence_all_active = Evidence {
        cpu: Some(CpuEvidence::Binomial {
            k: 10000.0,
            n: 10000.0,
            eta: None,
        }),
        ..Default::default()
    };
    let result = compute_posterior(&priors, &evidence_all_active).expect("all active failed");
    assert!(result.posterior.useful.is_finite());

    // k = 0 (0% active)
    let evidence_none_active = Evidence {
        cpu: Some(CpuEvidence::Binomial {
            k: 0.0,
            n: 10000.0,
            eta: None,
        }),
        ..Default::default()
    };
    let result = compute_posterior(&priors, &evidence_none_active).expect("none active failed");
    assert!(result.posterior.useful.is_finite());

    // Very small n (few samples)
    let evidence_few = Evidence {
        cpu: Some(CpuEvidence::Binomial {
            k: 1.0,
            n: 2.0,
            eta: None,
        }),
        ..Default::default()
    };
    let result = compute_posterior(&priors, &evidence_few).expect("few samples failed");
    assert!(result.posterior.useful.is_finite());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Property: posterior computation is deterministic (same input → same output).
    #[test]
    fn posterior_is_deterministic(evidence in evidence_strategy()) {
        let priors = Priors::default();

        let result1 = compute_posterior(&priors, &evidence).expect("first computation failed");
        let result2 = compute_posterior(&priors, &evidence).expect("second computation failed");

        // Posteriors should be exactly equal (deterministic)
        prop_assert_eq!(
            format!("{:?}", result1.posterior),
            format!("{:?}", result2.posterior),
            "posterior computation not deterministic"
        );

        prop_assert_eq!(
            format!("{:?}", result1.log_posterior),
            format!("{:?}", result2.log_posterior),
            "log posterior computation not deterministic"
        );
    }

    /// Property: high CPU occupancy produces valid posteriors (numerical stability).
    /// Note: very high CPU (>99%) may significantly reduce useful probability (model behavior).
    #[test]
    fn high_cpu_produces_valid_posterior(occupancy in 0.8f64..=1.0) {
        let priors = Priors::default();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy }),
            ..Default::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("computation failed");

        // High CPU evidence should produce a valid posterior
        prop_assert!(result.posterior.useful.is_finite());
        prop_assert!(result.posterior.useful > 0.0, "useful probability should be positive");

        // Useful should remain non-zero (model may heavily penalize very high CPU)
        prop_assert!(
            result.posterior.useful > 1e-10,
            "high CPU ({}%) should not eliminate useful class entirely, got {}",
            occupancy * 100.0,
            result.posterior.useful
        );
    }

    // ── HSMM properties ─────────────────────────────────────────────

    /// HSMM state posteriors sum to 1 (±epsilon) after each update.
    #[test]
    fn hsmm_posteriors_sum_to_one(
        n_obs in 1usize..30,
        seed in 0.0f64..100.0,
    ) {
        let config = HsmmConfig::short_lived();
        let features = config.num_features;
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();
        for i in 0..n_obs {
            let obs: Vec<f64> = (0..features)
                .map(|f| 0.1 + ((seed + i as f64) * 0.3 + f as f64 * 0.7) % 2.0)
                .collect();
            let probs = analyzer.update(&obs).unwrap();
            let sum: f64 = probs.iter().sum();
            prop_assert!((sum - 1.0).abs() < 1e-6,
                "posteriors sum to {} instead of 1.0 at step {}", sum, i);
        }
    }

    /// HSMM state_probs are all non-negative.
    #[test]
    fn hsmm_probs_non_negative(
        n_obs in 5usize..20,
    ) {
        let config = HsmmConfig::long_running();
        let features = config.num_features;
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();
        for i in 0..n_obs {
            let obs: Vec<f64> = (0..features)
                .map(|f| 0.5 + (i as f64 * 0.2 + f as f64 * 0.4) % 1.5)
                .collect();
            let _ = analyzer.update(&obs);
        }
        let probs = analyzer.state_probs();
        for (idx, &p) in probs.iter().enumerate() {
            prop_assert!(p >= 0.0, "state {} has negative probability {}", idx, p);
            prop_assert!(p.is_finite(), "state {} has non-finite probability", idx);
        }
    }

    /// HSMM summarize produces finite stability_score and log_likelihood.
    #[test]
    fn hsmm_summarize_finite(
        n_obs in 5usize..25,
    ) {
        let config = HsmmConfig::short_lived();
        let features = config.num_features;
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();
        for i in 0..n_obs {
            let obs: Vec<f64> = (0..features)
                .map(|f| 0.3 + (i as f64 * 0.5 + f as f64) % 2.0)
                .collect();
            let _ = analyzer.update(&obs);
        }
        let result = analyzer.summarize().unwrap();
        prop_assert!(result.stability_score.is_finite(),
            "stability_score not finite: {}", result.stability_score);
        prop_assert!(result.log_likelihood.is_finite(),
            "log_likelihood not finite: {}", result.log_likelihood);
        prop_assert!(result.state_entropy >= 0.0,
            "entropy negative: {}", result.state_entropy);
        prop_assert_eq!(result.num_observations, n_obs);
    }

    /// HSMM batch update produces same number of posteriors as observations.
    #[test]
    fn hsmm_batch_length_matches(
        n_obs in 1usize..30,
    ) {
        let config = HsmmConfig::short_lived();
        let features = config.num_features;
        let observations: Vec<Vec<f64>> = (0..n_obs)
            .map(|i| {
                (0..features)
                    .map(|f| 0.2 + (i as f64 * 0.4 + f as f64 * 0.6) % 1.8)
                    .collect()
            })
            .collect();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();
        let posteriors = analyzer.update_batch(&observations).unwrap();
        prop_assert_eq!(posteriors.len(), n_obs,
            "batch returned {} posteriors for {} observations", posteriors.len(), n_obs);
    }

    /// HsmmState round-trips through index.
    #[test]
    fn hsmm_state_index_roundtrip(
        idx in 0usize..4,
    ) {
        let state = HsmmState::from_index(idx).unwrap();
        prop_assert_eq!(state.index(), idx);
    }

    // ── Robust inference properties ─────────────────────────────────

    /// CredalSet width is non-negative and symmetric sets have expected width.
    #[test]
    fn credal_width_non_negative(
        center in 0.05f64..0.95,
        half in 0.01f64..0.4,
    ) {
        let half = half.min(center).min(1.0 - center); // keep within [0,1]
        let cs = CredalSet::symmetric(center, half);
        prop_assert!(cs.width() >= 0.0, "width {} is negative", cs.width());
        prop_assert!((cs.width() - 2.0 * half).abs() < 1e-10,
            "width {} != 2*half_width {}", cs.width(), 2.0 * half);
        prop_assert!(cs.contains(center), "center not in credal set");
    }

    /// CredalSet intersection is a subset of both operands.
    #[test]
    fn credal_intersection_subset(
        a_center in 0.2f64..0.8,
        a_half in 0.05f64..0.15,
        b_center in 0.2f64..0.8,
        b_half in 0.05f64..0.15,
    ) {
        let a = CredalSet::symmetric(a_center, a_half);
        let b = CredalSet::symmetric(b_center, b_half);
        if let Some(inter) = a.intersect(&b) {
            prop_assert!(inter.lower >= a.lower - 1e-10 && inter.lower >= b.lower - 1e-10);
            prop_assert!(inter.upper <= a.upper + 1e-10 && inter.upper <= b.upper + 1e-10);
            prop_assert!(inter.width() <= a.width() + 1e-10);
            prop_assert!(inter.width() <= b.width() + 1e-10);
        }
    }

    /// CredalSet hull contains both operands.
    #[test]
    fn credal_hull_contains_both(
        a_center in 0.1f64..0.9,
        a_half in 0.02f64..0.1,
        b_center in 0.1f64..0.9,
        b_half in 0.02f64..0.1,
    ) {
        let a = CredalSet::symmetric(a_center, a_half);
        let b = CredalSet::symmetric(b_center, b_half);
        let hull = a.hull(&b);
        prop_assert!(hull.lower <= a.lower + 1e-10);
        prop_assert!(hull.lower <= b.lower + 1e-10);
        prop_assert!(hull.upper >= a.upper - 1e-10);
        prop_assert!(hull.upper >= b.upper - 1e-10);
    }

    /// Tempered posterior mean is in [0,1] and variance is non-negative.
    #[test]
    fn tempered_posterior_bounds(
        n in 5usize..500,
        k_frac in 0.0f64..1.0,
    ) {
        let k = (k_frac * n as f64).floor() as usize;
        let gate = RobustGate::new(RobustConfig::default());
        let tp = gate.tempered_posterior(1.0, 1.0, n, k);
        prop_assert!(tp.mean() >= 0.0 && tp.mean() <= 1.0,
            "mean {} out of [0,1]", tp.mean());
        prop_assert!(tp.variance() >= 0.0,
            "variance {} is negative", tp.variance());
        prop_assert!(tp.variance().is_finite(),
            "variance not finite");
    }

    /// PPC failures decrease eta monotonically.
    #[test]
    fn robust_ppc_decreases_eta(
        n_signals in 1usize..10,
    ) {
        let mut gate = RobustGate::new(RobustConfig::default());
        let mut prev_eta = gate.eta();
        for _ in 0..n_signals {
            gate.signal_ppc_failure();
            let new_eta = gate.eta();
            prop_assert!(new_eta <= prev_eta,
                "eta increased from {} to {} after PPC failure", prev_eta, new_eta);
            prev_eta = new_eta;
        }
    }

    /// Minimax worst-case loss is >= best-case loss.
    #[test]
    fn minimax_worst_geq_best(
        n_classes in 2usize..6,
    ) {
        let config = MinimaxConfig { enabled: true, max_worst_case_loss: 100.0 };
        let gate = MinimaxGate::new(config);
        let loss_row: Vec<f64> = (0..n_classes)
            .map(|i| 1.0 + i as f64 * 2.5)
            .collect();
        let credal_sets: Vec<CredalSet> = (0..n_classes)
            .map(|i| {
                let c = 0.1 + (i as f64 * 0.15) % 0.7;
                CredalSet::symmetric(c, 0.05)
            })
            .collect();
        let result = gate.is_safe(&loss_row, &credal_sets);
        prop_assert!(result.worst_case_loss >= result.best_case_loss - 1e-10,
            "worst {} < best {}", result.worst_case_loss, result.best_case_loss);
    }

    // ── Compound Poisson properties ─────────────────────────────────

    /// Event count matches number of observations.
    #[test]
    fn cp_event_count_matches(
        n in 1usize..100,
    ) {
        let config = CompoundPoissonConfig::default();
        let mut analyzer = CompoundPoissonAnalyzer::new(config);
        for i in 0..n {
            analyzer.observe(BurstEvent::new(i as f64 * 5.0, 10.0 + i as f64, None));
        }
        prop_assert_eq!(analyzer.event_count(), n);
    }

    /// Analyze produces finite burstiness score and non-negative metrics.
    #[test]
    fn cp_analyze_finite(
        n in 5usize..50,
        mag_base in 1.0f64..100.0,
    ) {
        let config = CompoundPoissonConfig::default();
        let mut analyzer = CompoundPoissonAnalyzer::new(config);
        for i in 0..n {
            analyzer.observe(BurstEvent::new(
                i as f64 * 3.0,
                mag_base + (i as f64 * 2.7) % 50.0,
                None,
            ));
        }
        let result = analyzer.analyze();
        prop_assert!(result.burstiness_score.is_finite(),
            "burstiness_score not finite: {}", result.burstiness_score);
        prop_assert!(result.total_mass >= 0.0,
            "total_mass negative: {}", result.total_mass);
        prop_assert!(result.total_events == n);
        prop_assert!(result.kappa_posterior_mean.is_finite());
        prop_assert!(result.beta_posterior_mean.is_finite());
    }

    /// Evidence generation produces finite log Bayes factor.
    #[test]
    fn cp_evidence_finite(
        n in 10usize..40,
        baseline in 0.01f64..5.0,
    ) {
        let config = CompoundPoissonConfig::default();
        let mut analyzer = CompoundPoissonAnalyzer::new(config);
        for i in 0..n {
            analyzer.observe(BurstEvent::new(i as f64 * 4.0, 20.0 + i as f64, None));
        }
        let evidence = analyzer.generate_evidence(baseline);
        prop_assert!(evidence.log_bf_bursty.is_finite(),
            "log_bf_bursty not finite: {}", evidence.log_bf_bursty);
        prop_assert!(evidence.event_rate >= 0.0);
        prop_assert!(evidence.mean_burst_size >= 0.0);
    }

    /// Regime analysis with tagged events produces valid regime stats.
    #[test]
    fn cp_regime_stats_valid(
        n in 10usize..30,
        n_regimes in 2usize..4,
    ) {
        let config = CompoundPoissonConfig {
            enable_regimes: true,
            num_regimes: n_regimes,
            min_events: 3,
            ..CompoundPoissonConfig::default()
        };
        let mut analyzer = CompoundPoissonAnalyzer::new(config);
        for i in 0..n {
            analyzer.observe(BurstEvent::with_regime(
                i as f64 * 2.0,
                15.0 + (i as f64 * 1.5) % 30.0,
                i % n_regimes,
            ));
        }
        let result = analyzer.analyze();
        // Total events across regimes should add up
        let regime_total: usize = result.regime_stats.values().map(|r| r.event_count).sum();
        prop_assert_eq!(regime_total, n,
            "regime event total {} != total events {}", regime_total, n);
    }

}
