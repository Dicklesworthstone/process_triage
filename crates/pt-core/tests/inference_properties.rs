//! Property-based tests for inference engine invariants.

use proptest::prelude::*;
use pt_core::config::priors::Priors;
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
    let result_extreme = compute_posterior(&priors, &evidence_extreme).expect("extreme runtime failed");
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

    let result = compute_posterior(&priors, &abandoned_evidence).expect("abandoned evidence failed");

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

    /// Property: orphan=true + tty=false should favor abandoned classification.
    #[test]
    fn orphan_no_tty_favors_abandoned(_seed in 0u32..1000) {
        let priors = Priors::default();
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            ..Default::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("computation failed");

        // Orphan + no TTY should increase abandoned probability
        prop_assert!(
            result.posterior.abandoned >= priors.classes.abandoned.prior_prob,
            "orphan+no_tty should increase abandoned probability from {} to at least that",
            priors.classes.abandoned.prior_prob
        );
    }
}
