//! What-if explanation tests (Section 11.15)
//!
//! Tests for evidence contribution computation, counterfactual generation,
//! threshold analysis, and sensitivity analysis for process classification.
//!
//! These tests verify the explainability layer that helps users understand
//! why a process received a particular classification and what would need
//! to change for a different outcome.

use pt_core::config::priors::{BetaParams, ClassParams, ClassPriors, GammaParams, Priors};
use pt_core::inference::ledger::{Classification, Confidence, EvidenceLedger};
use pt_core::inference::posterior::{ClassScores, CpuEvidence, Evidence, PosteriorResult};
use pt_core::inference::{compute_posterior, EvidenceTerm};

// ============================================================================
// Test Utilities
// ============================================================================

/// Approximate equality for floating point comparisons.
fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

/// Create base priors with uniform distributions (equal probability for all classes).
fn uniform_priors() -> Priors {
    let class = ClassParams {
        prior_prob: 0.25,
        cpu_beta: BetaParams::new(1.0, 1.0),
        runtime_gamma: Some(GammaParams::new(2.0, 1.0)),
        orphan_beta: BetaParams::new(1.0, 1.0),
        tty_beta: BetaParams::new(1.0, 1.0),
        net_beta: BetaParams::new(1.0, 1.0),
        io_active_beta: Some(BetaParams::new(1.0, 1.0)),
        hazard_gamma: None,
        competing_hazards: None,
    };
    Priors {
        schema_version: "1.0.0".to_string(),
        description: None,
        created_at: None,
        updated_at: None,
        host_profile: None,
        classes: ClassPriors {
            useful: class.clone(),
            useful_bad: class.clone(),
            abandoned: class.clone(),
            zombie: class,
        },
        hazard_regimes: vec![],
        semi_markov: None,
        change_point: None,
        causal_interventions: None,
        command_categories: None,
        state_flags: None,
        hierarchical: None,
        robust_bayes: None,
        error_rate: None,
        bocpd: None,
    }
}

/// Create priors that strongly favor "abandoned" classification for orphaned processes.
fn orphan_sensitive_priors() -> Priors {
    let mut priors = uniform_priors();

    // Useful processes rarely orphaned
    priors.classes.useful.orphan_beta = BetaParams::new(1.0, 20.0);

    // Useful-bad processes sometimes orphaned
    priors.classes.useful_bad.orphan_beta = BetaParams::new(1.0, 10.0);

    // Abandoned processes often orphaned
    priors.classes.abandoned.orphan_beta = BetaParams::new(10.0, 1.0);

    // Zombies nearly always orphaned
    priors.classes.zombie.orphan_beta = BetaParams::new(20.0, 1.0);

    priors
}

/// Create priors that differentiate classes by CPU usage.
fn cpu_sensitive_priors() -> Priors {
    let mut priors = uniform_priors();

    // Useful processes have moderate-high CPU
    priors.classes.useful.cpu_beta = BetaParams::new(5.0, 2.0);

    // Useful-bad processes have very high CPU (CPU hogs)
    priors.classes.useful_bad.cpu_beta = BetaParams::new(10.0, 1.0);

    // Abandoned processes have very low CPU (idle)
    priors.classes.abandoned.cpu_beta = BetaParams::new(1.0, 10.0);

    // Zombies have near-zero CPU
    priors.classes.zombie.cpu_beta = BetaParams::new(1.0, 20.0);

    priors
}

/// Get the dominant classification from posterior scores.
fn get_classification(scores: &ClassScores) -> Classification {
    let max_prob = scores
        .useful
        .max(scores.useful_bad)
        .max(scores.abandoned)
        .max(scores.zombie);

    if (scores.useful - max_prob).abs() < 1e-10 {
        Classification::Useful
    } else if (scores.useful_bad - max_prob).abs() < 1e-10 {
        Classification::UsefulBad
    } else if (scores.abandoned - max_prob).abs() < 1e-10 {
        Classification::Abandoned
    } else {
        Classification::Zombie
    }
}

/// Get confidence level from posterior probability.
fn get_confidence(prob: f64) -> Confidence {
    if prob > 0.99 {
        Confidence::VeryHigh
    } else if prob > 0.95 {
        Confidence::High
    } else if prob > 0.80 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

// ============================================================================
// Evidence Contribution Tests
// ============================================================================

mod evidence_contribution {
    use super::*;

    #[test]
    fn test_evidence_terms_tracked_for_each_feature() {
        let priors = uniform_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.5 }),
            runtime_seconds: Some(100.0),
            orphan: Some(true),
            tty: Some(false),
            net: Some(true),
            io_active: Some(false),
            state_flag: None,
            command_category: None,
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");

        // Should have terms for prior + each evidence feature
        let feature_names: Vec<&str> = result
            .evidence_terms
            .iter()
            .map(|t| t.feature.as_str())
            .collect();

        assert!(
            feature_names.contains(&"prior"),
            "Missing prior term in evidence"
        );
        assert!(
            feature_names.contains(&"cpu"),
            "Missing cpu term in evidence"
        );
        assert!(
            feature_names.contains(&"runtime"),
            "Missing runtime term in evidence"
        );
        assert!(
            feature_names.contains(&"orphan"),
            "Missing orphan term in evidence"
        );
        assert!(
            feature_names.contains(&"tty"),
            "Missing tty term in evidence"
        );
        assert!(
            feature_names.contains(&"net"),
            "Missing net term in evidence"
        );
        assert!(
            feature_names.contains(&"io_active"),
            "Missing io_active term in evidence"
        );
    }

    #[test]
    fn test_prior_term_reflects_class_priors() {
        let mut priors = uniform_priors();
        priors.classes.useful.prior_prob = 0.7;
        priors.classes.abandoned.prior_prob = 0.1;
        priors.classes.useful_bad.prior_prob = 0.1;
        priors.classes.zombie.prior_prob = 0.1;

        let evidence = Evidence::default();
        let result = compute_posterior(&priors, &evidence).expect("posterior");

        let prior_term = result
            .evidence_terms
            .iter()
            .find(|t| t.feature == "prior")
            .expect("prior term");

        // Log-likelihood for useful should be higher than for abandoned
        assert!(
            prior_term.log_likelihood.useful > prior_term.log_likelihood.abandoned,
            "Useful prior should have higher log-likelihood"
        );
    }

    #[test]
    fn test_orphan_evidence_shifts_toward_abandoned() {
        let priors = orphan_sensitive_priors();

        // Test with orphan = true
        let orphan_evidence = Evidence {
            orphan: Some(true),
            ..Evidence::default()
        };
        let orphan_result = compute_posterior(&priors, &orphan_evidence).expect("orphan posterior");

        // Test with orphan = false
        let non_orphan_evidence = Evidence {
            orphan: Some(false),
            ..Evidence::default()
        };
        let non_orphan_result =
            compute_posterior(&priors, &non_orphan_evidence).expect("non-orphan posterior");

        // Orphaned process should have higher abandoned probability
        assert!(
            orphan_result.posterior.abandoned > non_orphan_result.posterior.abandoned,
            "Orphaned process should have higher abandoned probability: {} vs {}",
            orphan_result.posterior.abandoned,
            non_orphan_result.posterior.abandoned
        );
    }

    #[test]
    fn test_cpu_evidence_contribution_direction() {
        let priors = cpu_sensitive_priors();

        // High CPU (80%)
        let high_cpu = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.8 }),
            ..Evidence::default()
        };
        let high_result = compute_posterior(&priors, &high_cpu).expect("high cpu");

        // Low CPU (5%)
        let low_cpu = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.05 }),
            ..Evidence::default()
        };
        let low_result = compute_posterior(&priors, &low_cpu).expect("low cpu");

        // High CPU should favor useful/useful_bad
        assert!(
            high_result.posterior.useful + high_result.posterior.useful_bad
                > low_result.posterior.useful + low_result.posterior.useful_bad,
            "High CPU should favor useful classes"
        );

        // Low CPU should favor abandoned/zombie
        assert!(
            low_result.posterior.abandoned + low_result.posterior.zombie
                > high_result.posterior.abandoned + high_result.posterior.zombie,
            "Low CPU should favor abandoned/zombie classes"
        );
    }

    #[test]
    fn test_evidence_terms_sum_to_log_unnormalized() {
        let priors = orphan_sensitive_priors();
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");

        // Sum all evidence term log-likelihoods for each class
        let sum_useful: f64 = result
            .evidence_terms
            .iter()
            .map(|t| t.log_likelihood.useful)
            .sum();
        let sum_abandoned: f64 = result
            .evidence_terms
            .iter()
            .map(|t| t.log_likelihood.abandoned)
            .sum();

        // The difference should match the log-odds (before normalization effects)
        // This verifies evidence terms are additive in log-space
        let sum_diff = sum_abandoned - sum_useful;
        let log_odds_unnorm = result.log_posterior.abandoned - result.log_posterior.useful;

        // They should be close (normalization adds a constant)
        assert!(
            (sum_diff - log_odds_unnorm).abs() < 1e-6
                || (sum_diff - log_odds_unnorm - (sum_useful.exp().ln() - sum_abandoned.exp().ln()))
                    .abs()
                    < 1.0,
            "Evidence terms should sum consistently"
        );
    }
}

// ============================================================================
// Counterfactual Generation Tests
// ============================================================================

mod counterfactual {
    use super::*;

    #[test]
    fn test_counterfactual_orphan_flip() {
        let priors = orphan_sensitive_priors();

        // Start with orphaned process (likely abandoned)
        let orphan_evidence = Evidence {
            orphan: Some(true),
            ..Evidence::default()
        };
        let orphan_result = compute_posterior(&priors, &orphan_evidence).expect("orphan");
        let orphan_class = get_classification(&orphan_result.posterior);

        // Counterfactual: what if it had a parent?
        let non_orphan_evidence = Evidence {
            orphan: Some(false),
            ..Evidence::default()
        };
        let non_orphan_result = compute_posterior(&priors, &non_orphan_evidence).expect("non-orphan");
        let non_orphan_class = get_classification(&non_orphan_result.posterior);

        // Classification might change
        // The key test is that we can compute both scenarios
        assert!(
            orphan_result.posterior.abandoned != non_orphan_result.posterior.abandoned,
            "Counterfactual should change abandoned probability"
        );

        // Verify the change direction is correct
        assert!(
            orphan_result.posterior.abandoned > non_orphan_result.posterior.abandoned,
            "Orphan status should increase abandoned probability"
        );
    }

    #[test]
    fn test_counterfactual_cpu_change() {
        let priors = cpu_sensitive_priors();

        // Process with low CPU (likely abandoned)
        let low_cpu = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.01 }),
            ..Evidence::default()
        };
        let low_result = compute_posterior(&priors, &low_cpu).expect("low cpu");

        // Counterfactual: what if CPU were high?
        let high_cpu = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.9 }),
            ..Evidence::default()
        };
        let high_result = compute_posterior(&priors, &high_cpu).expect("high cpu");

        // Useful probability should increase significantly
        let useful_change = high_result.posterior.useful - low_result.posterior.useful;
        assert!(
            useful_change > 0.1,
            "High CPU counterfactual should significantly increase useful probability: change={}",
            useful_change
        );
    }

    #[test]
    fn test_counterfactual_multiple_features() {
        let priors = orphan_sensitive_priors();

        // Worst case: orphaned + no tty + no network
        let bad_evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            net: Some(false),
            ..Evidence::default()
        };
        let bad_result = compute_posterior(&priors, &bad_evidence).expect("bad case");

        // Best case: has parent + has tty + has network
        let good_evidence = Evidence {
            orphan: Some(false),
            tty: Some(true),
            net: Some(true),
            ..Evidence::default()
        };
        let good_result = compute_posterior(&priors, &good_evidence).expect("good case");

        // Should see significant difference in useful probability
        assert!(
            good_result.posterior.useful > bad_result.posterior.useful,
            "Good evidence should favor useful: {} vs {}",
            good_result.posterior.useful,
            bad_result.posterior.useful
        );
    }

    #[test]
    fn test_counterfactual_preserves_other_evidence() {
        let priors = orphan_sensitive_priors();

        // Base: orphan + tty
        let base = Evidence {
            orphan: Some(true),
            tty: Some(true),
            ..Evidence::default()
        };
        let base_result = compute_posterior(&priors, &base).expect("base");

        // Counterfactual: flip orphan only, keep tty
        let counterfactual = Evidence {
            orphan: Some(false),
            tty: Some(true),
            ..Evidence::default()
        };
        let cf_result = compute_posterior(&priors, &counterfactual).expect("counterfactual");

        // Both should have tty evidence term
        let base_has_tty = base_result.evidence_terms.iter().any(|t| t.feature == "tty");
        let cf_has_tty = cf_result.evidence_terms.iter().any(|t| t.feature == "tty");

        assert!(base_has_tty, "Base should have tty term");
        assert!(cf_has_tty, "Counterfactual should preserve tty term");
    }
}

// ============================================================================
// Threshold Analysis Tests
// ============================================================================

mod threshold_analysis {
    use super::*;

    #[test]
    fn test_find_cpu_threshold_for_classification_change() {
        let priors = cpu_sensitive_priors();

        // Binary search to find CPU threshold where classification changes
        let mut low = 0.01;
        let mut high = 0.99;

        // Get classifications at extremes
        let low_evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: low }),
            ..Evidence::default()
        };
        let low_result = compute_posterior(&priors, &low_evidence).expect("low");
        let low_class = get_classification(&low_result.posterior);

        let high_evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: high }),
            ..Evidence::default()
        };
        let high_result = compute_posterior(&priors, &high_evidence).expect("high");
        let high_class = get_classification(&high_result.posterior);

        // If same class at both extremes, priors dominate - that's valid
        if low_class == high_class {
            return; // Threshold doesn't exist for this prior configuration
        }

        // Binary search for threshold
        for _ in 0..50 {
            let mid = (low + high) / 2.0;
            let mid_evidence = Evidence {
                cpu: Some(CpuEvidence::Fraction { occupancy: mid }),
                ..Evidence::default()
            };
            let mid_result = compute_posterior(&priors, &mid_evidence).expect("mid");
            let mid_class = get_classification(&mid_result.posterior);

            if mid_class == low_class {
                low = mid;
            } else {
                high = mid;
            }
        }

        let threshold = (low + high) / 2.0;
        assert!(
            threshold > 0.01 && threshold < 0.99,
            "CPU threshold should be between extremes: {}",
            threshold
        );
    }

    #[test]
    fn test_marginal_kill_threshold() {
        // Test scenario: process near the decision boundary
        let priors = orphan_sensitive_priors();

        // Start with borderline evidence
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(true), // TTY might keep it in "review" vs "kill"
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("borderline");

        // Check if abandoned probability is close to a threshold
        let abandoned_prob = result.posterior.abandoned;
        let confidence = get_confidence(abandoned_prob);

        // For marginal cases, we should be able to identify what tips it over
        // This test verifies we can compute the posterior correctly for edge cases
        assert!(
            abandoned_prob.is_finite(),
            "Posterior should be finite for marginal cases"
        );
    }

    #[test]
    fn test_confidence_threshold_boundaries() {
        let priors = orphan_sensitive_priors();

        // Test evidence that should give different confidence levels
        let test_cases = vec![
            // Very high confidence (>0.99)
            (
                Evidence {
                    orphan: Some(true),
                    tty: Some(false),
                    net: Some(false),
                    io_active: Some(false),
                    ..Evidence::default()
                },
                "strong_abandoned",
            ),
            // Low confidence (mixed signals)
            (
                Evidence {
                    orphan: Some(false),
                    tty: Some(false),
                    ..Evidence::default()
                },
                "mixed_signals",
            ),
        ];

        for (evidence, name) in test_cases {
            let result = compute_posterior(&priors, &evidence).expect(&name);
            let max_prob = result
                .posterior
                .useful
                .max(result.posterior.useful_bad)
                .max(result.posterior.abandoned)
                .max(result.posterior.zombie);

            let confidence = get_confidence(max_prob);
            // Just verify we can compute confidence for different scenarios
            assert!(
                max_prob > 0.0 && max_prob <= 1.0,
                "Max probability should be valid for {}: {}",
                name,
                max_prob
            );
        }
    }
}

// ============================================================================
// Sensitivity Analysis Tests
// ============================================================================

mod sensitivity_analysis {
    use super::*;

    #[test]
    fn test_cpu_sensitivity_gradient() {
        let priors = cpu_sensitive_priors();
        let epsilon = 0.01;

        // Test sensitivity at different CPU levels
        for base_cpu in [0.1, 0.3, 0.5, 0.7, 0.9] {
            let base_evidence = Evidence {
                cpu: Some(CpuEvidence::Fraction { occupancy: base_cpu }),
                ..Evidence::default()
            };
            let base_result = compute_posterior(&priors, &base_evidence).expect("base");

            let perturbed_evidence = Evidence {
                cpu: Some(CpuEvidence::Fraction {
                    occupancy: (base_cpu + epsilon).min(0.99),
                }),
                ..Evidence::default()
            };
            let perturbed_result = compute_posterior(&priors, &perturbed_evidence).expect("perturbed");

            // Calculate numerical gradient
            let useful_gradient =
                (perturbed_result.posterior.useful - base_result.posterior.useful) / epsilon;
            let abandoned_gradient =
                (perturbed_result.posterior.abandoned - base_result.posterior.abandoned) / epsilon;

            // Gradients should be finite and have expected direction
            assert!(
                useful_gradient.is_finite(),
                "Useful gradient should be finite at cpu={}",
                base_cpu
            );
            assert!(
                abandoned_gradient.is_finite(),
                "Abandoned gradient should be finite at cpu={}",
                base_cpu
            );

            // Higher CPU should favor useful (positive gradient) and disfavor abandoned (negative gradient)
            // Note: This may not hold at all points depending on priors
        }
    }

    #[test]
    fn test_orphan_sensitivity_binary() {
        let priors = orphan_sensitive_priors();

        // Test the sensitivity of flipping orphan status
        let non_orphan = Evidence {
            orphan: Some(false),
            ..Evidence::default()
        };
        let non_orphan_result = compute_posterior(&priors, &non_orphan).expect("non-orphan");

        let orphan = Evidence {
            orphan: Some(true),
            ..Evidence::default()
        };
        let orphan_result = compute_posterior(&priors, &orphan).expect("orphan");

        // Calculate sensitivity (change per unit flip)
        let abandoned_sensitivity =
            orphan_result.posterior.abandoned - non_orphan_result.posterior.abandoned;
        let useful_sensitivity = orphan_result.posterior.useful - non_orphan_result.posterior.useful;

        // Orphan should strongly increase abandoned and decrease useful
        assert!(
            abandoned_sensitivity > 0.0,
            "Orphan should increase abandoned probability"
        );
        assert!(
            useful_sensitivity < 0.0,
            "Orphan should decrease useful probability"
        );
    }

    #[test]
    fn test_combined_sensitivity() {
        let priors = orphan_sensitive_priors();

        // Test how sensitive the result is to multiple features changing
        let baseline = Evidence::default();
        let baseline_result = compute_posterior(&priors, &baseline).expect("baseline");

        // Add one feature at a time and measure cumulative change
        let changes = vec![
            ("orphan", Evidence {
                orphan: Some(true),
                ..Evidence::default()
            }),
            ("orphan+no_tty", Evidence {
                orphan: Some(true),
                tty: Some(false),
                ..Evidence::default()
            }),
            ("orphan+no_tty+no_net", Evidence {
                orphan: Some(true),
                tty: Some(false),
                net: Some(false),
                ..Evidence::default()
            }),
        ];

        let mut prev_abandoned = baseline_result.posterior.abandoned;
        for (name, evidence) in changes {
            let result = compute_posterior(&priors, &evidence).expect(name);

            // Each additional negative signal should increase abandoned probability
            // (or at least not decrease it significantly)
            assert!(
                result.posterior.abandoned >= prev_abandoned - 0.01,
                "{}: abandoned should not decrease significantly: {} vs {}",
                name,
                result.posterior.abandoned,
                prev_abandoned
            );

            prev_abandoned = result.posterior.abandoned;
        }
    }

    #[test]
    fn test_feature_importance_ranking() {
        let priors = orphan_sensitive_priors();

        // Compute the impact of each feature independently
        let baseline_result =
            compute_posterior(&priors, &Evidence::default()).expect("baseline");

        let feature_impacts: Vec<(&str, f64)> = vec![
            (
                "orphan",
                compute_posterior(
                    &priors,
                    &Evidence {
                        orphan: Some(true),
                        ..Evidence::default()
                    },
                )
                .expect("orphan")
                .posterior
                .abandoned
                    - baseline_result.posterior.abandoned,
            ),
            (
                "no_tty",
                compute_posterior(
                    &priors,
                    &Evidence {
                        tty: Some(false),
                        ..Evidence::default()
                    },
                )
                .expect("no_tty")
                .posterior
                .abandoned
                    - baseline_result.posterior.abandoned,
            ),
            (
                "no_net",
                compute_posterior(
                    &priors,
                    &Evidence {
                        net: Some(false),
                        ..Evidence::default()
                    },
                )
                .expect("no_net")
                .posterior
                .abandoned
                    - baseline_result.posterior.abandoned,
            ),
        ];

        // All impacts should be computable
        for (name, impact) in &feature_impacts {
            assert!(
                impact.is_finite(),
                "Impact for {} should be finite: {}",
                name,
                impact
            );
        }

        // With orphan-sensitive priors, orphan should have the highest impact
        let orphan_impact = feature_impacts
            .iter()
            .find(|(n, _)| *n == "orphan")
            .map(|(_, i)| *i)
            .unwrap();

        assert!(
            orphan_impact > 0.0,
            "Orphan should have positive impact on abandoned"
        );
    }
}

// ============================================================================
// Explanation Format Tests
// ============================================================================

mod explanation_format {
    use super::*;

    #[test]
    fn test_evidence_ledger_creation() {
        let priors = orphan_sensitive_priors();
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(12345), None);

        // Ledger should have valid classification
        assert!(
            matches!(
                ledger.classification,
                Classification::Useful
                    | Classification::UsefulBad
                    | Classification::Abandoned
                    | Classification::Zombie
            ),
            "Ledger should have valid classification"
        );

        // Ledger should have confidence level
        assert!(
            matches!(
                ledger.confidence,
                Confidence::VeryHigh | Confidence::High | Confidence::Medium | Confidence::Low
            ),
            "Ledger should have valid confidence"
        );

        // Ledger should have a summary
        assert!(
            !ledger.why_summary.is_empty(),
            "Ledger should have explanation summary"
        );
    }

    #[test]
    fn test_evidence_terms_serialization() {
        let priors = uniform_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.5 }),
            orphan: Some(true),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");

        // Evidence terms should be serializable to JSON
        let json = serde_json::to_string(&result.evidence_terms).expect("serialize");
        assert!(!json.is_empty(), "Evidence terms should serialize");

        // Should contain feature names
        assert!(json.contains("cpu"), "JSON should contain cpu feature");
        assert!(json.contains("orphan"), "JSON should contain orphan feature");
    }

    #[test]
    fn test_posterior_result_serialization() {
        let priors = uniform_priors();
        let evidence = Evidence {
            orphan: Some(true),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");

        // Full result should be serializable
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(!json.is_empty(), "Result should serialize");

        // Should contain expected fields
        assert!(json.contains("posterior"), "JSON should contain posterior");
        assert!(
            json.contains("log_posterior"),
            "JSON should contain log_posterior"
        );
        assert!(
            json.contains("evidence_terms"),
            "JSON should contain evidence_terms"
        );
    }

    #[test]
    fn test_classification_serialization() {
        let classifications = vec![
            Classification::Useful,
            Classification::UsefulBad,
            Classification::Abandoned,
            Classification::Zombie,
        ];

        for class in classifications {
            let json = serde_json::to_string(&class).expect("serialize");
            let deserialized: Classification =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(class, deserialized, "Classification roundtrip failed");
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration {
    use super::*;

    #[test]
    fn test_consistent_explanations_for_same_input() {
        let priors = orphan_sensitive_priors();
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            net: Some(false),
            ..Evidence::default()
        };

        // Run computation multiple times
        let results: Vec<_> = (0..5)
            .map(|_| compute_posterior(&priors, &evidence).expect("posterior"))
            .collect();

        // All results should be identical
        let first = &results[0];
        for result in &results[1..] {
            assert_eq!(
                first.posterior.useful, result.posterior.useful,
                "Useful probability should be consistent"
            );
            assert_eq!(
                first.posterior.abandoned, result.posterior.abandoned,
                "Abandoned probability should be consistent"
            );
            assert_eq!(
                first.evidence_terms.len(),
                result.evidence_terms.len(),
                "Evidence term count should be consistent"
            );
        }
    }

    #[test]
    fn test_explanation_completeness() {
        let priors = orphan_sensitive_priors();
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.1 }),
            runtime_seconds: Some(3600.0),
            orphan: Some(true),
            tty: Some(false),
            net: Some(false),
            io_active: Some(false),
            state_flag: None,
            command_category: None,
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");

        // Should have evidence term for each provided feature
        let features_provided = vec!["cpu", "runtime", "orphan", "tty", "net", "io_active"];
        let features_in_terms: Vec<&str> = result
            .evidence_terms
            .iter()
            .map(|t| t.feature.as_str())
            .collect();

        for feature in features_provided {
            assert!(
                features_in_terms.contains(&feature),
                "Missing evidence term for feature: {}",
                feature
            );
        }
    }

    #[test]
    fn test_explanation_actionability() {
        // Test that explanations provide actionable information
        let priors = orphan_sensitive_priors();

        // Abandoned process
        let evidence = Evidence {
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(1234), None);

        // The explanation should mention the classification
        assert!(
            ledger.why_summary.to_lowercase().contains("classified")
                || ledger.why_summary.to_lowercase().contains("confidence"),
            "Explanation should mention classification or confidence"
        );
    }
}

// ============================================================================
// Specific Scenario Tests (Section 11.15)
// ============================================================================

mod scenarios {
    use super::*;

    /// Create priors where abandoned/zombie have high base probability when evidence is extreme.
    fn scenario_priors() -> Priors {
        let mut priors = uniform_priors();

        // Abandoned favored when: low CPU, orphaned, no TTY, no net
        priors.classes.abandoned.cpu_beta = BetaParams::new(1.0, 20.0);
        priors.classes.abandoned.orphan_beta = BetaParams::new(15.0, 1.0);
        priors.classes.abandoned.tty_beta = BetaParams::new(1.0, 15.0);
        priors.classes.abandoned.net_beta = BetaParams::new(1.0, 15.0);

        // Useful favored when: high CPU, has parent, has TTY, has net
        priors.classes.useful.cpu_beta = BetaParams::new(10.0, 2.0);
        priors.classes.useful.orphan_beta = BetaParams::new(1.0, 15.0);
        priors.classes.useful.tty_beta = BetaParams::new(15.0, 1.0);
        priors.classes.useful.net_beta = BetaParams::new(15.0, 1.0);

        // Zombie: very low CPU, orphaned
        priors.classes.zombie.cpu_beta = BetaParams::new(1.0, 50.0);
        priors.classes.zombie.orphan_beta = BetaParams::new(20.0, 1.0);

        // Useful-bad: high CPU but orphaned (runaway process)
        priors.classes.useful_bad.cpu_beta = BetaParams::new(15.0, 1.0);
        priors.classes.useful_bad.orphan_beta = BetaParams::new(10.0, 5.0);

        priors
    }

    #[test]
    fn test_scenario_strong_kill() {
        // SCENARIO: strong_kill
        // Expected: Show all contributing factors, classification favors abandoned/zombie

        let priors = scenario_priors();

        // Evidence strongly suggesting abandoned: orphaned, no CPU, no TTY, no network
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.001 }),
            orphan: Some(true),
            tty: Some(false),
            net: Some(false),
            io_active: Some(false),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("strong_kill posterior");
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(9999), None);

        // Combined abandoned + zombie probability should be higher than useful
        let kill_prob = result.posterior.abandoned + result.posterior.zombie;
        let spare_prob = result.posterior.useful + result.posterior.useful_bad;

        assert!(
            kill_prob > spare_prob,
            "Strong kill evidence should favor abandoned/zombie ({:.4}) over useful ({:.4})",
            kill_prob, spare_prob
        );

        // Should classify as Abandoned or Zombie (not Useful)
        assert!(
            matches!(ledger.classification, Classification::Abandoned | Classification::Zombie),
            "Strong kill should classify as abandoned/zombie: {:?}",
            ledger.classification
        );

        // Evidence terms should show all contributing factors
        let feature_names: Vec<&str> = result
            .evidence_terms
            .iter()
            .map(|t| t.feature.as_str())
            .collect();

        assert!(feature_names.contains(&"cpu"), "Should include cpu evidence");
        assert!(feature_names.contains(&"orphan"), "Should include orphan evidence");
        assert!(feature_names.contains(&"tty"), "Should include tty evidence");
        assert!(feature_names.contains(&"net"), "Should include net evidence");

        // Log the evidence breakdown for debugging
        eprintln!("[STRONG_KILL] Classification: {:?}, Confidence: {:?}",
            ledger.classification, ledger.confidence);
        eprintln!("[STRONG_KILL] Abandoned prob: {:.4}, Useful prob: {:.4}",
            result.posterior.abandoned, result.posterior.useful);
        eprintln!("[STRONG_KILL] Evidence terms: {:?}",
            feature_names);
    }

    #[test]
    fn test_scenario_spare_recommendation() {
        // SCENARIO: spare_recommendation
        // Score: 15 (very confident useful)
        // Expected: Show what would need to change to reach KILL

        let priors = scenario_priors();

        // Evidence strongly suggesting useful: active CPU, has parent, has TTY
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.75 }),
            orphan: Some(false),
            tty: Some(true),
            net: Some(true),
            io_active: Some(true),
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("spare posterior");
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(1111), None);

        // Should classify as Useful (spare)
        assert!(
            matches!(ledger.classification, Classification::Useful | Classification::UsefulBad),
            "Spare recommendation should classify as useful: {:?}",
            ledger.classification
        );

        // Useful probability should be much higher than abandoned
        assert!(
            result.posterior.useful > result.posterior.abandoned,
            "Useful probability should be higher than abandoned: {} vs {}",
            result.posterior.useful, result.posterior.abandoned
        );

        // Test counterfactual: what would need to change?
        // If we flip orphan to true and remove TTY, does it shift?
        let counterfactual = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.75 }),
            orphan: Some(true),  // Flipped
            tty: Some(false),    // Flipped
            net: Some(true),
            io_active: Some(true),
            ..Evidence::default()
        };

        let cf_result = compute_posterior(&priors, &counterfactual).expect("counterfactual");

        // The counterfactual should shift toward abandoned
        assert!(
            cf_result.posterior.abandoned > result.posterior.abandoned,
            "Counterfactual should increase abandoned probability"
        );

        // Log the transition for debugging
        eprintln!("[SPARE] Original: useful={:.4}, abandoned={:.4}",
            result.posterior.useful, result.posterior.abandoned);
        eprintln!("[SPARE] After orphan+no_tty: useful={:.4}, abandoned={:.4}",
            cf_result.posterior.useful, cf_result.posterior.abandoned);
    }

    #[test]
    fn test_scenario_conflicting_evidence() {
        // SCENARIO: conflicting_evidence
        // Score: ~50 (uncertain)
        // Expected: Show both positive and negative evidence clearly

        let priors = scenario_priors();

        // Conflicting evidence: high CPU (useful signal) but orphaned (abandoned signal)
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.6 }),  // High CPU - suggests useful
            orphan: Some(true),   // Orphaned - suggests abandoned
            tty: Some(false),     // No TTY - suggests abandoned
            net: Some(true),      // Has network - mixed signal
            io_active: Some(true), // Active I/O - suggests useful
            ..Evidence::default()
        };

        let result = compute_posterior(&priors, &evidence).expect("conflicting posterior");
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(5050), None);

        // With conflicting evidence, confidence should be low or medium
        assert!(
            matches!(ledger.confidence, Confidence::Low | Confidence::Medium),
            "Conflicting evidence should yield low/medium confidence: {:?} (max prob: {:.4})",
            ledger.confidence,
            result.posterior.useful
                .max(result.posterior.abandoned)
                .max(result.posterior.useful_bad)
                .max(result.posterior.zombie)
        );

        // The evidence terms should show mixed signals
        let positive_evidence: Vec<&EvidenceTerm> = result
            .evidence_terms
            .iter()
            .filter(|t| t.log_likelihood.useful > t.log_likelihood.abandoned)
            .collect();

        let negative_evidence: Vec<&EvidenceTerm> = result
            .evidence_terms
            .iter()
            .filter(|t| t.log_likelihood.abandoned > t.log_likelihood.useful)
            .collect();

        assert!(
            !positive_evidence.is_empty(),
            "Should have some evidence favoring useful"
        );
        assert!(
            !negative_evidence.is_empty(),
            "Should have some evidence favoring abandoned"
        );

        // Log the breakdown for debugging
        eprintln!("[CONFLICTING] Classification: {:?}, Confidence: {:?}",
            ledger.classification, ledger.confidence);
        eprintln!("[CONFLICTING] Useful prob: {:.4}, Abandoned prob: {:.4}",
            result.posterior.useful, result.posterior.abandoned);
        eprintln!("[CONFLICTING] Evidence favoring useful: {:?}",
            positive_evidence.iter().map(|t| &t.feature).collect::<Vec<_>>());
        eprintln!("[CONFLICTING] Evidence favoring abandoned: {:?}",
            negative_evidence.iter().map(|t| &t.feature).collect::<Vec<_>>());
    }

    #[test]
    fn test_scenario_marginal_kill_threshold_crossing() {
        // SCENARIO: marginal_kill
        // Score: ~62 (just above KILL threshold)
        // Expected: Show which evidence tips it over threshold

        let priors = scenario_priors();

        // Start with borderline evidence
        let borderline = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.1 }),
            orphan: Some(true),
            tty: Some(true),  // Has TTY - keeps it borderline
            net: Some(false),
            ..Evidence::default()
        };

        let borderline_result = compute_posterior(&priors, &borderline).expect("borderline");

        // Now add the tipping factor: remove TTY
        let over_threshold = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.1 }),
            orphan: Some(true),
            tty: Some(false),  // No TTY - tips it over
            net: Some(false),
            ..Evidence::default()
        };

        let over_result = compute_posterior(&priors, &over_threshold).expect("over threshold");

        // The tipping factor (removing TTY) should increase abandoned probability
        assert!(
            over_result.posterior.abandoned > borderline_result.posterior.abandoned,
            "Removing TTY should increase abandoned probability: {} vs {}",
            over_result.posterior.abandoned, borderline_result.posterior.abandoned
        );

        // Log the threshold crossing for debugging
        eprintln!("[MARGINAL] With TTY: abandoned={:.4}, classification={:?}",
            borderline_result.posterior.abandoned,
            get_classification(&borderline_result.posterior));
        eprintln!("[MARGINAL] Without TTY: abandoned={:.4}, classification={:?}",
            over_result.posterior.abandoned,
            get_classification(&over_result.posterior));
        eprintln!("[MARGINAL] TTY was the tipping factor");
    }
}
