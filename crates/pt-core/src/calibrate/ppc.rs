//! Posterior Predictive Checks (PPC) for shadow mode calibration.
//!
//! Compares observed feature frequencies with model predictions to detect
//! misspecification. When the model's predicted distribution of features
//! (CPU, memory, age, etc.) diverges from what's actually observed, this
//! module flags the discrepancy and suggests which priors/likelihoods to revise.
//!
//! # What PPCs Tell You
//!
//! - "Model says 60% of abandoned processes have zero CPU, but we observe only 30%"
//!   → CPU likelihood for abandoned class needs recalibration
//! - "Model expects orphaned rate of 40% among killed processes, we see 80%"
//!   → Orphan prior for abandoned class is too low

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single feature observation from shadow mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureObservation {
    /// Feature name (e.g., "cpu_zero", "orphaned", "has_tty").
    pub feature: String,
    /// Whether the feature was observed (true/false for binary features).
    pub observed: bool,
    /// Predicted probability of this feature under the model.
    pub predicted_prob: f64,
    /// Process classification at the time of observation.
    pub classification: String,
    /// Optional category (e.g., "test_runner").
    #[serde(default)]
    pub category: Option<String>,
}

/// Summary of a PPC check for a single feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpcFeatureCheck {
    /// Feature name.
    pub feature: String,
    /// Classification context (e.g., "abandoned").
    pub classification: String,
    /// Number of observations.
    pub n: usize,
    /// Observed frequency of the feature.
    pub observed_rate: f64,
    /// Mean predicted probability.
    pub predicted_rate: f64,
    /// Discrepancy (observed - predicted).
    pub discrepancy: f64,
    /// Standard error of the discrepancy.
    pub se: f64,
    /// z-score of the discrepancy.
    pub z_score: f64,
    /// Whether the discrepancy is statistically significant (|z| > 2, n >= 20).
    pub significant: bool,
    /// Human-readable interpretation.
    pub interpretation: String,
}

/// Aggregated PPC summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpcSummary {
    /// Total feature observations analyzed.
    pub total_observations: usize,
    /// Feature checks grouped by classification.
    pub checks: Vec<PpcFeatureCheck>,
    /// Features with significant miscalibration.
    pub miscalibrated: Vec<PpcFeatureCheck>,
    /// Recommendations for model revision.
    pub recommendations: Vec<PpcRecommendation>,
}

/// A recommendation based on PPC findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpcRecommendation {
    /// What to revise (e.g., "cpu_beta for abandoned class").
    pub target: String,
    /// Direction of revision.
    pub direction: String,
    /// Confidence in the recommendation.
    pub confidence: f64,
    /// Supporting evidence.
    pub evidence: String,
}

/// Multi-class calibration curves for all four posterior states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiClassCalibration {
    /// Per-class calibration data.
    pub classes: Vec<ClassCalibrationSummary>,
}

/// Calibration summary for a single class posterior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassCalibrationSummary {
    /// Class name (useful, useful_bad, abandoned, zombie).
    pub class_name: String,
    /// Number of predictions analyzed.
    pub n: usize,
    /// Brier score for this class.
    pub brier_score: f64,
    /// ECE for this class.
    pub ece: f64,
    /// Mean predicted probability.
    pub mean_predicted: f64,
    /// Actual rate for this class.
    pub actual_rate: f64,
    /// Bias (mean_predicted - actual_rate).
    pub bias: f64,
}

/// A prediction with multi-class posteriors and ground truth.
#[derive(Debug, Clone)]
pub struct MultiClassPrediction {
    /// Posterior probabilities per class.
    pub posteriors: HashMap<String, f64>,
    /// Actual class (ground truth).
    pub actual_class: String,
}

/// Compute PPC summary from feature observations.
pub fn compute_ppc(observations: &[FeatureObservation]) -> PpcSummary {
    // Group by (feature, classification).
    let mut groups: HashMap<(String, String), Vec<&FeatureObservation>> = HashMap::new();
    for obs in observations {
        groups
            .entry((obs.feature.clone(), obs.classification.clone()))
            .or_default()
            .push(obs);
    }

    let mut checks = Vec::new();
    for ((feature, classification), group) in &groups {
        let n = group.len();
        if n < 5 {
            continue;
        }

        let observed_count = group.iter().filter(|o| o.observed).count();
        let observed_rate = observed_count as f64 / n as f64;
        let predicted_rate = group.iter().map(|o| o.predicted_prob).sum::<f64>() / n as f64;
        let discrepancy = observed_rate - predicted_rate;

        // Standard error for binomial proportion.
        let se = if n > 1 {
            (observed_rate * (1.0 - observed_rate) / n as f64).sqrt()
        } else {
            0.0
        };

        let z_score = if se > 1e-10 {
            discrepancy / se
        } else {
            0.0
        };

        let significant = z_score.abs() > 2.0 && n >= 20;

        let interpretation = if significant {
            if discrepancy > 0.0 {
                format!(
                    "Feature '{}' is more common than predicted for {} processes ({:.1}% observed vs {:.1}% predicted)",
                    feature, classification,
                    observed_rate * 100.0, predicted_rate * 100.0
                )
            } else {
                format!(
                    "Feature '{}' is less common than predicted for {} processes ({:.1}% observed vs {:.1}% predicted)",
                    feature, classification,
                    observed_rate * 100.0, predicted_rate * 100.0
                )
            }
        } else {
            format!(
                "Feature '{}' for {} processes: no significant discrepancy (n={})",
                feature, classification, n
            )
        };

        checks.push(PpcFeatureCheck {
            feature: feature.clone(),
            classification: classification.clone(),
            n,
            observed_rate,
            predicted_rate,
            discrepancy,
            se,
            z_score,
            significant,
            interpretation,
        });
    }

    // Sort by absolute z-score descending.
    checks.sort_by(|a, b| {
        b.z_score
            .abs()
            .partial_cmp(&a.z_score.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let miscalibrated: Vec<PpcFeatureCheck> =
        checks.iter().filter(|c| c.significant).cloned().collect();

    let recommendations = generate_ppc_recommendations(&miscalibrated);

    PpcSummary {
        total_observations: observations.len(),
        checks,
        miscalibrated,
        recommendations,
    }
}

/// Compute multi-class calibration from predictions with multi-class posteriors.
pub fn compute_multi_class_calibration(
    predictions: &[MultiClassPrediction],
) -> MultiClassCalibration {
    let class_names = ["useful", "useful_bad", "abandoned", "zombie"];
    let mut classes = Vec::new();

    for class_name in &class_names {
        let mut brier_sum = 0.0;
        let mut n = 0usize;
        let mut sum_predicted = 0.0;
        let mut actual_count = 0usize;

        for pred in predictions {
            if let Some(&posterior) = pred.posteriors.get(*class_name) {
                let actual = if pred.actual_class == *class_name {
                    1.0
                } else {
                    0.0
                };
                brier_sum += (posterior - actual).powi(2);
                sum_predicted += posterior;
                if pred.actual_class == *class_name {
                    actual_count += 1;
                }
                n += 1;
            }
        }

        if n == 0 {
            continue;
        }

        let brier_score = brier_sum / n as f64;
        let mean_predicted = sum_predicted / n as f64;
        let actual_rate = actual_count as f64 / n as f64;

        // Compute ECE with 10 bins.
        let ece = compute_class_ece(predictions, class_name, 10);

        classes.push(ClassCalibrationSummary {
            class_name: class_name.to_string(),
            n,
            brier_score,
            ece,
            mean_predicted,
            actual_rate,
            bias: mean_predicted - actual_rate,
        });
    }

    MultiClassCalibration { classes }
}

fn compute_class_ece(
    predictions: &[MultiClassPrediction],
    class_name: &str,
    num_bins: usize,
) -> f64 {
    let bin_width = 1.0 / num_bins as f64;
    let mut bins: Vec<(f64, f64, usize)> = vec![(0.0, 0.0, 0); num_bins]; // (sum_pred, sum_actual, count)

    for pred in predictions {
        if let Some(&posterior) = pred.posteriors.get(class_name) {
            let actual = if pred.actual_class == class_name {
                1.0
            } else {
                0.0
            };
            let bin_idx = ((posterior / bin_width) as usize).min(num_bins - 1);
            bins[bin_idx].0 += posterior;
            bins[bin_idx].1 += actual;
            bins[bin_idx].2 += 1;
        }
    }

    let total = predictions.len() as f64;
    let mut ece = 0.0;
    for (sum_pred, sum_actual, count) in &bins {
        if *count == 0 {
            continue;
        }
        let avg_pred = sum_pred / *count as f64;
        let avg_actual = sum_actual / *count as f64;
        ece += (*count as f64 / total) * (avg_pred - avg_actual).abs();
    }
    ece
}

fn generate_ppc_recommendations(miscalibrated: &[PpcFeatureCheck]) -> Vec<PpcRecommendation> {
    let mut recs = Vec::new();

    for check in miscalibrated {
        let direction = if check.discrepancy > 0.0 {
            "increase"
        } else {
            "decrease"
        };

        let confidence = (1.0 - 2.0 / check.n as f64).max(0.0);

        recs.push(PpcRecommendation {
            target: format!(
                "{}_likelihood for {} class",
                check.feature, check.classification
            ),
            direction: direction.to_string(),
            confidence,
            evidence: format!(
                "z={:.2}, observed={:.3}, predicted={:.3}, n={}",
                check.z_score, check.observed_rate, check.predicted_rate, check.n
            ),
        });
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppc_no_significant_discrepancy() {
        // Create observations that match predictions well.
        let observations: Vec<FeatureObservation> = (0..50)
            .map(|i| FeatureObservation {
                feature: "cpu_zero".to_string(),
                observed: i % 2 == 0, // 50% rate
                predicted_prob: 0.5,
                classification: "abandoned".to_string(),
                category: None,
            })
            .collect();

        let summary = compute_ppc(&observations);
        assert_eq!(summary.total_observations, 50);
        assert!(summary.miscalibrated.is_empty());
    }

    #[test]
    fn test_ppc_detects_miscalibration() {
        // Model predicts 80% cpu_zero for abandoned, but only 20% observed.
        let observations: Vec<FeatureObservation> = (0..100)
            .map(|i| FeatureObservation {
                feature: "cpu_zero".to_string(),
                observed: i < 20, // 20% observed
                predicted_prob: 0.8, // 80% predicted
                classification: "abandoned".to_string(),
                category: None,
            })
            .collect();

        let summary = compute_ppc(&observations);
        assert!(!summary.miscalibrated.is_empty());

        let check = &summary.miscalibrated[0];
        assert_eq!(check.feature, "cpu_zero");
        assert!(check.discrepancy < 0.0); // Observed less than predicted
        assert!(check.significant);
    }

    #[test]
    fn test_ppc_recommendations() {
        let observations: Vec<FeatureObservation> = (0..100)
            .map(|i| FeatureObservation {
                feature: "orphaned".to_string(),
                observed: i < 80, // 80% observed
                predicted_prob: 0.3, // 30% predicted
                classification: "abandoned".to_string(),
                category: None,
            })
            .collect();

        let summary = compute_ppc(&observations);
        assert!(!summary.recommendations.is_empty());
        let rec = &summary.recommendations[0];
        assert_eq!(rec.direction, "increase");
        assert!(rec.target.contains("orphaned"));
    }

    #[test]
    fn test_multi_class_calibration() {
        let predictions: Vec<MultiClassPrediction> = (0..100)
            .map(|i| {
                let mut posteriors = HashMap::new();
                let abandoned_prob = i as f64 / 100.0;
                posteriors.insert("abandoned".to_string(), abandoned_prob);
                posteriors.insert("useful".to_string(), 1.0 - abandoned_prob);
                posteriors.insert("useful_bad".to_string(), 0.0);
                posteriors.insert("zombie".to_string(), 0.0);

                let actual_class = if i >= 50 { "abandoned" } else { "useful" };

                MultiClassPrediction {
                    posteriors,
                    actual_class: actual_class.to_string(),
                }
            })
            .collect();

        let cal = compute_multi_class_calibration(&predictions);
        assert!(!cal.classes.is_empty());

        let abandoned = cal.classes.iter().find(|c| c.class_name == "abandoned").unwrap();
        assert_eq!(abandoned.n, 100);
        assert!(abandoned.brier_score < 0.5); // Should be reasonably calibrated
    }

    #[test]
    fn test_ppc_small_group_skipped() {
        // Groups with fewer than 5 observations should be skipped.
        let observations: Vec<FeatureObservation> = (0..3)
            .map(|_| FeatureObservation {
                feature: "rare_feature".to_string(),
                observed: true,
                predicted_prob: 0.1,
                classification: "zombie".to_string(),
                category: None,
            })
            .collect();

        let summary = compute_ppc(&observations);
        assert!(summary.checks.is_empty());
    }
}
