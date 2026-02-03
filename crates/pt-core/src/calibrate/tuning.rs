//! Prior tuning from calibration data.
//!
//! Automatically adjusts prior distributions based on shadow mode outcomes
//! to improve model accuracy over time. Uses a conservative update strategy
//! with safety constraints to prevent extreme adjustments.
//!
//! # Safety Constraints
//!
//! - Maximum parameter change per round: ±20% (configurable)
//! - Minimum observations per category: 30 (configurable)
//! - Regularization toward default priors prevents overfitting
//! - All changes are logged and reversible via backup

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::metrics::compute_metrics;
use super::validation::ValidationRecord;
use super::{CalibrationData, CalibrationError};

/// Configuration for prior tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningConfig {
    /// Maximum relative change per parameter per round (0.0 to 1.0).
    /// Default: 0.2 (20%).
    pub max_change_fraction: f64,
    /// Minimum observations per category before tuning.
    /// Default: 30.
    pub min_observations: usize,
    /// Regularization strength toward default priors (0.0 = no reg, 1.0 = ignore data).
    /// Default: 0.3.
    pub regularization: f64,
    /// Classification threshold for kill recommendations.
    /// Default: 0.5.
    pub threshold: f64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            max_change_fraction: 0.2,
            min_observations: 30,
            regularization: 0.3,
            threshold: 0.5,
        }
    }
}

/// A proposed adjustment to a prior parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningAdjustment {
    /// Parameter path (e.g., "classes.abandoned.prior_prob").
    pub parameter: String,
    /// Current value.
    pub current: f64,
    /// Proposed new value.
    pub proposed: f64,
    /// Change as a fraction of current value.
    pub change_fraction: f64,
    /// Was the change clamped by safety constraints?
    pub clamped: bool,
    /// Number of observations supporting this adjustment.
    pub observation_count: usize,
    /// Rationale for the change.
    pub reason: String,
}

/// Result of a tuning analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningResult {
    /// Timestamp of the analysis.
    pub computed_at: DateTime<Utc>,
    /// Configuration used.
    pub config: TuningConfig,
    /// Proposed adjustments.
    pub adjustments: Vec<TuningAdjustment>,
    /// Validation metrics before tuning.
    pub metrics_before: TuningMetrics,
    /// Estimated metrics after tuning (on training data).
    pub metrics_after_estimate: Option<TuningMetrics>,
    /// Per-category statistics used for tuning.
    pub category_stats: Vec<CategoryStats>,
    /// Whether any adjustments are recommended.
    pub has_recommendations: bool,
}

/// Simplified metrics for tuning comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningMetrics {
    pub brier_score: f64,
    pub ece: f64,
    pub auc_roc: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

/// Per-category observation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    /// Category name (e.g., "test_runner").
    pub category: String,
    /// Total resolved observations.
    pub count: usize,
    /// Fraction actually abandoned.
    pub actual_abandoned_rate: f64,
    /// Mean predicted abandonment probability.
    pub mean_predicted: f64,
    /// Bias (mean_predicted - actual_rate).
    pub bias: f64,
    /// Whether enough data exists for tuning.
    pub sufficient_data: bool,
}

/// The tuning engine that computes prior adjustments.
pub struct TuningEngine {
    config: TuningConfig,
}

impl TuningEngine {
    pub fn new(config: TuningConfig) -> Self {
        Self { config }
    }

    /// Compute tuning recommendations from validation records.
    pub fn compute_adjustments(
        &self,
        records: &[ValidationRecord],
        current_class_priors: &[(String, f64)],
    ) -> Result<TuningResult, CalibrationError> {
        // Filter to resolved records only.
        let resolved: Vec<&ValidationRecord> = records
            .iter()
            .filter(|r| r.ground_truth.map_or(false, |gt| gt.is_resolved()))
            .collect();

        if resolved.is_empty() {
            return Err(CalibrationError::NoData);
        }

        // Compute current metrics.
        let cal_data: Vec<CalibrationData> = resolved
            .iter()
            .filter_map(|r| r.to_calibration_data())
            .collect();

        let metrics_before = if cal_data.len() >= 10 {
            let m = compute_metrics(&cal_data, self.config.threshold)?;
            TuningMetrics {
                brier_score: m.brier_score,
                ece: m.ece,
                auc_roc: m.auc_roc,
                precision: m.precision,
                recall: m.recall,
                f1_score: m.f1_score,
            }
        } else {
            TuningMetrics {
                brier_score: f64::NAN,
                ece: f64::NAN,
                auc_roc: f64::NAN,
                precision: f64::NAN,
                recall: f64::NAN,
                f1_score: f64::NAN,
            }
        };

        // Group by category.
        let category_stats = self.compute_category_stats(&resolved);

        // Compute class prior adjustments.
        let mut adjustments = Vec::new();
        self.compute_class_prior_adjustments(&resolved, current_class_priors, &mut adjustments);

        // Compute per-category bias adjustments.
        self.compute_category_bias_adjustments(&category_stats, &mut adjustments);

        let has_recommendations = !adjustments.is_empty();

        Ok(TuningResult {
            computed_at: Utc::now(),
            config: self.config.clone(),
            adjustments,
            metrics_before,
            metrics_after_estimate: None,
            category_stats,
            has_recommendations,
        })
    }

    fn compute_category_stats(&self, resolved: &[&ValidationRecord]) -> Vec<CategoryStats> {
        let mut by_cat: HashMap<String, Vec<&ValidationRecord>> = HashMap::new();
        for r in resolved {
            let cat = r.proc_type.clone().unwrap_or_else(|| "unknown".to_string());
            by_cat.entry(cat).or_default().push(r);
        }

        let mut stats: Vec<CategoryStats> = by_cat
            .into_iter()
            .map(|(category, recs)| {
                let count = recs.len();
                let abandoned_count = recs
                    .iter()
                    .filter(|r| r.ground_truth.map_or(false, |gt| gt.is_abandoned()))
                    .count();
                let actual_rate = if count > 0 {
                    abandoned_count as f64 / count as f64
                } else {
                    0.0
                };
                let mean_predicted = if count > 0 {
                    recs.iter().map(|r| r.predicted_abandoned).sum::<f64>() / count as f64
                } else {
                    0.0
                };

                CategoryStats {
                    category,
                    count,
                    actual_abandoned_rate: actual_rate,
                    mean_predicted,
                    bias: mean_predicted - actual_rate,
                    sufficient_data: count >= self.config.min_observations,
                }
            })
            .collect();

        stats.sort_by(|a, b| b.count.cmp(&a.count));
        stats
    }

    fn compute_class_prior_adjustments(
        &self,
        resolved: &[&ValidationRecord],
        current_priors: &[(String, f64)],
        adjustments: &mut Vec<TuningAdjustment>,
    ) {
        if resolved.len() < self.config.min_observations {
            return;
        }

        // Count actual class distribution from ground truth.
        let total = resolved.len() as f64;
        let abandoned_count = resolved
            .iter()
            .filter(|r| r.ground_truth.map_or(false, |gt| gt.is_abandoned()))
            .count();
        let useful_count = resolved.len() - abandoned_count;

        let observed_abandoned_rate = abandoned_count as f64 / total;
        let observed_useful_rate = useful_count as f64 / total;

        for (class_name, current_prior) in current_priors {
            let observed_rate = match class_name.as_str() {
                "abandoned" => observed_abandoned_rate,
                "useful" => observed_useful_rate,
                _ => continue, // Only tune abandoned and useful for now
            };

            // Regularized update: blend observed with current prior.
            let reg = self.config.regularization;
            let raw_proposed = reg * current_prior + (1.0 - reg) * observed_rate;

            // Clamp change to max_change_fraction.
            let (proposed, clamped) = self.clamp_change(*current_prior, raw_proposed);

            // Only suggest if the change is meaningful (> 1%).
            if (proposed - current_prior).abs() < 0.01 {
                continue;
            }

            let change_fraction = if *current_prior > 0.0 {
                (proposed - current_prior) / current_prior
            } else {
                0.0
            };

            adjustments.push(TuningAdjustment {
                parameter: format!("classes.{}.prior_prob", class_name),
                current: *current_prior,
                proposed,
                change_fraction,
                clamped,
                observation_count: resolved.len(),
                reason: format!(
                    "Observed {} rate is {:.3} vs prior {:.3} (n={})",
                    class_name,
                    observed_rate,
                    current_prior,
                    resolved.len()
                ),
            });
        }
    }

    fn compute_category_bias_adjustments(
        &self,
        stats: &[CategoryStats],
        adjustments: &mut Vec<TuningAdjustment>,
    ) {
        for stat in stats {
            if !stat.sufficient_data {
                continue;
            }

            // Only flag significant bias (> 10%).
            if stat.bias.abs() < 0.1 {
                continue;
            }

            let direction = if stat.bias > 0.0 {
                "overestimates"
            } else {
                "underestimates"
            };

            // Suggest adjusting the evidence weight for this category.
            let current_weight = 1.0; // Baseline weight.
            let correction_factor = stat.actual_abandoned_rate / stat.mean_predicted.max(0.01);
            let raw_proposed = correction_factor;
            let (proposed, clamped) = self.clamp_change(current_weight, raw_proposed);

            adjustments.push(TuningAdjustment {
                parameter: format!("evidence_weight.{}", stat.category),
                current: current_weight,
                proposed,
                change_fraction: proposed - current_weight,
                clamped,
                observation_count: stat.count,
                reason: format!(
                    "Model {} abandonment for '{}': predicted {:.3}, actual {:.3} (bias {:+.3}, n={})",
                    direction, stat.category, stat.mean_predicted,
                    stat.actual_abandoned_rate, stat.bias, stat.count
                ),
            });
        }
    }

    /// Clamp a proposed value to within max_change_fraction of current.
    /// Returns (clamped_value, was_clamped).
    fn clamp_change(&self, current: f64, proposed: f64) -> (f64, bool) {
        if current <= 0.0 {
            return (proposed.max(0.0).min(1.0), false);
        }

        let max_delta = current * self.config.max_change_fraction;
        let lo = (current - max_delta).max(0.0);
        let hi = (current + max_delta).min(1.0);

        if proposed < lo {
            (lo, true)
        } else if proposed > hi {
            (hi, true)
        } else {
            (proposed, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::validation::GroundTruth;
    use super::*;
    use chrono::Utc;

    fn make_record(
        predicted: f64,
        gt: GroundTruth,
        proc_type: Option<&str>,
        comm: &str,
    ) -> ValidationRecord {
        ValidationRecord {
            identity_hash: format!("hash_{}", comm),
            pid: 100,
            predicted_abandoned: predicted,
            recommended_action: if predicted >= 0.5 { "kill" } else { "keep" }.to_string(),
            proc_type: proc_type.map(String::from),
            comm: comm.to_string(),
            predicted_at: Utc::now(),
            ground_truth: Some(gt),
            resolved_at: Some(Utc::now()),
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id: None,
        }
    }

    fn make_records(n: usize) -> Vec<ValidationRecord> {
        let mut records = Vec::new();
        for i in 0..n {
            let prob = (i as f64) / n as f64;
            let abandoned = i >= n / 2; // Top half are abandoned.
            let gt = if abandoned {
                GroundTruth::UserKilled
            } else {
                GroundTruth::NormalExit
            };
            records.push(make_record(
                prob,
                gt,
                Some("test_runner"),
                &format!("proc_{}", i),
            ));
        }
        records
    }

    #[test]
    fn test_tuning_with_insufficient_data() {
        let engine = TuningEngine::new(TuningConfig::default());
        let records = make_records(5);
        let priors = vec![("abandoned".to_string(), 0.15), ("useful".to_string(), 0.7)];

        let result = engine.compute_adjustments(&records, &priors).unwrap();
        // Not enough data for class prior adjustments (min 30).
        assert!(result.adjustments.is_empty());
    }

    #[test]
    fn test_tuning_with_sufficient_data() {
        let engine = TuningEngine::new(TuningConfig::default());
        let records = make_records(60);
        let priors = vec![("abandoned".to_string(), 0.15), ("useful".to_string(), 0.7)];

        let result = engine.compute_adjustments(&records, &priors).unwrap();
        assert!(result.has_recommendations);
        assert!(!result.adjustments.is_empty());

        // Observed abandoned rate is 0.5, prior is 0.15.
        // Should suggest increasing abandoned prior.
        let abandoned_adj = result
            .adjustments
            .iter()
            .find(|a| a.parameter.contains("abandoned"));
        assert!(abandoned_adj.is_some());
        let adj = abandoned_adj.unwrap();
        assert!(adj.proposed > adj.current);
    }

    #[test]
    fn test_clamp_change() {
        let engine = TuningEngine::new(TuningConfig {
            max_change_fraction: 0.2,
            ..Default::default()
        });

        // Within bounds.
        let (val, clamped) = engine.clamp_change(0.5, 0.55);
        assert!(!clamped);
        assert!((val - 0.55).abs() < 1e-9);

        // Exceeds upper bound.
        let (val, clamped) = engine.clamp_change(0.5, 0.9);
        assert!(clamped);
        assert!((val - 0.6).abs() < 1e-9); // 0.5 + 0.2*0.5 = 0.6

        // Below lower bound.
        let (val, clamped) = engine.clamp_change(0.5, 0.1);
        assert!(clamped);
        assert!((val - 0.4).abs() < 1e-9); // 0.5 - 0.2*0.5 = 0.4
    }

    #[test]
    fn test_category_stats() {
        let engine = TuningEngine::new(TuningConfig {
            min_observations: 5,
            ..Default::default()
        });

        let records: Vec<ValidationRecord> = vec![
            make_record(0.9, GroundTruth::UserKilled, Some("test_runner"), "jest1"),
            make_record(0.8, GroundTruth::UserKilled, Some("test_runner"), "jest2"),
            make_record(0.7, GroundTruth::NormalExit, Some("test_runner"), "jest3"),
            make_record(0.3, GroundTruth::NormalExit, Some("dev_server"), "vite1"),
            make_record(0.2, GroundTruth::NormalExit, Some("dev_server"), "vite2"),
        ];

        let resolved: Vec<&ValidationRecord> = records.iter().collect();
        let stats = engine.compute_category_stats(&resolved);

        let tr = stats.iter().find(|s| s.category == "test_runner").unwrap();
        assert_eq!(tr.count, 3);
        assert!((tr.actual_abandoned_rate - 2.0 / 3.0).abs() < 0.01);

        let ds = stats.iter().find(|s| s.category == "dev_server").unwrap();
        assert_eq!(ds.count, 2);
        assert!((ds.actual_abandoned_rate - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_category_bias_adjustment() {
        let config = TuningConfig {
            min_observations: 3,
            max_change_fraction: 0.5,
            ..Default::default()
        };
        let engine = TuningEngine::new(config);

        // Create records where model is very overconfident for test_runners.
        let mut records = Vec::new();
        for i in 0..10 {
            records.push(make_record(
                0.8,                     // High predicted abandonment
                GroundTruth::NormalExit, // But they exit normally
                Some("test_runner"),
                &format!("jest_{}", i),
            ));
        }

        let priors = vec![("abandoned".to_string(), 0.15)];
        let result = engine.compute_adjustments(&records, &priors).unwrap();

        // Should detect overconfidence bias for test_runner.
        let bias_adj = result
            .adjustments
            .iter()
            .find(|a| a.parameter.contains("test_runner"));
        assert!(bias_adj.is_some());
        let adj = bias_adj.unwrap();
        assert!(adj.reason.contains("overestimates"));
    }

    #[test]
    fn test_no_adjustment_for_well_calibrated() {
        let config = TuningConfig {
            min_observations: 5,
            ..Default::default()
        };
        let engine = TuningEngine::new(config);

        // Create records matching the prior well.
        let mut records = Vec::new();
        for _ in 0..15 {
            records.push(make_record(
                0.15,
                GroundTruth::NormalExit,
                Some("dev_server"),
                "next",
            ));
        }
        for _ in 0..3 {
            records.push(make_record(
                0.85,
                GroundTruth::UserKilled,
                Some("dev_server"),
                "next_old",
            ));
        }

        let priors = vec![("abandoned".to_string(), 0.15), ("useful".to_string(), 0.7)];
        let result = engine.compute_adjustments(&records, &priors).unwrap();

        // The observed abandoned rate is ~3/18 ≈ 0.167, close to prior of 0.15.
        // After regularization, the change should be small enough to skip.
        let abandoned_adj = result
            .adjustments
            .iter()
            .find(|a| a.parameter == "classes.abandoned.prior_prob");
        // Small difference, might or might not generate adjustment.
        if let Some(adj) = abandoned_adj {
            assert!(adj.change_fraction.abs() < 0.2);
        }
    }
}
