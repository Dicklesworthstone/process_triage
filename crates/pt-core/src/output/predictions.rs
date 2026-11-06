//! Structured prediction output for agent consumption.
//!
//! Defines the `Predictions` schema that can be optionally included in
//! agent-oriented JSON output (gated behind `--include-predictions`).
//! Covers memory slope, CPU trend, ETAs, and trajectory confidence.
//!
//! Token-efficient: fields are `skip_serializing_if` by default so only
//! populated fields appear in output.

use serde::{Deserialize, Serialize};

use crate::calibrate::cpu_trend::{analyze_cpu_trend, CpuSample, CpuTrendConfig, CpuTrendLabel};
use crate::calibrate::mem_growth::{estimate_mem_growth, MemGrowthConfig, MemSample};

// ---------------------------------------------------------------------------
// Top-level predictions container
// ---------------------------------------------------------------------------

/// One measured resource observation for a single, externally verified process
/// incarnation. Missing measurements stay unknown rather than becoming zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSample {
    /// Observation time, in milliseconds since the Unix epoch.
    pub observed_at_unix_ms: i64,
    /// Measured resident memory, when available.
    pub rss_bytes: Option<u64>,
    /// Windowed CPU usage in percent, where 100 is one fully occupied core.
    /// Lifetime-average CPU usage must not be supplied here.
    pub cpu_percent: Option<f64>,
}

/// Per-process prediction output (opt-in via `--include-predictions`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Predictions {
    /// Memory trend prediction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryPrediction>,

    /// CPU trend prediction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuPrediction>,

    /// Estimated time to abandonment (if trending that way).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_abandoned: Option<EtaPrediction>,

    /// Estimated time to resource exhaustion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_resource_limit: Option<EtaPrediction>,

    /// Overall trajectory assessment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trajectory: Option<TrajectoryAssessment>,

    /// Diagnostics about prediction quality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<PredictionDiagnostics>,
}

impl Predictions {
    /// Returns true if all fields are None (nothing to show).
    pub fn is_empty(&self) -> bool {
        self.memory.is_none()
            && self.cpu.is_none()
            && self.eta_abandoned.is_none()
            && self.eta_resource_limit.is_none()
            && self.trajectory.is_none()
            && self.diagnostics.is_none()
    }
}

// ---------------------------------------------------------------------------
// Prediction components
// ---------------------------------------------------------------------------

/// Memory trend prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPrediction {
    /// RSS slope in bytes/second (positive = growing).
    pub rss_slope_bytes_per_sec: f64,
    /// Trend direction.
    pub trend: Trend,
    /// Linear fit quality (R², 0..1), or zero for an unresolved trend.
    /// This is model support, not an empirically calibrated probability.
    pub confidence: f64,
    /// Observation window in seconds.
    pub window_secs: f64,
}

/// CPU trend prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuPrediction {
    /// CPU usage slope in percent/second.
    pub usage_slope_pct_per_sec: f64,
    /// Trend direction.
    pub trend: Trend,
    /// Model support from sample count, fit and variability (0..1).
    /// This is not an empirically calibrated probability.
    pub confidence: f64,
    /// Observation window in seconds.
    pub window_secs: f64,
}

/// ETA prediction (time until some event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtaPrediction {
    /// Estimated seconds until the event.
    pub eta_secs: f64,
    /// Confidence in the estimate (0..1).
    pub confidence: f64,
    /// Lower bound of credible interval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lower_bound_secs: Option<f64>,
    /// Upper bound of credible interval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper_bound_secs: Option<f64>,
}

/// Observed trend direction or shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trend {
    Rising,
    Stable,
    Falling,
    /// Resource usage varies substantially within the observed window.
    Bursty,
    /// The observations do not support a definite direction.
    Unknown,
}

/// Overall trajectory assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryAssessment {
    /// Current trajectory label.
    pub label: TrajectoryLabel,
    /// Support from the underlying resource model (0..1), not an empirically
    /// calibrated probability of this trajectory or of abandonment.
    pub confidence: f64,
    /// Human-readable one-liner.
    pub summary: String,
}

/// Trajectory labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryLabel {
    /// Process is becoming more idle over time.
    WindingDown,
    /// Process is stable with consistent resource usage.
    Steady,
    /// Process resource usage is growing.
    Growing,
    /// Process shows erratic behaviour.
    Erratic,
    /// Insufficient data to assess.
    Unknown,
}

/// Diagnostics about prediction quality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionDiagnostics {
    /// Number of valid observations with at least one measured resource.
    /// Individual resource models may use fewer when measurements are absent.
    pub n_observations: usize,
    /// Whether predictions are within a calibrated regime.
    pub calibrated: bool,
    /// Model used for predictions.
    pub model: String,
    /// Any warnings about prediction quality.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Estimate resource trends from observed history of one process incarnation.
///
/// The caller must establish process identity and host identity before supplying
/// history. Samples must have strictly increasing, unique timestamps. Invalid
/// CPU measurements or ambiguous ordering reject the series; unknown resources
/// remain absent. The existing estimators retain their default evidence limits:
/// ten memory samples spanning 60 seconds and five CPU samples spanning 30 seconds.
///
/// Confidence describes fit and sample support only. No abandonment or resource
/// exhaustion ETA is inferred from these observations, and calibration remains
/// false until an independent calibration dataset establishes it.
pub fn build_observed_predictions(samples: &[ResourceSample]) -> Predictions {
    let mut result = Predictions {
        trajectory: Some(TrajectoryAssessment {
            label: TrajectoryLabel::Unknown,
            confidence: 0.0,
            summary: "Insufficient observed resource history to assess a trajectory".to_string(),
        }),
        diagnostics: Some(PredictionDiagnostics {
            n_observations: 0,
            calibrated: false,
            model: "observed_resource_trends".to_string(),
            warnings: vec!["confidence_is_model_support_not_calibrated_probability".to_string()],
        }),
        ..Predictions::default()
    };
    let diagnostics = result
        .diagnostics
        .as_mut()
        .expect("diagnostics initialized");
    if samples.is_empty() {
        diagnostics
            .warnings
            .push("insufficient_history".to_string());
        return result;
    }

    if samples
        .windows(2)
        .any(|pair| pair[0].observed_at_unix_ms >= pair[1].observed_at_unix_ms)
    {
        diagnostics
            .warnings
            .push("timestamps_must_be_strictly_increasing_and_unique".to_string());
        return result;
    }
    if samples.iter().any(|sample| {
        sample
            .cpu_percent
            .is_some_and(|cpu| !cpu.is_finite() || cpu < 0.0)
    }) {
        diagnostics
            .warnings
            .push("cpu_measurements_must_be_finite_and_nonnegative".to_string());
        return result;
    }

    // Center each resource on its own first measured observation. A much older
    // sample of the other resource (or of neither) must not leave epoch-sized
    // inputs in a filtered regression. Subtract integers before converting to
    // floats so closely spaced observations keep their original precision.
    let mut memory_origin = None;
    let memory_samples: Vec<MemSample> = samples
        .iter()
        .filter_map(|sample| {
            sample.rss_bytes.map(|rss_bytes| {
                let origin = *memory_origin.get_or_insert(sample.observed_at_unix_ms);
                MemSample {
                    t: (i128::from(sample.observed_at_unix_ms) - i128::from(origin)) as f64
                        / 1000.0,
                    rss_bytes,
                    uss_bytes: None,
                }
            })
        })
        .collect();
    let mut cpu_origin = None;
    let cpu_samples: Vec<CpuSample> = samples
        .iter()
        .filter_map(|sample| {
            sample.cpu_percent.map(|cpu| {
                let origin = *cpu_origin.get_or_insert(sample.observed_at_unix_ms);
                CpuSample {
                    t: (i128::from(sample.observed_at_unix_ms) - i128::from(origin)) as f64
                        / 1000.0,
                    cpu_frac: cpu / 100.0,
                }
            })
        })
        .collect();
    if memory_samples.windows(2).any(|pair| pair[0].t >= pair[1].t)
        || cpu_samples.windows(2).any(|pair| pair[0].t >= pair[1].t)
    {
        diagnostics
            .warnings
            .push("timestamp_span_exceeds_model_precision".to_string());
        return result;
    }

    diagnostics.n_observations = samples
        .iter()
        .filter(|sample| sample.rss_bytes.is_some() || sample.cpu_percent.is_some())
        .count();
    match estimate_mem_growth(&memory_samples, &MemGrowthConfig::default(), None) {
        Ok(estimate)
            if estimate.slope_bytes_per_sec.is_finite()
                && estimate.slope_ci_low.is_finite()
                && estimate.slope_ci_high.is_finite()
                && estimate.r_squared.is_finite() =>
        {
            let trend = if !estimate.diagnostics.reliable {
                diagnostics.warnings.push(format!(
                    "memory_estimate_unreliable: {}",
                    estimate
                        .diagnostics
                        .unreliable_reason
                        .as_deref()
                        .unwrap_or("insufficient model support")
                ));
                Trend::Unknown
            } else if estimate.slope_ci_low > 0.0 {
                Trend::Rising
            } else if estimate.slope_ci_high < 0.0 {
                Trend::Falling
            } else {
                diagnostics
                    .warnings
                    .push("memory_slope_interval_includes_zero".to_string());
                Trend::Unknown
            };
            result.memory = Some(MemoryPrediction {
                rss_slope_bytes_per_sec: estimate.slope_bytes_per_sec,
                trend,
                confidence: if trend == Trend::Unknown {
                    0.0
                } else {
                    estimate.r_squared.clamp(0.0, 1.0)
                },
                window_secs: estimate.diagnostics.time_span_secs,
            });
        }
        Ok(_) => diagnostics
            .warnings
            .push("memory_estimate_not_finite".to_string()),
        Err(error) => diagnostics.warnings.push(format!("memory: {error}")),
    }

    match analyze_cpu_trend(&cpu_samples, &CpuTrendConfig::default(), None) {
        Ok(estimate)
            if (estimate.slope_per_sec * 100.0).is_finite()
                && estimate.confidence.is_finite()
                && estimate.r_squared.is_finite()
                && estimate.variance.is_finite()
                && estimate.cv.is_finite()
                && estimate.smoothed_current.is_finite() =>
        {
            let trend = match estimate.label {
                CpuTrendLabel::Increasing => Trend::Rising,
                CpuTrendLabel::Stable => Trend::Stable,
                CpuTrendLabel::Decreasing => Trend::Falling,
                CpuTrendLabel::Bursty => Trend::Bursty,
                CpuTrendLabel::Unknown => Trend::Unknown,
            };
            if trend == Trend::Unknown {
                diagnostics
                    .warnings
                    .push("cpu_trend_unresolved".to_string());
            }
            result.cpu = Some(CpuPrediction {
                usage_slope_pct_per_sec: estimate.slope_per_sec * 100.0,
                trend,
                confidence: estimate.confidence.clamp(0.0, 1.0),
                window_secs: estimate.window_secs,
            });
        }
        Ok(_) => diagnostics
            .warnings
            .push("cpu_estimate_not_finite".to_string()),
        Err(error) => diagnostics.warnings.push(format!("cpu: {error}")),
    }

    result.trajectory = Some(observed_trajectory(
        result.memory.as_ref(),
        result.cpu.as_ref(),
    ));
    result
}

fn observed_trajectory(
    memory: Option<&MemoryPrediction>,
    cpu: Option<&CpuPrediction>,
) -> TrajectoryAssessment {
    let memory_trend = memory.map(|estimate| estimate.trend);
    let cpu_trend = cpu.map(|estimate| estimate.trend);
    let (label, confidence, summary) = match (memory_trend, cpu_trend) {
        (_, Some(Trend::Bursty)) => (
            TrajectoryLabel::Erratic,
            cpu.map_or(0.0, |estimate| estimate.confidence),
            "Windowed CPU usage is bursty across the recorded observations",
        ),
        (Some(Trend::Rising), Some(Trend::Falling))
        | (Some(Trend::Falling), Some(Trend::Rising)) => (
            TrajectoryLabel::Unknown,
            0.0,
            "RSS and CPU trends point in different directions; inspect the individual estimates",
        ),
        (Some(Trend::Rising), Some(Trend::Rising)) => (
            TrajectoryLabel::Growing,
            memory
                .map_or(0.0, |estimate| estimate.confidence)
                .min(cpu.map_or(0.0, |estimate| estimate.confidence)),
            "RSS and windowed CPU usage are increasing across the recorded observations",
        ),
        (Some(Trend::Rising), _) => (
            TrajectoryLabel::Growing,
            memory.map_or(0.0, |estimate| estimate.confidence),
            "RSS is increasing across the recorded observations",
        ),
        (_, Some(Trend::Rising)) => (
            TrajectoryLabel::Growing,
            cpu.map_or(0.0, |estimate| estimate.confidence),
            "Windowed CPU usage is increasing across the recorded observations",
        ),
        (_, Some(Trend::Falling)) => (
            TrajectoryLabel::WindingDown,
            cpu.map_or(0.0, |estimate| estimate.confidence),
            "Windowed CPU usage is decreasing across the recorded observations",
        ),
        (_, Some(Trend::Stable)) => (
            TrajectoryLabel::Steady,
            cpu.map_or(0.0, |estimate| estimate.confidence),
            "Windowed CPU usage is steady across the recorded observations",
        ),
        _ => (
            TrajectoryLabel::Unknown,
            0.0,
            "The observed resources do not establish an overall trajectory",
        ),
    };
    TrajectoryAssessment {
        label,
        confidence,
        summary: summary.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Field selection
// ---------------------------------------------------------------------------

/// Select which prediction subfields to include.
#[derive(Debug, Clone, Default)]
pub struct PredictionFieldSelector {
    /// If non-empty, only include these fields.
    pub include: Vec<PredictionField>,
}

/// Selectable prediction fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionField {
    Memory,
    Cpu,
    EtaAbandoned,
    EtaResourceLimit,
    Trajectory,
    Diagnostics,
}

/// Apply field selection to predictions, clearing non-selected fields.
pub fn apply_field_selection(
    predictions: &Predictions,
    selector: &PredictionFieldSelector,
) -> Predictions {
    if selector.include.is_empty() {
        return predictions.clone();
    }

    let has = |f: PredictionField| selector.include.contains(&f);

    Predictions {
        memory: if has(PredictionField::Memory) {
            predictions.memory.clone()
        } else {
            None
        },
        cpu: if has(PredictionField::Cpu) {
            predictions.cpu.clone()
        } else {
            None
        },
        eta_abandoned: if has(PredictionField::EtaAbandoned) {
            predictions.eta_abandoned.clone()
        } else {
            None
        },
        eta_resource_limit: if has(PredictionField::EtaResourceLimit) {
            predictions.eta_resource_limit.clone()
        } else {
            None
        },
        trajectory: if has(PredictionField::Trajectory) {
            predictions.trajectory.clone()
        } else {
            None
        },
        diagnostics: if has(PredictionField::Diagnostics) {
            predictions.diagnostics.clone()
        } else {
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn observations(count: usize, step_ms: i64) -> Vec<ResourceSample> {
        (0..count)
            .map(|index| ResourceSample {
                observed_at_unix_ms: 1_800_000_000_000 + index as i64 * step_ms,
                rss_bytes: None,
                cpu_percent: None,
            })
            .collect()
    }

    fn growing_observations() -> Vec<ResourceSample> {
        observations(20, 10_000)
            .into_iter()
            .enumerate()
            .map(|(index, mut sample)| {
                sample.rss_bytes = Some(64 * 1024 * 1024 + index as u64 * 10 * 1024);
                sample.cpu_percent = Some(150.0 + index as f64 * 2.0);
                sample
            })
            .collect()
    }

    #[test]
    fn observed_memory_and_multicore_cpu_growth_use_measured_units() {
        let predictions = build_observed_predictions(&growing_observations());
        let memory = predictions.memory.as_ref().unwrap();
        assert!((memory.rss_slope_bytes_per_sec - 1024.0).abs() < 0.01);
        assert_eq!(memory.trend, Trend::Rising);
        assert!(memory.confidence > 0.99);
        assert_eq!(memory.window_secs, 190.0);
        let cpu = predictions.cpu.as_ref().unwrap();
        assert!((cpu.usage_slope_pct_per_sec - 0.2).abs() < 1e-10);
        assert_eq!(cpu.trend, Trend::Rising);
        assert_eq!(cpu.window_secs, 190.0);
        assert_eq!(
            predictions.trajectory.as_ref().unwrap().label,
            TrajectoryLabel::Growing
        );
        let diagnostics = predictions.diagnostics.as_ref().unwrap();
        assert_eq!(diagnostics.n_observations, 20);
        assert!(!diagnostics.calibrated);
        assert!(diagnostics.warnings.iter().any(|warning| {
            warning == "confidence_is_model_support_not_calibrated_probability"
        }));
        assert!(predictions.eta_abandoned.is_none());
        assert!(predictions.eta_resource_limit.is_none());
    }

    #[test]
    fn observed_cpu_bursts_are_not_reported_as_stable() {
        let mut samples = observations(20, 10_000);
        for (index, sample) in samples.iter_mut().enumerate() {
            sample.cpu_percent = Some(if index % 2 == 0 { 0.0 } else { 200.0 });
        }
        let predictions = build_observed_predictions(&samples);
        assert!(predictions.memory.is_none());
        assert_eq!(predictions.cpu.as_ref().unwrap().trend, Trend::Bursty);
        assert_eq!(
            predictions.trajectory.as_ref().unwrap().label,
            TrajectoryLabel::Erratic
        );
        assert_eq!(
            serde_json::to_value(&predictions).unwrap()["cpu"]["trend"],
            "bursty"
        );
    }

    #[test]
    fn observed_cpu_can_be_steady_including_measured_zero_usage() {
        for cpu_percent in [0.0, 200.0] {
            let mut samples = observations(20, 10_000);
            for sample in &mut samples {
                sample.cpu_percent = Some(cpu_percent);
            }
            let predictions = build_observed_predictions(&samples);
            let cpu = predictions.cpu.as_ref().unwrap();
            assert_eq!(cpu.trend, Trend::Stable);
            assert_eq!(cpu.usage_slope_pct_per_sec, 0.0);
            assert_eq!(
                predictions.trajectory.as_ref().unwrap().label,
                TrajectoryLabel::Steady
            );
            assert!(!predictions.diagnostics.as_ref().unwrap().calibrated);
        }
    }

    #[test]
    fn conflicting_resource_directions_do_not_imply_one_trajectory() {
        let mut samples = growing_observations();
        for (index, sample) in samples.iter_mut().enumerate() {
            sample.cpu_percent = Some(100.0 - index as f64 * 3.0);
        }
        let predictions = build_observed_predictions(&samples);
        assert_eq!(predictions.memory.as_ref().unwrap().trend, Trend::Rising);
        assert_eq!(predictions.cpu.as_ref().unwrap().trend, Trend::Falling);
        assert_eq!(
            predictions.trajectory.as_ref().unwrap().label,
            TrajectoryLabel::Unknown
        );
        assert_eq!(predictions.trajectory.as_ref().unwrap().confidence, 0.0);
    }

    #[test]
    fn observations_retain_existing_sample_and_window_thresholds() {
        let empty = build_observed_predictions(&[]);
        assert_eq!(empty.diagnostics.as_ref().unwrap().n_observations, 0);
        assert!(empty.memory.is_none());
        assert!(empty.cpu.is_none());

        let few = build_observed_predictions(&growing_observations()[..4]);
        assert_eq!(few.diagnostics.as_ref().unwrap().n_observations, 4);
        assert!(few.memory.is_none());
        assert!(few.cpu.is_none());

        let mut short = growing_observations();
        for (index, sample) in short.iter_mut().enumerate() {
            sample.observed_at_unix_ms = 1_800_000_000_000 + index as i64 * 100;
        }
        let predictions = build_observed_predictions(&short);
        assert!(predictions.memory.is_none());
        assert!(predictions.cpu.is_none());
        assert!(predictions
            .diagnostics
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning.contains("Time span too short")));

        let mut cpu_boundary = observations(5, 7_500);
        for sample in &mut cpu_boundary {
            sample.cpu_percent = Some(25.0);
        }
        assert!(build_observed_predictions(&cpu_boundary).cpu.is_some());
        cpu_boundary.last_mut().unwrap().observed_at_unix_ms -= 1;
        assert!(build_observed_predictions(&cpu_boundary).cpu.is_none());

        let mut memory_boundary = growing_observations()[..10].to_vec();
        for (index, sample) in memory_boundary.iter_mut().enumerate() {
            sample.observed_at_unix_ms = 1_800_000_000_000 + index as i64 * 6_000;
        }
        memory_boundary.last_mut().unwrap().observed_at_unix_ms = 1_800_000_060_000;
        let predictions = build_observed_predictions(&memory_boundary);
        let memory = predictions.memory.as_ref().unwrap();
        // The estimator's default trimming leaves eight samples, so a slope can
        // be shown but its direction remains unsupported at this boundary.
        assert_eq!(memory.trend, Trend::Unknown);
        assert_eq!(memory.confidence, 0.0);
        memory_boundary.last_mut().unwrap().observed_at_unix_ms -= 1;
        assert!(build_observed_predictions(&memory_boundary)
            .memory
            .is_none());
    }

    #[test]
    fn unknown_resource_values_do_not_become_zero_measurements() {
        let empty_resources = build_observed_predictions(&observations(20, 10_000));
        assert_eq!(
            empty_resources.diagnostics.as_ref().unwrap().n_observations,
            0
        );
        assert!(empty_resources.memory.is_none());
        assert!(empty_resources.cpu.is_none());

        let mut samples = growing_observations();
        for sample in &mut samples[4..] {
            sample.cpu_percent = None;
        }
        let predictions = build_observed_predictions(&samples);
        assert_eq!(predictions.memory.as_ref().unwrap().trend, Trend::Rising);
        assert!(predictions.cpu.is_none());
        assert_eq!(predictions.diagnostics.as_ref().unwrap().n_observations, 20);
    }

    #[test]
    fn shuffled_and_duplicate_timestamps_reject_the_entire_series() {
        let mut shuffled = growing_observations();
        shuffled.swap(5, 6);
        let mut duplicate = growing_observations();
        duplicate[6] = duplicate[5].clone();
        let mut conflicting = growing_observations();
        conflicting[6].observed_at_unix_ms = conflicting[5].observed_at_unix_ms;
        for samples in [shuffled, duplicate, conflicting] {
            let predictions = build_observed_predictions(&samples);
            assert!(predictions.memory.is_none());
            assert!(predictions.cpu.is_none());
            let diagnostics = predictions.diagnostics.as_ref().unwrap();
            assert_eq!(diagnostics.n_observations, 0);
            assert!(diagnostics
                .warnings
                .iter()
                .any(|warning| { warning == "timestamps_must_be_strictly_increasing_and_unique" }));
        }
    }

    #[test]
    fn invalid_cpu_measurements_reject_the_series_without_fabricated_values() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut samples = growing_observations();
            samples[5].cpu_percent = Some(invalid);
            let predictions = build_observed_predictions(&samples);
            assert!(predictions.memory.is_none());
            assert!(predictions.cpu.is_none());
            let diagnostics = predictions.diagnostics.as_ref().unwrap();
            assert_eq!(diagnostics.n_observations, 0);
            assert!(diagnostics
                .warnings
                .iter()
                .any(|warning| { warning == "cpu_measurements_must_be_finite_and_nonnegative" }));
        }
    }

    #[test]
    fn finite_cpu_inputs_cannot_publish_overflowed_model_results() {
        let mut samples = observations(20, 10_000);
        for sample in &mut samples {
            sample.cpu_percent = Some(f64::MAX);
        }
        let predictions = build_observed_predictions(&samples);
        assert!(predictions.cpu.is_none());
        assert!(predictions
            .diagnostics
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning == "cpu_estimate_not_finite"));
    }

    #[test]
    fn relative_timestamps_preserve_slopes_near_the_integer_limit() {
        let samples = growing_observations();
        let mut shifted = samples.clone();
        for (index, sample) in shifted.iter_mut().enumerate() {
            sample.observed_at_unix_ms = i64::MAX - 600_000 + index as i64 * 10_000;
        }
        let original = build_observed_predictions(&samples);
        let shifted = build_observed_predictions(&shifted);
        assert!(
            (original.memory.unwrap().rss_slope_bytes_per_sec
                - shifted.memory.unwrap().rss_slope_bytes_per_sec)
                .abs()
                < 1e-6
        );
        assert!(
            (original.cpu.unwrap().usage_slope_pct_per_sec
                - shifted.cpu.unwrap().usage_slope_pct_per_sec)
                .abs()
                < 1e-10
        );

        let mut unrepresentable = observations(3, 1);
        unrepresentable[0].observed_at_unix_ms = i64::MIN;
        unrepresentable[1].observed_at_unix_ms = i64::MAX - 1;
        unrepresentable[2].observed_at_unix_ms = i64::MAX;
        for sample in &mut unrepresentable {
            sample.cpu_percent = Some(25.0);
        }
        let predictions = build_observed_predictions(&unrepresentable);
        assert!(predictions
            .diagnostics
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning == "timestamp_span_exceeds_model_precision"));
    }

    #[test]
    fn delayed_resource_observations_use_their_own_time_origin() {
        let mut cpu_history = growing_observations();
        for sample in &mut cpu_history {
            sample.rss_bytes = None;
        }
        cpu_history.insert(
            0,
            ResourceSample {
                observed_at_unix_ms: 0,
                rss_bytes: Some(64 * 1024 * 1024),
                cpu_percent: None,
            },
        );
        let predictions = build_observed_predictions(&cpu_history);
        assert!(predictions.memory.is_none());
        let cpu = predictions.cpu.unwrap();
        assert_eq!(cpu.trend, Trend::Rising);
        assert!((cpu.usage_slope_pct_per_sec - 0.2).abs() < 1e-10);
        assert_eq!(cpu.window_secs, 190.0);

        let mut memory_history = growing_observations();
        for sample in &mut memory_history {
            sample.cpu_percent = None;
        }
        memory_history.insert(
            0,
            ResourceSample {
                observed_at_unix_ms: 0,
                rss_bytes: None,
                cpu_percent: Some(25.0),
            },
        );
        let predictions = build_observed_predictions(&memory_history);
        assert!(predictions.cpu.is_none());
        let memory = predictions.memory.unwrap();
        assert_eq!(memory.trend, Trend::Rising);
        assert!((memory.rss_slope_bytes_per_sec - 1024.0).abs() < 0.01);
        assert_eq!(memory.window_secs, 190.0);

        let mut empty_prefix = growing_observations();
        empty_prefix.insert(
            0,
            ResourceSample {
                observed_at_unix_ms: i64::MIN,
                rss_bytes: None,
                cpu_percent: None,
            },
        );
        let predictions = build_observed_predictions(&empty_prefix);
        assert_eq!(predictions.diagnostics.as_ref().unwrap().n_observations, 20);
        assert_eq!(predictions.memory.unwrap().trend, Trend::Rising);
        assert_eq!(predictions.cpu.unwrap().trend, Trend::Rising);
    }

    fn sample_predictions() -> Predictions {
        Predictions {
            memory: Some(MemoryPrediction {
                rss_slope_bytes_per_sec: -1024.0,
                trend: Trend::Falling,
                confidence: 0.85,
                window_secs: 3600.0,
            }),
            cpu: Some(CpuPrediction {
                usage_slope_pct_per_sec: -0.001,
                trend: Trend::Falling,
                confidence: 0.72,
                window_secs: 3600.0,
            }),
            eta_abandoned: Some(EtaPrediction {
                eta_secs: 86400.0,
                confidence: 0.6,
                lower_bound_secs: Some(43200.0),
                upper_bound_secs: Some(172800.0),
            }),
            eta_resource_limit: None,
            trajectory: Some(TrajectoryAssessment {
                label: TrajectoryLabel::WindingDown,
                confidence: 0.78,
                summary: "Process is gradually becoming idle.".to_string(),
            }),
            diagnostics: Some(PredictionDiagnostics {
                n_observations: 48,
                calibrated: true,
                model: "kalman".to_string(),
                warnings: vec![],
            }),
        }
    }

    #[test]
    fn test_empty_predictions() {
        let p = Predictions::default();
        assert!(p.is_empty());
    }

    #[test]
    fn test_non_empty_predictions() {
        let p = sample_predictions();
        assert!(!p.is_empty());
    }

    #[test]
    fn test_serialization_skips_none() {
        let p = Predictions {
            memory: Some(MemoryPrediction {
                rss_slope_bytes_per_sec: 0.0,
                trend: Trend::Stable,
                confidence: 0.5,
                window_secs: 60.0,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("memory"));
        assert!(!json.contains("cpu"));
        assert!(!json.contains("trajectory"));
    }

    #[test]
    fn test_full_roundtrip() {
        let p = sample_predictions();
        let json = serde_json::to_string_pretty(&p).unwrap();
        let restored: Predictions = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.memory.as_ref().unwrap().trend, Trend::Falling);
        assert_eq!(
            restored.trajectory.as_ref().unwrap().label,
            TrajectoryLabel::WindingDown,
        );
    }

    #[test]
    fn test_field_selection_all() {
        let p = sample_predictions();
        let selector = PredictionFieldSelector::default(); // empty = include all
        let filtered = apply_field_selection(&p, &selector);
        assert!(filtered.memory.is_some());
        assert!(filtered.cpu.is_some());
        assert!(filtered.trajectory.is_some());
    }

    #[test]
    fn test_field_selection_memory_only() {
        let p = sample_predictions();
        let selector = PredictionFieldSelector {
            include: vec![PredictionField::Memory],
        };
        let filtered = apply_field_selection(&p, &selector);
        assert!(filtered.memory.is_some());
        assert!(filtered.cpu.is_none());
        assert!(filtered.trajectory.is_none());
        assert!(filtered.diagnostics.is_none());
    }

    #[test]
    fn test_field_selection_multiple() {
        let p = sample_predictions();
        let selector = PredictionFieldSelector {
            include: vec![PredictionField::Memory, PredictionField::Trajectory],
        };
        let filtered = apply_field_selection(&p, &selector);
        assert!(filtered.memory.is_some());
        assert!(filtered.cpu.is_none());
        assert!(filtered.trajectory.is_some());
    }

    #[test]
    fn test_eta_bounds_serialization() {
        let eta = EtaPrediction {
            eta_secs: 3600.0,
            confidence: 0.8,
            lower_bound_secs: None,
            upper_bound_secs: None,
        };
        let json = serde_json::to_string(&eta).unwrap();
        assert!(!json.contains("lower_bound"));
        assert!(!json.contains("upper_bound"));
    }

    #[test]
    fn test_diagnostics_warnings_skipped_when_empty() {
        let diag = PredictionDiagnostics {
            n_observations: 10,
            calibrated: false,
            model: "linear".to_string(),
            warnings: vec![],
        };
        let json = serde_json::to_string(&diag).unwrap();
        assert!(!json.contains("warnings"));
    }

    #[test]
    fn test_trend_values() {
        let json_rising = serde_json::to_string(&Trend::Rising).unwrap();
        assert_eq!(json_rising, "\"rising\"");

        let json_stable = serde_json::to_string(&Trend::Stable).unwrap();
        assert_eq!(json_stable, "\"stable\"");
    }
}
