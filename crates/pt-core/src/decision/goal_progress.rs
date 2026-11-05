//! Post-apply goal progress measurement and discrepancy logging.
//!
//! Closes the loop between expected and actual goal achievement by
//! comparing predicted vs observed outcomes and logging discrepancies
//! for calibration.

use serde::{Deserialize, Serialize};

/// Metric snapshot (before or after action application).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    /// Total available memory bytes; absent when the reading is unavailable.
    pub available_memory_bytes: Option<u64>,
    /// Interval-derived host CPU utilization fraction in [0, 1].
    /// Lifetime process CPU averages are not comparable before/after samples.
    pub total_cpu_frac: Option<f64>,
    /// Complete set of occupied ports; an absent census is not an empty set.
    pub occupied_ports: Option<Vec<u16>>,
    /// Total open file descriptors in a consistent, completely observed scope.
    pub total_fds: Option<u64>,
    /// Timestamp (epoch seconds).
    pub timestamp: f64,
}

/// Outcome of a single action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// Process identifier.
    pub pid: u32,
    /// Label.
    pub label: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Whether a respawn was detected.
    pub respawn_detected: bool,
    /// Expected contribution in the same units and scope as the measured metric.
    /// CPU predictions must be host utilization fractions, not lifetime process
    /// CPU or cores. `None` means no comparable prediction; zero is `Some(0.0)`.
    #[serde(default)]
    pub expected_contribution: Option<f64>,
}

/// Goal progress measurement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalProgressReport {
    /// Complete expected total, absent if any action's prediction is unavailable
    /// or invalid. A known subtotal is not a prediction for the whole action set.
    #[serde(default)]
    pub expected_progress: Option<f64>,
    /// Observed progress, absent unless both required readings are available.
    pub observed_progress: Option<f64>,
    /// Discrepancy (observed - expected), absent without a valid comparison.
    pub discrepancy: Option<f64>,
    /// Discrepancy as a fraction of expected, absent without a valid comparison.
    pub discrepancy_fraction: Option<f64>,
    /// Why measurement or comparison could not be established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_unavailable_reason: Option<String>,
    /// Classification of the discrepancy.
    pub classification: DiscrepancyClass,
    /// Per-action outcomes.
    pub action_outcomes: Vec<ActionOutcome>,
    /// Suspected causes for discrepancy.
    pub suspected_causes: Vec<SuspectedCause>,
    /// Session ID.
    pub session_id: Option<String>,
}

/// Classification of observed vs expected discrepancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscrepancyClass {
    /// Observed matches expected within tolerance.
    AsExpected,
    /// Observed significantly less than expected (underperformance).
    Underperformance,
    /// Observed significantly more than expected (overperformance).
    Overperformance,
    /// No progress observed despite actions.
    NoEffect,
    /// No valid observed-versus-expected comparison can be made.
    Unavailable,
}

impl std::fmt::Display for DiscrepancyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsExpected => write!(f, "as_expected"),
            Self::Underperformance => write!(f, "underperformance"),
            Self::Overperformance => write!(f, "overperformance"),
            Self::NoEffect => write!(f, "no_effect"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Suspected causes for a discrepancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspectedCause {
    pub cause: String,
    pub confidence: f64,
}

/// Metric type for goal measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalMetric {
    Memory,
    Cpu,
    Port,
    FileDescriptors,
}

/// Configuration for progress measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressConfig {
    /// Tolerance for "as expected" classification (fraction).
    pub tolerance: f64,
    /// Threshold below which we classify as "no effect".
    pub no_effect_threshold: f64,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            tolerance: 0.2,
            no_effect_threshold: 0.05,
        }
    }
}

/// Measure goal progress by comparing before/after snapshots.
///
/// Callers must keep collection scope and methods comparable and validate CPU
/// sample windows before supplying them. A valid host delta is an observation,
/// not evidence that a particular action caused the change.
pub fn measure_progress(
    metric: GoalMetric,
    target_port: Option<u16>,
    before: &MetricSnapshot,
    after: &MetricSnapshot,
    action_outcomes: Vec<ActionOutcome>,
    config: &ProgressConfig,
    session_id: Option<String>,
) -> GoalProgressReport {
    let observation = compute_observed_delta(metric, target_port, before, after);
    let observed = observation.as_ref().ok().copied();
    let mut measurement_unavailable_reason = observation.err().map(str::to_string);
    let expected = match compute_expected_total(&action_outcomes) {
        Ok(expected) => Some(expected),
        Err(reason) => {
            match &mut measurement_unavailable_reason {
                Some(existing) => {
                    existing.push_str("; ");
                    existing.push_str(reason);
                }
                missing => *missing = Some(reason.to_string()),
            }
            None
        }
    };
    let mut discrepancy = None;
    let mut discrepancy_fraction = None;
    let mut classification = DiscrepancyClass::Unavailable;

    if let Some((observed, expected)) = observed.zip(expected) {
        if !config.tolerance.is_finite()
            || config.tolerance < 0.0
            || !config.no_effect_threshold.is_finite()
            || !(0.0..=1.0).contains(&config.no_effect_threshold)
        {
            measurement_unavailable_reason =
                Some("The discrepancy classification thresholds are invalid".to_string());
        } else {
            let delta = observed - expected;
            let fraction = if expected.abs() > 1e-12 {
                delta / expected
            } else if observed.abs() > 1e-12 {
                observed.signum() // All observed, nothing expected.
            } else {
                0.0
            };
            if delta.is_finite() && fraction.is_finite() {
                discrepancy = Some(delta);
                discrepancy_fraction = Some(fraction);
                classification = classify_discrepancy(expected, observed, fraction, config);
            } else {
                measurement_unavailable_reason =
                    Some("The observed-versus-expected comparison is not finite".to_string());
            }
        }
    }

    let suspected_causes = if classification == DiscrepancyClass::Unavailable {
        // Missing evidence says nothing about an action's effect or its causes.
        Vec::new()
    } else {
        diagnose_causes(&action_outcomes, classification)
    };

    GoalProgressReport {
        expected_progress: expected,
        observed_progress: observed,
        discrepancy,
        discrepancy_fraction,
        measurement_unavailable_reason,
        classification,
        action_outcomes,
        suspected_causes,
        session_id,
    }
}

fn compute_expected_total(outcomes: &[ActionOutcome]) -> Result<f64, &'static str> {
    if outcomes
        .iter()
        .any(|action| action.expected_contribution.is_none())
    {
        return Err("Expected contribution is unavailable for one or more actions");
    }
    if outcomes
        .iter()
        .filter_map(|action| action.expected_contribution)
        .any(|value| !value.is_finite() || value < 0.0)
    {
        return Err("Expected contributions must be finite and nonnegative");
    }
    let total: f64 = outcomes
        .iter()
        .filter_map(|action| action.expected_contribution)
        .sum();
    if !total.is_finite() {
        return Err("The complete expected contribution total is not finite");
    }
    Ok(total)
}

fn compute_observed_delta(
    metric: GoalMetric,
    target_port: Option<u16>,
    before: &MetricSnapshot,
    after: &MetricSnapshot,
) -> Result<f64, &'static str> {
    if !before.timestamp.is_finite()
        || !after.timestamp.is_finite()
        || after.timestamp <= before.timestamp
    {
        return Err("Metric observations do not have ordered, finite before/after timestamps");
    }
    match metric {
        GoalMetric::Memory => {
            // Freed memory = after_available - before_available.
            let before = before
                .available_memory_bytes
                .ok_or("Available memory was not observed before application")?;
            let after = after
                .available_memory_bytes
                .ok_or("Available memory was not observed after application")?;
            Ok((i128::from(after) - i128::from(before)) as f64)
        }
        GoalMetric::Cpu => {
            // CPU reduction = before_cpu - after_cpu.
            let before = before
                .total_cpu_frac
                .ok_or("An interval CPU observation is unavailable before application")?;
            let after = after
                .total_cpu_frac
                .ok_or("An interval CPU observation is unavailable after application")?;
            if !before.is_finite()
                || !after.is_finite()
                || !(0.0..=1.0).contains(&before)
                || !(0.0..=1.0).contains(&after)
            {
                return Err("CPU observations must be finite host utilization fractions in [0, 1]");
            }
            Ok(before - after)
        }
        GoalMetric::Port => {
            let before_ports = before
                .occupied_ports
                .as_ref()
                .ok_or("A complete occupied-port census is unavailable before application")?;
            let after_ports = after
                .occupied_ports
                .as_ref()
                .ok_or("A complete occupied-port census is unavailable after application")?;
            if let Some(port) = target_port {
                let was_occupied = before_ports.contains(&port);
                let is_occupied = after_ports.contains(&port);
                if was_occupied && !is_occupied {
                    Ok(1.0)
                } else {
                    Ok(0.0)
                }
            } else {
                let before_ports: std::collections::HashSet<u16> =
                    before_ports.iter().copied().collect();
                let after_ports: std::collections::HashSet<u16> =
                    after_ports.iter().copied().collect();
                Ok(before_ports.difference(&after_ports).count() as f64)
            }
        }
        GoalMetric::FileDescriptors => {
            // FDs freed = before_fds - after_fds.
            let before = before
                .total_fds
                .ok_or("A complete file-descriptor total is unavailable before application")?;
            let after = after
                .total_fds
                .ok_or("A complete file-descriptor total is unavailable after application")?;
            Ok((i128::from(before) - i128::from(after)) as f64)
        }
    }
}

fn classify_discrepancy(
    expected: f64,
    observed: f64,
    frac: f64,
    config: &ProgressConfig,
) -> DiscrepancyClass {
    if expected.abs() < 1e-12 && observed.abs() < 1e-12 {
        return DiscrepancyClass::NoEffect;
    }
    if expected > 0.0 && observed.abs() < expected * config.no_effect_threshold {
        return DiscrepancyClass::NoEffect;
    }
    if frac.abs() <= config.tolerance {
        DiscrepancyClass::AsExpected
    } else if frac < -config.tolerance {
        DiscrepancyClass::Underperformance
    } else {
        DiscrepancyClass::Overperformance
    }
}

fn diagnose_causes(outcomes: &[ActionOutcome], class: DiscrepancyClass) -> Vec<SuspectedCause> {
    let mut causes = Vec::new();

    let respawn_count = outcomes.iter().filter(|a| a.respawn_detected).count();
    let fail_count = outcomes.iter().filter(|a| !a.success).count();

    if class == DiscrepancyClass::Underperformance || class == DiscrepancyClass::NoEffect {
        if respawn_count > 0 {
            causes.push(SuspectedCause {
                cause: format!(
                    "{} process(es) respawned after kill; consider supervisor-level action",
                    respawn_count
                ),
                confidence: 0.9,
            });
        }
        if fail_count > 0 {
            causes.push(SuspectedCause {
                cause: format!("{} action(s) failed to execute", fail_count),
                confidence: 0.95,
            });
        }
    }

    // A host-wide metric delta does not establish shared-memory cleanup,
    // termination of children, or individual action causation. Only execution
    // and identity-bound respawn evidence can support a concrete diagnosis.
    causes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_before() -> MetricSnapshot {
        MetricSnapshot {
            available_memory_bytes: Some(2_000_000_000),
            total_cpu_frac: Some(0.8),
            occupied_ports: Some(vec![3000, 8080]),
            total_fds: Some(5000),
            timestamp: 1000.0,
        }
    }

    fn make_after_good() -> MetricSnapshot {
        MetricSnapshot {
            available_memory_bytes: Some(3_000_000_000), // 1GB freed
            total_cpu_frac: Some(0.5),
            occupied_ports: Some(vec![8080]), // Port 3000 freed
            total_fds: Some(4500),
            timestamp: 1010.0,
        }
    }

    fn make_outcomes(expected: f64, success: bool, respawn: bool) -> Vec<ActionOutcome> {
        vec![ActionOutcome {
            pid: 1234,
            label: "test-process".to_string(),
            success,
            respawn_detected: respawn,
            expected_contribution: Some(expected),
        }]
    }

    #[test]
    fn test_memory_as_expected() {
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &make_after_good(),
            make_outcomes(1_000_000_000.0, true, false),
            &ProgressConfig::default(),
            Some("pt-test".to_string()),
        );
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
        assert!((report.observed_progress.unwrap() - 1_000_000_000.0).abs() < 1.0);
    }

    #[test]
    fn test_underperformance_with_respawn() {
        let after = MetricSnapshot {
            available_memory_bytes: Some(2_100_000_000), // Only 100MB freed
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &after,
            make_outcomes(1_000_000_000.0, true, true),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.classification, DiscrepancyClass::Underperformance);
        assert!(report
            .suspected_causes
            .iter()
            .any(|c| c.cause.contains("respawn")));
    }

    #[test]
    fn test_no_effect() {
        let after = MetricSnapshot {
            available_memory_bytes: Some(2_010_000_000), // ~10MB, negligible
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &after,
            make_outcomes(1_000_000_000.0, false, false),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.classification, DiscrepancyClass::NoEffect);
    }

    #[test]
    fn test_port_release() {
        let report = measure_progress(
            GoalMetric::Port,
            Some(3000),
            &make_before(),
            &make_after_good(),
            make_outcomes(1.0, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
        assert!((report.observed_progress.unwrap() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_port_not_released() {
        let after = MetricSnapshot {
            occupied_ports: Some(vec![3000, 8080]), // Port still occupied
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Port,
            Some(3000),
            &make_before(),
            &after,
            make_outcomes(1.0, true, true),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.observed_progress, Some(0.0));
    }

    #[test]
    fn test_port_release_without_specific_target() {
        let report = measure_progress(
            GoalMetric::Port,
            None,
            &make_before(),
            &make_after_good(),
            make_outcomes(1.0, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.observed_progress, Some(1.0));
    }

    #[test]
    fn test_cpu_reduction() {
        let report = measure_progress(
            GoalMetric::Cpu,
            None,
            &make_before(),
            &make_after_good(),
            make_outcomes(0.3, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert!((report.observed_progress.unwrap() - 0.3).abs() < 0.01);
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
    }

    #[test]
    fn unavailable_prediction_preserves_real_cpu_reduction_without_comparison() {
        let mut outcomes = make_outcomes(0.0, false, true);
        outcomes[0].expected_contribution = None;
        let report = measure_progress(
            GoalMetric::Cpu,
            None,
            &make_before(),
            &make_after_good(),
            outcomes,
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.expected_progress, None);
        assert!((report.observed_progress.unwrap() - 0.3).abs() < 1e-12);
        assert_eq!(report.discrepancy, None);
        assert_eq!(report.discrepancy_fraction, None);
        assert_eq!(report.classification, DiscrepancyClass::Unavailable);
        assert!(report
            .measurement_unavailable_reason
            .as_deref()
            .unwrap()
            .contains("Expected contribution is unavailable"));
        assert!(report.suspected_causes.is_empty());
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["expected_progress"].is_null());
        assert!(json["action_outcomes"][0]["expected_contribution"].is_null());
        assert!(json["observed_progress"].is_number());
        let roundtrip: GoalProgressReport = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.expected_progress, None);
        assert_eq!(roundtrip.observed_progress, report.observed_progress);
    }

    #[test]
    fn one_unknown_prediction_prevents_a_misleading_known_subtotal() {
        let mut outcomes = make_outcomes(500_000_000.0, true, false);
        let mut missing = outcomes[0].clone();
        missing.pid += 1;
        missing.expected_contribution = None;
        outcomes.push(missing);
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &make_after_good(),
            outcomes,
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.expected_progress, None);
        assert_eq!(report.observed_progress, Some(1_000_000_000.0));
        assert_eq!(report.classification, DiscrepancyClass::Unavailable);
        assert_eq!(
            report.action_outcomes[0].expected_contribution,
            Some(500_000_000.0)
        );
        assert_eq!(report.discrepancy, None);
    }

    #[test]
    fn known_zero_prediction_is_not_an_unknown_prediction() {
        let after = MetricSnapshot {
            timestamp: 1010.0,
            ..make_before()
        };
        let mut outcomes = make_outcomes(0.0, true, false);
        let known = measure_progress(
            GoalMetric::Cpu,
            None,
            &make_before(),
            &after,
            outcomes.clone(),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(known.expected_progress, Some(0.0));
        assert_eq!(known.discrepancy, Some(0.0));
        assert_eq!(known.classification, DiscrepancyClass::NoEffect);
        outcomes[0].expected_contribution = None;
        let unknown = measure_progress(
            GoalMetric::Cpu,
            None,
            &make_before(),
            &after,
            outcomes,
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(unknown.expected_progress, None);
        assert_eq!(unknown.observed_progress, Some(0.0));
        assert_eq!(unknown.discrepancy, None);
        assert_eq!(unknown.classification, DiscrepancyClass::Unavailable);
    }

    #[test]
    fn missing_prediction_and_measurement_reasons_are_both_retained() {
        let before = MetricSnapshot {
            total_cpu_frac: None,
            ..make_before()
        };
        let mut outcomes = make_outcomes(0.0, true, false);
        outcomes[0].expected_contribution = None;
        let report = measure_progress(
            GoalMetric::Cpu,
            None,
            &before,
            &make_after_good(),
            outcomes,
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.expected_progress, None);
        assert_eq!(report.observed_progress, None);
        let reason = report.measurement_unavailable_reason.as_deref().unwrap();
        assert!(reason.contains("unavailable before application"));
        assert!(reason.contains("Expected contribution is unavailable"));
        let missing: ActionOutcome = serde_json::from_value(serde_json::json!({
            "pid": 1234, "label": "no prediction", "success": true, "respawn_detected": false,
        }))
        .unwrap();
        assert_eq!(missing.expected_contribution, None);
    }

    #[test]
    fn test_fd_reduction() {
        let report = measure_progress(
            GoalMetric::FileDescriptors,
            None,
            &make_before(),
            &make_after_good(),
            make_outcomes(500.0, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert!((report.observed_progress.unwrap() - 500.0).abs() < 1.0);
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
    }

    #[test]
    fn test_overperformance() {
        let after = MetricSnapshot {
            available_memory_bytes: Some(4_000_000_000), // 2GB freed
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &after,
            make_outcomes(1_000_000_000.0, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.classification, DiscrepancyClass::Overperformance);
        assert!(report.suspected_causes.is_empty());
    }

    #[test]
    fn test_failed_actions_diagnosed() {
        let after = MetricSnapshot {
            available_memory_bytes: Some(2_000_000_000), // No change
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &after,
            make_outcomes(1_000_000_000.0, false, false),
            &ProgressConfig::default(),
            None,
        );
        assert!(report
            .suspected_causes
            .iter()
            .any(|c| c.cause.contains("failed")));
    }

    #[test]
    fn missing_metric_readings_are_unknown_in_both_directions() {
        for metric in [
            GoalMetric::Memory,
            GoalMetric::Cpu,
            GoalMetric::Port,
            GoalMetric::FileDescriptors,
        ] {
            for missing_before in [true, false] {
                let mut before = make_before();
                let mut after = make_after_good();
                let missing = if missing_before {
                    &mut before
                } else {
                    &mut after
                };
                match metric {
                    GoalMetric::Memory => missing.available_memory_bytes = None,
                    GoalMetric::Cpu => missing.total_cpu_frac = None,
                    GoalMetric::Port => missing.occupied_ports = None,
                    GoalMetric::FileDescriptors => missing.total_fds = None,
                }
                let report = measure_progress(
                    metric,
                    Some(3000),
                    &before,
                    &after,
                    make_outcomes(5.0, false, true),
                    &ProgressConfig::default(),
                    None,
                );
                assert_eq!(report.classification, DiscrepancyClass::Unavailable);
                assert_eq!(report.expected_progress, Some(5.0));
                assert_eq!(report.observed_progress, None);
                assert_eq!(report.discrepancy, None);
                assert_eq!(report.discrepancy_fraction, None);
                assert!(report.measurement_unavailable_reason.is_some());
                assert!(
                    report.suspected_causes.is_empty(),
                    "missing readings cannot establish failed relief or its causes"
                );
                let json = serde_json::to_value(&report).unwrap();
                assert!(json["observed_progress"].is_null());
                assert!(json["discrepancy"].is_null());
                assert_eq!(json["classification"], "Unavailable");
            }
        }
    }

    #[test]
    fn observed_zero_is_distinct_from_missing_and_other_metrics_do_not_gate_it() {
        let zero = MetricSnapshot {
            available_memory_bytes: Some(0),
            total_cpu_frac: Some(0.0),
            occupied_ports: Some(Vec::new()),
            total_fds: Some(0),
            timestamp: 1.0,
        };
        let after = MetricSnapshot {
            timestamp: 2.0,
            ..zero.clone()
        };
        for metric in [
            GoalMetric::Memory,
            GoalMetric::Cpu,
            GoalMetric::Port,
            GoalMetric::FileDescriptors,
        ] {
            let report = measure_progress(
                metric,
                None,
                &zero,
                &after,
                Vec::new(),
                &ProgressConfig::default(),
                None,
            );
            assert_eq!(report.observed_progress, Some(0.0));
            assert_eq!(report.discrepancy, Some(0.0));
            assert_eq!(report.classification, DiscrepancyClass::NoEffect);
            assert!(report.measurement_unavailable_reason.is_none());
        }
        let before = MetricSnapshot {
            available_memory_bytes: None,
            total_cpu_frac: Some(0.8),
            occupied_ports: None,
            total_fds: None,
            timestamp: 1.0,
        };
        let after = MetricSnapshot {
            total_cpu_frac: Some(0.5),
            timestamp: 2.0,
            ..before.clone()
        };
        let report = measure_progress(
            GoalMetric::Cpu,
            None,
            &before,
            &after,
            make_outcomes(0.3, true, false),
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
        assert!((report.observed_progress.unwrap() - 0.3).abs() < 1e-12);
        assert!(report.suspected_causes.is_empty());
    }

    #[test]
    fn invalid_cpu_observations_are_unavailable_not_clamped() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 1.1] {
            for invalid_before in [true, false] {
                let mut before = make_before();
                let mut after = make_after_good();
                if invalid_before {
                    before.total_cpu_frac = Some(invalid);
                } else {
                    after.total_cpu_frac = Some(invalid);
                }
                let report = measure_progress(
                    GoalMetric::Cpu,
                    None,
                    &before,
                    &after,
                    make_outcomes(0.3, true, false),
                    &ProgressConfig::default(),
                    None,
                );
                assert_eq!(report.observed_progress, None);
                assert_eq!(report.classification, DiscrepancyClass::Unavailable);
                assert!(report.measurement_unavailable_reason.is_some());
                assert!(report.suspected_causes.is_empty());
            }
        }
    }

    #[test]
    fn unordered_or_nonfinite_observation_times_cannot_prove_progress() {
        for (start, end) in [
            (1000.0, 1000.0),
            (1010.0, 1000.0),
            (f64::NAN, 1010.0),
            (1000.0, f64::INFINITY),
        ] {
            let before = MetricSnapshot {
                timestamp: start,
                ..make_before()
            };
            let after = MetricSnapshot {
                timestamp: end,
                ..make_after_good()
            };
            let report = measure_progress(
                GoalMetric::Memory,
                None,
                &before,
                &after,
                make_outcomes(1_000_000_000.0, true, false),
                &ProgressConfig::default(),
                None,
            );
            assert_eq!(report.observed_progress, None);
            assert_eq!(report.classification, DiscrepancyClass::Unavailable);
            assert!(report.suspected_causes.is_empty());
        }
    }

    #[test]
    fn invalid_predictions_or_thresholds_preserve_observed_data_without_comparison() {
        for expected in [f64::NAN, f64::INFINITY, -1.0] {
            let report = measure_progress(
                GoalMetric::Memory,
                None,
                &make_before(),
                &make_after_good(),
                make_outcomes(expected, false, true),
                &ProgressConfig::default(),
                None,
            );
            assert_eq!(report.observed_progress, Some(1_000_000_000.0));
            assert_eq!(report.expected_progress, None);
            assert_eq!(report.discrepancy, None);
            assert_eq!(report.discrepancy_fraction, None);
            assert_eq!(report.classification, DiscrepancyClass::Unavailable);
            assert!(report.suspected_causes.is_empty());
        }
        let mut outcomes = make_outcomes(f64::MAX, false, true);
        outcomes.extend(make_outcomes(f64::MAX, false, true));
        let report = measure_progress(
            GoalMetric::Memory,
            None,
            &make_before(),
            &make_after_good(),
            outcomes,
            &ProgressConfig::default(),
            None,
        );
        assert_eq!(report.observed_progress, Some(1_000_000_000.0));
        assert_eq!(report.expected_progress, None);
        assert_eq!(report.discrepancy, None);
        assert_eq!(report.classification, DiscrepancyClass::Unavailable);

        for config in [
            ProgressConfig {
                tolerance: f64::NAN,
                ..ProgressConfig::default()
            },
            ProgressConfig {
                tolerance: -0.1,
                ..ProgressConfig::default()
            },
            ProgressConfig {
                no_effect_threshold: f64::INFINITY,
                ..ProgressConfig::default()
            },
            ProgressConfig {
                no_effect_threshold: 2.0,
                ..ProgressConfig::default()
            },
        ] {
            let report = measure_progress(
                GoalMetric::Memory,
                None,
                &make_before(),
                &make_after_good(),
                make_outcomes(1_000_000_000.0, true, false),
                &config,
                None,
            );
            assert_eq!(report.observed_progress, Some(1_000_000_000.0));
            assert_eq!(report.discrepancy_fraction, None);
            assert_eq!(report.classification, DiscrepancyClass::Unavailable);
            assert!(report.suspected_causes.is_empty());
        }
    }

    #[test]
    fn a_resource_regression_with_zero_prediction_is_not_overperformance() {
        let before = make_before();
        let after = MetricSnapshot {
            total_cpu_frac: Some(0.9),
            ..make_after_good()
        };
        let report = measure_progress(
            GoalMetric::Cpu,
            None,
            &before,
            &after,
            Vec::new(),
            &ProgressConfig::default(),
            None,
        );
        assert!(report.observed_progress.unwrap() < 0.0);
        assert_eq!(report.discrepancy_fraction, Some(-1.0));
        assert_eq!(report.classification, DiscrepancyClass::Underperformance);
        assert!(report.suspected_causes.is_empty());
    }

    #[test]
    fn integer_deltas_preserve_small_changes_in_large_counters() {
        let before = MetricSnapshot {
            available_memory_bytes: Some(u64::MAX - 1),
            total_fds: Some(u64::MAX),
            ..make_before()
        };
        let after = MetricSnapshot {
            available_memory_bytes: Some(u64::MAX),
            total_fds: Some(u64::MAX - 1),
            ..make_after_good()
        };
        for metric in [GoalMetric::Memory, GoalMetric::FileDescriptors] {
            let report = measure_progress(
                metric,
                None,
                &before,
                &after,
                make_outcomes(1.0, true, false),
                &ProgressConfig::default(),
                None,
            );
            assert_eq!(report.observed_progress, Some(1.0));
            assert_eq!(report.discrepancy, Some(0.0));
            assert_eq!(report.classification, DiscrepancyClass::AsExpected);
        }
    }
}
