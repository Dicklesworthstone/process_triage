//! Post-apply goal progress measurement and discrepancy logging.
//!
//! Closes the loop between expected and actual goal achievement by
//! comparing predicted vs observed outcomes and logging discrepancies
//! for calibration.

use serde::{Deserialize, Serialize};

/// Metric snapshot (before or after action application).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    /// Total available memory bytes.
    pub available_memory_bytes: u64,
    /// Total CPU utilization fraction.
    pub total_cpu_frac: f64,
    /// Set of occupied ports.
    pub occupied_ports: Vec<u16>,
    /// Total open file descriptors (system-wide or scoped).
    pub total_fds: u64,
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
    /// Expected contribution (from planner).
    pub expected_contribution: f64,
}

/// Goal progress measurement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalProgressReport {
    /// Expected total progress (sum of expected contributions).
    pub expected_progress: f64,
    /// Observed progress (measured metric delta).
    pub observed_progress: f64,
    /// Discrepancy (observed - expected).
    pub discrepancy: f64,
    /// Discrepancy as a fraction of expected.
    pub discrepancy_fraction: f64,
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
}

impl std::fmt::Display for DiscrepancyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsExpected => write!(f, "as_expected"),
            Self::Underperformance => write!(f, "underperformance"),
            Self::Overperformance => write!(f, "overperformance"),
            Self::NoEffect => write!(f, "no_effect"),
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
pub fn measure_progress(
    metric: GoalMetric,
    target_port: Option<u16>,
    before: &MetricSnapshot,
    after: &MetricSnapshot,
    action_outcomes: Vec<ActionOutcome>,
    config: &ProgressConfig,
    session_id: Option<String>,
) -> GoalProgressReport {
    let observed = compute_observed_delta(metric, target_port, before, after);
    let expected: f64 = action_outcomes
        .iter()
        .map(|a| a.expected_contribution)
        .sum();

    let discrepancy = observed - expected;
    let discrepancy_fraction = if expected.abs() > 1e-12 {
        discrepancy / expected
    } else if observed.abs() > 1e-12 {
        1.0 // All observed, nothing expected.
    } else {
        0.0
    };

    let classification = classify_discrepancy(expected, observed, discrepancy_fraction, config);

    let suspected_causes = diagnose_causes(&action_outcomes, classification, discrepancy_fraction);

    GoalProgressReport {
        expected_progress: expected,
        observed_progress: observed,
        discrepancy,
        discrepancy_fraction,
        classification,
        action_outcomes,
        suspected_causes,
        session_id,
    }
}

fn compute_observed_delta(
    metric: GoalMetric,
    target_port: Option<u16>,
    before: &MetricSnapshot,
    after: &MetricSnapshot,
) -> f64 {
    match metric {
        GoalMetric::Memory => {
            // Freed memory = after_available - before_available.
            after.available_memory_bytes as f64 - before.available_memory_bytes as f64
        }
        GoalMetric::Cpu => {
            // CPU reduction = before_cpu - after_cpu.
            before.total_cpu_frac - after.total_cpu_frac
        }
        GoalMetric::Port => {
            if let Some(port) = target_port {
                let was_occupied = before.occupied_ports.contains(&port);
                let is_occupied = after.occupied_ports.contains(&port);
                if was_occupied && !is_occupied {
                    1.0
                } else {
                    0.0
                }
            } else {
                0.0
            }
        }
        GoalMetric::FileDescriptors => {
            // FDs freed = before_fds - after_fds.
            before.total_fds as f64 - after.total_fds as f64
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

fn diagnose_causes(
    outcomes: &[ActionOutcome],
    class: DiscrepancyClass,
    _discrepancy_fraction: f64,
) -> Vec<SuspectedCause> {
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
        if respawn_count == 0 && fail_count == 0 {
            causes.push(SuspectedCause {
                cause: "Shared memory not fully released, or delayed cleanup".to_string(),
                confidence: 0.5,
            });
        }
    }

    if class == DiscrepancyClass::Overperformance {
        causes.push(SuspectedCause {
            cause: "Cascade effect: child processes also terminated".to_string(),
            confidence: 0.6,
        });
    }

    causes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_before() -> MetricSnapshot {
        MetricSnapshot {
            available_memory_bytes: 2_000_000_000,
            total_cpu_frac: 0.8,
            occupied_ports: vec![3000, 8080],
            total_fds: 5000,
            timestamp: 1000.0,
        }
    }

    fn make_after_good() -> MetricSnapshot {
        MetricSnapshot {
            available_memory_bytes: 3_000_000_000, // 1GB freed
            total_cpu_frac: 0.5,
            occupied_ports: vec![8080], // Port 3000 freed
            total_fds: 4500,
            timestamp: 1010.0,
        }
    }

    fn make_outcomes(expected: f64, success: bool, respawn: bool) -> Vec<ActionOutcome> {
        vec![ActionOutcome {
            pid: 1234,
            label: "test-process".to_string(),
            success,
            respawn_detected: respawn,
            expected_contribution: expected,
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
        assert!((report.observed_progress - 1_000_000_000.0).abs() < 1.0);
    }

    #[test]
    fn test_underperformance_with_respawn() {
        let after = MetricSnapshot {
            available_memory_bytes: 2_100_000_000, // Only 100MB freed
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
            available_memory_bytes: 2_010_000_000, // ~10MB, negligible
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
        assert!((report.observed_progress - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_port_not_released() {
        let after = MetricSnapshot {
            occupied_ports: vec![3000, 8080], // Port still occupied
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
        assert_eq!(report.observed_progress, 0.0);
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
        assert!((report.observed_progress - 0.3).abs() < 0.01);
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
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
        assert!((report.observed_progress - 500.0).abs() < 1.0);
        assert_eq!(report.classification, DiscrepancyClass::AsExpected);
    }

    #[test]
    fn test_overperformance() {
        let after = MetricSnapshot {
            available_memory_bytes: 4_000_000_000, // 2GB freed
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
        assert!(report
            .suspected_causes
            .iter()
            .any(|c| c.cause.contains("child")));
    }

    #[test]
    fn test_failed_actions_diagnosed() {
        let after = MetricSnapshot {
            available_memory_bytes: 2_000_000_000, // No change
            ..make_before()
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
}
