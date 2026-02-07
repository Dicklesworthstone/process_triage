//! Session comparison reports: trends, recurring offenders, and drift summaries.
//!
//! Builds on the diff module to produce human/agent-consumable comparison
//! reports between two session snapshots.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::diff::{DeltaKind, DiffSummary, SessionDiff};
use super::snapshot_persist::PersistedInference;

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// Complete comparison report between two sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub old_session_id: String,
    pub new_session_id: String,
    pub generated_at: String,
    pub diff_summary: DiffSummary,
    pub class_distribution: ClassDistributionComparison,
    pub action_distribution: ActionDistributionComparison,
    pub recurring_offenders: Vec<RecurringOffender>,
    pub drift_summary: DriftSummary,
}

/// Per-class process count comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassDistributionComparison {
    pub old_counts: HashMap<String, usize>,
    pub new_counts: HashMap<String, usize>,
    pub changes: Vec<ClassChange>,
}

/// Change in one classification category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassChange {
    pub classification: String,
    pub old_count: usize,
    pub new_count: usize,
    pub delta: i64,
    pub direction: TrendDirection,
}

/// Per-action recommendation count comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionDistributionComparison {
    pub old_counts: HashMap<String, usize>,
    pub new_counts: HashMap<String, usize>,
    pub changes: Vec<ActionChange>,
}

/// Change in one action category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionChange {
    pub action: String,
    pub old_count: usize,
    pub new_count: usize,
    pub delta: i64,
    pub direction: TrendDirection,
}

/// Direction of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
}

/// A process that appears as a candidate in multiple sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecurringOffender {
    /// Identity key (start_id).
    pub identity_key: String,
    pub pid: u32,
    /// Classification in old session (if present).
    pub old_classification: Option<String>,
    /// Classification in new session (if present).
    pub new_classification: Option<String>,
    pub old_score: Option<u32>,
    pub new_score: Option<u32>,
    /// How the score changed.
    pub score_trend: TrendDirection,
    /// Explanation of why this is notable.
    pub explanation: String,
}

/// Aggregate drift summary across all processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftSummary {
    /// Mean score drift across changed+unchanged processes.
    pub mean_score_drift: f64,
    /// Median score drift.
    pub median_score_drift: f64,
    /// Number of processes that worsened.
    pub worsened_count: usize,
    /// Number of processes that improved.
    pub improved_count: usize,
    /// Mean posterior_abandoned drift.
    pub mean_abandoned_drift: f64,
    /// Overall system trend.
    pub overall_trend: TrendDirection,
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/// Generate a comparison report from a session diff and inference data.
pub fn generate_comparison_report(
    diff: &SessionDiff,
    old_inferences: &[PersistedInference],
    new_inferences: &[PersistedInference],
) -> ComparisonReport {
    let class_dist = compute_class_distribution(old_inferences, new_inferences);
    let action_dist = compute_action_distribution(old_inferences, new_inferences);
    let recurring = find_recurring_offenders(diff, old_inferences, new_inferences);
    let drift = compute_drift_summary(diff, old_inferences, new_inferences);

    ComparisonReport {
        old_session_id: diff.old_session_id.clone(),
        new_session_id: diff.new_session_id.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        diff_summary: diff.summary.clone(),
        class_distribution: class_dist,
        action_distribution: action_dist,
        recurring_offenders: recurring,
        drift_summary: drift,
    }
}

fn count_by<F>(inferences: &[PersistedInference], key_fn: F) -> HashMap<String, usize>
where
    F: Fn(&PersistedInference) -> String,
{
    let mut counts = HashMap::new();
    for inf in inferences {
        *counts.entry(key_fn(inf)).or_insert(0) += 1;
    }
    counts
}

fn compute_class_distribution(
    old: &[PersistedInference],
    new: &[PersistedInference],
) -> ClassDistributionComparison {
    let old_counts = count_by(old, |i| i.classification.clone());
    let new_counts = count_by(new, |i| i.classification.clone());

    let mut all_classes: Vec<String> = old_counts
        .keys()
        .chain(new_counts.keys())
        .cloned()
        .collect();
    all_classes.sort();
    all_classes.dedup();

    let changes = all_classes
        .into_iter()
        .map(|class| {
            let old_c = *old_counts.get(&class).unwrap_or(&0);
            let new_c = *new_counts.get(&class).unwrap_or(&0);
            let delta = new_c as i64 - old_c as i64;
            ClassChange {
                classification: class,
                old_count: old_c,
                new_count: new_c,
                delta,
                direction: trend_from_delta(delta),
            }
        })
        .collect();

    ClassDistributionComparison {
        old_counts,
        new_counts,
        changes,
    }
}

fn compute_action_distribution(
    old: &[PersistedInference],
    new: &[PersistedInference],
) -> ActionDistributionComparison {
    let old_counts = count_by(old, |i| i.recommended_action.clone());
    let new_counts = count_by(new, |i| i.recommended_action.clone());

    let mut all_actions: Vec<String> = old_counts
        .keys()
        .chain(new_counts.keys())
        .cloned()
        .collect();
    all_actions.sort();
    all_actions.dedup();

    let changes = all_actions
        .into_iter()
        .map(|action| {
            let old_c = *old_counts.get(&action).unwrap_or(&0);
            let new_c = *new_counts.get(&action).unwrap_or(&0);
            let delta = new_c as i64 - old_c as i64;
            ActionChange {
                action,
                old_count: old_c,
                new_count: new_c,
                delta,
                direction: trend_from_delta(delta),
            }
        })
        .collect();

    ActionDistributionComparison {
        old_counts,
        new_counts,
        changes,
    }
}

fn find_recurring_offenders(
    diff: &SessionDiff,
    old_inferences: &[PersistedInference],
    new_inferences: &[PersistedInference],
) -> Vec<RecurringOffender> {
    let old_map: HashMap<String, &PersistedInference> = old_inferences
        .iter()
        .map(|i| (i.start_id.clone(), i))
        .collect();
    let new_map: HashMap<String, &PersistedInference> = new_inferences
        .iter()
        .map(|i| (i.start_id.clone(), i))
        .collect();

    let mut offenders = Vec::new();

    // A recurring offender is present in both sessions with non-keep recommendation.
    for delta in &diff.deltas {
        if delta.kind == DeltaKind::New || delta.kind == DeltaKind::Resolved {
            continue;
        }

        let old_inf = old_map.get(&delta.start_id);
        let new_inf = new_map.get(&delta.start_id);

        if let (Some(old), Some(new)) = (old_inf, new_inf) {
            // Both sessions have this candidate — check if it's notable.
            let is_actionable_old = old.recommended_action != "keep";
            let is_actionable_new = new.recommended_action != "keep";

            if is_actionable_old || is_actionable_new {
                let score_drift = new.score as i64 - old.score as i64;
                let trend = trend_from_delta(score_drift);

                let explanation = if is_actionable_old && is_actionable_new {
                    format!(
                        "Flagged in both sessions ({}→{}), score {}→{}",
                        old.classification, new.classification, old.score, new.score
                    )
                } else if is_actionable_new {
                    format!(
                        "Newly flagged as {} (was {})",
                        new.classification, old.classification
                    )
                } else {
                    format!(
                        "Previously flagged as {} (now {})",
                        old.classification, new.classification
                    )
                };

                offenders.push(RecurringOffender {
                    identity_key: delta.start_id.clone(),
                    pid: delta.pid,
                    old_classification: Some(old.classification.clone()),
                    new_classification: Some(new.classification.clone()),
                    old_score: Some(old.score),
                    new_score: Some(new.score),
                    score_trend: trend,
                    explanation,
                });
            }
        }
    }

    // Sort by new score descending (most suspicious first).
    offenders.sort_by_key(|b| std::cmp::Reverse(b.new_score.unwrap_or(0)));

    offenders
}

fn compute_drift_summary(
    diff: &SessionDiff,
    old_inferences: &[PersistedInference],
    new_inferences: &[PersistedInference],
) -> DriftSummary {
    let old_map: HashMap<String, &PersistedInference> = old_inferences
        .iter()
        .map(|i| (i.start_id.clone(), i))
        .collect();
    let new_map: HashMap<String, &PersistedInference> = new_inferences
        .iter()
        .map(|i| (i.start_id.clone(), i))
        .collect();

    let mut score_drifts = Vec::new();
    let mut abandoned_drifts = Vec::new();
    let mut worsened = 0;
    let mut improved = 0;

    for delta in &diff.deltas {
        if delta.kind == DeltaKind::New || delta.kind == DeltaKind::Resolved {
            continue;
        }
        if let (Some(old), Some(new)) = (old_map.get(&delta.start_id), new_map.get(&delta.start_id))
        {
            let sd = new.score as f64 - old.score as f64;
            score_drifts.push(sd);
            abandoned_drifts.push(new.posterior_abandoned - old.posterior_abandoned);
            if sd > 0.0 {
                worsened += 1;
            } else if sd < 0.0 {
                improved += 1;
            }
        }
    }

    let mean_score = if score_drifts.is_empty() {
        0.0
    } else {
        score_drifts.iter().sum::<f64>() / score_drifts.len() as f64
    };

    let median_score = if score_drifts.is_empty() {
        0.0
    } else {
        let mut sorted = score_drifts.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    };

    let mean_abandoned = if abandoned_drifts.is_empty() {
        0.0
    } else {
        abandoned_drifts.iter().sum::<f64>() / abandoned_drifts.len() as f64
    };

    let overall = if mean_score > 2.0 {
        TrendDirection::Increasing
    } else if mean_score < -2.0 {
        TrendDirection::Decreasing
    } else {
        TrendDirection::Stable
    };

    DriftSummary {
        mean_score_drift: mean_score,
        median_score_drift: median_score,
        worsened_count: worsened,
        improved_count: improved,
        mean_abandoned_drift: mean_abandoned,
        overall_trend: overall,
    }
}

fn trend_from_delta(delta: i64) -> TrendDirection {
    if delta > 0 {
        TrendDirection::Increasing
    } else if delta < 0 {
        TrendDirection::Decreasing
    } else {
        TrendDirection::Stable
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::diff::{compute_diff, DiffConfig};
    use crate::session::snapshot_persist::PersistedProcess;

    fn proc(pid: u32, sid: &str) -> PersistedProcess {
        PersistedProcess {
            pid,
            ppid: 1,
            uid: 1000,
            start_id: sid.to_string(),
            comm: "test".to_string(),
            cmd: "test cmd".to_string(),
            state: "S".to_string(),
            start_time_unix: 1700000000,
            elapsed_secs: 100,
            identity_quality: "Full".to_string(),
        }
    }

    fn inf(pid: u32, sid: &str, class: &str, score: u32, action: &str) -> PersistedInference {
        PersistedInference {
            pid,
            start_id: sid.to_string(),
            classification: class.to_string(),
            posterior_useful: 0.1,
            posterior_useful_bad: 0.1,
            posterior_abandoned: if class == "abandoned" { 0.8 } else { 0.1 },
            posterior_zombie: 0.0,
            confidence: "high".to_string(),
            recommended_action: action.to_string(),
            score,
        }
    }

    #[test]
    fn test_empty_report() {
        let diff = compute_diff("s1", "s2", &[], &[], &[], &[], &DiffConfig::default());
        let report = generate_comparison_report(&diff, &[], &[]);
        assert!(report.recurring_offenders.is_empty());
        assert_eq!(report.drift_summary.overall_trend, TrendDirection::Stable);
    }

    #[test]
    fn test_class_distribution() {
        let old = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "abandoned", 80, "kill"),
        ];
        let new = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "abandoned", 85, "kill"),
            inf(3, "c", "abandoned", 90, "kill"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &[proc(1, "a"), proc(2, "b")],
            &old,
            &[proc(1, "a"), proc(2, "b"), proc(3, "c")],
            &new,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old, &new);
        let abandoned = report
            .class_distribution
            .changes
            .iter()
            .find(|c| c.classification == "abandoned")
            .unwrap();
        assert_eq!(abandoned.delta, 1);
        assert_eq!(abandoned.direction, TrendDirection::Increasing);
    }

    #[test]
    fn test_recurring_offender_detected() {
        let procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let old_infs = vec![
            inf(1, "a:1:1", "abandoned", 75, "kill"),
            inf(2, "a:2:2", "useful", 10, "keep"),
        ];
        let new_infs = vec![
            inf(1, "a:1:1", "abandoned", 85, "kill"),
            inf(2, "a:2:2", "useful", 12, "keep"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.recurring_offenders.len(), 1);
        assert_eq!(report.recurring_offenders[0].pid, 1);
        assert!(report.recurring_offenders[0]
            .explanation
            .contains("both sessions"));
    }

    #[test]
    fn test_drift_summary_worsening() {
        let procs = vec![proc(1, "a"), proc(2, "b")];
        let old_infs = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "useful", 20, "keep"),
        ];
        let new_infs = vec![
            inf(1, "a", "abandoned", 80, "kill"),
            inf(2, "b", "abandoned", 70, "kill"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.drift_summary.worsened_count, 2);
        assert!(report.drift_summary.mean_score_drift > 0.0);
        assert_eq!(
            report.drift_summary.overall_trend,
            TrendDirection::Increasing
        );
    }

    #[test]
    fn test_drift_summary_improving() {
        let procs = vec![proc(1, "a"), proc(2, "b")];
        let old_infs = vec![
            inf(1, "a", "abandoned", 80, "kill"),
            inf(2, "b", "abandoned", 70, "kill"),
        ];
        let new_infs = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "useful", 15, "keep"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.drift_summary.improved_count, 2);
        assert!(report.drift_summary.mean_score_drift < 0.0);
        assert_eq!(
            report.drift_summary.overall_trend,
            TrendDirection::Decreasing
        );
    }

    #[test]
    fn test_action_distribution_changes() {
        let old = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "useful", 15, "keep"),
        ];
        let new = vec![
            inf(1, "a", "abandoned", 80, "kill"),
            inf(2, "b", "useful", 12, "keep"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &[proc(1, "a"), proc(2, "b")],
            &old,
            &[proc(1, "a"), proc(2, "b")],
            &new,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old, &new);
        let keep_change = report
            .action_distribution
            .changes
            .iter()
            .find(|c| c.action == "keep")
            .unwrap();
        assert_eq!(keep_change.delta, -1);
        let kill_change = report
            .action_distribution
            .changes
            .iter()
            .find(|c| c.action == "kill")
            .unwrap();
        assert_eq!(kill_change.delta, 1);
    }

    #[test]
    fn test_recurring_offenders_sorted_by_score() {
        let procs = vec![proc(1, "a"), proc(2, "b"), proc(3, "c")];
        let old_infs = vec![
            inf(1, "a", "abandoned", 60, "kill"),
            inf(2, "b", "abandoned", 70, "kill"),
            inf(3, "c", "abandoned", 50, "kill"),
        ];
        let new_infs = vec![
            inf(1, "a", "abandoned", 65, "kill"),
            inf(2, "b", "abandoned", 90, "kill"),
            inf(3, "c", "abandoned", 55, "kill"),
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        // Should be sorted by new score descending.
        assert_eq!(report.recurring_offenders[0].new_score, Some(90));
        assert_eq!(report.recurring_offenders[1].new_score, Some(65));
        assert_eq!(report.recurring_offenders[2].new_score, Some(55));
    }

    #[test]
    fn test_stable_drift() {
        let procs = vec![proc(1, "a")];
        let old_infs = vec![inf(1, "a", "useful", 10, "keep")];
        let new_infs = vec![inf(1, "a", "useful", 11, "keep")];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.drift_summary.overall_trend, TrendDirection::Stable);
    }

    #[test]
    fn test_median_drift_even() {
        let procs = vec![proc(1, "a"), proc(2, "b")];
        let old_infs = vec![
            inf(1, "a", "useful", 10, "keep"),
            inf(2, "b", "useful", 20, "keep"),
        ];
        let new_infs = vec![
            inf(1, "a", "useful", 20, "keep"), // +10
            inf(2, "b", "useful", 40, "keep"), // +20
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert!((report.drift_summary.median_score_drift - 15.0).abs() < 0.01);
    }
}
