//! Differential scanning: compare two session snapshots and classify changes.
//!
//! Produces a structured delta (new, resolved, changed, unchanged) that
//! downstream commands can use for incremental display and agent diffs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::snapshot_persist::{PersistedInference, PersistedProcess};

// ---------------------------------------------------------------------------
// Delta types
// ---------------------------------------------------------------------------

/// Classification of how a candidate changed between snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    /// Present only in the newer snapshot.
    New,
    /// Present only in the older snapshot (no longer running).
    Resolved,
    /// Present in both but classification/score changed.
    Changed,
    /// Present in both, effectively the same.
    Unchanged,
}

/// A single process delta entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDelta {
    pub pid: u32,
    pub start_id: String,
    pub kind: DeltaKind,
    /// Previous inference (if present in old snapshot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_inference: Option<InferenceSummary>,
    /// Current inference (if present in new snapshot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_inference: Option<InferenceSummary>,
    /// Score drift (new - old), if both present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_drift: Option<i64>,
    /// Classification changed.
    pub classification_changed: bool,
    /// Worsened (score increased = more suspicious).
    pub worsened: bool,
    /// Improved (score decreased = less suspicious).
    pub improved: bool,
}

/// Compact inference summary for delta display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceSummary {
    pub classification: String,
    pub score: u32,
    pub recommended_action: String,
    pub posterior_abandoned: f64,
    pub posterior_zombie: f64,
}

impl From<&PersistedInference> for InferenceSummary {
    fn from(inf: &PersistedInference) -> Self {
        Self {
            classification: inf.classification.clone(),
            score: inf.score,
            recommended_action: inf.recommended_action.clone(),
            posterior_abandoned: inf.posterior_abandoned,
            posterior_zombie: inf.posterior_zombie,
        }
    }
}

/// Complete session diff result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDiff {
    pub old_session_id: String,
    pub new_session_id: String,
    pub generated_at: String,
    /// Per-process deltas.
    pub deltas: Vec<ProcessDelta>,
    /// Summary counts.
    pub summary: DiffSummary,
}

/// Aggregate diff statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffSummary {
    pub total_old: usize,
    pub total_new: usize,
    pub new_count: usize,
    pub resolved_count: usize,
    pub changed_count: usize,
    pub unchanged_count: usize,
    pub worsened_count: usize,
    pub improved_count: usize,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Thresholds for classifying changes.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Minimum absolute score drift to classify as "changed" (vs unchanged).
    pub score_drift_threshold: u32,
    /// Always treat classification changes as "changed" regardless of score.
    pub always_flag_classification_change: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            score_drift_threshold: 5,
            always_flag_classification_change: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Core diff algorithm
// ---------------------------------------------------------------------------

/// Compute the diff between two session snapshots.
///
/// `old_procs` / `old_inferences` are from the baseline session.
/// `new_procs` / `new_inferences` are from the current session.
pub fn compute_diff(
    old_session_id: &str,
    new_session_id: &str,
    old_procs: &[PersistedProcess],
    old_inferences: &[PersistedInference],
    new_procs: &[PersistedProcess],
    new_inferences: &[PersistedInference],
    config: &DiffConfig,
) -> SessionDiff {
    // Build lookup maps by identity key.
    let old_proc_map: HashMap<&str, &PersistedProcess> =
        old_procs.iter().map(|p| (p.start_id.as_str(), p)).collect();
    let new_proc_map: HashMap<&str, &PersistedProcess> =
        new_procs.iter().map(|p| (p.start_id.as_str(), p)).collect();

    let old_inf_map: HashMap<&str, &PersistedInference> = old_inferences
        .iter()
        .map(|i| (i.start_id.as_str(), i))
        .collect();
    let new_inf_map: HashMap<&str, &PersistedInference> = new_inferences
        .iter()
        .map(|i| (i.start_id.as_str(), i))
        .collect();

    let mut deltas = Vec::new();

    // Processes in new snapshot: either New or Changed/Unchanged.
    for (key, new_proc) in &new_proc_map {
        let new_inf = new_inf_map.get(key);
        let old_inf = old_inf_map.get(key);

        if old_proc_map.contains_key(key) {
            // Present in both snapshots.
            let delta = classify_change(new_proc, old_inf.copied(), new_inf.copied(), config);
            deltas.push(delta);
        } else {
            // New process.
            deltas.push(ProcessDelta {
                pid: new_proc.pid,
                start_id: new_proc.start_id.clone(),
                kind: DeltaKind::New,
                old_inference: None,
                new_inference: new_inf.map(|i| InferenceSummary::from(*i)),
                score_drift: None,
                classification_changed: false,
                worsened: false,
                improved: false,
            });
        }
    }

    // Processes only in old snapshot: Resolved.
    for (key, old_proc) in &old_proc_map {
        if !new_proc_map.contains_key(key) {
            let old_inf = old_inf_map.get(key);
            deltas.push(ProcessDelta {
                pid: old_proc.pid,
                start_id: old_proc.start_id.clone(),
                kind: DeltaKind::Resolved,
                old_inference: old_inf.map(|i| InferenceSummary::from(*i)),
                new_inference: None,
                score_drift: None,
                classification_changed: false,
                worsened: false,
                improved: false,
            });
        }
    }

    // Sort deterministically:
    // 1) kind priority (New, Changed, Unchanged, Resolved)
    // 2) stable identity key (start_id)
    // 3) pid as final tie-breaker.
    deltas.sort_by(|a, b| {
        delta_kind_rank(a.kind)
            .cmp(&delta_kind_rank(b.kind))
            .then_with(|| a.start_id.cmp(&b.start_id))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    // Compute summary in a single pass.
    let mut summary = DiffSummary {
        total_old: old_procs.len(),
        total_new: new_procs.len(),
        new_count: 0,
        resolved_count: 0,
        changed_count: 0,
        unchanged_count: 0,
        worsened_count: 0,
        improved_count: 0,
    };
    for delta in &deltas {
        match delta.kind {
            DeltaKind::New => summary.new_count += 1,
            DeltaKind::Resolved => summary.resolved_count += 1,
            DeltaKind::Changed => summary.changed_count += 1,
            DeltaKind::Unchanged => summary.unchanged_count += 1,
        }
        if delta.worsened {
            summary.worsened_count += 1;
        }
        if delta.improved {
            summary.improved_count += 1;
        }
    }

    SessionDiff {
        old_session_id: old_session_id.to_string(),
        new_session_id: new_session_id.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        deltas,
        summary,
    }
}

#[inline]
fn delta_kind_rank(kind: DeltaKind) -> u8 {
    match kind {
        DeltaKind::New => 0,
        DeltaKind::Changed => 1,
        DeltaKind::Unchanged => 2,
        DeltaKind::Resolved => 3,
    }
}

fn classify_change(
    proc: &PersistedProcess,
    old_inf: Option<&PersistedInference>,
    new_inf: Option<&PersistedInference>,
    config: &DiffConfig,
) -> ProcessDelta {
    let (score_drift, classification_changed) = match (old_inf, new_inf) {
        (Some(old), Some(new)) => {
            let drift = new.score as i64 - old.score as i64;
            let class_changed = old.classification != new.classification;
            (Some(drift), class_changed)
        }
        _ => (None, false),
    };

    let is_changed = classification_changed && config.always_flag_classification_change
        || score_drift
            .map(|d| d.unsigned_abs() as u32 >= config.score_drift_threshold)
            .unwrap_or(false);

    let worsened = score_drift.map(|d| d > 0).unwrap_or(false) && is_changed;
    let improved = score_drift.map(|d| d < 0).unwrap_or(false) && is_changed;

    ProcessDelta {
        pid: proc.pid,
        start_id: proc.start_id.clone(),
        kind: if is_changed {
            DeltaKind::Changed
        } else {
            DeltaKind::Unchanged
        },
        old_inference: old_inf.map(InferenceSummary::from),
        new_inference: new_inf.map(InferenceSummary::from),
        score_drift,
        classification_changed,
        worsened,
        improved,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, start_id: &str) -> PersistedProcess {
        PersistedProcess {
            pid,
            ppid: 1,
            uid: 1000,
            start_id: start_id.to_string(),
            comm: "test".to_string(),
            cmd: "test cmd".to_string(),
            state: "S".to_string(),
            start_time_unix: 1700000000,
            elapsed_secs: 100,
            identity_quality: "Full".to_string(),
        }
    }

    fn inf(pid: u32, start_id: &str, class: &str, score: u32, action: &str) -> PersistedInference {
        PersistedInference {
            pid,
            start_id: start_id.to_string(),
            classification: class.to_string(),
            posterior_useful: 0.1,
            posterior_useful_bad: 0.1,
            posterior_abandoned: if class == "abandoned" { 0.7 } else { 0.1 },
            posterior_zombie: if class == "zombie" { 0.7 } else { 0.1 },
            confidence: "high".to_string(),
            recommended_action: action.to_string(),
            score,
        }
    }

    #[test]
    fn test_empty_diff() {
        let diff = compute_diff("s1", "s2", &[], &[], &[], &[], &DiffConfig::default());
        assert_eq!(diff.summary.total_old, 0);
        assert_eq!(diff.summary.total_new, 0);
        assert!(diff.deltas.is_empty());
    }

    #[test]
    fn test_self_diff_all_unchanged() {
        let procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let infs = vec![
            inf(1, "a:1:1", "useful", 10, "keep"),
            inf(2, "a:2:2", "useful", 15, "keep"),
        ];
        let diff = compute_diff(
            "s1",
            "s1",
            &procs,
            &infs,
            &procs,
            &infs,
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.unchanged_count, 2);
        assert_eq!(diff.summary.new_count, 0);
        assert_eq!(diff.summary.resolved_count, 0);
        assert_eq!(diff.summary.changed_count, 0);
    }

    #[test]
    fn test_new_process() {
        let old_procs = vec![proc(1, "a:1:1")];
        let new_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &[],
            &new_procs,
            &[],
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.unchanged_count, 1);
        let new_delta = diff
            .deltas
            .iter()
            .find(|d| d.kind == DeltaKind::New)
            .unwrap();
        assert_eq!(new_delta.pid, 2);
    }

    #[test]
    fn test_resolved_process() {
        let old_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let new_procs = vec![proc(1, "a:1:1")];
        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &[],
            &new_procs,
            &[],
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.resolved_count, 1);
        let resolved = diff
            .deltas
            .iter()
            .find(|d| d.kind == DeltaKind::Resolved)
            .unwrap();
        assert_eq!(resolved.pid, 2);
    }

    #[test]
    fn test_classification_change() {
        let procs = vec![proc(1, "a:1:1")];
        let old_infs = vec![inf(1, "a:1:1", "useful", 10, "keep")];
        let new_infs = vec![inf(1, "a:1:1", "abandoned", 85, "kill")];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.changed_count, 1);
        let changed = diff
            .deltas
            .iter()
            .find(|d| d.kind == DeltaKind::Changed)
            .unwrap();
        assert!(changed.classification_changed);
        assert!(changed.worsened);
        assert_eq!(changed.score_drift, Some(75));
    }

    #[test]
    fn test_score_improvement() {
        let procs = vec![proc(1, "a:1:1")];
        let old_infs = vec![inf(1, "a:1:1", "abandoned", 80, "kill")];
        let new_infs = vec![inf(1, "a:1:1", "useful", 10, "keep")];
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let changed = diff
            .deltas
            .iter()
            .find(|d| d.kind == DeltaKind::Changed)
            .unwrap();
        assert!(changed.improved);
        assert!(!changed.worsened);
        assert_eq!(changed.score_drift, Some(-70));
    }

    #[test]
    fn test_small_drift_unchanged() {
        let procs = vec![proc(1, "a:1:1")];
        let old_infs = vec![inf(1, "a:1:1", "useful", 10, "keep")];
        let new_infs = vec![inf(1, "a:1:1", "useful", 13, "keep")]; // drift=3 < threshold=5
        let diff = compute_diff(
            "s1",
            "s2",
            &procs,
            &old_infs,
            &procs,
            &new_infs,
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.unchanged_count, 1);
        assert_eq!(diff.summary.changed_count, 0);
    }

    #[test]
    fn test_custom_threshold() {
        let procs = vec![proc(1, "a:1:1")];
        let old_infs = vec![inf(1, "a:1:1", "useful", 10, "keep")];
        let new_infs = vec![inf(1, "a:1:1", "useful", 13, "keep")];
        let config = DiffConfig {
            score_drift_threshold: 2, // Now 3 >= 2 triggers change
            ..Default::default()
        };
        let diff = compute_diff("s1", "s2", &procs, &old_infs, &procs, &new_infs, &config);
        assert_eq!(diff.summary.changed_count, 1);
    }

    #[test]
    fn test_sort_order() {
        let old_procs = vec![proc(1, "a:1:1"), proc(3, "a:3:3")];
        let new_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let old_infs = vec![inf(1, "a:1:1", "useful", 10, "keep")];
        let new_infs = vec![inf(1, "a:1:1", "abandoned", 90, "kill")];
        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &old_infs,
            &new_procs,
            &new_infs,
            &DiffConfig::default(),
        );
        // Order: New (pid=2), Changed (pid=1), Resolved (pid=3)
        assert_eq!(diff.deltas[0].kind, DeltaKind::New);
        assert_eq!(diff.deltas[1].kind, DeltaKind::Changed);
        assert_eq!(diff.deltas[2].kind, DeltaKind::Resolved);
    }

    #[test]
    fn test_deterministic_order_within_kind() {
        let old_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2")];
        let new_procs = vec![
            proc(3, "a:3:3"), // New
            proc(2, "a:2:2"), // Unchanged
            proc(4, "a:0:0"), // New
            proc(1, "a:1:1"), // Unchanged
        ];

        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &[],
            &new_procs,
            &[],
            &DiffConfig::default(),
        );

        let ordered: Vec<(DeltaKind, String)> = diff
            .deltas
            .iter()
            .map(|d| (d.kind, d.start_id.clone()))
            .collect();

        assert_eq!(
            ordered,
            vec![
                (DeltaKind::New, "a:0:0".to_string()),
                (DeltaKind::New, "a:3:3".to_string()),
                (DeltaKind::Unchanged, "a:1:1".to_string()),
                (DeltaKind::Unchanged, "a:2:2".to_string()),
            ]
        );
    }

    #[test]
    fn test_summary_counts_consistent() {
        let old_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2"), proc(3, "a:3:3")];
        let new_procs = vec![proc(1, "a:1:1"), proc(2, "a:2:2"), proc(4, "a:4:4")];
        let old_infs = vec![
            inf(1, "a:1:1", "useful", 10, "keep"),
            inf(2, "a:2:2", "useful", 20, "keep"),
        ];
        let new_infs = vec![
            inf(1, "a:1:1", "useful", 12, "keep"), // small drift → unchanged
            inf(2, "a:2:2", "abandoned", 85, "kill"), // classification change → changed
        ];
        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &old_infs,
            &new_procs,
            &new_infs,
            &DiffConfig::default(),
        );
        let s = &diff.summary;
        assert_eq!(
            s.new_count + s.resolved_count + s.changed_count + s.unchanged_count,
            diff.deltas.len()
        );
        assert_eq!(s.total_old, 3);
        assert_eq!(s.total_new, 3);
    }

    #[test]
    fn test_identity_based_matching() {
        // Same PID but different start_id → treated as different processes
        let old_procs = vec![proc(1, "boot1:100:1")];
        let new_procs = vec![proc(1, "boot2:200:1")]; // PID reused after reboot
        let diff = compute_diff(
            "s1",
            "s2",
            &old_procs,
            &[],
            &new_procs,
            &[],
            &DiffConfig::default(),
        );
        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.resolved_count, 1);
    }
}
