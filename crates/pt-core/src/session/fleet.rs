//! Fleet session management: multi-host sessions with aggregated results.
//!
//! A fleet session wraps multiple per-host sub-sessions into a single
//! coordinated view. It provides:
//!
//! - **Schema**: `FleetSession` with per-host summaries and shared budgets.
//! - **Aggregation**: merge per-host scan/inference results into fleet-level
//!   risk metrics and deduplicated recurring patterns.
//! - **Persistence**: serialize/deserialize fleet sessions for resume.
//! - **Safety budgets**: track fleet-wide false-discovery rate (FDR) / alpha
//!   spending across hosts.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// A fleet session spanning multiple hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSession {
    pub fleet_session_id: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub hosts: Vec<HostEntry>,
    pub aggregate: FleetAggregate,
    pub safety_budget: SafetyBudget,
}

/// Per-host entry in a fleet session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host_id: String,
    pub session_id: String,
    pub scanned_at: String,
    pub process_count: u32,
    pub candidate_count: u32,
    pub summary: HostSummary,
}

/// Per-host classification and action summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSummary {
    /// Classification distribution: class_name → count.
    pub class_counts: HashMap<String, u32>,
    /// Action distribution: action_name → count.
    pub action_counts: HashMap<String, u32>,
    /// Mean posterior score for candidates on this host.
    pub mean_candidate_score: f64,
    /// Maximum posterior score across candidates.
    pub max_candidate_score: f64,
}

/// Aggregated fleet-level metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAggregate {
    pub total_hosts: usize,
    pub total_processes: u32,
    pub total_candidates: u32,
    /// Merged classification counts across all hosts.
    pub class_counts: HashMap<String, u32>,
    /// Merged action counts across all hosts.
    pub action_counts: HashMap<String, u32>,
    /// Fleet-wide mean candidate score.
    pub mean_candidate_score: f64,
    /// Fleet-wide max candidate score.
    pub max_candidate_score: f64,
    /// Patterns recurring across multiple hosts.
    pub recurring_patterns: Vec<RecurringPattern>,
}

/// A pattern (command signature) seen on multiple hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringPattern {
    /// Normalized command signature (e.g., the binary name).
    pub signature: String,
    /// Number of hosts where this pattern appears.
    pub host_count: usize,
    /// Total instances across all hosts.
    pub total_instances: u32,
    /// Host IDs where this pattern was found.
    pub hosts: Vec<String>,
    /// Most common recommended action for this pattern.
    pub dominant_action: String,
}

/// Fleet-wide safety budget for coordinated FDR control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyBudget {
    /// Maximum fleet-wide false discovery rate.
    pub max_fdr: f64,
    /// Alpha already spent across hosts.
    pub alpha_spent: f64,
    /// Alpha remaining.
    pub alpha_remaining: f64,
    /// Per-host alpha allocations.
    pub host_allocations: HashMap<String, f64>,
}

// ---------------------------------------------------------------------------
// Candidate info for aggregation
// ---------------------------------------------------------------------------

/// Minimal candidate info needed for fleet aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateInfo {
    pub pid: u32,
    pub signature: String,
    pub classification: String,
    pub recommended_action: String,
    pub score: f64,
}

/// Per-host input for fleet aggregation.
#[derive(Debug, Clone)]
pub struct HostInput {
    pub host_id: String,
    pub session_id: String,
    pub scanned_at: String,
    pub total_processes: u32,
    pub candidates: Vec<CandidateInfo>,
}

// ---------------------------------------------------------------------------
// Construction and aggregation
// ---------------------------------------------------------------------------

/// Create a new fleet session from per-host inputs.
pub fn create_fleet_session(
    fleet_session_id: &str,
    label: Option<&str>,
    host_inputs: &[HostInput],
    max_fdr: f64,
) -> FleetSession {
    let hosts: Vec<HostEntry> = host_inputs
        .iter()
        .map(|input| {
            let summary = compute_host_summary(&input.candidates);
            HostEntry {
                host_id: input.host_id.clone(),
                session_id: input.session_id.clone(),
                scanned_at: input.scanned_at.clone(),
                process_count: input.total_processes,
                candidate_count: input.candidates.len() as u32,
                summary,
            }
        })
        .collect();

    let aggregate = compute_aggregate(&hosts, host_inputs);
    let safety_budget = compute_safety_budget(&hosts, max_fdr);

    FleetSession {
        fleet_session_id: fleet_session_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
        label: label.map(|s| s.to_string()),
        hosts,
        aggregate,
        safety_budget,
    }
}

fn compute_host_summary(candidates: &[CandidateInfo]) -> HostSummary {
    let mut class_counts: HashMap<String, u32> = HashMap::new();
    let mut action_counts: HashMap<String, u32> = HashMap::new();
    let mut score_sum = 0.0;
    let mut max_score = 0.0f64;

    for c in candidates {
        *class_counts.entry(c.classification.clone()).or_default() += 1;
        *action_counts.entry(c.recommended_action.clone()).or_default() += 1;
        score_sum += c.score;
        max_score = max_score.max(c.score);
    }

    let mean = if candidates.is_empty() {
        0.0
    } else {
        score_sum / candidates.len() as f64
    };

    HostSummary {
        class_counts,
        action_counts,
        mean_candidate_score: mean,
        max_candidate_score: max_score,
    }
}

fn compute_aggregate(hosts: &[HostEntry], inputs: &[HostInput]) -> FleetAggregate {
    let mut class_counts: HashMap<String, u32> = HashMap::new();
    let mut action_counts: HashMap<String, u32> = HashMap::new();
    let mut total_processes = 0u32;
    let mut total_candidates = 0u32;
    let mut score_sum = 0.0;
    let mut score_count = 0u32;
    let mut max_score = 0.0f64;

    for host in hosts {
        total_processes += host.process_count;
        total_candidates += host.candidate_count;
        for (k, v) in &host.summary.class_counts {
            *class_counts.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &host.summary.action_counts {
            *action_counts.entry(k.clone()).or_default() += v;
        }
        score_sum += host.summary.mean_candidate_score * host.candidate_count as f64;
        score_count += host.candidate_count;
        max_score = max_score.max(host.summary.max_candidate_score);
    }

    let mean = if score_count == 0 {
        0.0
    } else {
        score_sum / score_count as f64
    };

    let recurring_patterns = find_recurring_patterns(inputs);

    FleetAggregate {
        total_hosts: hosts.len(),
        total_processes,
        total_candidates,
        class_counts,
        action_counts,
        mean_candidate_score: mean,
        max_candidate_score: max_score,
        recurring_patterns,
    }
}

fn find_recurring_patterns(inputs: &[HostInput]) -> Vec<RecurringPattern> {
    // Group candidates by signature across hosts.
    let mut sig_map: HashMap<String, Vec<(String, u32)>> = HashMap::new();
    // sig_map: signature → [(host_id, count)]

    for input in inputs {
        let mut per_host: HashMap<String, u32> = HashMap::new();
        for c in &input.candidates {
            *per_host.entry(c.signature.clone()).or_default() += 1;
        }
        for (sig, count) in per_host {
            sig_map
                .entry(sig)
                .or_default()
                .push((input.host_id.clone(), count));
        }
    }

    // Collect dominant action per signature.
    let mut sig_actions: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for input in inputs {
        for c in &input.candidates {
            *sig_actions
                .entry(c.signature.clone())
                .or_default()
                .entry(c.recommended_action.clone())
                .or_default() += 1;
        }
    }

    let mut patterns: Vec<RecurringPattern> = sig_map
        .into_iter()
        .filter(|(_, entries)| entries.len() > 1) // Must appear on >1 host
        .map(|(sig, entries)| {
            let host_count = entries.len();
            let total_instances: u32 = entries.iter().map(|(_, c)| c).sum();
            let hosts: Vec<String> = entries.into_iter().map(|(h, _)| h).collect();
            let dominant_action = sig_actions
                .get(&sig)
                .and_then(|actions| actions.iter().max_by_key(|(_, &v)| v).map(|(k, _)| k.clone()))
                .unwrap_or_default();
            RecurringPattern {
                signature: sig,
                host_count,
                total_instances,
                hosts,
                dominant_action,
            }
        })
        .collect();

    // Sort by host_count desc, then total_instances desc.
    patterns.sort_by(|a, b| {
        b.host_count
            .cmp(&a.host_count)
            .then(b.total_instances.cmp(&a.total_instances))
    });

    patterns
}

fn compute_safety_budget(hosts: &[HostEntry], max_fdr: f64) -> SafetyBudget {
    let n = hosts.len().max(1) as f64;
    let per_host_alpha = max_fdr / n;

    let mut host_allocations = HashMap::new();
    for host in hosts {
        host_allocations.insert(host.host_id.clone(), per_host_alpha);
    }

    SafetyBudget {
        max_fdr,
        alpha_spent: 0.0,
        alpha_remaining: max_fdr,
        host_allocations,
    }
}

/// Record alpha spending for a host (after executing actions).
pub fn record_alpha_spend(budget: &mut SafetyBudget, host_id: &str, spent: f64) {
    budget.alpha_spent += spent;
    budget.alpha_remaining = (budget.max_fdr - budget.alpha_spent).max(0.0);
    if let Some(alloc) = budget.host_allocations.get_mut(host_id) {
        *alloc = (*alloc - spent).max(0.0);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, candidates: Vec<CandidateInfo>) -> HostInput {
        HostInput {
            host_id: id.to_string(),
            session_id: format!("session-{}", id),
            scanned_at: "2026-02-01T12:00:00Z".to_string(),
            total_processes: 100 + candidates.len() as u32,
            candidates,
        }
    }

    fn cand(pid: u32, sig: &str, class: &str, action: &str, score: f64) -> CandidateInfo {
        CandidateInfo {
            pid,
            signature: sig.to_string(),
            classification: class.to_string(),
            recommended_action: action.to_string(),
            score,
        }
    }

    #[test]
    fn test_single_host() {
        let inputs = vec![host(
            "host1",
            vec![
                cand(1, "nginx", "useful", "spare", 0.2),
                cand(2, "zombie_proc", "zombie", "kill", 0.95),
            ],
        )];
        let fleet = create_fleet_session("f1", Some("test"), &inputs, 0.05);

        assert_eq!(fleet.hosts.len(), 1);
        assert_eq!(fleet.aggregate.total_hosts, 1);
        assert_eq!(fleet.aggregate.total_candidates, 2);
        assert_eq!(fleet.aggregate.total_processes, 102);
        assert!(fleet.aggregate.recurring_patterns.is_empty()); // Only 1 host
    }

    #[test]
    fn test_multi_host_aggregation() {
        let inputs = vec![
            host(
                "host1",
                vec![
                    cand(1, "nginx", "useful", "spare", 0.1),
                    cand(2, "old_worker", "abandoned", "kill", 0.9),
                ],
            ),
            host(
                "host2",
                vec![
                    cand(3, "nginx", "useful", "spare", 0.15),
                    cand(4, "old_worker", "abandoned", "kill", 0.85),
                    cand(5, "test_runner", "zombie", "kill", 0.95),
                ],
            ),
        ];
        let fleet = create_fleet_session("f2", None, &inputs, 0.05);

        assert_eq!(fleet.aggregate.total_hosts, 2);
        assert_eq!(fleet.aggregate.total_candidates, 5);
        assert_eq!(*fleet.aggregate.class_counts.get("useful").unwrap(), 2);
        assert_eq!(*fleet.aggregate.class_counts.get("abandoned").unwrap(), 2);
        assert_eq!(*fleet.aggregate.class_counts.get("zombie").unwrap(), 1);
    }

    #[test]
    fn test_recurring_patterns() {
        let inputs = vec![
            host(
                "host1",
                vec![
                    cand(1, "nginx", "useful", "spare", 0.1),
                    cand(2, "old_worker", "abandoned", "kill", 0.9),
                ],
            ),
            host(
                "host2",
                vec![
                    cand(3, "nginx", "useful", "spare", 0.15),
                    cand(4, "old_worker", "abandoned", "kill", 0.85),
                ],
            ),
            host(
                "host3",
                vec![cand(5, "old_worker", "abandoned", "kill", 0.88)],
            ),
        ];
        let fleet = create_fleet_session("f3", None, &inputs, 0.05);
        let patterns = &fleet.aggregate.recurring_patterns;

        // old_worker appears on 3 hosts, nginx on 2.
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].signature, "old_worker");
        assert_eq!(patterns[0].host_count, 3);
        assert_eq!(patterns[0].total_instances, 3);
        assert_eq!(patterns[0].dominant_action, "kill");

        assert_eq!(patterns[1].signature, "nginx");
        assert_eq!(patterns[1].host_count, 2);
    }

    #[test]
    fn test_safety_budget() {
        let inputs = vec![
            host("h1", vec![cand(1, "x", "z", "kill", 0.9)]),
            host("h2", vec![cand(2, "y", "z", "kill", 0.8)]),
        ];
        let fleet = create_fleet_session("f4", None, &inputs, 0.10);

        assert!((fleet.safety_budget.max_fdr - 0.10).abs() < f64::EPSILON);
        assert!((fleet.safety_budget.alpha_remaining - 0.10).abs() < f64::EPSILON);
        assert!((fleet.safety_budget.alpha_spent - 0.0).abs() < f64::EPSILON);
        // Each host gets 0.05 allocation.
        assert!(
            (*fleet.safety_budget.host_allocations.get("h1").unwrap() - 0.05).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_alpha_spending() {
        let inputs = vec![
            host("h1", vec![cand(1, "x", "z", "kill", 0.9)]),
            host("h2", vec![cand(2, "y", "z", "kill", 0.8)]),
        ];
        let mut fleet = create_fleet_session("f5", None, &inputs, 0.10);

        record_alpha_spend(&mut fleet.safety_budget, "h1", 0.03);
        assert!((fleet.safety_budget.alpha_spent - 0.03).abs() < f64::EPSILON);
        assert!((fleet.safety_budget.alpha_remaining - 0.07).abs() < f64::EPSILON);
        assert!(
            (*fleet.safety_budget.host_allocations.get("h1").unwrap() - 0.02).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_empty_fleet() {
        let fleet = create_fleet_session("f6", None, &[], 0.05);
        assert_eq!(fleet.aggregate.total_hosts, 0);
        assert_eq!(fleet.aggregate.total_candidates, 0);
        assert!((fleet.aggregate.mean_candidate_score - 0.0).abs() < f64::EPSILON);
        assert!(fleet.aggregate.recurring_patterns.is_empty());
    }

    #[test]
    fn test_host_with_no_candidates() {
        let inputs = vec![
            host("h1", vec![]),
            host("h2", vec![cand(1, "x", "z", "kill", 0.9)]),
        ];
        let fleet = create_fleet_session("f7", None, &inputs, 0.05);

        assert_eq!(fleet.aggregate.total_candidates, 1);
        assert_eq!(fleet.hosts[0].candidate_count, 0);
        assert!((fleet.hosts[0].summary.mean_candidate_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let inputs = vec![
            host(
                "h1",
                vec![cand(1, "nginx", "useful", "spare", 0.1)],
            ),
            host(
                "h2",
                vec![cand(2, "nginx", "useful", "spare", 0.15)],
            ),
        ];
        let fleet = create_fleet_session("f8", Some("roundtrip test"), &inputs, 0.05);

        let json = serde_json::to_string_pretty(&fleet).unwrap();
        let restored: FleetSession = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.fleet_session_id, "f8");
        assert_eq!(restored.hosts.len(), 2);
        assert_eq!(restored.aggregate.total_hosts, 2);
        assert_eq!(restored.aggregate.recurring_patterns.len(), 1);
        assert_eq!(restored.label.as_deref(), Some("roundtrip test"));
    }

    #[test]
    fn test_deterministic_aggregation() {
        let inputs = vec![
            host(
                "h1",
                vec![
                    cand(1, "a", "zombie", "kill", 0.9),
                    cand(2, "b", "abandoned", "kill", 0.8),
                ],
            ),
            host(
                "h2",
                vec![
                    cand(3, "a", "zombie", "kill", 0.95),
                    cand(4, "c", "useful", "spare", 0.1),
                ],
            ),
        ];

        // Run twice and compare.
        let f1 = create_fleet_session("det", None, &inputs, 0.05);
        let f2 = create_fleet_session("det", None, &inputs, 0.05);

        assert_eq!(f1.aggregate.total_candidates, f2.aggregate.total_candidates);
        assert_eq!(f1.aggregate.class_counts, f2.aggregate.class_counts);
        assert_eq!(f1.aggregate.action_counts, f2.aggregate.action_counts);
        assert!(
            (f1.aggregate.mean_candidate_score - f2.aggregate.mean_candidate_score).abs()
                < f64::EPSILON
        );
        assert_eq!(
            f1.aggregate.recurring_patterns.len(),
            f2.aggregate.recurring_patterns.len()
        );
    }
}
