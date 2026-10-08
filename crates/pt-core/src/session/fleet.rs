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
use std::collections::{HashMap, HashSet};

use crate::decision::{select_fdr, FdrCandidate, FdrMethod, TargetIdentity};

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
    /// Pooled fleet-wide FDR status for kill recommendations.
    pub pooled_fdr: PooledFdrStatus,
}

/// Summary of pooled fleet-wide FDR selection for kill recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PooledFdrStatus {
    /// FDR method used for selection.
    pub method: String,
    /// Alpha level used for pooled selection.
    pub alpha: f64,
    /// Number of kill recommendations evaluated across all hosts.
    pub total_kill_candidates: usize,
    /// Number of kill recommendations approved by pooled FDR.
    pub selected_kills: usize,
    /// Number of kill recommendations rejected by pooled FDR.
    pub rejected_kills: usize,
    /// Selection threshold at the decision boundary: an e-value for `eby`, the lowest
    /// selected P(abandoned or zombie) for `bayes_expected_fdr`.
    pub selection_threshold: Option<f64>,
    /// BY correction factor when applicable.
    pub correction_factor: Option<f64>,
    /// Approved kill counts per host.
    pub selected_by_host: HashMap<String, u32>,
    /// Rejected kill counts per host.
    pub rejected_by_host: HashMap<String, u32>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e_value: Option<f64>,
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
    let (selected_kill_keys, pooled_fdr) = compute_pooled_fdr(host_inputs, max_fdr);

    let hosts: Vec<HostEntry> = host_inputs
        .iter()
        .map(|input| {
            let summary =
                compute_host_summary(&input.host_id, &input.candidates, &selected_kill_keys);
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

    let aggregate = compute_aggregate(&hosts, host_inputs, &selected_kill_keys);
    let safety_budget = compute_safety_budget(&hosts, max_fdr, pooled_fdr);

    FleetSession {
        fleet_session_id: fleet_session_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
        label: label.map(|s| s.to_string()),
        hosts,
        aggregate,
        safety_budget,
    }
}

fn compute_host_summary(
    host_id: &str,
    candidates: &[CandidateInfo],
    selected_kill_keys: &HashSet<String>,
) -> HostSummary {
    let mut class_counts: HashMap<String, u32> = HashMap::new();
    let mut action_counts: HashMap<String, u32> = HashMap::new();
    let mut score_sum = 0.0;
    let mut max_score = 0.0f64;

    for c in candidates {
        let action = effective_action(host_id, c, selected_kill_keys);
        *class_counts.entry(c.classification.clone()).or_default() += 1;
        *action_counts.entry(action).or_default() += 1;
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

fn compute_aggregate(
    hosts: &[HostEntry],
    inputs: &[HostInput],
    selected_kill_keys: &HashSet<String>,
) -> FleetAggregate {
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

    let recurring_patterns = find_recurring_patterns(inputs, selected_kill_keys);

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

fn find_recurring_patterns(
    inputs: &[HostInput],
    selected_kill_keys: &HashSet<String>,
) -> Vec<RecurringPattern> {
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
            let action = effective_action(&input.host_id, c, selected_kill_keys);
            *sig_actions
                .entry(c.signature.clone())
                .or_default()
                .entry(action)
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
                .and_then(|actions| {
                    actions
                        .iter()
                        .max_by_key(|(_, &v)| v)
                        .map(|(k, _)| k.clone())
                })
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

fn compute_safety_budget(
    hosts: &[HostEntry],
    max_fdr: f64,
    pooled_fdr: PooledFdrStatus,
) -> SafetyBudget {
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
        pooled_fdr,
    }
}

fn candidate_key(host_id: &str, pid: u32) -> String {
    format!("{}:{}", host_id, pid)
}

fn effective_action(
    host_id: &str,
    candidate: &CandidateInfo,
    selected_kill_keys: &HashSet<String>,
) -> String {
    let action = candidate.recommended_action.to_ascii_lowercase();
    if action == "kill" && !selected_kill_keys.contains(&candidate_key(host_id, candidate.pid)) {
        "review".to_string()
    } else {
        action
    }
}

/// Bayesian FDR selection: the largest set of kill candidates, most probable first,
/// whose posterior expected false discovery proportion (the mean of 1 - P(abandoned
/// or zombie) over the set) is at most `alpha`. If the posteriors are calibrated, the
/// expected FDP of the selected set is at most `alpha`; it claims nothing more.
///
/// Used when candidates carry posteriors but no e-values: a posterior is not an
/// e-value, and turning one into an "e-value" (as odds^3 once did) voids the eBY
/// guarantee instead of providing it.
fn select_bayes_expected_fdr(scores: &[(usize, f64)], alpha: f64) -> (Vec<usize>, Option<f64>) {
    let mut ranked: Vec<(usize, f64)> = scores
        .iter()
        .map(|&(i, p)| {
            (
                i,
                if p.is_finite() {
                    p.clamp(0.0, 1.0)
                } else {
                    0.0
                },
            )
        })
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut false_mass = 0.0;
    let mut selected = 0;
    for (k, &(_, p)) in ranked.iter().enumerate() {
        false_mass += 1.0 - p;
        if false_mass / (k + 1) as f64 <= alpha {
            selected = k + 1;
        }
    }
    let threshold = selected
        .checked_sub(1)
        .and_then(|last| ranked.get(last))
        .map(|&(_, p)| p);
    (
        ranked[..selected].iter().map(|&(i, _)| i).collect(),
        threshold,
    )
}

fn compute_pooled_fdr(host_inputs: &[HostInput], alpha: f64) -> (HashSet<String>, PooledFdrStatus) {
    // Real e-values (when every kill candidate brings one) go through e-BY; otherwise
    // the posteriors are pooled with Bayesian expected-FDR selection.
    let all_have_evalues = host_inputs
        .iter()
        .flat_map(|input| &input.candidates)
        .filter(|cand| cand.recommended_action.eq_ignore_ascii_case("kill"))
        .all(|cand| cand.e_value.is_some());
    if !all_have_evalues {
        return compute_pooled_bayes_fdr(host_inputs, alpha);
    }

    let mut pool: Vec<(String, String, FdrCandidate)> = Vec::new();
    for input in host_inputs {
        for cand in &input.candidates {
            if !cand.recommended_action.eq_ignore_ascii_case("kill") {
                continue;
            }
            let key = candidate_key(&input.host_id, cand.pid);
            let e_value = cand.e_value.unwrap_or(0.0).max(0.0);
            let fdr_candidate = FdrCandidate {
                target: TargetIdentity {
                    pid: cand.pid as i32,
                    start_id: key.clone(),
                    uid: 0,
                },
                e_value,
            };
            pool.push((key, input.host_id.clone(), fdr_candidate));
        }
    }

    if pool.is_empty() {
        return (
            HashSet::new(),
            PooledFdrStatus {
                method: "eby".to_string(),
                alpha,
                total_kill_candidates: 0,
                selected_kills: 0,
                rejected_kills: 0,
                selection_threshold: None,
                correction_factor: None,
                selected_by_host: HashMap::new(),
                rejected_by_host: HashMap::new(),
            },
        );
    }

    let candidates: Vec<FdrCandidate> = pool.iter().map(|(_, _, c)| c.clone()).collect();
    let selection = select_fdr(&candidates, alpha, FdrMethod::EBy);

    let mut selected_keys = HashSet::new();
    let mut selected_by_host: HashMap<String, u32> = HashMap::new();
    let mut rejected_by_host: HashMap<String, u32> = HashMap::new();

    let (selected_count, selection_threshold, correction_factor) = match selection {
        Ok(result) => {
            for selected in &result.selected_ids {
                selected_keys.insert(selected.start_id.clone());
            }

            for (key, host_id, _) in &pool {
                if selected_keys.contains(key) {
                    *selected_by_host.entry(host_id.clone()).or_default() += 1;
                } else {
                    *rejected_by_host.entry(host_id.clone()).or_default() += 1;
                }
            }

            (
                result.selected_k,
                if result.selection_threshold.is_finite() {
                    Some(result.selection_threshold)
                } else {
                    None
                },
                result.correction_factor,
            )
        }
        Err(_) => {
            for (_, host_id, _) in &pool {
                *rejected_by_host.entry(host_id.clone()).or_default() += 1;
            }
            (0, None, None)
        }
    };

    let total = pool.len();
    let status = PooledFdrStatus {
        method: "eby".to_string(),
        alpha,
        total_kill_candidates: total,
        selected_kills: selected_count,
        rejected_kills: total.saturating_sub(selected_count),
        selection_threshold,
        correction_factor,
        selected_by_host,
        rejected_by_host,
    };

    (selected_keys, status)
}

fn compute_pooled_bayes_fdr(
    host_inputs: &[HostInput],
    alpha: f64,
) -> (HashSet<String>, PooledFdrStatus) {
    let pool: Vec<(String, String, f64)> = host_inputs
        .iter()
        .flat_map(|input| {
            input
                .candidates
                .iter()
                .filter(|cand| cand.recommended_action.eq_ignore_ascii_case("kill"))
                .map(move |cand| {
                    (
                        candidate_key(&input.host_id, cand.pid),
                        input.host_id.clone(),
                        cand.score,
                    )
                })
        })
        .collect();
    let scores: Vec<(usize, f64)> = pool.iter().enumerate().map(|(i, c)| (i, c.2)).collect();
    let (chosen, threshold) = select_bayes_expected_fdr(&scores, alpha);
    let chosen: HashSet<usize> = chosen.into_iter().collect();

    let mut selected_keys = HashSet::new();
    let mut selected_by_host: HashMap<String, u32> = HashMap::new();
    let mut rejected_by_host: HashMap<String, u32> = HashMap::new();
    for (i, (key, host_id, _)) in pool.iter().enumerate() {
        if chosen.contains(&i) {
            selected_keys.insert(key.clone());
            *selected_by_host.entry(host_id.clone()).or_default() += 1;
        } else {
            *rejected_by_host.entry(host_id.clone()).or_default() += 1;
        }
    }
    let status = PooledFdrStatus {
        method: "bayes_expected_fdr".to_string(),
        alpha,
        total_kill_candidates: pool.len(),
        selected_kills: chosen.len(),
        rejected_kills: pool.len() - chosen.len(),
        selection_threshold: threshold,
        correction_factor: None,
        selected_by_host,
        rejected_by_host,
    };
    (selected_keys, status)
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
            e_value: None,
        }
    }

    fn cand_with_e(
        pid: u32,
        sig: &str,
        class: &str,
        action: &str,
        score: f64,
        e_value: f64,
    ) -> CandidateInfo {
        CandidateInfo {
            pid,
            signature: sig.to_string(),
            classification: class.to_string(),
            recommended_action: action.to_string(),
            score,
            e_value: Some(e_value),
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
        // Kill posteriors high enough that the 5% fleet FDR budget admits all three
        // (expected FDP 0.0117); at ~0.88 they would be held for review.
        let inputs = vec![
            host(
                "host1",
                vec![
                    cand(1, "nginx", "useful", "spare", 0.1),
                    cand(2, "old_worker", "abandoned", "kill", 0.99),
                ],
            ),
            host(
                "host2",
                vec![
                    cand(3, "nginx", "useful", "spare", 0.15),
                    cand(4, "old_worker", "abandoned", "kill", 0.985),
                ],
            ),
            host(
                "host3",
                vec![cand(5, "old_worker", "abandoned", "kill", 0.99)],
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
        // Posteriors without e-values: Bayesian expected-FDR selection, not e-BY.
        assert_eq!(fleet.safety_budget.pooled_fdr.method, "bayes_expected_fdr");
        assert_eq!(fleet.safety_budget.pooled_fdr.total_kill_candidates, 2);
        // Each host gets 0.05 allocation.
        assert!(
            (*fleet.safety_budget.host_allocations.get("h1").unwrap() - 0.05).abs() < f64::EPSILON
        );
    }

    #[test]
    fn test_pooled_fdr_filters_low_evidence_kills() {
        let inputs = vec![
            host(
                "h1",
                vec![
                    cand_with_e(1, "sig-a", "abandoned", "kill", 0.99, 220.0),
                    cand_with_e(2, "sig-b", "abandoned", "kill", 0.80, 30.0),
                ],
            ),
            host(
                "h2",
                vec![cand_with_e(3, "sig-c", "zombie", "kill", 0.97, 130.0)],
            ),
        ];

        let fleet = create_fleet_session("fdr-filter", None, &inputs, 0.05);

        // For m=3 and alpha=0.05 with eBY, first two pass and one is filtered.
        assert_eq!(fleet.safety_budget.pooled_fdr.total_kill_candidates, 3);
        assert_eq!(fleet.safety_budget.pooled_fdr.selected_kills, 2);
        assert_eq!(fleet.safety_budget.pooled_fdr.rejected_kills, 1);

        // One kill should be downgraded to review in aggregate action counts.
        assert_eq!(*fleet.aggregate.action_counts.get("kill").unwrap_or(&0), 2);
        assert_eq!(
            *fleet.aggregate.action_counts.get("review").unwrap_or(&0),
            1
        );
    }

    #[test]
    fn bayes_fdr_selects_the_largest_set_within_alpha() {
        // Sorted: 0.99, 0.97, 0.80. Expected FDP: 0.01, 0.02, then 0.08 > 0.05.
        let inputs = vec![
            host(
                "h1",
                vec![
                    cand(1, "a", "abandoned", "kill", 0.99),
                    cand(2, "b", "abandoned", "kill", 0.80),
                    cand(9, "c", "useful", "keep", 0.10),
                ],
            ),
            host("h2", vec![cand(3, "c", "zombie", "kill", 0.97)]),
        ];
        let fleet = create_fleet_session("bayes", None, &inputs, 0.05);
        let fdr = &fleet.safety_budget.pooled_fdr;
        assert_eq!(fdr.method, "bayes_expected_fdr");
        assert_eq!((fdr.total_kill_candidates, fdr.selected_kills), (3, 2));
        assert_eq!(fdr.selection_threshold, Some(0.97));
        assert_eq!(*fleet.aggregate.action_counts.get("kill").unwrap_or(&0), 2);

        let (none, threshold) = select_bayes_expected_fdr(&[(0, 0.5), (1, 0.6)], 0.05);
        assert!(none.is_empty() && threshold.is_none());
    }

    /// The guarantee, checked by simulation: when the truth is drawn from the
    /// posteriors (a calibrated model), the realized false discovery proportion of the
    /// selected set averages at most alpha.
    #[test]
    fn bayes_fdr_controls_expected_fdp_under_calibrated_posteriors() {
        // Deterministic xorshift so the test needs no RNG crate.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut uniform = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as f64 / (1u64 << 53) as f64
        };
        let alpha = 0.05;
        let trials = 4000;
        let mut fdp_sum = 0.0;
        let mut selections = 0;
        for _ in 0..trials {
            let scores: Vec<(usize, f64)> = (0..12)
                .map(|i| (i, 0.5 + 0.5 * uniform().powf(0.3)))
                .collect();
            let (chosen, _) = select_bayes_expected_fdr(&scores, alpha);
            if chosen.is_empty() {
                continue;
            }
            selections += 1;
            let false_discoveries = chosen
                .iter()
                .filter(|&&i| uniform() >= scores[i].1) // truth: abandoned with prob p
                .count();
            fdp_sum += false_discoveries as f64 / chosen.len() as f64;
        }
        assert!(
            selections > trials / 2,
            "selection should usually pick something"
        );
        let mean_fdp = fdp_sum / trials as f64;
        assert!(
            mean_fdp <= alpha + 0.01,
            "mean FDP {mean_fdp} exceeds {alpha}"
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
            (*fleet.safety_budget.host_allocations.get("h1").unwrap() - 0.02).abs() < f64::EPSILON
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
            host("h1", vec![cand(1, "nginx", "useful", "spare", 0.1)]),
            host("h2", vec![cand(2, "nginx", "useful", "spare", 0.15)]),
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
