//! Provenance explanation ranking, evidence prioritization, and
//! counterfactual story generation.
//!
//! Produces human-readable explanations for triage decisions by ranking
//! evidence by decision relevance, generating counterfactual stories
//! ("what would break if killed"), and surfacing missing evidence that
//! prevented a stronger claim.
//!
//! # Output Contract
//!
//! Every explanation includes:
//! 1. **Why it exists** — process origin, supervisor, workspace context
//! 2. **Why it's suspicious** — ranked evidence driving the posterior
//! 3. **What would break** — blast-radius impact summary
//! 4. **What's missing** — evidence gaps that lowered confidence

use crate::decision::blast_radius_estimator::{BlastRadiusEstimate, RiskLevel};
use crate::decision::provenance_scoring::ProvenanceAdjustedScore;
use serde::{Deserialize, Serialize};

/// A ranked piece of evidence for explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedEvidence {
    /// Evidence category (e.g., "cpu", "orphan", "queue_saturated").
    pub category: String,
    /// Relative importance [0, 1]. Higher = more decision-relevant.
    pub importance: f64,
    /// Direction: positive = supports kill, negative = supports spare.
    pub direction: EvidenceDirection,
    /// Human-readable description.
    pub description: String,
}

/// Whether evidence supports killing or sparing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceDirection {
    /// Evidence supports killing (process is abandoned/zombie).
    SupportsKill,
    /// Evidence supports sparing (process is useful).
    SupportsSpare,
    /// Evidence is neutral or uninformative.
    Neutral,
}

/// A counterfactual story about what would happen if the process is killed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualStory {
    /// Short headline (e.g., "Killing would affect 3 processes").
    pub headline: String,
    /// Detailed impact description.
    pub details: Vec<String>,
    /// Risk level from blast-radius estimation.
    pub risk_level: RiskLevel,
}

/// Missing evidence that could have increased confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEvidence {
    /// What evidence is missing.
    pub category: String,
    /// Why it matters.
    pub reason: String,
    /// How much it could improve confidence (rough estimate).
    pub potential_improvement: PotentialImprovement,
}

/// Rough estimate of how much missing evidence could help.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PotentialImprovement {
    /// Could significantly change the decision.
    High,
    /// Would moderately improve confidence.
    Medium,
    /// Minor improvement expected.
    Low,
}

/// Complete explanation for a triage decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceExplanation {
    /// Target process.
    pub pid: u32,
    /// Ranked evidence (most important first).
    pub ranked_evidence: Vec<RankedEvidence>,
    /// Counterfactual story.
    pub counterfactual: CounterfactualStory,
    /// Missing evidence that reduced confidence.
    pub missing_evidence: Vec<MissingEvidence>,
    /// One-line summary.
    pub summary: String,
}

/// Build a provenance explanation from scoring and blast-radius results.
pub fn build_explanation(
    pid: u32,
    adjusted: &ProvenanceAdjustedScore,
    blast_radius: &BlastRadiusEstimate,
    evidence_terms: &[(String, f64)],
    has_deep_scan: bool,
    has_network_scan: bool,
) -> ProvenanceExplanation {
    let ranked_evidence = rank_evidence(evidence_terms, adjusted.original_confidence);
    let counterfactual = build_counterfactual(blast_radius);
    let missing_evidence = identify_missing(has_deep_scan, has_network_scan, blast_radius);
    let summary = build_one_liner(pid, adjusted, blast_radius);

    ProvenanceExplanation {
        pid,
        ranked_evidence,
        counterfactual,
        missing_evidence,
        summary,
    }
}

fn rank_evidence(terms: &[(String, f64)], posterior: f64) -> Vec<RankedEvidence> {
    let mut ranked: Vec<RankedEvidence> = terms
        .iter()
        .filter(|(name, _)| name != "prior") // Don't show prior as evidence.
        .map(|(name, log_lik)| {
            let abs_contribution = log_lik.abs();
            let direction = if *log_lik > 0.1 {
                EvidenceDirection::SupportsKill
            } else if *log_lik < -0.1 {
                EvidenceDirection::SupportsSpare
            } else {
                EvidenceDirection::Neutral
            };
            let description = describe_evidence(name, *log_lik, posterior);
            RankedEvidence {
                category: name.clone(),
                importance: abs_contribution.min(5.0) / 5.0, // Normalize to [0, 1].
                direction,
                description,
            }
        })
        .collect();

    // Sort by importance descending.
    ranked.sort_by(|a, b| {
        b.importance
            .partial_cmp(&a.importance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked
}

fn describe_evidence(name: &str, log_lik: f64, _posterior: f64) -> String {
    let strength = if log_lik.abs() > 3.0 {
        "strongly"
    } else if log_lik.abs() > 1.0 {
        "moderately"
    } else {
        "weakly"
    };

    let direction = if log_lik > 0.0 {
        "suspicious"
    } else {
        "normal"
    };

    match name {
        "cpu" => format!("CPU activity {strength} suggests process is {direction}"),
        "runtime" => format!("Runtime duration {strength} suggests process is {direction}"),
        "orphan" => format!("Orphan status {strength} suggests process is {direction}"),
        "tty" => format!("Terminal attachment {strength} suggests process is {direction}"),
        "net" => format!("Network activity {strength} suggests process is {direction}"),
        "io_active" => format!("I/O activity {strength} suggests process is {direction}"),
        "queue_saturated" => format!("Queue saturation {strength} suggests process is {direction}"),
        "state_flag" => format!("Process state {strength} suggests process is {direction}"),
        "command_category" => format!("Command type {strength} suggests process is {direction}"),
        _ => format!("{name} {strength} suggests process is {direction}"),
    }
}

fn build_counterfactual(blast_radius: &BlastRadiusEstimate) -> CounterfactualStory {
    let total = blast_radius.total_affected;
    let risk = blast_radius.risk_level;

    let headline = if total == 0 {
        "Killing this process is unlikely to affect other processes".to_string()
    } else {
        format!(
            "Killing would affect {} other process{}",
            total,
            if total == 1 { "" } else { "es" }
        )
    };

    let mut details = Vec::new();

    let direct = &blast_radius.direct;
    if direct.components.co_holder_count > 0 {
        details.push(format!(
            "{} process(es) share resources directly",
            direct.components.co_holder_count
        ));
    }
    if direct.components.contested_count > 0 {
        details.push(format!(
            "{} contested resource(s) would lose a holder",
            direct.components.contested_count
        ));
    }
    if direct.components.listener_count > 0 {
        details.push(format!(
            "{} network listener(s) would go down",
            direct.components.listener_count
        ));
    }
    if direct.components.child_count > 0 {
        details.push(format!(
            "{} child process(es) would be orphaned",
            direct.components.child_count
        ));
    }
    if direct.components.is_supervised {
        details.push("Supervisor may auto-restart (reducing kill effectiveness)".to_string());
    }

    CounterfactualStory {
        headline,
        details,
        risk_level: risk,
    }
}

fn identify_missing(
    has_deep_scan: bool,
    has_network_scan: bool,
    blast_radius: &BlastRadiusEstimate,
) -> Vec<MissingEvidence> {
    let mut missing = Vec::new();

    if !has_deep_scan {
        missing.push(MissingEvidence {
            category: "deep_scan".to_string(),
            reason: "No /proc inspection — CPU progress, I/O activity, and TTY state unknown"
                .to_string(),
            potential_improvement: PotentialImprovement::High,
        });
    }

    if !has_network_scan {
        missing.push(MissingEvidence {
            category: "network_scan".to_string(),
            reason: "No network scan — socket states and queue depths unknown".to_string(),
            potential_improvement: PotentialImprovement::Medium,
        });
    }

    if blast_radius.confidence < 0.5 {
        missing.push(MissingEvidence {
            category: "evidence_completeness".to_string(),
            reason: format!(
                "Only {:.0}% of expected probes ran — blast radius estimate is uncertain",
                blast_radius.confidence * 100.0
            ),
            potential_improvement: PotentialImprovement::High,
        });
    }

    missing
}

fn build_one_liner(
    pid: u32,
    adjusted: &ProvenanceAdjustedScore,
    blast_radius: &BlastRadiusEstimate,
) -> String {
    let action = match adjusted.recommendation {
        crate::decision::provenance_scoring::ActionRecommendation::AutoKill => {
            "auto-kill recommended"
        }
        crate::decision::provenance_scoring::ActionRecommendation::ConfirmKill => {
            "kill after confirmation"
        }
        crate::decision::provenance_scoring::ActionRecommendation::Review => "review recommended",
        crate::decision::provenance_scoring::ActionRecommendation::Block => "kill blocked",
        crate::decision::provenance_scoring::ActionRecommendation::NoAction => "no action",
    };
    format!(
        "PID {}: {} (confidence={:.0}%, risk={:?}, {} affected)",
        pid,
        action,
        adjusted.adjusted_confidence * 100.0,
        blast_radius.risk_level,
        blast_radius.total_affected,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::shared_resource_graph::SharedResourceGraph;
    use crate::decision::blast_radius_estimator::estimate_blast_radius;
    use crate::decision::provenance_scoring::compute_provenance_adjusted_score;
    use pt_common::{
        LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
        ResourceKind, ResourceState,
    };

    fn lock_ev(pid: u32, path: &str) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: path.to_string(),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcFd,
            state: ResourceState::Active,
            details: ResourceDetails::Lockfile {
                path: path.to_string(),
                mechanism: LockMechanism::Existence,
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn test_explanation() -> ProvenanceExplanation {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let br = estimate_blast_radius(100, &graph, None, &[300, 400], 0.8, &Default::default());
        let adj = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        let terms = vec![
            ("cpu".to_string(), -0.5),
            ("runtime".to_string(), 2.0),
            ("orphan".to_string(), 1.5),
            ("prior".to_string(), -1.0),
        ];
        build_explanation(100, &adj, &br, &terms, true, true)
    }

    #[test]
    fn explanation_has_ranked_evidence() {
        let exp = test_explanation();
        assert!(!exp.ranked_evidence.is_empty());
        // Prior should be filtered out.
        assert!(!exp.ranked_evidence.iter().any(|e| e.category == "prior"));
    }

    #[test]
    fn evidence_sorted_by_importance_descending() {
        let exp = test_explanation();
        for pair in exp.ranked_evidence.windows(2) {
            assert!(
                pair[0].importance >= pair[1].importance,
                "{} ({}) should >= {} ({})",
                pair[0].category,
                pair[0].importance,
                pair[1].category,
                pair[1].importance,
            );
        }
    }

    #[test]
    fn counterfactual_has_headline() {
        let exp = test_explanation();
        assert!(!exp.counterfactual.headline.is_empty());
    }

    #[test]
    fn counterfactual_mentions_children() {
        let exp = test_explanation();
        // The test has child_pids = [300, 400].
        assert!(
            exp.counterfactual
                .details
                .iter()
                .any(|d| d.contains("child")),
            "details: {:?}",
            exp.counterfactual.details,
        );
    }

    #[test]
    fn missing_evidence_when_no_deep_scan() {
        let graph = SharedResourceGraph::default();
        let br = estimate_blast_radius(100, &graph, None, &[], 1.0, &Default::default());
        let adj = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        let exp = build_explanation(100, &adj, &br, &[], false, true);
        assert!(exp
            .missing_evidence
            .iter()
            .any(|m| m.category == "deep_scan"));
    }

    #[test]
    fn missing_evidence_when_low_completeness() {
        let graph = SharedResourceGraph::default();
        let br = estimate_blast_radius(100, &graph, None, &[], 0.3, &Default::default());
        let adj = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        let exp = build_explanation(100, &adj, &br, &[], true, true);
        assert!(
            exp.missing_evidence
                .iter()
                .any(|m| m.category == "evidence_completeness"),
            "missing: {:?}",
            exp.missing_evidence,
        );
    }

    #[test]
    fn no_missing_evidence_when_full_scan() {
        let graph = SharedResourceGraph::default();
        let br = estimate_blast_radius(100, &graph, None, &[], 1.0, &Default::default());
        let adj = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        let exp = build_explanation(100, &adj, &br, &[], true, true);
        assert!(exp.missing_evidence.is_empty());
    }

    #[test]
    fn summary_is_one_liner() {
        let exp = test_explanation();
        assert!(exp.summary.contains("PID 100"));
        assert!(!exp.summary.contains('\n'));
    }

    #[test]
    fn evidence_direction_correct() {
        let terms = vec![
            ("runtime".to_string(), 2.0), // supports kill
            ("cpu".to_string(), -1.5),    // supports spare
            ("tty".to_string(), 0.01),    // neutral
        ];
        let ranked = rank_evidence(&terms, 0.8);
        assert_eq!(ranked[0].direction, EvidenceDirection::SupportsKill);
        assert_eq!(ranked[1].direction, EvidenceDirection::SupportsSpare);
        assert_eq!(ranked[2].direction, EvidenceDirection::Neutral);
    }

    #[test]
    fn serde_roundtrip() {
        let exp = test_explanation();
        let json = serde_json::to_string(&exp).unwrap();
        let deser: ProvenanceExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pid, 100);
        assert_eq!(deser.ranked_evidence.len(), exp.ranked_evidence.len());
    }
}
