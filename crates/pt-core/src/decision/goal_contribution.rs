//! Expected goal contribution per action, with uncertainty.
//!
//! Estimates how much each candidate kill/stop contributes toward a
//! resource goal, accounting for shared memory, respawn probability,
//! and blast radius.

use serde::{Deserialize, Serialize};

/// A candidate process for goal contribution estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionCandidate {
    /// Process identifier.
    pub pid: u32,
    /// RSS bytes.
    pub rss_bytes: u64,
    /// USS bytes (if known).
    pub uss_bytes: Option<u64>,
    /// CPU fraction (0.0 to 1.0+).
    pub cpu_frac: f64,
    /// File descriptor count.
    pub fd_count: u32,
    /// Bound ports.
    pub bound_ports: Vec<u16>,
    /// Probability of respawn after kill (0.0 to 1.0).
    pub respawn_probability: f64,
    /// Whether this process has shared memory segments.
    pub has_shared_memory: bool,
    /// Number of child processes.
    pub child_count: usize,
}

/// Estimated contribution toward a goal metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalContribution {
    /// Expected value of the contribution.
    pub expected: f64,
    /// Lower bound (pessimistic).
    pub low: f64,
    /// Upper bound (optimistic).
    pub high: f64,
    /// Confidence in the estimate (0.0 to 1.0).
    pub confidence: f64,
    /// Factors affecting the estimate.
    pub factors: Vec<ContributionFactor>,
}

/// A factor that modifies the contribution estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionFactor {
    pub name: String,
    pub multiplier: f64,
    pub explanation: String,
}

/// Estimate memory contribution from killing a process.
pub fn estimate_memory_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    // Base: use USS if available (true private memory), else RSS.
    let base_bytes = candidate.uss_bytes.unwrap_or(candidate.rss_bytes) as f64;

    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    // Shared memory discount: RSS includes shared pages.
    if candidate.uss_bytes.is_none() && candidate.has_shared_memory {
        let shared_discount = 0.6; // Assume 40% shared.
        multiplier *= shared_discount;
        factors.push(ContributionFactor {
            name: "shared_memory".to_string(),
            multiplier: shared_discount,
            explanation: "RSS includes shared pages; estimated 40% shared".to_string(),
        });
    }

    // Respawn discount: if process respawns, memory isn't permanently freed.
    if candidate.respawn_probability > 0.0 {
        let respawn_discount = 1.0 - candidate.respawn_probability;
        multiplier *= respawn_discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: respawn_discount,
            explanation: format!(
                "Respawn probability {:.0}% reduces expected contribution",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    let expected = base_bytes * multiplier;

    // Uncertainty: wider when USS unknown or respawn likely.
    let uncertainty_factor = if candidate.uss_bytes.is_some() {
        0.1
    } else {
        0.3
    };
    let low = expected * (1.0 - uncertainty_factor);
    let high = base_bytes * (1.0 + uncertainty_factor * 0.5); // High can exceed expected

    let confidence = if candidate.uss_bytes.is_some() {
        0.9
    } else {
        0.6
    };
    let confidence = confidence * (1.0 - candidate.respawn_probability * 0.5);

    GoalContribution {
        expected,
        low: low.max(0.0),
        high,
        confidence: confidence.max(0.0).min(1.0),
        factors,
    }
}

/// Estimate CPU contribution from killing a process.
pub fn estimate_cpu_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    let base_cpu = candidate.cpu_frac;
    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    if candidate.respawn_probability > 0.0 {
        let discount = 1.0 - candidate.respawn_probability;
        multiplier *= discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: discount,
            explanation: format!(
                "Respawn probability {:.0}%",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    let expected = base_cpu * multiplier;
    let low = expected * 0.8;
    let high = base_cpu * 1.1; // CPU slightly fluctuates

    GoalContribution {
        expected,
        low: low.max(0.0),
        high: high.min(1.0),
        confidence: (0.8 * (1.0 - candidate.respawn_probability * 0.5))
            .max(0.0)
            .min(1.0),
        factors,
    }
}

/// Estimate port release contribution.
pub fn estimate_port_contribution(
    candidate: &ContributionCandidate,
    target_port: u16,
) -> GoalContribution {
    let holds_port = candidate.bound_ports.contains(&target_port);

    if !holds_port {
        return GoalContribution {
            expected: 0.0,
            low: 0.0,
            high: 0.0,
            confidence: 1.0,
            factors: vec![],
        };
    }

    let mut factors = Vec::new();
    let mut prob = 1.0;

    if candidate.respawn_probability > 0.0 {
        prob *= 1.0 - candidate.respawn_probability;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: 1.0 - candidate.respawn_probability,
            explanation: "Process may respawn and rebind port".to_string(),
        });
    }

    GoalContribution {
        expected: prob,
        low: prob * 0.9,
        high: 1.0,
        confidence: (0.9 * (1.0 - candidate.respawn_probability * 0.5))
            .max(0.0)
            .min(1.0),
        factors,
    }
}

/// Estimate FD contribution from killing a process.
pub fn estimate_fd_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    let base = candidate.fd_count as f64;
    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    if candidate.respawn_probability > 0.0 {
        let discount = 1.0 - candidate.respawn_probability;
        multiplier *= discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: discount,
            explanation: format!(
                "Respawn probability {:.0}%",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    // Child processes also hold FDs.
    if candidate.child_count > 0 {
        let child_factor = 1.0 + (candidate.child_count as f64 * 0.5).min(3.0);
        multiplier *= child_factor;
        factors.push(ContributionFactor {
            name: "children".to_string(),
            multiplier: child_factor,
            explanation: format!(
                "Process has {} children that may also release FDs",
                candidate.child_count
            ),
        });
    }

    let expected = base * multiplier;

    GoalContribution {
        expected,
        low: (base * 0.8).max(0.0),
        high: expected * 1.2,
        confidence: 0.7,
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate() -> ContributionCandidate {
        ContributionCandidate {
            pid: 1234,
            rss_bytes: 1_000_000_000, // 1GB
            uss_bytes: None,
            cpu_frac: 0.25,
            fd_count: 50,
            bound_ports: vec![3000],
            respawn_probability: 0.0,
            has_shared_memory: false,
            child_count: 0,
        }
    }

    #[test]
    fn test_memory_basic() {
        let c = make_candidate();
        let contrib = estimate_memory_contribution(&c);
        assert!(contrib.expected > 0.0);
        assert!(contrib.low < contrib.expected);
        assert!(contrib.high > contrib.expected);
        assert!(contrib.confidence > 0.5);
    }

    #[test]
    fn test_memory_with_uss() {
        let c = ContributionCandidate {
            uss_bytes: Some(500_000_000),
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        // Should use USS, not RSS.
        assert!((contrib.expected - 500_000_000.0).abs() < 100_000_000.0);
        assert!(contrib.confidence > 0.8); // Higher confidence with USS.
    }

    #[test]
    fn test_memory_shared_discount() {
        let c = ContributionCandidate {
            has_shared_memory: true,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        // Should be discounted below RSS.
        assert!(contrib.expected < 1_000_000_000.0);
        assert!(
            contrib.factors.iter().any(|f| f.name == "shared_memory"),
            "Should have shared_memory factor"
        );
    }

    #[test]
    fn test_memory_respawn_discount() {
        let c = ContributionCandidate {
            respawn_probability: 0.8,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        assert!(contrib.expected < 300_000_000.0); // 1GB * (1-0.8) = 200MB
        assert!(contrib.confidence < 0.7);
    }

    #[test]
    fn test_cpu_basic() {
        let c = make_candidate();
        let contrib = estimate_cpu_contribution(&c);
        assert!((contrib.expected - 0.25).abs() < 0.05);
    }

    #[test]
    fn test_cpu_respawn() {
        let c = ContributionCandidate {
            respawn_probability: 0.5,
            ..make_candidate()
        };
        let contrib = estimate_cpu_contribution(&c);
        assert!((contrib.expected - 0.125).abs() < 0.05); // 0.25 * 0.5
    }

    #[test]
    fn test_port_holds_target() {
        let c = make_candidate();
        let contrib = estimate_port_contribution(&c, 3000);
        assert!(contrib.expected > 0.9);
    }

    #[test]
    fn test_port_does_not_hold() {
        let c = make_candidate();
        let contrib = estimate_port_contribution(&c, 8080);
        assert_eq!(contrib.expected, 0.0);
    }

    #[test]
    fn test_port_with_respawn() {
        let c = ContributionCandidate {
            respawn_probability: 0.7,
            ..make_candidate()
        };
        let contrib = estimate_port_contribution(&c, 3000);
        assert!(contrib.expected < 0.5); // High respawn probability.
    }

    #[test]
    fn test_fd_basic() {
        let c = make_candidate();
        let contrib = estimate_fd_contribution(&c);
        assert!((contrib.expected - 50.0).abs() < 10.0);
    }

    #[test]
    fn test_fd_with_children() {
        let c = ContributionCandidate {
            child_count: 4,
            ..make_candidate()
        };
        let contrib = estimate_fd_contribution(&c);
        // Should account for children's FDs.
        assert!(contrib.expected > 50.0);
        assert!(
            contrib.factors.iter().any(|f| f.name == "children"),
            "Should have children factor"
        );
    }

    #[test]
    fn test_all_contributions_have_intervals() {
        let c = make_candidate();
        for contrib in [
            estimate_memory_contribution(&c),
            estimate_cpu_contribution(&c),
            estimate_port_contribution(&c, 3000),
            estimate_fd_contribution(&c),
        ] {
            assert!(contrib.low <= contrib.expected, "low should be <= expected");
            assert!(
                contrib.high >= contrib.expected || contrib.expected == 0.0,
                "high should be >= expected"
            );
        }
    }
}
