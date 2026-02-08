//! Value of Information (VOI) computation for decision-theoretic probe scheduling.
//!
//! This module implements VOI analysis for deciding whether to gather more evidence
//! (probe / wait / deep scan) or act now. VOI compares acting immediately versus
//! acting after acquiring one more measurement.
//!
//! # Mathematical Foundation
//!
//! ```text
//! VOI(m) = E_y[ min_a E[L(a,S) | b ⊕ (m,y)] ] - min_a E[L(a,S) | b ] - cost(m)
//!
//! Act now if: min_m VOI(m) >= 0
//! Probe with m* if: VOI(m*) < 0 (probing reduces expected loss enough to justify cost)
//! ```
//!
//! Note: Negative VOI means the probe is worthwhile (reduces expected loss).

use crate::config::policy::{LossMatrix, Policy};
use crate::decision::expected_loss::{
    expected_loss_for_action, select_optimal_action, Action, ActionFeasibility, DecisionError,
    ExpectedLoss,
};
use crate::inference::ClassScores;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Available probe types for gathering additional evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// Wait for a period (free but slow) - allows process state to evolve.
    Wait15Min,
    /// Wait for a shorter period.
    Wait5Min,
    /// Quick scan - fast ps-based collection.
    QuickScan,
    /// Deep scan - comprehensive /proc inspection.
    DeepScan,
    /// Stack sampling via perf or gdb.
    StackSample,
    /// System call tracing (strace/sysdig).
    Strace,
    /// Network connection snapshot.
    NetSnapshot,
    /// I/O activity monitoring.
    IoSnapshot,
    /// Cgroup resource inspection.
    CgroupInspect,
}

impl ProbeType {
    /// All available probe types.
    pub const ALL: &'static [ProbeType] = &[
        ProbeType::Wait15Min,
        ProbeType::Wait5Min,
        ProbeType::QuickScan,
        ProbeType::DeepScan,
        ProbeType::StackSample,
        ProbeType::Strace,
        ProbeType::NetSnapshot,
        ProbeType::IoSnapshot,
        ProbeType::CgroupInspect,
    ];

    /// Returns the display name for this probe type.
    pub fn name(&self) -> &'static str {
        match self {
            ProbeType::Wait15Min => "wait_15min",
            ProbeType::Wait5Min => "wait_5min",
            ProbeType::QuickScan => "quick_scan",
            ProbeType::DeepScan => "deep_scan",
            ProbeType::StackSample => "stack_sample",
            ProbeType::Strace => "strace",
            ProbeType::NetSnapshot => "net_snapshot",
            ProbeType::IoSnapshot => "io_snapshot",
            ProbeType::CgroupInspect => "cgroup_inspect",
        }
    }
}

/// Cost structure for a probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCost {
    /// Wall-clock time cost in seconds.
    pub time_seconds: f64,
    /// Computational overhead (0.0 = free, 1.0 = high).
    pub overhead: f64,
    /// Intrusiveness factor (0.0 = passive, 1.0 = highly intrusive).
    pub intrusiveness: f64,
    /// Risk factor (probability probe causes issues).
    pub risk: f64,
}

impl ProbeCost {
    /// Compute total normalized cost (higher = more expensive).
    pub fn total(&self) -> f64 {
        // Weighted combination of factors
        let time_weight = 0.3;
        let overhead_weight = 0.3;
        let intrusiveness_weight = 0.2;
        let risk_weight = 0.2;

        // Normalize time (log scale for 1s to 1hr range)
        let time_normalized = (self.time_seconds.max(1.0).ln() / 8.5).min(1.0);

        time_weight * time_normalized
            + overhead_weight * self.overhead
            + intrusiveness_weight * self.intrusiveness
            + risk_weight * self.risk
    }
}

/// Default probe costs (conservative estimates).
impl Default for ProbeCost {
    fn default() -> Self {
        Self {
            time_seconds: 1.0,
            overhead: 0.1,
            intrusiveness: 0.1,
            risk: 0.01,
        }
    }
}

/// Configuration for probe costs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCostModel {
    /// Per-probe cost overrides.
    pub costs: HashMap<ProbeType, ProbeCost>,
    /// Base cost multiplier (scales all costs).
    #[serde(default = "default_base_multiplier")]
    pub base_multiplier: f64,
}

fn default_base_multiplier() -> f64 {
    1.0
}

impl Default for ProbeCostModel {
    fn default() -> Self {
        let mut costs = HashMap::new();

        // Wait probes: free overhead but time cost
        costs.insert(
            ProbeType::Wait15Min,
            ProbeCost {
                time_seconds: 900.0,
                overhead: 0.0,
                intrusiveness: 0.0,
                risk: 0.0,
            },
        );
        costs.insert(
            ProbeType::Wait5Min,
            ProbeCost {
                time_seconds: 300.0,
                overhead: 0.0,
                intrusiveness: 0.0,
                risk: 0.0,
            },
        );

        // Quick scan: fast, low cost
        costs.insert(
            ProbeType::QuickScan,
            ProbeCost {
                time_seconds: 2.0,
                overhead: 0.1,
                intrusiveness: 0.0,
                risk: 0.0,
            },
        );

        // Deep scan: moderate cost
        costs.insert(
            ProbeType::DeepScan,
            ProbeCost {
                time_seconds: 30.0,
                overhead: 0.4,
                intrusiveness: 0.1,
                risk: 0.01,
            },
        );

        // Stack sample: higher cost, specific info
        costs.insert(
            ProbeType::StackSample,
            ProbeCost {
                time_seconds: 5.0,
                overhead: 0.5,
                intrusiveness: 0.3,
                risk: 0.02,
            },
        );

        // Strace: high cost, intrusive
        costs.insert(
            ProbeType::Strace,
            ProbeCost {
                time_seconds: 10.0,
                overhead: 0.8,
                intrusiveness: 0.7,
                risk: 0.05,
            },
        );

        // Net snapshot: moderate cost
        costs.insert(
            ProbeType::NetSnapshot,
            ProbeCost {
                time_seconds: 3.0,
                overhead: 0.3,
                intrusiveness: 0.1,
                risk: 0.01,
            },
        );

        // I/O snapshot: moderate cost
        costs.insert(
            ProbeType::IoSnapshot,
            ProbeCost {
                time_seconds: 5.0,
                overhead: 0.3,
                intrusiveness: 0.1,
                risk: 0.01,
            },
        );

        // Cgroup inspect: low cost
        costs.insert(
            ProbeType::CgroupInspect,
            ProbeCost {
                time_seconds: 1.0,
                overhead: 0.1,
                intrusiveness: 0.0,
                risk: 0.0,
            },
        );

        Self {
            costs,
            base_multiplier: 1.0,
        }
    }
}

impl ProbeCostModel {
    /// Get the cost for a probe type.
    pub fn cost(&self, probe: ProbeType) -> f64 {
        let base = self.costs.get(&probe).map(|c| c.total()).unwrap_or(0.5);
        base * self.base_multiplier
    }

    /// Get detailed cost breakdown.
    pub fn cost_details(&self, probe: ProbeType) -> ProbeCost {
        self.costs.get(&probe).cloned().unwrap_or_default()
    }
}

/// Expected information gain from a probe (how much it changes posteriors).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeInformationGain {
    /// Probe type.
    pub probe: ProbeType,
    /// Expected entropy reduction (bits).
    pub entropy_reduction: f64,
    /// Expected posterior shift magnitude.
    pub posterior_shift: f64,
    /// Probability of changing optimal action.
    pub action_change_prob: f64,
}

/// Result of VOI analysis for a single probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeVoi {
    /// Probe type.
    pub probe: ProbeType,
    /// VOI value (negative = probe is worthwhile).
    pub voi: f64,
    /// Total cost of the probe.
    pub cost: f64,
    /// VOI to cost ratio (higher = better value).
    pub ratio: f64,
    /// Expected loss after acquiring this probe's evidence.
    pub expected_loss_after: f64,
}

/// Complete VOI analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiAnalysis {
    /// Current expected losses for each action.
    pub current_expected_loss: Vec<ExpectedLoss>,
    /// Current optimal action (without additional probing).
    pub current_optimal_action: Action,
    /// Current minimum expected loss.
    pub current_min_loss: f64,
    /// VOI analysis for each considered probe.
    pub probes: Vec<ProbeVoi>,
    /// Best probe to acquire (if any).
    pub best_probe: Option<ProbeType>,
    /// Whether to act now (true) or probe (false).
    pub act_now: bool,
    /// Explanation of the decision.
    pub rationale: String,
}

/// Errors from VOI computation.
#[derive(Debug, Error)]
pub enum VoiError {
    #[error("decision error: {0}")]
    Decision(#[from] DecisionError),
    #[error("invalid posterior for VOI: {message}")]
    InvalidPosterior { message: String },
    #[error("no probes available")]
    NoProbesAvailable,
}

/// Compute expected loss given posterior and loss matrix (internal helper).
fn compute_expected_losses(
    posterior: &ClassScores,
    loss_matrix: &LossMatrix,
    feasibility: &ActionFeasibility,
) -> Result<Vec<ExpectedLoss>, VoiError> {
    let mut losses = Vec::new();

    for action in Action::ALL {
        if !feasibility.is_allowed(action) {
            continue;
        }
        match expected_loss_for_action(action, posterior, loss_matrix) {
            Ok(loss) => losses.push(ExpectedLoss { action, loss }),
            Err(_) => continue, // Skip actions with missing loss entries
        }
    }

    if losses.is_empty() {
        return Err(VoiError::InvalidPosterior {
            message: "no feasible actions".to_string(),
        });
    }

    Ok(losses)
}

/// Estimate how a probe would update the posterior.
///
/// This is a simplified model that estimates the expected posterior shift
/// based on probe characteristics. In practice, this would use prior
/// predictive distributions for more accurate estimates.
fn estimate_posterior_after_probe(posterior: &ClassScores, probe: ProbeType) -> ClassScores {
    // Information gain factors per probe type
    // These represent how much each probe type typically clarifies classification
    let (useful_shift, abandoned_shift) = match probe {
        ProbeType::Wait15Min | ProbeType::Wait5Min => {
            // Waiting reveals whether process stays active
            // Tends to polarize: active processes stay active, abandoned stay idle
            (0.1, 0.1)
        }
        ProbeType::QuickScan => {
            // Basic refresh, minor update
            (0.02, 0.02)
        }
        ProbeType::DeepScan => {
            // Substantial evidence update
            (0.15, 0.15)
        }
        ProbeType::StackSample => {
            // Stack reveals if process is stuck
            (0.2, 0.2)
        }
        ProbeType::Strace => {
            // Syscall tracing is highly informative
            (0.25, 0.25)
        }
        ProbeType::NetSnapshot => {
            // Network activity is good signal for daemon-like processes
            (0.1, 0.1)
        }
        ProbeType::IoSnapshot => {
            // I/O activity helps distinguish useful vs abandoned
            (0.12, 0.12)
        }
        ProbeType::CgroupInspect => {
            // Resource limits and usage
            (0.05, 0.05)
        }
    };

    // Model: probe shifts posterior toward extreme values
    // If already confident, probe confirms; if uncertain, probe clarifies
    let uncertainty = 1.0 - (posterior.useful - posterior.abandoned).abs();
    let shift_magnitude = useful_shift * uncertainty;

    // Expected shift direction based on current belief
    // (Higher useful prob -> probe likely confirms useful)
    let useful_direction = if posterior.useful > posterior.abandoned {
        1.0
    } else {
        -1.0
    };

    let new_useful = (posterior.useful + useful_direction * shift_magnitude).clamp(0.01, 0.98);
    let new_abandoned =
        (posterior.abandoned - useful_direction * abandoned_shift * uncertainty).clamp(0.01, 0.98);

    // Renormalize
    let new_useful_bad = posterior.useful_bad;
    let new_zombie = posterior.zombie;
    let total = new_useful + new_useful_bad + new_abandoned + new_zombie;

    ClassScores {
        useful: new_useful / total,
        useful_bad: new_useful_bad / total,
        abandoned: new_abandoned / total,
        zombie: new_zombie / total,
    }
}

/// Compute VOI for a single probe.
fn compute_probe_voi(
    probe: ProbeType,
    current_min_loss: f64,
    posterior: &ClassScores,
    loss_matrix: &LossMatrix,
    feasibility: &ActionFeasibility,
    cost_model: &ProbeCostModel,
) -> Result<ProbeVoi, VoiError> {
    let cost = cost_model.cost(probe);

    // Estimate posterior after probe
    let posterior_after = estimate_posterior_after_probe(posterior, probe);

    // Compute expected loss after probe
    let losses_after = compute_expected_losses(&posterior_after, loss_matrix, feasibility)?;
    let (_, _) = select_optimal_action(&losses_after);
    let min_loss_after = losses_after
        .iter()
        .map(|e| e.loss)
        .fold(f64::INFINITY, f64::min);

    // VOI = E[loss_after] - E[loss_now] - cost
    // Negative VOI means probe is worthwhile
    let voi = min_loss_after - current_min_loss + cost;

    let ratio = if cost > 0.0 {
        -voi / cost // Higher ratio = better (more loss reduction per cost)
    } else if voi < 0.0 {
        f64::INFINITY
    } else {
        0.0
    };

    Ok(ProbeVoi {
        probe,
        voi,
        cost,
        ratio,
        expected_loss_after: min_loss_after,
    })
}

/// Compute VOI analysis for all available probes.
///
/// Returns analysis indicating whether to act now or which probe to acquire.
pub fn compute_voi(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    cost_model: &ProbeCostModel,
    available_probes: Option<&[ProbeType]>,
) -> Result<VoiAnalysis, VoiError> {
    // Validate posterior
    let values = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];
    if values
        .iter()
        .any(|v| v.is_nan() || v.is_infinite() || *v < 0.0)
    {
        return Err(VoiError::InvalidPosterior {
            message: "posterior contains invalid values".to_string(),
        });
    }

    // Compute current expected losses
    let current_losses = compute_expected_losses(posterior, &policy.loss_matrix, feasibility)?;
    let (current_optimal, _) = select_optimal_action(&current_losses);
    let current_min_loss = current_losses
        .iter()
        .map(|e| e.loss)
        .fold(f64::INFINITY, f64::min);

    // Determine which probes to consider
    let probes_to_check = available_probes.unwrap_or(ProbeType::ALL);

    if probes_to_check.is_empty() {
        return Err(VoiError::NoProbesAvailable);
    }

    // Compute VOI for each probe
    let mut probe_vois = Vec::new();
    for &probe in probes_to_check {
        match compute_probe_voi(
            probe,
            current_min_loss,
            posterior,
            &policy.loss_matrix,
            feasibility,
            cost_model,
        ) {
            Ok(voi) => probe_vois.push(voi),
            Err(_) => continue, // Skip probes that fail
        }
    }

    if probe_vois.is_empty() {
        return Err(VoiError::NoProbesAvailable);
    }

    // Find best probe (most negative VOI = most worthwhile)
    let best = probe_vois.iter().min_by(|a, b| {
        a.voi
            .partial_cmp(&b.voi)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let (best_probe, act_now, rationale) = match best {
        Some(p) if p.voi < 0.0 => {
            // Probe is worthwhile
            (
                Some(p.probe),
                false,
                format!(
                    "Probe '{}' reduces expected loss by {:.2} at cost {:.2} (net gain: {:.2})",
                    p.probe.name(),
                    current_min_loss - p.expected_loss_after,
                    p.cost,
                    -p.voi
                ),
            )
        }
        Some(p) => {
            // Best probe still not worth it
            (
                None,
                true,
                format!(
                    "Act now: best probe '{}' has VOI {:.2} (cost exceeds benefit)",
                    p.probe.name(),
                    p.voi
                ),
            )
        }
        None => (None, true, "Act now: no probes available".to_string()),
    };

    Ok(VoiAnalysis {
        current_expected_loss: current_losses,
        current_optimal_action: current_optimal,
        current_min_loss,
        probes: probe_vois,
        best_probe,
        act_now,
        rationale,
    })
}

/// Select the best probe using active sensing (entropy reduction / cost ratio).
///
/// This is an alternative to pure VOI that maximizes information gain per unit cost,
/// useful when the goal is learning rather than immediate decision quality.
pub fn select_probe_by_information_gain(
    posterior: &ClassScores,
    cost_model: &ProbeCostModel,
    available_probes: Option<&[ProbeType]>,
) -> Option<ProbeType> {
    let probes = available_probes.unwrap_or(ProbeType::ALL);

    // Current entropy (Shannon)
    let current_entropy = shannon_entropy(posterior);

    let mut best_probe = None;
    let mut best_ratio = f64::NEG_INFINITY;

    for &probe in probes {
        let cost = cost_model.cost(probe);
        if cost <= 0.0 {
            continue;
        }

        let posterior_after = estimate_posterior_after_probe(posterior, probe);
        let entropy_after = shannon_entropy(&posterior_after);
        let entropy_reduction = current_entropy - entropy_after;

        let ratio = entropy_reduction / cost;
        if ratio > best_ratio {
            best_ratio = ratio;
            best_probe = Some(probe);
        }
    }

    best_probe
}

/// Compute Shannon entropy of posterior (in bits).
fn shannon_entropy(posterior: &ClassScores) -> f64 {
    let probs = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];

    let mut entropy = 0.0;
    for &p in &probs {
        if p > 1e-10 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_posterior() -> ClassScores {
        ClassScores {
            useful: 0.4,
            useful_bad: 0.1,
            abandoned: 0.4,
            zombie: 0.1,
        }
    }

    fn confident_useful_posterior() -> ClassScores {
        ClassScores {
            useful: 0.97,
            useful_bad: 0.01,
            abandoned: 0.01,
            zombie: 0.01,
        }
    }

    fn confident_abandoned_posterior() -> ClassScores {
        ClassScores {
            useful: 0.01,
            useful_bad: 0.01,
            abandoned: 0.97,
            zombie: 0.01,
        }
    }

    #[test]
    fn test_probe_cost_model_defaults() {
        let model = ProbeCostModel::default();

        // Wait probes should have low total cost despite time
        let wait_cost = model.cost(ProbeType::Wait15Min);
        let strace_cost = model.cost(ProbeType::Strace);

        // Strace should be more expensive due to intrusiveness
        assert!(
            strace_cost > wait_cost * 0.5,
            "strace should be relatively expensive"
        );

        // Quick scan should be cheapest active probe
        let quick_cost = model.cost(ProbeType::QuickScan);
        let deep_cost = model.cost(ProbeType::DeepScan);
        assert!(
            quick_cost < deep_cost,
            "quick scan should be cheaper than deep scan"
        );
    }

    #[test]
    fn test_voi_uncertain_posterior_prefers_probing() {
        let posterior = test_posterior(); // Uncertain (0.4 vs 0.4)
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .expect("VOI computation should succeed");

        // With high uncertainty, at least some probes should be worthwhile
        let has_worthwhile_probe = result.probes.iter().any(|p| p.voi < 0.0);
        assert!(
            has_worthwhile_probe || result.act_now,
            "should either find worthwhile probe or decide to act"
        );
    }

    #[test]
    fn test_voi_confident_posterior_prefers_acting() {
        let posterior = confident_abandoned_posterior(); // Very confident
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .expect("VOI computation should succeed");

        // With high confidence, probing has diminishing returns
        // Most probes should have positive VOI (not worthwhile)
        let worthwhile_count = result.probes.iter().filter(|p| p.voi < 0.0).count();
        assert!(
            worthwhile_count < result.probes.len() / 2,
            "confident posterior should make most probes not worthwhile"
        );
    }

    #[test]
    fn test_voi_analysis_structure() {
        let posterior = test_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .expect("VOI computation should succeed");

        // Check structure
        assert!(!result.current_expected_loss.is_empty());
        assert!(!result.probes.is_empty());
        assert!(result.current_min_loss.is_finite());
        assert!(!result.rationale.is_empty());
    }

    #[test]
    fn test_probe_voi_includes_cost() {
        let posterior = test_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .expect("VOI computation should succeed");

        // Each probe should have positive cost
        for probe in &result.probes {
            assert!(probe.cost >= 0.0, "probe cost should be non-negative");
        }

        // Strace should have higher cost than quick scan
        let strace_voi = result.probes.iter().find(|p| p.probe == ProbeType::Strace);
        let quick_voi = result
            .probes
            .iter()
            .find(|p| p.probe == ProbeType::QuickScan);

        if let (Some(s), Some(q)) = (strace_voi, quick_voi) {
            assert!(s.cost > q.cost, "strace should have higher cost");
        }
    }

    #[test]
    fn test_entropy_computation() {
        // Uniform distribution has maximum entropy
        let uniform = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let entropy_uniform = shannon_entropy(&uniform);
        assert!(
            (entropy_uniform - 2.0).abs() < 0.01,
            "uniform should have ~2 bits entropy"
        );

        // Confident distribution has low entropy
        let confident = confident_abandoned_posterior();
        let entropy_confident = shannon_entropy(&confident);
        assert!(
            entropy_confident < entropy_uniform,
            "confident should have lower entropy"
        );
    }

    #[test]
    fn test_select_probe_by_information_gain() {
        let posterior = test_posterior();
        let cost_model = ProbeCostModel::default();

        let best_probe = select_probe_by_information_gain(&posterior, &cost_model, None);

        assert!(best_probe.is_some(), "should select a probe");
    }

    #[test]
    fn test_invalid_posterior_rejected() {
        let invalid = ClassScores {
            useful: f64::NAN,
            useful_bad: 0.3,
            abandoned: 0.3,
            zombie: 0.1,
        };
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &invalid,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        );

        assert!(result.is_err(), "should reject invalid posterior");
    }

    #[test]
    fn test_limited_probe_set() {
        let posterior = test_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let limited_probes = &[ProbeType::QuickScan, ProbeType::DeepScan];

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            Some(limited_probes),
        )
        .expect("VOI computation should succeed");

        assert_eq!(
            result.probes.len(),
            2,
            "should only evaluate specified probes"
        );
        assert!(result
            .probes
            .iter()
            .all(|p| { p.probe == ProbeType::QuickScan || p.probe == ProbeType::DeepScan }));
    }

    #[test]
    fn test_voi_confident_useful_has_low_loss() {
        // When confident the process is useful, expected loss should be low
        // and the recommended action should not be destructive (Kill)
        let posterior = confident_useful_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .expect("VOI computation should succeed");

        // Expected loss should be low for confident useful posterior
        // (Keep has 0 loss for useful, and useful has 0.85 probability)
        assert!(
            result.current_min_loss < 10.0,
            "confident useful posterior should have low expected loss, got {}",
            result.current_min_loss
        );

        // Optimal action should be low-impact (Keep or Renice, not Kill)
        assert!(
            result.current_optimal_action != Action::Kill,
            "confident useful posterior should not recommend Kill"
        );

        // Entropy should be lower for confident useful posterior vs uncertain
        let uncertain = test_posterior();
        let entropy_confident = shannon_entropy(&posterior);
        let entropy_uncertain = shannon_entropy(&uncertain);
        assert!(
            entropy_confident < entropy_uncertain,
            "confident posterior should have lower entropy"
        );
    }

    // ── ProbeType ALL constant + name() ─────────────────────────────

    #[test]
    fn probe_type_all_contains_all_nine() {
        assert_eq!(ProbeType::ALL.len(), 9);
    }

    #[test]
    fn probe_type_name_returns_snake_case() {
        let names: Vec<&str> = ProbeType::ALL.iter().map(|p| p.name()).collect();
        let expected = vec![
            "wait_15min",
            "wait_5min",
            "quick_scan",
            "deep_scan",
            "stack_sample",
            "strace",
            "net_snapshot",
            "io_snapshot",
            "cgroup_inspect",
        ];
        assert_eq!(names, expected);
    }

    // ── ProbeType serde snake_case ──────────────────────────────────

    #[test]
    fn probe_type_serde_all_variants() {
        for &probe in ProbeType::ALL {
            let json = serde_json::to_string(&probe).unwrap();
            let back: ProbeType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, probe);
            // Verify snake_case
            let raw: String = serde_json::from_str(&json).unwrap();
            assert!(
                raw.chars()
                    .all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_'),
                "expected snake_case for {:?}, got {}",
                probe,
                raw
            );
        }
    }

    // ── ProbeCost total() ───────────────────────────────────────────

    #[test]
    fn probe_cost_total_default() {
        let cost = ProbeCost::default();
        let total = cost.total();
        assert!(total > 0.0, "default probe cost total should be positive");
        assert!(total < 1.0, "default probe cost total should be < 1.0");
    }

    #[test]
    fn probe_cost_total_zero_components() {
        let cost = ProbeCost {
            time_seconds: 1.0,
            overhead: 0.0,
            intrusiveness: 0.0,
            risk: 0.0,
        };
        let total = cost.total();
        // Only time component contributes: time_weight * (ln(1)/8.5).min(1.0) = 0.3 * 0 = 0
        assert!(
            total.abs() < 1e-6,
            "zero components with 1s time should have near-zero total, got {}",
            total
        );
    }

    #[test]
    fn probe_cost_total_max_components() {
        let cost = ProbeCost {
            time_seconds: 4000.0, // High time (above e^8.5 ~ 4914)
            overhead: 1.0,
            intrusiveness: 1.0,
            risk: 1.0,
        };
        let total = cost.total();
        // Should approach sum of weights (0.3+0.3+0.2+0.2 = 1.0)
        assert!(
            total > 0.9 && total <= 1.0,
            "max cost total should be near 1.0, got {}",
            total
        );
    }

    #[test]
    fn probe_cost_serde_roundtrip() {
        let cost = ProbeCost {
            time_seconds: 10.0,
            overhead: 0.5,
            intrusiveness: 0.3,
            risk: 0.1,
        };
        let json = serde_json::to_string(&cost).unwrap();
        let back: ProbeCost = serde_json::from_str(&json).unwrap();
        assert!((back.time_seconds - 10.0).abs() < 1e-9);
        assert!((back.overhead - 0.5).abs() < 1e-9);
    }

    // ── ProbeCostModel cost() + cost_details() ──────────────────────

    #[test]
    fn probe_cost_model_cost_known_probe() {
        let model = ProbeCostModel::default();
        let cost = model.cost(ProbeType::QuickScan);
        assert!(cost > 0.0, "QuickScan cost should be positive");
    }

    #[test]
    fn probe_cost_model_cost_details_known() {
        let model = ProbeCostModel::default();
        let details = model.cost_details(ProbeType::Strace);
        assert!((details.intrusiveness - 0.7).abs() < 1e-9);
        assert!((details.risk - 0.05).abs() < 1e-9);
    }

    #[test]
    fn probe_cost_model_cost_details_missing_returns_default() {
        let model = ProbeCostModel {
            costs: HashMap::new(), // empty
            base_multiplier: 1.0,
        };
        let details = model.cost_details(ProbeType::Strace);
        // Should return ProbeCost::default()
        assert!((details.time_seconds - 1.0).abs() < 1e-9);
        assert!((details.overhead - 0.1).abs() < 1e-9);
    }

    #[test]
    fn probe_cost_model_base_multiplier_scales() {
        let mut model = ProbeCostModel::default();
        let cost_1x = model.cost(ProbeType::DeepScan);
        model.base_multiplier = 2.0;
        let cost_2x = model.cost(ProbeType::DeepScan);
        assert!(
            (cost_2x - 2.0 * cost_1x).abs() < 1e-9,
            "2x multiplier should double cost"
        );
    }

    #[test]
    fn probe_cost_model_serde_roundtrip() {
        let model = ProbeCostModel::default();
        let json = serde_json::to_string(&model).unwrap();
        let back: ProbeCostModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.costs.len(), model.costs.len());
        assert!((back.base_multiplier - 1.0).abs() < 1e-9);
    }

    // ── ProbeInformationGain serde ──────────────────────────────────

    #[test]
    fn probe_information_gain_serde() {
        let pig = ProbeInformationGain {
            probe: ProbeType::DeepScan,
            entropy_reduction: 0.5,
            posterior_shift: 0.1,
            action_change_prob: 0.3,
        };
        let json = serde_json::to_string(&pig).unwrap();
        let back: ProbeInformationGain = serde_json::from_str(&json).unwrap();
        assert_eq!(back.probe, ProbeType::DeepScan);
        assert!((back.entropy_reduction - 0.5).abs() < 1e-9);
    }

    // ── ProbeVoi serde ──────────────────────────────────────────────

    #[test]
    fn probe_voi_serde_roundtrip() {
        let pv = ProbeVoi {
            probe: ProbeType::StackSample,
            voi: -0.3,
            cost: 0.15,
            ratio: 2.0,
            expected_loss_after: 5.0,
        };
        let json = serde_json::to_string(&pv).unwrap();
        let back: ProbeVoi = serde_json::from_str(&json).unwrap();
        assert_eq!(back.probe, ProbeType::StackSample);
        assert!((back.voi - (-0.3)).abs() < 1e-9);
    }

    // ── VoiAnalysis serde ───────────────────────────────────────────

    #[test]
    fn voi_analysis_serde_roundtrip() {
        let analysis = VoiAnalysis {
            current_expected_loss: vec![ExpectedLoss {
                action: Action::Keep,
                loss: 2.0,
            }],
            current_optimal_action: Action::Keep,
            current_min_loss: 2.0,
            probes: vec![],
            best_probe: Some(ProbeType::QuickScan),
            act_now: false,
            rationale: "probe recommended".to_string(),
        };
        let json = serde_json::to_string(&analysis).unwrap();
        let back: VoiAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_optimal_action, Action::Keep);
        assert!(!back.act_now);
        assert_eq!(back.best_probe, Some(ProbeType::QuickScan));
    }

    // ── VoiError display ────────────────────────────────────────────

    #[test]
    fn voi_error_display_invalid_posterior() {
        let err = VoiError::InvalidPosterior {
            message: "negative values".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid posterior"));
        assert!(msg.contains("negative values"));
    }

    #[test]
    fn voi_error_display_no_probes() {
        let err = VoiError::NoProbesAvailable;
        let msg = format!("{}", err);
        assert!(msg.contains("no probes available"));
    }

    // ── empty probes list rejected ──────────────────────────────────

    #[test]
    fn compute_voi_empty_probes_errors() {
        let posterior = test_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            Some(&[]), // empty
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoiError::NoProbesAvailable));
    }

    // ── negative posterior rejected ──────────────────────────────────

    #[test]
    fn compute_voi_negative_posterior_rejected() {
        let invalid = ClassScores {
            useful: -0.1,
            useful_bad: 0.4,
            abandoned: 0.4,
            zombie: 0.3,
        };
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &invalid,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        );
        assert!(result.is_err());
    }

    // ── infinite posterior rejected ──────────────────────────────────

    #[test]
    fn compute_voi_infinite_posterior_rejected() {
        let invalid = ClassScores {
            useful: f64::INFINITY,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &invalid,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        );
        assert!(result.is_err());
    }

    // ── estimate_posterior_after_probe shifts posterior ───────────────

    #[test]
    fn estimate_posterior_after_probe_shifts() {
        let posterior = test_posterior(); // 0.4 useful, 0.4 abandoned
        let shifted = estimate_posterior_after_probe(&posterior, ProbeType::DeepScan);

        // Should still sum to ~1.0
        let total = shifted.useful + shifted.useful_bad + shifted.abandoned + shifted.zombie;
        assert!(
            (total - 1.0).abs() < 1e-6,
            "shifted posterior should sum to 1.0, got {}",
            total
        );

        // Should be different from original
        assert!(
            (shifted.useful - posterior.useful).abs() > 1e-6
                || (shifted.abandoned - posterior.abandoned).abs() > 1e-6,
            "deep scan should shift the posterior"
        );
    }

    #[test]
    fn estimate_posterior_after_probe_quick_scan_small_shift() {
        let posterior = test_posterior();
        let shifted = estimate_posterior_after_probe(&posterior, ProbeType::QuickScan);

        // QuickScan has small shifts (0.02), so the change should be small
        let useful_delta = (shifted.useful - posterior.useful).abs();
        assert!(
            useful_delta < 0.1,
            "QuickScan shift should be small, got {}",
            useful_delta
        );
    }

    // ── shannon_entropy edge cases ──────────────────────────────────

    #[test]
    fn shannon_entropy_certain() {
        let certain = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let entropy = shannon_entropy(&certain);
        assert!(
            entropy.abs() < 1e-6,
            "certain distribution should have 0 entropy, got {}",
            entropy
        );
    }

    #[test]
    fn shannon_entropy_near_zero_probs() {
        let near_zero = ClassScores {
            useful: 1e-15,
            useful_bad: 1e-15,
            abandoned: 1.0 - 2e-15,
            zombie: 1e-15,
        };
        let entropy = shannon_entropy(&near_zero);
        assert!(entropy.is_finite());
        assert!(entropy >= 0.0);
    }

    // ── select_probe_by_information_gain edge cases ─────────────────

    #[test]
    fn select_probe_by_information_gain_single_probe() {
        let posterior = test_posterior();
        let cost_model = ProbeCostModel::default();

        let best = select_probe_by_information_gain(
            &posterior,
            &cost_model,
            Some(&[ProbeType::IoSnapshot]),
        );
        assert_eq!(best, Some(ProbeType::IoSnapshot));
    }

    #[test]
    fn select_probe_by_information_gain_confident() {
        let posterior = confident_useful_posterior();
        let cost_model = ProbeCostModel::default();

        // Should still pick something even for confident posteriors
        let best = select_probe_by_information_gain(&posterior, &cost_model, None);
        assert!(best.is_some());
    }

    // ── VOI rationale content ───────────────────────────────────────

    #[test]
    fn voi_act_now_rationale_mentions_cost() {
        let posterior = confident_abandoned_posterior();
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();

        let result = compute_voi(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cost_model,
            None,
        )
        .unwrap();

        if result.act_now {
            assert!(
                result.rationale.contains("Act now") || result.rationale.contains("cost"),
                "act_now rationale should mention 'Act now' or 'cost': {}",
                result.rationale
            );
        }
    }

    // ── ProbeCostModel default has all 9 probes ─────────────────────

    #[test]
    fn probe_cost_model_default_complete() {
        let model = ProbeCostModel::default();
        assert_eq!(
            model.costs.len(),
            9,
            "default model should have costs for all 9 probe types"
        );
        for &probe in ProbeType::ALL {
            assert!(
                model.costs.contains_key(&probe),
                "missing cost for {:?}",
                probe
            );
        }
    }

    // ── Wait probes have zero overhead/intrusiveness/risk ────────────

    #[test]
    fn wait_probes_zero_overhead() {
        let model = ProbeCostModel::default();
        for &wait_probe in &[ProbeType::Wait15Min, ProbeType::Wait5Min] {
            let details = model.cost_details(wait_probe);
            assert!(
                details.overhead.abs() < 1e-9,
                "{:?} should have zero overhead",
                wait_probe
            );
            assert!(
                details.intrusiveness.abs() < 1e-9,
                "{:?} should have zero intrusiveness",
                wait_probe
            );
            assert!(
                details.risk.abs() < 1e-9,
                "{:?} should have zero risk",
                wait_probe
            );
        }
    }
}
