//! False Discovery Rate (FDR) control for kill-set selection.
//!
//! Implements e-value based FDR control (eBH/eBY) for selecting
//! which processes are safe enough to include in the kill set.
//!
//! See: Plan §5.8 / §4.32

use serde::Serialize;
use std::cmp::Ordering;
use thiserror::Error;

/// FDR control method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FdrMethod {
    /// e-value Benjamini-Hochberg (assumes independence or PRDS).
    EBh,
    /// e-value Benjamini-Yekutieli (conservative, handles arbitrary dependence).
    EBy,
    /// No FDR control (select all with e-value > 1).
    None,
}

impl Default for FdrMethod {
    fn default() -> Self {
        FdrMethod::EBy // Conservative default
    }
}

/// Target identity for a candidate process.
#[derive(Debug, Clone, Serialize)]
pub struct TargetIdentity {
    /// Process ID.
    pub pid: i32,
    /// Stable start ID (pid + start_time + boot_id).
    pub start_id: String,
    /// User ID owning the process.
    pub uid: u32,
}

/// Per-candidate selection result with diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateSelection {
    /// Target identity tuple (for TOCTOU safety).
    pub target: TargetIdentity,
    /// E-value for this candidate (Bayes factor H1/H0).
    pub e_value: f64,
    /// Derived p-value (min(1, 1/e_value)).
    pub p_value: f64,
    /// Rank in descending e-value order (1-indexed).
    pub rank: usize,
    /// Selection threshold used for this rank.
    pub threshold: f64,
    /// Whether this candidate was selected.
    pub selected: bool,
}

/// FDR selection result for a batch of candidates.
#[derive(Debug, Clone, Serialize)]
pub struct FdrSelectionResult {
    /// Target alpha level used.
    pub alpha: f64,
    /// FDR control method applied.
    pub method: FdrMethod,
    /// BY correction factor c(m) if applicable.
    pub correction_factor: Option<f64>,
    /// Total number of candidates evaluated.
    pub m_candidates: usize,
    /// Number of candidates selected.
    pub selected_k: usize,
    /// Selection threshold at the boundary.
    pub selection_threshold: f64,
    /// Per-candidate selection details (sorted by e_value descending).
    pub candidates: Vec<CandidateSelection>,
    /// Identity tuples of selected candidates.
    pub selected_ids: Vec<TargetIdentity>,
}

/// Errors during FDR selection.
#[derive(Debug, Error)]
pub enum FdrError {
    #[error("alpha must be in (0, 1], got {alpha}")]
    InvalidAlpha { alpha: f64 },
    #[error("e-values must be non-negative")]
    NegativeEvalue,
    #[error("no candidates provided")]
    NoCandidates,
}

/// Input candidate for FDR selection.
#[derive(Debug, Clone)]
pub struct FdrCandidate {
    /// Target identity tuple.
    pub target: TargetIdentity,
    /// E-value (Bayes factor H1/H0).
    pub e_value: f64,
}

/// Select candidates using e-value based FDR control.
///
/// # Arguments
/// * `candidates` - Candidates with e-values (Bayes factors)
/// * `alpha` - Target FDR level (e.g., 0.05)
/// * `method` - FDR control method (eBH, eBY, None)
///
/// # Returns
/// Selection result with per-candidate diagnostics.
pub fn select_fdr(
    candidates: &[FdrCandidate],
    alpha: f64,
    method: FdrMethod,
) -> Result<FdrSelectionResult, FdrError> {
    // Validate inputs
    if alpha <= 0.0 || alpha > 1.0 {
        return Err(FdrError::InvalidAlpha { alpha });
    }
    if candidates.is_empty() {
        return Err(FdrError::NoCandidates);
    }
    for c in candidates {
        if c.e_value < 0.0 {
            return Err(FdrError::NegativeEvalue);
        }
    }

    let m = candidates.len();

    // Sort indices by e_value descending
    let mut sorted_indices: Vec<usize> = (0..m).collect();
    sorted_indices.sort_by(|&a, &b| {
        candidates[b]
            .e_value
            .partial_cmp(&candidates[a].e_value)
            .unwrap_or(Ordering::Equal)
    });

    // Compute BY correction factor c(m) = sum_{j=1..m} 1/j
    let correction = match method {
        FdrMethod::EBy => {
            let c_m: f64 = (1..=m).map(|j| 1.0 / j as f64).sum();
            Some(c_m)
        }
        _ => None,
    };

    // Effective alpha after correction
    let effective_alpha = match method {
        FdrMethod::EBy => alpha / correction.unwrap(),
        FdrMethod::EBh | FdrMethod::None => alpha,
    };

    // Find largest k where e_(k) >= m / (effective_alpha * k)
    // This is the eBH rule: e_(k) >= m / (alpha * k)
    let selected_k = match method {
        FdrMethod::None => {
            // Select all with e > 1
            sorted_indices.iter().filter(|&&i| candidates[i].e_value > 1.0).count()
        }
        FdrMethod::EBh | FdrMethod::EBy => {
            let mut k = 0;
            for (rank_0, &idx) in sorted_indices.iter().enumerate() {
                let rank = rank_0 + 1; // 1-indexed
                let threshold = (m as f64) / (effective_alpha * rank as f64);
                if candidates[idx].e_value >= threshold {
                    k = rank;
                }
            }
            k
        }
    };

    // Compute the selection threshold at the boundary
    let selection_threshold = if selected_k > 0 {
        (m as f64) / (effective_alpha * selected_k as f64)
    } else {
        f64::INFINITY
    };

    // Build per-candidate results
    let mut candidate_results = Vec::with_capacity(m);
    let mut selected_ids = Vec::new();

    for (rank_0, &idx) in sorted_indices.iter().enumerate() {
        let rank = rank_0 + 1;
        let e_val = candidates[idx].e_value;
        let p_val = if e_val > 0.0 { (1.0 / e_val).min(1.0) } else { 1.0 };
        let threshold = (m as f64) / (effective_alpha * rank as f64);
        let selected = rank <= selected_k;

        let selection = CandidateSelection {
            target: candidates[idx].target.clone(),
            e_value: e_val,
            p_value: p_val,
            rank,
            threshold,
            selected,
        };

        if selected {
            selected_ids.push(candidates[idx].target.clone());
        }

        candidate_results.push(selection);
    }

    Ok(FdrSelectionResult {
        alpha,
        method,
        correction_factor: correction,
        m_candidates: m,
        selected_k,
        selection_threshold,
        candidates: candidate_results,
        selected_ids,
    })
}

/// Compute the BY correction factor c(m) = sum_{j=1..m} 1/j.
///
/// This is the harmonic number H_m, used to control FDR under
/// arbitrary dependence structures.
pub fn by_correction_factor(m: usize) -> f64 {
    (1..=m).map(|j| 1.0 / j as f64).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(pid: i32, e_value: f64) -> FdrCandidate {
        FdrCandidate {
            target: TargetIdentity {
                pid,
                start_id: format!("{}-12345-boot123", pid),
                uid: 1000,
            },
            e_value,
        }
    }

    #[test]
    fn test_ebh_simple_selection() {
        // e-values: [10, 5, 2, 0.5]
        // m = 4, alpha = 0.1
        // Thresholds at ranks 1,2,3,4: 40, 20, 13.33, 10
        // e_(1)=10 < 40: not selected at k=1
        // e_(2)=5 < 20: not selected at k=2
        // e_(3)=2 < 13.33: not selected at k=3
        // e_(4)=0.5 < 10: not selected at k=4
        // So k=0
        let candidates = vec![
            make_candidate(1, 10.0),
            make_candidate(2, 5.0),
            make_candidate(3, 2.0),
            make_candidate(4, 0.5),
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        assert_eq!(result.selected_k, 0);
    }

    #[test]
    fn test_ebh_high_evidence_selection() {
        // e-values: [100, 50, 20, 1]
        // m = 4, alpha = 0.1
        // Thresholds at ranks 1,2,3,4: 40, 20, 13.33, 10
        // e_(1)=100 >= 40: can select k>=1
        // e_(2)=50 >= 20: can select k>=2
        // e_(3)=20 >= 13.33: can select k>=3
        // e_(4)=1 < 10: cannot extend to k=4
        // So k=3
        let candidates = vec![
            make_candidate(1, 100.0),
            make_candidate(2, 50.0),
            make_candidate(3, 20.0),
            make_candidate(4, 1.0),
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        assert_eq!(result.selected_k, 3);
        assert_eq!(result.selected_ids.len(), 3);
        // Verify correct PIDs selected (sorted by e-value)
        let selected_pids: Vec<i32> = result.selected_ids.iter().map(|t| t.pid).collect();
        assert_eq!(selected_pids, vec![1, 2, 3]);
    }

    #[test]
    fn test_eby_is_more_conservative() {
        // Same e-values but with BY correction
        let candidates = vec![
            make_candidate(1, 100.0),
            make_candidate(2, 50.0),
            make_candidate(3, 20.0),
            make_candidate(4, 1.0),
        ];

        let ebh = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        let eby = select_fdr(&candidates, 0.1, FdrMethod::EBy).unwrap();

        // BY should select same or fewer
        assert!(eby.selected_k <= ebh.selected_k);
        assert!(eby.correction_factor.is_some());
        // c(4) = 1 + 1/2 + 1/3 + 1/4 ≈ 2.083
        let c4 = by_correction_factor(4);
        assert!((c4 - 2.083).abs() < 0.01);
    }

    #[test]
    fn test_deterministic_ordering() {
        // Selection should be deterministic for same inputs
        let candidates = vec![
            make_candidate(3, 15.0),
            make_candidate(1, 50.0),
            make_candidate(2, 30.0),
        ];

        let result1 = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        let result2 = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();

        assert_eq!(result1.selected_k, result2.selected_k);
        assert_eq!(result1.candidates.len(), result2.candidates.len());
        for (c1, c2) in result1.candidates.iter().zip(result2.candidates.iter()) {
            assert_eq!(c1.rank, c2.rank);
            assert_eq!(c1.selected, c2.selected);
        }
    }

    #[test]
    fn test_monotonicity() {
        // Increasing any e-value should never decrease k
        let base = vec![
            make_candidate(1, 50.0),
            make_candidate(2, 30.0),
            make_candidate(3, 10.0),
        ];
        let base_result = select_fdr(&base, 0.1, FdrMethod::EBh).unwrap();

        // Increase one e-value
        let increased = vec![
            make_candidate(1, 100.0), // Doubled
            make_candidate(2, 30.0),
            make_candidate(3, 10.0),
        ];
        let inc_result = select_fdr(&increased, 0.1, FdrMethod::EBh).unwrap();

        assert!(inc_result.selected_k >= base_result.selected_k);
    }

    #[test]
    fn test_invalid_alpha() {
        let candidates = vec![make_candidate(1, 10.0)];
        assert!(select_fdr(&candidates, 0.0, FdrMethod::EBh).is_err());
        assert!(select_fdr(&candidates, -0.1, FdrMethod::EBh).is_err());
        assert!(select_fdr(&candidates, 1.5, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_empty_candidates() {
        assert!(select_fdr(&[], 0.1, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_negative_evalue() {
        let candidates = vec![make_candidate(1, -1.0)];
        assert!(select_fdr(&candidates, 0.1, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_none_method_selects_evalue_gt_1() {
        let candidates = vec![
            make_candidate(1, 2.0),   // > 1, selected
            make_candidate(2, 1.5),   // > 1, selected
            make_candidate(3, 0.8),   // < 1, not selected
            make_candidate(4, 0.1),   // < 1, not selected
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::None).unwrap();
        assert_eq!(result.selected_k, 2);
    }

    #[test]
    fn test_by_correction_factor_computation() {
        // c(1) = 1
        assert!((by_correction_factor(1) - 1.0).abs() < 1e-10);
        // c(2) = 1 + 0.5 = 1.5
        assert!((by_correction_factor(2) - 1.5).abs() < 1e-10);
        // c(3) = 1 + 0.5 + 0.333... ≈ 1.833
        assert!((by_correction_factor(3) - 1.833333).abs() < 0.001);
        // c(10) ≈ 2.928
        assert!((by_correction_factor(10) - 2.928968).abs() < 0.001);
    }

    #[test]
    fn test_p_value_derivation() {
        let candidates = vec![
            make_candidate(1, 10.0),  // p = 0.1
            make_candidate(2, 2.0),   // p = 0.5
            make_candidate(3, 0.5),   // p = 1.0 (capped)
        ];
        let result = select_fdr(&candidates, 0.5, FdrMethod::EBh).unwrap();

        // Check p-values in sorted order
        assert!((result.candidates[0].p_value - 0.1).abs() < 1e-10);
        assert!((result.candidates[1].p_value - 0.5).abs() < 1e-10);
        assert!((result.candidates[2].p_value - 1.0).abs() < 1e-10);
    }
}
