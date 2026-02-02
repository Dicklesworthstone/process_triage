//! Bayesian credible bounds for shadow-mode error rates.
//!
//! Computes upper credible bounds on an error rate using a Beta posterior.
//! This is used to gate more aggressive robot thresholds.

use pt_math::beta_inv_cdf;
use serde::{Deserialize, Serialize};

/// Assumptions used for a credible-bounds computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredibleBoundAssumptions {
    /// Definition of a "trial" for the error rate.
    pub trial_definition: String,
    /// Optional windowing metadata for time-bounded analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowSpec>,
}

/// Optional window specification for time-bounded bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSpec {
    /// Window length in seconds.
    pub window_seconds: u64,
    /// Optional human-readable label (e.g., "last_30_days").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A single credible bound entry at a given delta level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredibleBoundEntry {
    /// Tail probability delta.
    pub delta: f64,
    /// Upper bound on error rate at (1-delta) credibility.
    pub upper: f64,
}

/// Computed credible bounds for an error rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredibleBounds {
    pub prior_alpha: f64,
    pub prior_beta: f64,
    pub posterior_alpha: f64,
    pub posterior_beta: f64,
    pub errors: u64,
    pub trials: u64,
    /// Classification threshold used to determine kills vs spares.
    pub threshold: f64,
    /// Observed error rate (errors / trials), or 0 if no trials.
    pub observed_rate: f64,
    /// Posterior mean of the error rate.
    pub posterior_mean: f64,
    /// Per-delta upper bound entries.
    pub bounds: Vec<CredibleBoundEntry>,
    /// Definition of what counts as a "trial".
    pub trial_definition: String,
    /// Definition of what counts as an "error".
    pub error_definition: String,
    /// Legacy: raw delta values.
    pub deltas: Vec<f64>,
    /// Legacy: raw upper bound values (parallel to deltas).
    pub upper_bounds: Vec<f64>,
    pub assumptions: CredibleBoundAssumptions,
}

/// Errors returned by credible bound computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredibleBoundError {
    InvalidPrior,
    InvalidCounts,
    InvalidDelta,
}

/// Compute upper credible bounds on error rate e ~ Beta(a+k, b+n-k).
pub fn compute_credible_bounds(
    prior_alpha: f64,
    prior_beta: f64,
    errors: u64,
    trials: u64,
    deltas: &[f64],
    assumptions: CredibleBoundAssumptions,
) -> Result<CredibleBounds, CredibleBoundError> {
    if prior_alpha <= 0.0 || prior_beta <= 0.0 {
        return Err(CredibleBoundError::InvalidPrior);
    }
    if errors > trials {
        return Err(CredibleBoundError::InvalidCounts);
    }
    for &delta in deltas {
        if !(0.0 < delta && delta < 1.0) {
            return Err(CredibleBoundError::InvalidDelta);
        }
    }

    let posterior_alpha = prior_alpha + errors as f64;
    let posterior_beta = prior_beta + (trials - errors) as f64;

    let mut upper_bounds = Vec::with_capacity(deltas.len());
    for &delta in deltas {
        let p = 1.0 - delta;
        let bound = beta_inv_cdf(p, posterior_alpha, posterior_beta);
        upper_bounds.push(bound);
    }

    let observed_rate = if trials > 0 {
        errors as f64 / trials as f64
    } else {
        0.0
    };
    let posterior_mean = posterior_alpha / (posterior_alpha + posterior_beta);

    let bounds_entries: Vec<CredibleBoundEntry> = deltas
        .iter()
        .zip(upper_bounds.iter())
        .map(|(&d, &u)| CredibleBoundEntry { delta: d, upper: u })
        .collect();

    Ok(CredibleBounds {
        prior_alpha,
        prior_beta,
        posterior_alpha,
        posterior_beta,
        errors,
        trials,
        threshold: 0.5,
        observed_rate,
        posterior_mean,
        bounds: bounds_entries,
        trial_definition: assumptions.trial_definition.clone(),
        error_definition: "predicted kill for a process that was actually useful".to_string(),
        deltas: deltas.to_vec(),
        upper_bounds,
        assumptions,
    })
}

/// Compute false-kill credible bounds from calibration data.
///
/// Counts how many predictions above `threshold` were actually not abandoned (false kills),
/// then computes Bayesian credible bounds on the false-kill rate.
pub fn false_kill_credible_bounds(
    data: &[super::CalibrationData],
    threshold: f64,
    prior_alpha: f64,
    prior_beta: f64,
    deltas: &[f64],
) -> Option<CredibleBounds> {
    let mut errors: u64 = 0;
    let mut trials: u64 = 0;

    for d in data {
        if d.predicted >= threshold {
            trials += 1;
            if !d.actual {
                errors += 1;
            }
        }
    }

    if trials == 0 {
        return None;
    }

    let assumptions = CredibleBoundAssumptions {
        trial_definition: format!("predictions >= {:.2} threshold", threshold),
        window: None,
    };

    let mut result = compute_credible_bounds(prior_alpha, prior_beta, errors, trials, deltas, assumptions).ok()?;
    result.threshold = threshold;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_prior_zero_trials() {
        let assumptions = CredibleBoundAssumptions {
            trial_definition: "recommended kill vs spared".to_string(),
            window: None,
        };
        let bounds = compute_credible_bounds(1.0, 1.0, 0, 0, &[0.05], assumptions).unwrap();
        assert!((bounds.upper_bounds[0] - 0.95).abs() < 1e-6);
    }

    #[test]
    fn smaller_delta_gives_larger_bound() {
        let assumptions = CredibleBoundAssumptions {
            trial_definition: "recommended kill vs spared".to_string(),
            window: None,
        };
        let bounds = compute_credible_bounds(1.0, 1.0, 2, 10, &[0.1, 0.01], assumptions).unwrap();
        assert!(bounds.upper_bounds[1] >= bounds.upper_bounds[0]);
    }

    #[test]
    fn invalid_counts_rejected() {
        let assumptions = CredibleBoundAssumptions {
            trial_definition: "recommended kill vs spared".to_string(),
            window: None,
        };
        let err = compute_credible_bounds(1.0, 1.0, 3, 2, &[0.05], assumptions)
            .err()
            .unwrap();
        assert_eq!(err, CredibleBoundError::InvalidCounts);
    }

    #[test]
    fn invalid_delta_rejected() {
        let assumptions = CredibleBoundAssumptions {
            trial_definition: "recommended kill vs spared".to_string(),
            window: None,
        };
        let err = compute_credible_bounds(1.0, 1.0, 0, 0, &[1.0], assumptions)
            .err()
            .unwrap();
        assert_eq!(err, CredibleBoundError::InvalidDelta);
    }
}
