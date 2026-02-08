//! Beta-Stacy discrete-time survival model (Bayesian nonparametric hazard).
//!
//! Implements a discrete-time hazard model with Beta priors per time bin.
//! Closed-form posterior updates:
//!   h_t ~ Beta(a_t, b_t)
//!   h_t | data ~ Beta(a_t + d_t, b_t + n_t - d_t)
//! Survival:
//!   S(t) = ∏_{j=1..t} (1 - E[h_j | data])

use serde::Serialize;
use thiserror::Error;

/// Versioned binning scheme for discrete-time hazards.
#[derive(Debug, Clone, Serialize)]
pub struct BinningScheme {
    pub version: String,
    pub kind: BinningKind,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinningKind {
    Fixed {
        bin_width_s: f64,
        max_bins: usize,
    },
    Log {
        start_width_s: f64,
        growth_factor: f64,
        max_bins: usize,
    },
}

/// A single time bin specification.
#[derive(Debug, Clone, Serialize)]
pub struct BinSpec {
    pub index: usize,
    pub start_s: f64,
    pub end_s: f64,
}

impl BinningScheme {
    pub fn fixed(bin_width_s: f64, max_bins: usize) -> Self {
        Self {
            version: "1.0.0".to_string(),
            kind: BinningKind::Fixed {
                bin_width_s,
                max_bins,
            },
        }
    }

    pub fn log(start_width_s: f64, growth_factor: f64, max_bins: usize) -> Self {
        Self {
            version: "1.0.0".to_string(),
            kind: BinningKind::Log {
                start_width_s,
                growth_factor,
                max_bins,
            },
        }
    }

    pub fn bins(&self) -> Vec<BinSpec> {
        match self.kind {
            BinningKind::Fixed {
                bin_width_s,
                max_bins,
            } => (0..max_bins)
                .map(|idx| BinSpec {
                    index: idx,
                    start_s: bin_width_s * idx as f64,
                    end_s: bin_width_s * (idx as f64 + 1.0),
                })
                .collect(),
            BinningKind::Log {
                start_width_s,
                growth_factor,
                max_bins,
            } => {
                let mut bins = Vec::with_capacity(max_bins);
                let mut start = 0.0;
                let mut width = start_width_s;
                for idx in 0..max_bins {
                    let end = start + width;
                    bins.push(BinSpec {
                        index: idx,
                        start_s: start,
                        end_s: end,
                    });
                    start = end;
                    width *= growth_factor;
                }
                bins
            }
        }
    }

    pub fn index_for_duration(&self, duration_s: f64) -> Option<usize> {
        if duration_s < 0.0 || duration_s.is_nan() {
            return None;
        }
        match self.kind {
            BinningKind::Fixed {
                bin_width_s,
                max_bins,
            } => {
                if bin_width_s <= 0.0 {
                    return None;
                }
                let idx = (duration_s / bin_width_s).floor() as usize;
                if idx < max_bins {
                    Some(idx)
                } else {
                    None
                }
            }
            BinningKind::Log {
                start_width_s,
                growth_factor,
                max_bins,
            } => {
                if start_width_s <= 0.0 || growth_factor <= 1.0 {
                    return None;
                }
                let mut start = 0.0;
                let mut width = start_width_s;
                for idx in 0..max_bins {
                    let end = start + width;
                    if duration_s < end {
                        return Some(idx);
                    }
                    start = end;
                    width *= growth_factor;
                }
                None
            }
        }
    }
}

/// Beta prior parameters for a hazard bin.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BetaParams {
    pub alpha: f64,
    pub beta: f64,
}

impl BetaParams {
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self { alpha, beta }
    }

    pub fn mean(&self) -> f64 {
        let denom = self.alpha + self.beta;
        if denom <= 0.0 {
            0.0
        } else {
            self.alpha / denom
        }
    }
}

impl Default for BetaParams {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

/// A single Beta-Stacy hazard bin.
#[derive(Debug, Clone, Serialize)]
pub struct BetaStacyBin {
    pub index: usize,
    pub prior: BetaParams,
    pub at_risk: u32,
    pub events: u32,
}

impl BetaStacyBin {
    pub fn posterior(&self) -> BetaParams {
        BetaParams::new(
            self.prior.alpha + self.events as f64,
            self.prior.beta + (self.at_risk.saturating_sub(self.events)) as f64,
        )
    }

    pub fn hazard_mean(&self) -> f64 {
        let posterior = self.posterior();
        posterior.mean().clamp(0.0, 1.0)
    }
}

/// A discrete-time survival model with Beta priors per bin.
#[derive(Debug, Clone, Serialize)]
pub struct BetaStacyModel {
    pub scheme: BinningScheme,
    pub bins: Vec<BetaStacyBin>,
}

/// A lifetime sample for updating the model.
#[derive(Debug, Clone, Copy)]
pub struct LifetimeSample {
    pub duration_s: f64,
    pub event: bool,
}

#[derive(Debug, Error)]
pub enum BetaStacyError {
    #[error("binning scheme produced no bins")]
    NoBins,
    #[error("invalid duration {value}")]
    InvalidDuration { value: f64 },
}

impl BetaStacyModel {
    pub fn new(scheme: BinningScheme, prior: BetaParams) -> Result<Self, BetaStacyError> {
        let bins = scheme
            .bins()
            .into_iter()
            .map(|spec| BetaStacyBin {
                index: spec.index,
                prior,
                at_risk: 0,
                events: 0,
            })
            .collect::<Vec<_>>();
        if bins.is_empty() {
            return Err(BetaStacyError::NoBins);
        }
        Ok(Self { scheme, bins })
    }

    pub fn update_from_counts(&mut self, at_risk: &[u32], events: &[u32]) {
        for (idx, bin) in self.bins.iter_mut().enumerate() {
            if idx < at_risk.len() {
                bin.at_risk = bin.at_risk.saturating_add(at_risk[idx]);
            }
            if idx < events.len() {
                bin.events = bin.events.saturating_add(events[idx]);
            }
        }
    }

    pub fn update_from_samples(
        &mut self,
        samples: &[LifetimeSample],
    ) -> Result<(), BetaStacyError> {
        let mut at_risk = vec![0u32; self.bins.len()];
        let mut events = vec![0u32; self.bins.len()];

        for sample in samples {
            if !sample.duration_s.is_finite() || sample.duration_s < 0.0 {
                return Err(BetaStacyError::InvalidDuration {
                    value: sample.duration_s,
                });
            }

            if let Some(idx) = self.scheme.index_for_duration(sample.duration_s) {
                // Sample falls within our binning range
                for item in at_risk.iter_mut().take(idx + 1) {
                    *item = item.saturating_add(1);
                }
                if sample.event {
                    events[idx] = events[idx].saturating_add(1);
                }
            } else {
                // Sample exceeds the max bin range.
                // It was at risk for all bins.
                // We treat it as right-censored at the end of the last bin.
                for item in at_risk.iter_mut().take(self.bins.len()) {
                    *item = item.saturating_add(1);
                }
            }
        }

        self.update_from_counts(&at_risk, &events);
        Ok(())
    }

    pub fn survival_curve(&self) -> Vec<f64> {
        let mut survival = Vec::with_capacity(self.bins.len());
        let mut s = 1.0;
        for bin in &self.bins {
            let h = bin.hazard_mean().clamp(0.0, 1.0);
            s *= 1.0 - h;
            survival.push(s.max(0.0));
        }
        survival
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posterior_update_matches_counts() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let prior = BetaParams::new(1.0, 1.0);
        let mut model = BetaStacyModel::new(scheme, prior).unwrap();

        let samples = vec![
            LifetimeSample {
                duration_s: 5.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 12.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 25.0,
                event: false,
            },
        ];
        model.update_from_samples(&samples).unwrap();

        let bin0 = &model.bins[0];
        let bin1 = &model.bins[1];
        let bin2 = &model.bins[2];

        assert_eq!(bin0.at_risk, 3);
        assert_eq!(bin0.events, 1);
        assert_eq!(bin1.at_risk, 2);
        assert_eq!(bin1.events, 1);
        assert_eq!(bin2.at_risk, 1);
        assert_eq!(bin2.events, 0);

        let post0 = bin0.posterior();
        assert!((post0.alpha - 2.0).abs() < 1e-9);
        assert!((post0.beta - 3.0).abs() < 1e-9);
    }

    #[test]
    fn survival_curve_is_monotone() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let prior = BetaParams::new(1.0, 1.0);
        let mut model = BetaStacyModel::new(scheme, prior).unwrap();
        let samples = vec![
            LifetimeSample {
                duration_s: 5.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 12.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 25.0,
                event: false,
            },
        ];
        model.update_from_samples(&samples).unwrap();

        let curve = model.survival_curve();
        assert_eq!(curve.len(), 3);
        assert!(curve[0] >= curve[1]);
        assert!(curve[1] >= curve[2]);
    }

    #[test]
    fn test_beta_stacy_out_of_bounds_handling() {
        // Create a scheme covering 0..30s (bins: 0-10, 10-20, 20-30)
        let scheme = BinningScheme::fixed(10.0, 3);
        let prior = BetaParams::new(1.0, 1.0);
        let mut model = BetaStacyModel::new(scheme, prior).unwrap();

        // Sample 1: 5.0s, event=true (in bin 0)
        // Sample 2: 40.0s, event=true (out of bounds)
        // Sample 3: 50.0s, event=false (out of bounds)
        let samples = vec![
            LifetimeSample {
                duration_s: 5.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 40.0,
                event: true,
            },
            LifetimeSample {
                duration_s: 50.0,
                event: false,
            },
        ];

        model.update_from_samples(&samples).unwrap();

        // Bin 0 (0-10s):
        // - Sample 1 was at risk, event happened.
        // - Sample 2 survived this bin.
        // - Sample 3 survived this bin.
        // Expected at_risk: 3
        assert_eq!(
            model.bins[0].at_risk, 3,
            "Bin 0 at_risk should include out-of-bounds samples"
        );

        // Bin 1 (10-20s):
        // - Sample 1 already failed/censored.
        // - Sample 2 survived this bin.
        // - Sample 3 survived this bin.
        // Expected at_risk: 2
        assert_eq!(
            model.bins[1].at_risk, 2,
            "Bin 1 at_risk should include out-of-bounds samples"
        );

        // Bin 2 (20-30s):
        // - Sample 2 survived this bin.
        // - Sample 3 survived this bin.
        // Expected at_risk: 2
        assert_eq!(
            model.bins[2].at_risk, 2,
            "Bin 2 at_risk should include out-of-bounds samples"
        );
    }

    // ── BetaParams ──────────────────────────────────────────────────

    #[test]
    fn beta_params_new() {
        let p = BetaParams::new(2.0, 3.0);
        assert_eq!(p.alpha, 2.0);
        assert_eq!(p.beta, 3.0);
    }

    #[test]
    fn beta_params_default_uniform() {
        let p = BetaParams::default();
        assert_eq!(p.alpha, 1.0);
        assert_eq!(p.beta, 1.0);
    }

    #[test]
    fn beta_params_mean_uniform() {
        let p = BetaParams::new(1.0, 1.0);
        assert!((p.mean() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn beta_params_mean_asymmetric() {
        let p = BetaParams::new(9.0, 1.0);
        assert!((p.mean() - 0.9).abs() < 1e-12);
    }

    #[test]
    fn beta_params_mean_zero_denom() {
        let p = BetaParams::new(0.0, 0.0);
        assert_eq!(p.mean(), 0.0);
    }

    #[test]
    fn beta_params_mean_negative_denom() {
        let p = BetaParams::new(-1.0, 0.5);
        // denom = -0.5 <= 0
        assert_eq!(p.mean(), 0.0);
    }

    // ── BinningScheme fixed ─────────────────────────────────────────

    #[test]
    fn fixed_scheme_bins_count() {
        let scheme = BinningScheme::fixed(10.0, 5);
        assert_eq!(scheme.bins().len(), 5);
    }

    #[test]
    fn fixed_scheme_bins_boundaries() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let bins = scheme.bins();
        assert!((bins[0].start_s - 0.0).abs() < 1e-12);
        assert!((bins[0].end_s - 10.0).abs() < 1e-12);
        assert!((bins[1].start_s - 10.0).abs() < 1e-12);
        assert!((bins[1].end_s - 20.0).abs() < 1e-12);
        assert!((bins[2].start_s - 20.0).abs() < 1e-12);
        assert!((bins[2].end_s - 30.0).abs() < 1e-12);
    }

    #[test]
    fn fixed_scheme_index_for_duration() {
        let scheme = BinningScheme::fixed(10.0, 3);
        assert_eq!(scheme.index_for_duration(0.0), Some(0));
        assert_eq!(scheme.index_for_duration(5.0), Some(0));
        assert_eq!(scheme.index_for_duration(9.99), Some(0));
        assert_eq!(scheme.index_for_duration(10.0), Some(1));
        assert_eq!(scheme.index_for_duration(20.0), Some(2));
        assert_eq!(scheme.index_for_duration(29.99), Some(2));
        assert_eq!(scheme.index_for_duration(30.0), None); // out of range
    }

    #[test]
    fn fixed_scheme_negative_duration_returns_none() {
        let scheme = BinningScheme::fixed(10.0, 3);
        assert_eq!(scheme.index_for_duration(-1.0), None);
    }

    #[test]
    fn fixed_scheme_nan_duration_returns_none() {
        let scheme = BinningScheme::fixed(10.0, 3);
        assert_eq!(scheme.index_for_duration(f64::NAN), None);
    }

    #[test]
    fn fixed_scheme_zero_width_returns_none() {
        let scheme = BinningScheme::fixed(0.0, 3);
        assert_eq!(scheme.index_for_duration(5.0), None);
    }

    // ── BinningScheme log ───────────────────────────────────────────

    #[test]
    fn log_scheme_bins_count() {
        let scheme = BinningScheme::log(1.0, 2.0, 4);
        assert_eq!(scheme.bins().len(), 4);
    }

    #[test]
    fn log_scheme_bins_grow_exponentially() {
        let scheme = BinningScheme::log(1.0, 2.0, 3);
        let bins = scheme.bins();
        // Bin 0: 0..1, Bin 1: 1..3, Bin 2: 3..7
        assert!((bins[0].start_s - 0.0).abs() < 1e-12);
        assert!((bins[0].end_s - 1.0).abs() < 1e-12);
        assert!((bins[1].start_s - 1.0).abs() < 1e-12);
        assert!((bins[1].end_s - 3.0).abs() < 1e-12);
        assert!((bins[2].start_s - 3.0).abs() < 1e-12);
        assert!((bins[2].end_s - 7.0).abs() < 1e-12);
    }

    #[test]
    fn log_scheme_index_for_duration() {
        let scheme = BinningScheme::log(1.0, 2.0, 3);
        assert_eq!(scheme.index_for_duration(0.5), Some(0));
        assert_eq!(scheme.index_for_duration(2.0), Some(1));
        assert_eq!(scheme.index_for_duration(5.0), Some(2));
        assert_eq!(scheme.index_for_duration(7.0), None); // out of range
    }

    #[test]
    fn log_scheme_invalid_growth_factor_returns_none() {
        let scheme = BinningScheme::log(1.0, 1.0, 3); // growth=1.0 is not > 1.0
        assert_eq!(scheme.index_for_duration(5.0), None);
    }

    #[test]
    fn log_scheme_zero_start_width_returns_none() {
        let scheme = BinningScheme::log(0.0, 2.0, 3);
        assert_eq!(scheme.index_for_duration(5.0), None);
    }

    // ── BetaStacyBin ────────────────────────────────────────────────

    #[test]
    fn bin_posterior_with_no_data() {
        let bin = BetaStacyBin {
            index: 0,
            prior: BetaParams::new(1.0, 1.0),
            at_risk: 0,
            events: 0,
        };
        let post = bin.posterior();
        assert_eq!(post.alpha, 1.0);
        assert_eq!(post.beta, 1.0);
    }

    #[test]
    fn bin_posterior_with_events() {
        let bin = BetaStacyBin {
            index: 0,
            prior: BetaParams::new(1.0, 1.0),
            at_risk: 10,
            events: 3,
        };
        let post = bin.posterior();
        assert!((post.alpha - 4.0).abs() < 1e-12); // 1 + 3
        assert!((post.beta - 8.0).abs() < 1e-12); // 1 + (10 - 3)
    }

    #[test]
    fn bin_hazard_mean_no_data() {
        let bin = BetaStacyBin {
            index: 0,
            prior: BetaParams::new(1.0, 1.0),
            at_risk: 0,
            events: 0,
        };
        assert!((bin.hazard_mean() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn bin_hazard_mean_all_events() {
        let bin = BetaStacyBin {
            index: 0,
            prior: BetaParams::new(1.0, 1.0),
            at_risk: 10,
            events: 10,
        };
        // posterior alpha = 11, beta = 1, mean = 11/12
        let expected = 11.0 / 12.0;
        assert!((bin.hazard_mean() - expected).abs() < 1e-12);
    }

    #[test]
    fn bin_hazard_mean_clamped() {
        let bin = BetaStacyBin {
            index: 0,
            prior: BetaParams::new(1.0, 1.0),
            at_risk: 5,
            events: 3,
        };
        let h = bin.hazard_mean();
        assert!(h >= 0.0 && h <= 1.0);
    }

    // ── BetaStacyModel ─────────────────────────────────────────────

    #[test]
    fn model_new_creates_bins() {
        let scheme = BinningScheme::fixed(10.0, 5);
        let model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        assert_eq!(model.bins.len(), 5);
    }

    #[test]
    fn model_new_zero_bins_errors() {
        let scheme = BinningScheme::fixed(10.0, 0);
        let err = BetaStacyModel::new(scheme, BetaParams::default())
            .err()
            .unwrap();
        matches!(err, BetaStacyError::NoBins);
    }

    #[test]
    fn model_update_from_counts() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        model.update_from_counts(&[10, 5, 2], &[3, 1, 0]);
        assert_eq!(model.bins[0].at_risk, 10);
        assert_eq!(model.bins[0].events, 3);
        assert_eq!(model.bins[1].at_risk, 5);
        assert_eq!(model.bins[2].events, 0);
    }

    #[test]
    fn model_update_from_counts_accumulates() {
        let scheme = BinningScheme::fixed(10.0, 2);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        model.update_from_counts(&[5, 3], &[2, 1]);
        model.update_from_counts(&[3, 2], &[1, 0]);
        assert_eq!(model.bins[0].at_risk, 8);
        assert_eq!(model.bins[0].events, 3);
    }

    #[test]
    fn model_update_from_samples_negative_duration_errors() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        let samples = vec![LifetimeSample {
            duration_s: -5.0,
            event: true,
        }];
        assert!(model.update_from_samples(&samples).is_err());
    }

    #[test]
    fn model_update_from_samples_nan_errors() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        let samples = vec![LifetimeSample {
            duration_s: f64::NAN,
            event: false,
        }];
        assert!(model.update_from_samples(&samples).is_err());
    }

    #[test]
    fn model_update_from_samples_infinity_treated_as_out_of_bounds() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        let samples = vec![LifetimeSample {
            duration_s: f64::INFINITY,
            event: false,
        }];
        // Infinity is not finite, should error
        assert!(model.update_from_samples(&samples).is_err());
    }

    #[test]
    fn survival_curve_starts_below_one() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        let curve = model.survival_curve();
        // With uniform priors and no data, hazard mean = 0.5 per bin
        // S(1) = 0.5, S(2) = 0.25, S(3) = 0.125
        assert!(curve[0] < 1.0);
        assert!(curve[0] > 0.0);
    }

    #[test]
    fn survival_curve_non_negative() {
        let scheme = BinningScheme::fixed(10.0, 3);
        let mut model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        model.update_from_counts(&[100, 50, 10], &[90, 45, 10]);
        let curve = model.survival_curve();
        for val in &curve {
            assert!(*val >= 0.0);
        }
    }

    #[test]
    fn survival_curve_length_matches_bins() {
        let scheme = BinningScheme::fixed(10.0, 7);
        let model = BetaStacyModel::new(scheme, BetaParams::default()).unwrap();
        assert_eq!(model.survival_curve().len(), 7);
    }

    // ── BetaStacyError ──────────────────────────────────────────────

    #[test]
    fn error_no_bins_display() {
        let err = BetaStacyError::NoBins;
        assert_eq!(err.to_string(), "binning scheme produced no bins");
    }

    #[test]
    fn error_invalid_duration_display() {
        let err = BetaStacyError::InvalidDuration { value: -3.14 };
        assert!(err.to_string().contains("-3.14"));
    }

    // ── BinSpec ─────────────────────────────────────────────────────

    #[test]
    fn bin_spec_indices_sequential() {
        let scheme = BinningScheme::fixed(5.0, 4);
        let bins = scheme.bins();
        for (i, bin) in bins.iter().enumerate() {
            assert_eq!(bin.index, i);
        }
    }

    #[test]
    fn bin_spec_contiguous() {
        let scheme = BinningScheme::log(2.0, 1.5, 5);
        let bins = scheme.bins();
        for i in 1..bins.len() {
            assert!((bins[i].start_s - bins[i - 1].end_s).abs() < 1e-12);
        }
    }

    // ── LifetimeSample ──────────────────────────────────────────────

    #[test]
    fn lifetime_sample_event_true() {
        let s = LifetimeSample {
            duration_s: 42.0,
            event: true,
        };
        assert_eq!(s.duration_s, 42.0);
        assert!(s.event);
    }

    #[test]
    fn lifetime_sample_censored() {
        let s = LifetimeSample {
            duration_s: 100.0,
            event: false,
        };
        assert!(!s.event);
    }
}
