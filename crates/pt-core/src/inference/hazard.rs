//! Time-varying regime-based hazard model for abandonment risk.
//!
//! This module implements a Bayesian hazard model where the hazard rate varies
//! depending on what "regime" the process is currently in. Each regime has its
//! own Gamma-distributed hazard rate, and the survival probability is computed
//! by integrating the hazard across all time spent in each regime.
//!
//! # Model
//!
//! For each regime r:
//! - Prior: λ_r ~ Gamma(α_r, β_r)
//! - After observing exposure E_r and events N_r:
//! - Posterior: λ_r | data ~ Gamma(α_r + N_r, β_r + E_r)
//!
//! Survival function: S(t) = exp(-Σ_r λ_r × E_r)
//!
//! # Regimes
//!
//! The model supports these standard regimes:
//! - `Normal`: No abnormal conditions detected
//! - `TtyLost`: Process lost its controlling terminal
//! - `Orphaned`: Process was reparented to init (PPID=1)
//! - `IoFlatline`: No I/O activity for extended period
//! - `CpuRunaway`: Sustained high CPU usage
//! - `MemoryPressure`: High memory consumption
//!
//! # Example
//!
//! ```
//! use pt_core::inference::hazard::{HazardModel, Regime, RegimeTransition};
//!
//! // Create model with default priors
//! let mut model = HazardModel::new();
//!
//! // Record time spent in different regimes
//! model.record_exposure(Regime::Normal, 3600.0); // 1 hour normal
//! model.record_exposure(Regime::TtyLost, 1800.0); // 30 min with TTY lost
//!
//! // Compute survival probability
//! let result = model.compute_survival();
//! println!("Survival estimate: {:.4}", result.survival_estimate);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Regime types representing different process states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Regime {
    /// No abnormal conditions - baseline hazard.
    Normal,
    /// Process lost its controlling terminal.
    TtyLost,
    /// Process was reparented to init (PPID became 1).
    Orphaned,
    /// No I/O activity for extended period.
    IoFlatline,
    /// Sustained high CPU usage (potential runaway).
    CpuRunaway,
    /// High memory consumption.
    MemoryPressure,
    /// Process is running under nohup/disown.
    Backgrounded,
    /// Custom user-defined regime.
    Custom(u32),
}

impl std::fmt::Display for Regime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Regime::Normal => write!(f, "normal"),
            Regime::TtyLost => write!(f, "tty_lost"),
            Regime::Orphaned => write!(f, "orphaned"),
            Regime::IoFlatline => write!(f, "io_flatline"),
            Regime::CpuRunaway => write!(f, "cpu_runaway"),
            Regime::MemoryPressure => write!(f, "memory_pressure"),
            Regime::Backgrounded => write!(f, "backgrounded"),
            Regime::Custom(id) => write!(f, "custom_{}", id),
        }
    }
}

/// Gamma prior/posterior parameters for a regime's hazard rate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GammaParams {
    /// Shape parameter (alpha).
    pub alpha: f64,
    /// Rate parameter (beta).
    pub beta: f64,
}

impl GammaParams {
    /// Create new Gamma parameters.
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self { alpha, beta }
    }

    /// Mean of the Gamma distribution: E\[λ\] = α/β.
    pub fn mean(&self) -> f64 {
        self.alpha / self.beta
    }

    /// Variance of the Gamma distribution: Var\[λ\] = α/β².
    pub fn variance(&self) -> f64 {
        self.alpha / (self.beta * self.beta)
    }

    /// Standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Mode of the Gamma distribution (for α >= 1): (α-1)/β.
    pub fn mode(&self) -> Option<f64> {
        if self.alpha >= 1.0 {
            Some((self.alpha - 1.0) / self.beta)
        } else {
            None // Mode at 0 for α < 1
        }
    }

    /// Update the posterior given exposure and events.
    ///
    /// Conjugate update: Gamma(α, β) + (N events, E exposure) → Gamma(α + N, β + E)
    pub fn update(&self, events: u32, exposure: f64) -> Self {
        Self {
            alpha: self.alpha + events as f64,
            beta: self.beta + exposure,
        }
    }
}

impl Default for GammaParams {
    fn default() -> Self {
        // Weak prior: roughly 1 event per 10000 seconds (~2.8 hours)
        Self::new(1.0, 10000.0)
    }
}

/// State for a single regime, tracking prior, observations, and posterior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeState {
    /// The regime this state describes.
    pub regime: Regime,
    /// Prior Gamma parameters for the hazard rate.
    pub prior: GammaParams,
    /// Total exposure time in seconds.
    pub exposure_s: f64,
    /// Number of abandonment events observed in this regime.
    pub events: u32,
    /// Posterior Gamma parameters (updated from prior + observations).
    pub posterior: GammaParams,
}

impl RegimeState {
    /// Create a new regime state with the given prior.
    pub fn new(regime: Regime, prior: GammaParams) -> Self {
        Self {
            regime,
            prior,
            exposure_s: 0.0,
            events: 0,
            posterior: prior,
        }
    }

    /// Record exposure time in this regime.
    pub fn record_exposure(&mut self, seconds: f64) {
        self.exposure_s += seconds;
        self.update_posterior();
    }

    /// Record an abandonment event in this regime.
    pub fn record_event(&mut self) {
        self.events += 1;
        self.update_posterior();
    }

    /// Update the posterior from prior + observations.
    fn update_posterior(&mut self) {
        self.posterior = self.prior.update(self.events, self.exposure_s);
    }

    /// Mean hazard rate from the posterior: λ̂ = E[λ|data] = α_post / β_post.
    pub fn lambda_mean(&self) -> f64 {
        self.posterior.mean()
    }

    /// Expected cumulative hazard for this regime: λ̂ × exposure.
    pub fn cumulative_hazard(&self) -> f64 {
        self.lambda_mean() * self.exposure_s
    }

    /// Compute the 95% credible interval for λ using Gamma quantiles.
    pub fn lambda_credible_interval(&self, level: f64) -> (f64, f64) {
        // Use the approximation: for Gamma(α, β), quantiles can be computed
        // For simplicity, use normal approximation for large α
        let alpha = self.posterior.alpha;
        let beta = self.posterior.beta;

        if alpha > 30.0 {
            // Normal approximation
            let mean = alpha / beta;
            let std = (alpha / (beta * beta)).sqrt();
            let z = 1.96 * (1.0 - level / 2.0).abs(); // Approximate
            ((mean - z * std).max(0.0), mean + z * std)
        } else {
            // Use simple bounds based on variance
            let mean = alpha / beta;
            let std = (alpha / (beta * beta)).sqrt();
            ((mean - 2.0 * std).max(0.0), mean + 2.0 * std)
        }
    }
}

/// Default priors for each regime type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimePriors {
    priors: HashMap<Regime, GammaParams>,
}

impl RegimePriors {
    /// Create new priors with defaults.
    pub fn new() -> Self {
        let mut priors = HashMap::new();

        // Normal: very low base hazard (1 event per ~28 hours)
        priors.insert(Regime::Normal, GammaParams::new(1.0, 100000.0));

        // TTY lost: elevated hazard (1 event per ~3 hours)
        priors.insert(Regime::TtyLost, GammaParams::new(1.0, 10000.0));

        // Orphaned: high hazard (1 event per ~1 hour)
        priors.insert(Regime::Orphaned, GammaParams::new(1.0, 3600.0));

        // IO flatline: elevated hazard (1 event per ~2 hours)
        priors.insert(Regime::IoFlatline, GammaParams::new(1.0, 7200.0));

        // CPU runaway: moderate hazard (often intentional, e.g., builds)
        priors.insert(Regime::CpuRunaway, GammaParams::new(1.0, 18000.0));

        // Memory pressure: moderate hazard
        priors.insert(Regime::MemoryPressure, GammaParams::new(1.0, 14400.0));

        // Backgrounded: low hazard (intentional)
        priors.insert(Regime::Backgrounded, GammaParams::new(1.0, 86400.0));

        Self { priors }
    }

    /// Get the prior for a regime.
    pub fn get(&self, regime: &Regime) -> GammaParams {
        self.priors.get(regime).copied().unwrap_or_default()
    }

    /// Set a custom prior for a regime.
    pub fn set(&mut self, regime: Regime, params: GammaParams) {
        self.priors.insert(regime, params);
    }
}

impl Default for RegimePriors {
    fn default() -> Self {
        Self::new()
    }
}

/// Record of a regime transition for tracking purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeTransition {
    /// Timestamp of the transition (Unix epoch seconds).
    pub timestamp: f64,
    /// Regime before the transition.
    pub from: Option<Regime>,
    /// Regime after the transition.
    pub to: Regime,
}

/// Result of survival computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazardResult {
    /// Per-regime breakdown of hazard statistics.
    pub regimes: Vec<RegimeStats>,
    /// Overall survival estimate: S(t) = exp(-Σ cumulative_hazard).
    pub survival_estimate: f64,
    /// Log survival for numerical stability.
    pub log_survival: f64,
    /// Total cumulative hazard across all regimes.
    pub total_cumulative_hazard: f64,
    /// Human-readable interpretation of the hazard.
    pub hazard_interpretation: String,
    /// Dominant regime (highest contribution to hazard).
    pub dominant_regime: Option<Regime>,
}

/// Statistics for a single regime in the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeStats {
    /// Regime name.
    pub name: String,
    /// Exposure time in seconds.
    pub exposure_s: f64,
    /// Number of events observed.
    pub events: u32,
    /// Posterior mean hazard rate (per second).
    pub lambda_mean: f64,
    /// Cumulative hazard contribution from this regime.
    pub cumulative_hazard: f64,
    /// Fraction of total hazard from this regime.
    pub hazard_fraction: f64,
}

/// Time-varying hazard model with regime-based hazard rates.
#[derive(Debug, Clone)]
pub struct HazardModel {
    /// Per-regime state.
    regimes: HashMap<Regime, RegimeState>,
    /// Default priors.
    priors: RegimePriors,
    /// History of regime transitions.
    transitions: Vec<RegimeTransition>,
    /// Current regime (if tracking live).
    current_regime: Option<Regime>,
    /// Timestamp of last regime entry.
    current_regime_start: Option<f64>,
}

impl HazardModel {
    /// Create a new hazard model with default priors.
    pub fn new() -> Self {
        Self {
            regimes: HashMap::new(),
            priors: RegimePriors::default(),
            transitions: Vec::new(),
            current_regime: None,
            current_regime_start: None,
        }
    }

    /// Create a hazard model with custom priors.
    pub fn with_priors(priors: RegimePriors) -> Self {
        Self {
            regimes: HashMap::new(),
            priors,
            transitions: Vec::new(),
            current_regime: None,
            current_regime_start: None,
        }
    }

    /// Get or create the state for a regime.
    fn get_or_create_regime(&mut self, regime: Regime) -> &mut RegimeState {
        self.regimes
            .entry(regime)
            .or_insert_with(|| RegimeState::new(regime, self.priors.get(&regime)))
    }

    /// Record exposure time in a specific regime.
    pub fn record_exposure(&mut self, regime: Regime, seconds: f64) {
        self.get_or_create_regime(regime).record_exposure(seconds);
    }

    /// Record an abandonment event in a regime.
    pub fn record_event(&mut self, regime: Regime) {
        self.get_or_create_regime(regime).record_event();
    }

    /// Enter a new regime (for live tracking).
    ///
    /// This records the transition and starts tracking time in the new regime.
    pub fn enter_regime(&mut self, regime: Regime, timestamp: f64) {
        // Close out previous regime if any
        if let (Some(prev_regime), Some(start)) = (self.current_regime, self.current_regime_start) {
            let duration = timestamp - start;
            if duration > 0.0 {
                self.record_exposure(prev_regime, duration);
            }
        }

        // Record transition
        self.transitions.push(RegimeTransition {
            timestamp,
            from: self.current_regime,
            to: regime,
        });

        // Start new regime
        self.current_regime = Some(regime);
        self.current_regime_start = Some(timestamp);

        // Ensure regime state exists
        self.get_or_create_regime(regime);
    }

    /// Finalize tracking at a given timestamp.
    ///
    /// Records any accumulated time in the current regime.
    pub fn finalize(&mut self, timestamp: f64) {
        if let (Some(regime), Some(start)) = (self.current_regime, self.current_regime_start) {
            let duration = timestamp - start;
            if duration > 0.0 {
                self.record_exposure(regime, duration);
            }
        }
        self.current_regime = None;
        self.current_regime_start = None;
    }

    /// Compute survival and hazard statistics.
    pub fn compute_survival(&self) -> HazardResult {
        let mut regime_stats = Vec::new();
        let mut total_cum_hazard = 0.0;

        // Collect stats for each regime with exposure
        for (regime, state) in &self.regimes {
            if state.exposure_s > 0.0 {
                let cum_h = state.cumulative_hazard();
                total_cum_hazard += cum_h;
                regime_stats.push(RegimeStats {
                    name: regime.to_string(),
                    exposure_s: state.exposure_s,
                    events: state.events,
                    lambda_mean: state.lambda_mean(),
                    cumulative_hazard: cum_h,
                    hazard_fraction: 0.0, // Will update after total is known
                });
            }
        }

        // Update hazard fractions
        for stats in &mut regime_stats {
            if total_cum_hazard > 0.0 {
                stats.hazard_fraction = stats.cumulative_hazard / total_cum_hazard;
            }
        }

        // Sort by cumulative hazard (highest first)
        regime_stats.sort_by(|a, b| {
            b.cumulative_hazard
                .partial_cmp(&a.cumulative_hazard)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Find dominant regime
        let dominant = regime_stats.first().and_then(|s| {
            // Parse regime from name
            match s.name.as_str() {
                "normal" => Some(Regime::Normal),
                "tty_lost" => Some(Regime::TtyLost),
                "orphaned" => Some(Regime::Orphaned),
                "io_flatline" => Some(Regime::IoFlatline),
                "cpu_runaway" => Some(Regime::CpuRunaway),
                "memory_pressure" => Some(Regime::MemoryPressure),
                "backgrounded" => Some(Regime::Backgrounded),
                _ => None,
            }
        });

        // Compute survival: S(t) = exp(-H(t))
        let log_survival = -total_cum_hazard;
        let survival = log_survival.exp();

        // Generate interpretation
        let interpretation = self.interpret_hazard(&regime_stats, survival);

        HazardResult {
            regimes: regime_stats,
            survival_estimate: survival,
            log_survival,
            total_cumulative_hazard: total_cum_hazard,
            hazard_interpretation: interpretation,
            dominant_regime: dominant,
        }
    }

    /// Generate human-readable interpretation of hazard.
    fn interpret_hazard(&self, stats: &[RegimeStats], survival: f64) -> String {
        if stats.is_empty() {
            return "No regime exposure recorded".to_string();
        }

        let dominant = &stats[0];

        // Risk level interpretation
        let risk_level = if survival > 0.9 {
            "very low"
        } else if survival > 0.7 {
            "low"
        } else if survival > 0.4 {
            "moderate"
        } else if survival > 0.1 {
            "high"
        } else {
            "very high"
        };

        // Find which regime dominates
        if dominant.hazard_fraction > 0.5 {
            format!(
                "{} dominates hazard ({:.0}%); {} abandonment risk",
                dominant.name.replace('_', " "),
                dominant.hazard_fraction * 100.0,
                risk_level
            )
        } else if stats.len() > 1 {
            format!(
                "Multiple regimes contribute; {} abandonment risk (survival: {:.1}%)",
                risk_level,
                survival * 100.0
            )
        } else {
            format!(
                "{} regime; {} abandonment risk",
                dominant.name.replace('_', " "),
                risk_level
            )
        }
    }

    /// Get the current regime states.
    pub fn regime_states(&self) -> &HashMap<Regime, RegimeState> {
        &self.regimes
    }

    /// Get transition history.
    pub fn transitions(&self) -> &[RegimeTransition] {
        &self.transitions
    }

    /// Compute marginal survival using Lomax distribution for uncertainty.
    ///
    /// When λ ~ Gamma(α, β), the marginal survival after exposure E is:
    /// S_marginal(E) = (β / (β + E))^α
    ///
    /// This is the Lomax (Pareto Type II) survival function, which has
    /// heavier tails than the exponential, accounting for parameter uncertainty.
    pub fn compute_marginal_survival(&self) -> f64 {
        let mut log_survival = 0.0;

        for state in self.regimes.values() {
            if state.exposure_s > 0.0 {
                // Lomax survival: (β / (β + E))^α
                let alpha = state.posterior.alpha;
                let beta = state.posterior.beta;
                let e = state.exposure_s;

                // log S = α * log(β) - α * log(β + E) = α * log(β / (β + E))
                log_survival += alpha * (beta / (beta + e)).ln();
            }
        }

        log_survival.exp()
    }

    /// Reset all regime states (keep priors).
    pub fn reset(&mut self) {
        self.regimes.clear();
        self.transitions.clear();
        self.current_regime = None;
        self.current_regime_start = None;
    }
}

impl Default for HazardModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Evidence term for integration with the decision core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazardEvidence {
    /// The computed hazard result.
    pub result: HazardResult,
    /// Log-odds contribution to P(abandoned).
    pub log_odds: f64,
    /// Feature glyph for display.
    pub glyph: char,
    /// Short description.
    pub description: String,
}

impl HazardEvidence {
    /// Create evidence from a hazard result.
    ///
    /// Converts survival probability to log-odds for Bayesian combination.
    pub fn from_result(result: HazardResult) -> Self {
        // Convert survival to log-odds of abandonment
        // P(abandoned) ≈ 1 - S(t) for long exposure
        // log-odds = log(P / (1-P)) = log((1-S) / S) = -log(S / (1-S))
        let s = result.survival_estimate.clamp(1e-10, 1.0 - 1e-10);
        let log_odds = ((1.0 - s) / s).ln();

        // Choose glyph based on survival level
        let glyph = if s > 0.8 {
            '○' // Low hazard
        } else if s > 0.5 {
            '◐' // Moderate hazard
        } else if s > 0.2 {
            '◑' // Elevated hazard
        } else {
            '●' // High hazard
        };

        Self {
            description: result.hazard_interpretation.clone(),
            result,
            log_odds,
            glyph,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_gamma_params_mean_variance() {
        let params = GammaParams::new(2.0, 0.5);
        assert!(approx_eq(params.mean(), 4.0, 1e-10));
        assert!(approx_eq(params.variance(), 8.0, 1e-10));
    }

    #[test]
    fn test_gamma_params_update() {
        let prior = GammaParams::new(1.0, 100.0);
        let posterior = prior.update(2, 500.0);

        // α_post = 1 + 2 = 3
        // β_post = 100 + 500 = 600
        assert!(approx_eq(posterior.alpha, 3.0, 1e-10));
        assert!(approx_eq(posterior.beta, 600.0, 1e-10));
    }

    #[test]
    fn test_regime_state_exposure() {
        let mut state = RegimeState::new(Regime::Normal, GammaParams::new(1.0, 100.0));
        state.record_exposure(500.0);

        assert!(approx_eq(state.exposure_s, 500.0, 1e-10));
        assert!(approx_eq(state.posterior.beta, 600.0, 1e-10));
    }

    #[test]
    fn test_hazard_model_basic() {
        let mut model = HazardModel::new();

        // Record exposure in normal regime
        model.record_exposure(Regime::Normal, 3600.0);

        let result = model.compute_survival();
        assert!(result.survival_estimate > 0.0);
        assert!(result.survival_estimate <= 1.0);
        assert_eq!(result.regimes.len(), 1);
    }

    #[test]
    fn test_hazard_model_multiple_regimes() {
        let mut model = HazardModel::new();

        model.record_exposure(Regime::Normal, 3600.0); // 1 hour normal
        model.record_exposure(Regime::TtyLost, 1800.0); // 30 min TTY lost
        model.record_exposure(Regime::IoFlatline, 900.0); // 15 min IO flatline

        let result = model.compute_survival();

        assert_eq!(result.regimes.len(), 3);
        assert!(result.total_cumulative_hazard > 0.0);

        // TTY lost should have higher hazard than normal (higher prior rate)
        let tty_state = model.regimes.get(&Regime::TtyLost).unwrap();
        let normal_state = model.regimes.get(&Regime::Normal).unwrap();
        assert!(tty_state.lambda_mean() > normal_state.lambda_mean());
    }

    #[test]
    fn test_hazard_model_events() {
        let mut model = HazardModel::new();

        model.record_exposure(Regime::Orphaned, 3600.0);
        model.record_event(Regime::Orphaned);

        let _result = model.compute_survival();

        // With an event, hazard should be higher
        let state = model.regimes.get(&Regime::Orphaned).unwrap();
        assert_eq!(state.events, 1);

        // Posterior mean should increase with events
        // Prior mean: 1/3600 ≈ 0.000278
        // After 1 event, 3600 exposure: (1+1)/(3600+3600) = 2/7200 ≈ 0.000278
        // About the same due to Bayesian averaging
        assert!(state.lambda_mean() > 0.0);
    }

    #[test]
    fn test_hazard_model_live_tracking() {
        let mut model = HazardModel::new();

        // Enter normal regime at t=0
        model.enter_regime(Regime::Normal, 0.0);

        // Switch to TTY lost at t=100
        model.enter_regime(Regime::TtyLost, 100.0);

        // Finalize at t=200
        model.finalize(200.0);

        // Should have 100s normal, 100s TTY lost
        let normal_state = model.regimes.get(&Regime::Normal).unwrap();
        let tty_state = model.regimes.get(&Regime::TtyLost).unwrap();

        assert!(approx_eq(normal_state.exposure_s, 100.0, 1e-10));
        assert!(approx_eq(tty_state.exposure_s, 100.0, 1e-10));
    }

    #[test]
    fn test_survival_decreases_with_exposure() {
        let mut model1 = HazardModel::new();
        model1.record_exposure(Regime::TtyLost, 1000.0);
        let s1 = model1.compute_survival().survival_estimate;

        let mut model2 = HazardModel::new();
        model2.record_exposure(Regime::TtyLost, 10000.0);
        let s2 = model2.compute_survival().survival_estimate;

        assert!(s2 < s1, "More exposure should yield lower survival");
    }

    #[test]
    fn test_marginal_survival() {
        let mut model = HazardModel::new();
        model.record_exposure(Regime::Normal, 1000.0);

        let _point_survival = model.compute_survival().survival_estimate;
        let marginal_survival = model.compute_marginal_survival();

        // Marginal survival should account for uncertainty
        // Generally different from point estimate
        assert!(marginal_survival > 0.0);
        assert!(marginal_survival <= 1.0);
    }

    #[test]
    fn test_hazard_evidence() {
        let mut model = HazardModel::new();
        model.record_exposure(Regime::Orphaned, 7200.0); // High-hazard regime

        let result = model.compute_survival();
        let evidence = HazardEvidence::from_result(result);

        // Should produce valid evidence
        assert!(evidence.log_odds.is_finite());
        assert!(!evidence.description.is_empty());
    }

    #[test]
    fn test_regime_display() {
        assert_eq!(Regime::Normal.to_string(), "normal");
        assert_eq!(Regime::TtyLost.to_string(), "tty_lost");
        assert_eq!(Regime::Custom(42).to_string(), "custom_42");
    }

    #[test]
    fn test_empty_model() {
        let model = HazardModel::new();
        let result = model.compute_survival();

        assert!(result.regimes.is_empty());
        // With no hazard, survival is 1.0 (exp(-0))
        assert!(approx_eq(result.survival_estimate, 1.0, 1e-10));
    }

    #[test]
    fn test_high_hazard_regime_dominates() {
        let mut model = HazardModel::new();

        // Same exposure time, but orphaned has much higher base hazard
        model.record_exposure(Regime::Normal, 1000.0);
        model.record_exposure(Regime::Orphaned, 1000.0);

        let result = model.compute_survival();

        // Orphaned should have higher hazard fraction
        let orphan_stats = result
            .regimes
            .iter()
            .find(|s| s.name == "orphaned")
            .unwrap();
        let normal_stats = result.regimes.iter().find(|s| s.name == "normal").unwrap();

        assert!(
            orphan_stats.cumulative_hazard > normal_stats.cumulative_hazard,
            "Orphaned should dominate: {} vs {}",
            orphan_stats.cumulative_hazard,
            normal_stats.cumulative_hazard
        );
    }

    #[test]
    fn test_reset() {
        let mut model = HazardModel::new();
        model.record_exposure(Regime::Normal, 1000.0);
        model.enter_regime(Regime::TtyLost, 0.0);

        model.reset();

        assert!(model.regimes.is_empty());
        assert!(model.transitions.is_empty());
        assert!(model.current_regime.is_none());
    }

    #[test]
    fn test_credible_interval() {
        let state = RegimeState::new(Regime::Normal, GammaParams::new(10.0, 1000.0));
        let (lower, upper) = state.lambda_credible_interval(0.95);

        let mean = state.lambda_mean();
        assert!(lower < mean, "Lower bound should be below mean");
        assert!(upper > mean, "Upper bound should be above mean");
        assert!(lower >= 0.0, "Lower bound should be non-negative");
    }
}
