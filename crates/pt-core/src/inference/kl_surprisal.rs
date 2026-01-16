//! KL-divergence surprisal analysis for anomaly detection.
//!
//! This module implements Plan §4.8/§4.8b and §2(M)/§2(AG): information-theoretic
//! abnormality signals as interpretable evidence terms.
//!
//! # Mathematical Foundation
//!
//! ## KL Divergence (Kullback-Leibler)
//!
//! For discrete distributions P and Q over the same support:
//! ```text
//! D_KL(P || Q) = Σ P(x) log(P(x) / Q(x))
//! ```
//!
//! For Bernoulli distributions with parameters p (observed) and q (reference):
//! ```text
//! D_KL(p || q) = p·ln(p/q) + (1-p)·ln((1-p)/(1-q))
//! ```
//!
//! ## Large Deviation / Rate Function Bounds
//!
//! Cramér's theorem gives exponential decay for rare events:
//! ```text
//! P(X̄ₙ ≥ p̂) ≤ exp(-n · D_KL(p̂ || p_useful))
//! ```
//!
//! This provides "how rare is this under the useful model?" as a scalar.
//!
//! ## Surprisal (Self-Information)
//!
//! Surprisal in bits: `I(x) = -log₂(P(x))`
//!
//! Large surprisal indicates unlikely events under the reference model.
//!
//! # Usage
//!
//! ```
//! use pt_core::inference::kl_surprisal::{KlSurprisalAnalyzer, KlSurprisalConfig};
//!
//! let mut analyzer = KlSurprisalAnalyzer::new(KlSurprisalConfig::default());
//! analyzer.update_weighted(true, 1.0); // event occurred
//! analyzer.update_weighted(false, 1.0);
//!
//! let result = analyzer.analyze(0.05); // reference rate
//! if let Ok(res) = result {
//!     println!("KL divergence: {:.4} nats", res.evidence.kl_divergence);
//!     println!("Tail probability bound: {:.6}", res.rate_bound);
//! }
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from KL surprisal analysis.
#[derive(Debug, Error, Clone)]
pub enum KlSurprisalError {
    #[error("insufficient data for KL analysis: need {needed}, have {have}")]
    InsufficientData { needed: usize, have: usize },

    #[error("invalid reference probability: {value} (must be in (0, 1))")]
    InvalidReferenceProbability { value: f64 },

    #[error("invalid smoothing parameter: {value} (must be positive)")]
    InvalidSmoothing { value: f64 },

    #[error("numerical error in KL computation: {details}")]
    NumericalError { details: String },

    #[error("invalid n_eff adjustment factor: {value} (must be > 0)")]
    InvalidNEffFactor { value: f64 },
}

/// Configuration for KL surprisal analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KlSurprisalConfig {
    /// Minimum samples before computing KL divergence.
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,

    /// Additive smoothing (Laplace) for probability estimates.
    /// Prevents log(0) issues. Effective observed rate becomes (k + α) / (n + 2α).
    #[serde(default = "default_smoothing")]
    pub smoothing: f64,

    /// Threshold for flagging abnormality (in nats of KL divergence).
    /// Values above this are considered anomalous.
    #[serde(default = "default_abnormality_threshold")]
    pub abnormality_threshold: f64,

    /// n_eff adjustment factor for conservative bounds.
    /// Effective sample size = n * n_eff_factor (typically < 1 for correlated data).
    #[serde(default = "default_n_eff_factor")]
    pub n_eff_factor: f64,

    /// Whether to use log-domain arithmetic for numerical stability.
    #[serde(default = "default_use_log_domain")]
    pub use_log_domain: bool,

    /// Minimum probability value to prevent log(0).
    #[serde(default = "default_min_prob")]
    pub min_prob: f64,
}

fn default_min_samples() -> usize {
    10
}

fn default_smoothing() -> f64 {
    0.5 // Jeffreys prior: α = 0.5
}

fn default_abnormality_threshold() -> f64 {
    0.5 // ~0.72 bits, moderate deviation
}

fn default_n_eff_factor() -> f64 {
    1.0
}

fn default_use_log_domain() -> bool {
    true
}

fn default_min_prob() -> f64 {
    1e-10
}

impl Default for KlSurprisalConfig {
    fn default() -> Self {
        Self {
            min_samples: default_min_samples(),
            smoothing: default_smoothing(),
            abnormality_threshold: default_abnormality_threshold(),
            n_eff_factor: default_n_eff_factor(),
            use_log_domain: default_use_log_domain(),
            min_prob: default_min_prob(),
        }
    }
}

impl KlSurprisalConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), KlSurprisalError> {
        if self.smoothing < 0.0 {
            return Err(KlSurprisalError::InvalidSmoothing {
                value: self.smoothing,
            });
        }
        if self.n_eff_factor <= 0.0 {
            return Err(KlSurprisalError::InvalidNEffFactor {
                value: self.n_eff_factor,
            });
        }
        Ok(())
    }
}

/// Reference class for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceClass {
    /// Global baseline across all processes.
    Global,
    /// Per-category baseline (e.g., all dev servers).
    Category,
    /// Per-signature baseline (e.g., all "jest" processes).
    Signature,
    /// Historical baseline for this specific process.
    Historical,
}

impl std::fmt::Display for ReferenceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReferenceClass::Global => write!(f, "global"),
            ReferenceClass::Category => write!(f, "category"),
            ReferenceClass::Signature => write!(f, "signature"),
            ReferenceClass::Historical => write!(f, "historical"),
        }
    }
}

/// Type of deviation detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviationType {
    /// CPU usage deviation.
    CpuUsage,
    /// Memory usage deviation.
    MemoryUsage,
    /// I/O pattern deviation.
    IoPattern,
    /// Network activity deviation.
    NetworkActivity,
    /// Timing/scheduling deviation.
    Timing,
    /// General behavioral deviation.
    General,
}

impl std::fmt::Display for DeviationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviationType::CpuUsage => write!(f, "CPU usage"),
            DeviationType::MemoryUsage => write!(f, "memory usage"),
            DeviationType::IoPattern => write!(f, "I/O pattern"),
            DeviationType::NetworkActivity => write!(f, "network activity"),
            DeviationType::Timing => write!(f, "timing"),
            DeviationType::General => write!(f, "general"),
        }
    }
}

/// Severity of detected abnormality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AbnormalitySeverity {
    /// Within normal variation.
    Normal,
    /// Slightly unusual but not concerning.
    Mild,
    /// Notable deviation worth monitoring.
    Moderate,
    /// Significant deviation requiring attention.
    Severe,
    /// Critical deviation requiring immediate action.
    Critical,
}

impl AbnormalitySeverity {
    /// Determine severity from KL divergence value (in nats).
    pub fn from_kl_divergence(kl: f64) -> Self {
        if kl < 0.1 {
            AbnormalitySeverity::Normal
        } else if kl < 0.3 {
            AbnormalitySeverity::Mild
        } else if kl < 0.7 {
            AbnormalitySeverity::Moderate
        } else if kl < 1.5 {
            AbnormalitySeverity::Severe
        } else {
            AbnormalitySeverity::Critical
        }
    }

    /// Determine severity from tail probability bound.
    pub fn from_tail_bound(p: f64) -> Self {
        if p > 0.1 {
            AbnormalitySeverity::Normal
        } else if p > 0.01 {
            AbnormalitySeverity::Mild
        } else if p > 0.001 {
            AbnormalitySeverity::Moderate
        } else if p > 0.0001 {
            AbnormalitySeverity::Severe
        } else {
            AbnormalitySeverity::Critical
        }
    }
}

impl std::fmt::Display for AbnormalitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbnormalitySeverity::Normal => write!(f, "normal"),
            AbnormalitySeverity::Mild => write!(f, "mild"),
            AbnormalitySeverity::Moderate => write!(f, "moderate"),
            AbnormalitySeverity::Severe => write!(f, "severe"),
            AbnormalitySeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Evidence from KL surprisal analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KlSurprisalEvidence {
    /// KL divergence value from reference (in nats).
    pub kl_divergence: f64,

    /// KL divergence in bits (log base 2).
    pub kl_divergence_bits: f64,

    /// Type of deviation detected.
    pub deviation_type: DeviationType,

    /// Severity assessment.
    pub severity: AbnormalitySeverity,

    /// Reference class used for comparison.
    pub reference_class: ReferenceClass,

    /// Observed probability/rate.
    pub observed_rate: f64,

    /// Reference probability/rate.
    pub reference_rate: f64,

    /// Effective sample size used.
    pub n_eff: f64,

    /// Human-readable description.
    pub description: String,
}

/// Result of KL surprisal analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KlSurprisalResult {
    /// KL divergence from reference (in nats).
    pub kl_divergence: f64,

    /// KL divergence in bits.
    pub kl_divergence_bits: f64,

    /// Surprisal of observed rate under reference (in bits).
    pub surprisal_bits: f64,

    /// Large deviation rate function bound.
    /// P(observed deviation) ≤ exp(-n_eff * kl_divergence).
    pub rate_bound: f64,

    /// Log of rate bound (for numerical stability).
    pub log_rate_bound: f64,

    /// Observed probability estimate.
    pub observed_rate: f64,

    /// Reference probability.
    pub reference_rate: f64,

    /// Direction of deviation.
    pub direction: DeviationDirection,

    /// Number of observations.
    pub n: usize,

    /// Effective sample size.
    pub n_eff: f64,

    /// Whether process is flagged as abnormal.
    pub is_abnormal: bool,

    /// Overall severity assessment.
    pub severity: AbnormalitySeverity,

    /// Evidence for ledger integration.
    pub evidence: KlSurprisalEvidence,
}

/// Direction of deviation from reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviationDirection {
    /// Observed rate is higher than reference.
    Higher,
    /// Observed rate is lower than reference.
    Lower,
    /// Observed rate matches reference (within noise).
    Match,
}

impl std::fmt::Display for DeviationDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviationDirection::Higher => write!(f, "higher"),
            DeviationDirection::Lower => write!(f, "lower"),
            DeviationDirection::Match => write!(f, "match"),
        }
    }
}

/// A single binary observation for Bernoulli analysis.
#[derive(Debug, Clone, Copy)]
pub struct BernoulliObservation {
    /// Whether the event occurred (true) or not (false).
    pub occurred: bool,
    /// Optional weight for this observation.
    pub weight: Option<f64>,
}

impl From<bool> for BernoulliObservation {
    fn from(occurred: bool) -> Self {
        Self {
            occurred,
            weight: None,
        }
    }
}

/// Streaming KL surprisal analyzer for Bernoulli (binary) observations.
///
/// Tracks successes and total observations, computing KL divergence
/// against reference rates.
#[derive(Debug, Clone)]
pub struct KlSurprisalAnalyzer {
    config: KlSurprisalConfig,
    /// Total number of observations.
    n: usize,
    /// Number of successes (events occurred).
    k: usize,
    /// Sum of weights (if weighted observations used).
    total_weight: f64,
    /// Weighted successes.
    weighted_k: f64,
}

impl KlSurprisalAnalyzer {
    /// Create a new analyzer with the given config.
    pub fn new(config: KlSurprisalConfig) -> Self {
        Self {
            config,
            n: 0,
            k: 0,
            total_weight: 0.0,
            weighted_k: 0.0,
        }
    }

    /// Create analyzer with default config.
    pub fn with_defaults() -> Self {
        Self::new(KlSurprisalConfig::default())
    }

    /// Get the configuration.
    pub fn config(&self) -> &KlSurprisalConfig {
        &self.config
    }

    /// Get the number of observations.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Check if analyzer is empty.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Get the raw success count.
    pub fn successes(&self) -> usize {
        self.k
    }

    /// Reset the analyzer state.
    pub fn reset(&mut self) {
        self.n = 0;
        self.k = 0;
        self.total_weight = 0.0;
        self.weighted_k = 0.0;
    }

    /// Update with a binary observation.
    pub fn update_bernoulli(&mut self, occurred: bool) {
        self.n += 1;
        if occurred {
            self.k += 1;
        }
        self.total_weight += 1.0;
        if occurred {
            self.weighted_k += 1.0;
        }
    }

    /// Update with a weighted observation.
    pub fn update_weighted(&mut self, occurred: bool, weight: f64) {
        let w = weight.max(0.0);
        self.n += 1;
        if occurred {
            self.k += 1;
        }
        self.total_weight += w;
        if occurred {
            self.weighted_k += w;
        }
    }

    /// Get smoothed observed rate.
    fn smoothed_rate(&self) -> f64 {
        let alpha = self.config.smoothing;
        (self.weighted_k + alpha) / (self.total_weight + 2.0 * alpha)
    }

    /// Get effective sample size.
    fn effective_n(&self) -> f64 {
        self.total_weight * self.config.n_eff_factor
    }

    /// Compute KL divergence D_KL(p || q) for Bernoulli distributions.
    ///
    /// # Arguments
    /// * `p` - Observed rate (will be clamped to (min_prob, 1-min_prob))
    /// * `q` - Reference rate (must be in (0, 1))
    ///
    /// # Returns
    /// KL divergence in nats (natural log base).
    pub fn kl_divergence_bernoulli(&self, p: f64, q: f64) -> Result<f64, KlSurprisalError> {
        if q <= 0.0 || q >= 1.0 {
            return Err(KlSurprisalError::InvalidReferenceProbability { value: q });
        }

        let min_p = self.config.min_prob;
        let p = p.clamp(min_p, 1.0 - min_p);

        // D_KL(p || q) = p * ln(p/q) + (1-p) * ln((1-p)/(1-q))
        let term1 = if p > min_p { p * (p / q).ln() } else { 0.0 };

        let term2 = if (1.0 - p) > min_p {
            (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
        } else {
            0.0
        };

        let kl = term1 + term2;

        if !kl.is_finite() {
            return Err(KlSurprisalError::NumericalError {
                details: format!(
                    "KL computation produced non-finite result: p={}, q={}",
                    p, q
                ),
            });
        }

        Ok(kl.max(0.0)) // KL is always non-negative
    }

    /// Compute large deviation rate function bound.
    ///
    /// P(X̄ₙ ≥ p̂ | p = q) ≤ exp(-n * D_KL(p̂ || q))
    ///
    /// This is Cramér's theorem applied to Bernoulli observations.
    fn rate_function_bound(&self, kl: f64, n_eff: f64) -> (f64, f64) {
        let log_bound = -n_eff * kl;
        let bound = if self.config.use_log_domain {
            log_bound.exp().min(1.0)
        } else {
            (-n_eff * kl).exp().min(1.0)
        };
        (bound, log_bound)
    }

    /// Compute surprisal (self-information) in bits.
    ///
    /// I(p | q) = -log₂(Binomial PMF at k successes under q)
    /// Approximated for large n as: n * D_KL(p || q) / ln(2)
    fn surprisal_bits(&self, kl: f64, n_eff: f64) -> f64 {
        // Convert nats to bits: bits = nats / ln(2)
        (n_eff * kl) / std::f64::consts::LN_2
    }

    /// Analyze observations against a reference rate.
    ///
    /// # Arguments
    /// * `reference_rate` - The expected rate under the "useful" model (0 < q < 1)
    ///
    /// # Returns
    /// Analysis result with KL divergence, bounds, and evidence.
    pub fn analyze(&self, reference_rate: f64) -> Result<KlSurprisalResult, KlSurprisalError> {
        if self.n < self.config.min_samples {
            return Err(KlSurprisalError::InsufficientData {
                needed: self.config.min_samples,
                have: self.n,
            });
        }

        if reference_rate <= 0.0 || reference_rate >= 1.0 {
            return Err(KlSurprisalError::InvalidReferenceProbability {
                value: reference_rate,
            });
        }

        let observed_rate = self.smoothed_rate();
        let n_eff = self.effective_n();

        let kl = self.kl_divergence_bernoulli(observed_rate, reference_rate)?;
        let kl_bits = kl / std::f64::consts::LN_2;

        let (rate_bound, log_rate_bound) = self.rate_function_bound(kl, n_eff);
        let surprisal = self.surprisal_bits(kl, n_eff);

        let direction = if (observed_rate - reference_rate).abs() < 0.01 {
            DeviationDirection::Match
        } else if observed_rate > reference_rate {
            DeviationDirection::Higher
        } else {
            DeviationDirection::Lower
        };

        let is_abnormal = kl > self.config.abnormality_threshold;
        let severity = AbnormalitySeverity::from_kl_divergence(kl);

        let description = format!(
            "Observed rate {:.2}% vs reference {:.2}% ({} by {:.1}pp); KL={:.3} nats ({:.2} bits); tail bound={:.2e}",
            observed_rate * 100.0,
            reference_rate * 100.0,
            direction,
            (observed_rate - reference_rate).abs() * 100.0,
            kl,
            kl_bits,
            rate_bound
        );

        let evidence = KlSurprisalEvidence {
            kl_divergence: kl,
            kl_divergence_bits: kl_bits,
            deviation_type: DeviationType::General,
            severity,
            reference_class: ReferenceClass::Global,
            observed_rate,
            reference_rate,
            n_eff,
            description: description.clone(),
        };

        Ok(KlSurprisalResult {
            kl_divergence: kl,
            kl_divergence_bits: kl_bits,
            surprisal_bits: surprisal,
            rate_bound,
            log_rate_bound,
            observed_rate,
            reference_rate,
            direction,
            n: self.n,
            n_eff,
            is_abnormal,
            severity,
            evidence,
        })
    }

    /// Analyze with a specific deviation type and reference class.
    pub fn analyze_typed(
        &self,
        reference_rate: f64,
        deviation_type: DeviationType,
        reference_class: ReferenceClass,
    ) -> Result<KlSurprisalResult, KlSurprisalError> {
        let mut result = self.analyze(reference_rate)?;
        result.evidence.deviation_type = deviation_type;
        result.evidence.reference_class = reference_class;
        Ok(result)
    }
}

impl Default for KlSurprisalAnalyzer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Telemetry-ready features from KL surprisal analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KlSurprisalFeatures {
    /// Process ID.
    pub pid: u32,

    /// Signal type being analyzed.
    pub signal_type: String,

    /// Number of observations.
    pub n: usize,

    /// Effective sample size.
    pub n_eff: f64,

    /// Observed rate.
    pub observed_rate: f64,

    /// Reference rate.
    pub reference_rate: f64,

    /// KL divergence in nats.
    pub kl_surprisal: f64,

    /// KL divergence in bits.
    pub kl_surprisal_bits: f64,

    /// Total surprisal in bits.
    pub surprisal_bits: f64,

    /// Rate function bound (tail probability).
    pub rate_bound: f64,

    /// Log of rate bound.
    pub log_rate_bound: f64,

    /// Normalized anomaly score [0, 1].
    pub anomaly_score: f64,

    /// Deviation direction.
    pub direction: String,

    /// Severity level.
    pub severity: String,

    /// Whether flagged as abnormal.
    pub is_abnormal: bool,
}

impl KlSurprisalFeatures {
    /// Create features from analysis result.
    pub fn from_result(pid: u32, result: &KlSurprisalResult, signal_type: &str) -> Self {
        // Normalize KL to [0, 1] using sigmoid-like transform
        // score = 1 - exp(-kl)
        let anomaly_score = (1.0 - (-result.kl_divergence).exp()).clamp(0.0, 1.0);

        Self {
            pid,
            signal_type: signal_type.to_string(),
            n: result.n,
            n_eff: result.n_eff,
            observed_rate: result.observed_rate,
            reference_rate: result.reference_rate,
            kl_surprisal: result.kl_divergence,
            kl_surprisal_bits: result.kl_divergence_bits,
            surprisal_bits: result.surprisal_bits,
            rate_bound: result.rate_bound,
            log_rate_bound: result.log_rate_bound,
            anomaly_score,
            direction: result.direction.to_string(),
            severity: result.severity.to_string(),
            is_abnormal: result.is_abnormal,
        }
    }
}

/// Batch analyzer for multiple processes/signals.
#[derive(Debug, Clone)]
pub struct BatchKlAnalyzer {
    config: KlSurprisalConfig,
    analyzers: std::collections::HashMap<String, KlSurprisalAnalyzer>,
}

impl BatchKlAnalyzer {
    /// Create a new batch analyzer.
    pub fn new(config: KlSurprisalConfig) -> Self {
        Self {
            config,
            analyzers: std::collections::HashMap::new(),
        }
    }

    /// Create with default config.
    pub fn with_defaults() -> Self {
        Self::new(KlSurprisalConfig::default())
    }

    /// Update a named stream with a binary observation.
    pub fn update(&mut self, name: &str, occurred: bool) {
        self.analyzers
            .entry(name.to_string())
            .or_insert_with(|| KlSurprisalAnalyzer::new(self.config.clone()))
            .update_bernoulli(occurred);
    }

    /// Update a named stream with a weighted observation.
    pub fn update_weighted(&mut self, name: &str, occurred: bool, weight: f64) {
        self.analyzers
            .entry(name.to_string())
            .or_insert_with(|| KlSurprisalAnalyzer::new(self.config.clone()))
            .update_weighted(occurred, weight);
    }

    /// Analyze a specific stream.
    pub fn analyze(
        &self,
        name: &str,
        reference_rate: f64,
    ) -> Option<Result<KlSurprisalResult, KlSurprisalError>> {
        self.analyzers.get(name).map(|a| a.analyze(reference_rate))
    }

    /// Get all stream names.
    pub fn streams(&self) -> impl Iterator<Item = &str> {
        self.analyzers.keys().map(|s| s.as_str())
    }

    /// Get analyzer for a specific stream.
    pub fn get(&self, name: &str) -> Option<&KlSurprisalAnalyzer> {
        self.analyzers.get(name)
    }

    /// Reset all analyzers.
    pub fn reset(&mut self) {
        for analyzer in self.analyzers.values_mut() {
            analyzer.reset();
        }
    }

    /// Clear all streams.
    pub fn clear(&mut self) {
        self.analyzers.clear();
    }
}

impl Default for BatchKlAnalyzer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Compute KL divergence for general discrete distributions.
///
/// # Arguments
/// * `p` - Observed distribution (slice of probabilities, should sum to ~1)
/// * `q` - Reference distribution (slice of probabilities, should sum to ~1)
///
/// # Returns
/// KL divergence in nats, or error if inputs are invalid.
pub fn kl_divergence_discrete(p: &[f64], q: &[f64]) -> Result<f64, KlSurprisalError> {
    if p.len() != q.len() {
        return Err(KlSurprisalError::NumericalError {
            details: format!(
                "Distribution lengths must match: p has {}, q has {}",
                p.len(),
                q.len()
            ),
        });
    }

    let min_prob = 1e-10;
    let mut kl = 0.0;

    for (&pi, &qi) in p.iter().zip(q.iter()) {
        if pi > min_prob {
            if qi <= 0.0 {
                return Err(KlSurprisalError::NumericalError {
                    details:
                        "Reference distribution has zero probability where observed is nonzero"
                            .to_string(),
                });
            }
            kl += pi * (pi / qi.max(min_prob)).ln();
        }
    }

    if !kl.is_finite() {
        return Err(KlSurprisalError::NumericalError {
            details: "KL computation produced non-finite result".to_string(),
        });
    }

    Ok(kl.max(0.0))
}

/// Compute symmetric KL divergence (Jensen-Shannon-like).
///
/// sym_KL(p, q) = (D_KL(p || q) + D_KL(q || p)) / 2
pub fn symmetric_kl_divergence(p: &[f64], q: &[f64]) -> Result<f64, KlSurprisalError> {
    let kl_pq = kl_divergence_discrete(p, q)?;
    let kl_qp = kl_divergence_discrete(q, p)?;
    Ok((kl_pq + kl_qp) / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = KlSurprisalConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.min_samples, 10);
        assert!((config.smoothing - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = KlSurprisalConfig::default();

        config.smoothing = -1.0;
        assert!(config.validate().is_err());

        config.smoothing = 0.5;
        config.n_eff_factor = 0.0;
        assert!(config.validate().is_err());

        config.n_eff_factor = -1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_analyzer_empty() {
        let analyzer = KlSurprisalAnalyzer::default();
        assert!(analyzer.is_empty());
        assert_eq!(analyzer.len(), 0);
        assert_eq!(analyzer.successes(), 0);
    }

    #[test]
    fn test_insufficient_data() {
        let mut analyzer = KlSurprisalAnalyzer::default();
        for _ in 0..5 {
            analyzer.update_bernoulli(true);
        }

        let result = analyzer.analyze(0.5);
        assert!(matches!(
            result,
            Err(KlSurprisalError::InsufficientData { .. })
        ));
    }

    #[test]
    fn test_invalid_reference_rate() {
        let mut analyzer = KlSurprisalAnalyzer::default();
        for _ in 0..20 {
            analyzer.update_bernoulli(true);
        }

        assert!(analyzer.analyze(0.0).is_err());
        assert!(analyzer.analyze(1.0).is_err());
        assert!(analyzer.analyze(-0.1).is_err());
        assert!(analyzer.analyze(1.1).is_err());
    }

    #[test]
    fn test_kl_divergence_same_distribution() {
        let analyzer = KlSurprisalAnalyzer::default();
        let kl = analyzer.kl_divergence_bernoulli(0.5, 0.5).unwrap();
        assert!(
            kl < 1e-10,
            "KL divergence should be ~0 for identical distributions"
        );
    }

    #[test]
    fn test_kl_divergence_different_distributions() {
        let analyzer = KlSurprisalAnalyzer::default();

        // D_KL(0.8 || 0.5) should be positive
        let kl = analyzer.kl_divergence_bernoulli(0.8, 0.5).unwrap();
        assert!(
            kl > 0.0,
            "KL divergence should be positive for different distributions"
        );

        // Known analytical value:
        // D_KL(0.8 || 0.5) = 0.8 * ln(0.8/0.5) + 0.2 * ln(0.2/0.5)
        //                  = 0.8 * ln(1.6) + 0.2 * ln(0.4)
        //                  ≈ 0.8 * 0.470 + 0.2 * (-0.916)
        //                  ≈ 0.376 - 0.183 ≈ 0.193
        let expected = 0.8 * (0.8_f64 / 0.5).ln() + 0.2 * (0.2_f64 / 0.5).ln();
        assert!(
            (kl - expected).abs() < 0.01,
            "KL divergence mismatch: got {}, expected {}",
            kl,
            expected
        );
    }

    #[test]
    fn test_kl_divergence_asymmetry() {
        let analyzer = KlSurprisalAnalyzer::default();

        let kl_pq = analyzer.kl_divergence_bernoulli(0.8, 0.3).unwrap();
        let kl_qp = analyzer.kl_divergence_bernoulli(0.3, 0.8).unwrap();

        // KL divergence is asymmetric
        assert!(
            (kl_pq - kl_qp).abs() > 0.01,
            "KL divergence should be asymmetric"
        );
    }

    #[test]
    fn test_kl_divergence_non_negative() {
        let analyzer = KlSurprisalAnalyzer::default();

        for p in [0.1, 0.3, 0.5, 0.7, 0.9] {
            for q in [0.1, 0.3, 0.5, 0.7, 0.9] {
                let kl = analyzer.kl_divergence_bernoulli(p, q).unwrap();
                assert!(
                    kl >= 0.0,
                    "KL divergence must be non-negative: p={}, q={}, kl={}",
                    p,
                    q,
                    kl
                );
            }
        }
    }

    #[test]
    fn test_analyze_matching_rate() {
        let mut analyzer = KlSurprisalAnalyzer::default();

        // Observed rate ~50%
        for i in 0..100 {
            analyzer.update_bernoulli(i % 2 == 0);
        }

        let result = analyzer.analyze(0.5).unwrap();
        assert!(
            result.kl_divergence < 0.01,
            "KL should be small when rates match"
        );
        assert!(!result.is_abnormal);
        assert_eq!(result.severity, AbnormalitySeverity::Normal);
    }

    #[test]
    fn test_analyze_high_deviation() {
        let mut analyzer = KlSurprisalAnalyzer::default();

        // Observed rate ~90%
        for _ in 0..90 {
            analyzer.update_bernoulli(true);
        }
        for _ in 0..10 {
            analyzer.update_bernoulli(false);
        }

        // Reference rate 30%
        let result = analyzer.analyze(0.3).unwrap();
        assert!(
            result.kl_divergence > 0.5,
            "KL should be large for significant deviation"
        );
        assert!(result.is_abnormal);
        assert!(result.severity >= AbnormalitySeverity::Moderate);
        assert_eq!(result.direction, DeviationDirection::Higher);
    }

    #[test]
    fn test_analyze_low_deviation() {
        let mut analyzer = KlSurprisalAnalyzer::default();

        // Observed rate ~10%
        for _ in 0..10 {
            analyzer.update_bernoulli(true);
        }
        for _ in 0..90 {
            analyzer.update_bernoulli(false);
        }

        // Reference rate 70%
        let result = analyzer.analyze(0.7).unwrap();
        assert!(result.kl_divergence > 0.5);
        assert_eq!(result.direction, DeviationDirection::Lower);
    }

    #[test]
    fn test_rate_bound_monotonicity() {
        // Larger KL divergence should give smaller (tighter) tail bound
        let mut analyzer1 = KlSurprisalAnalyzer::default();
        let mut analyzer2 = KlSurprisalAnalyzer::default();

        // Analyzer 1: slight deviation (60% vs 50%)
        for i in 0..100 {
            analyzer1.update_bernoulli(i < 60);
        }

        // Analyzer 2: large deviation (90% vs 50%)
        for i in 0..100 {
            analyzer2.update_bernoulli(i < 90);
        }

        let result1 = analyzer1.analyze(0.5).unwrap();
        let result2 = analyzer2.analyze(0.5).unwrap();

        assert!(
            result2.rate_bound < result1.rate_bound,
            "Larger deviation should give smaller tail bound"
        );
        assert!(
            result2.kl_divergence > result1.kl_divergence,
            "Larger deviation should give larger KL divergence"
        );
    }

    #[test]
    fn test_n_eff_factor() {
        let config = KlSurprisalConfig {
            n_eff_factor: 0.5,
            min_samples: 10,
            ..Default::default()
        };
        let mut analyzer = KlSurprisalAnalyzer::new(config);

        for _ in 0..20 {
            analyzer.update_bernoulli(true);
        }

        let result = analyzer.analyze(0.5).unwrap();
        assert!(
            (result.n_eff - 10.0).abs() < 0.1,
            "n_eff should be n * factor = 20 * 0.5 = 10"
        );
    }

    #[test]
    fn test_weighted_observations() {
        let mut analyzer = KlSurprisalAnalyzer::default();

        // High-weight successes
        for _ in 0..5 {
            analyzer.update_weighted(true, 2.0);
        }
        // Low-weight failures
        for _ in 0..5 {
            analyzer.update_weighted(false, 0.5);
        }

        // Effective rate should be biased toward successes
        let result = analyzer.analyze(0.5).unwrap();
        assert!(
            result.observed_rate > 0.7,
            "Weighted rate should favor high-weight successes"
        );
    }

    #[test]
    fn test_batch_analyzer() {
        let mut batch = BatchKlAnalyzer::with_defaults();

        // Two different streams
        for _ in 0..50 {
            batch.update("cpu_busy", true);
            batch.update("io_active", false);
        }

        let cpu_result = batch.analyze("cpu_busy", 0.5).unwrap().unwrap();
        let io_result = batch.analyze("io_active", 0.5).unwrap().unwrap();

        assert!(cpu_result.observed_rate > 0.9);
        assert!(io_result.observed_rate < 0.1);
    }

    #[test]
    fn test_batch_analyzer_nonexistent() {
        let batch = BatchKlAnalyzer::with_defaults();
        assert!(batch.analyze("nonexistent", 0.5).is_none());
    }

    #[test]
    fn test_discrete_kl_divergence() {
        // Uniform vs uniform should be 0
        let p = vec![0.25, 0.25, 0.25, 0.25];
        let q = vec![0.25, 0.25, 0.25, 0.25];
        let kl = kl_divergence_discrete(&p, &q).unwrap();
        assert!(kl < 1e-10);

        // Non-uniform should be positive
        let p = vec![0.5, 0.3, 0.15, 0.05];
        let q = vec![0.25, 0.25, 0.25, 0.25];
        let kl = kl_divergence_discrete(&p, &q).unwrap();
        assert!(kl > 0.0);
    }

    #[test]
    fn test_symmetric_kl() {
        let p = vec![0.6, 0.4];
        let q = vec![0.4, 0.6];

        let sym_kl = symmetric_kl_divergence(&p, &q).unwrap();
        assert!(sym_kl > 0.0);

        // Symmetric KL should be symmetric
        let sym_kl_rev = symmetric_kl_divergence(&q, &p).unwrap();
        assert!((sym_kl - sym_kl_rev).abs() < 1e-10);
    }

    #[test]
    fn test_features_from_result() {
        let mut analyzer = KlSurprisalAnalyzer::default();
        for _ in 0..50 {
            analyzer.update_bernoulli(true);
        }
        for _ in 0..50 {
            analyzer.update_bernoulli(false);
        }

        let result = analyzer.analyze(0.3).unwrap();
        let features = KlSurprisalFeatures::from_result(1234, &result, "cpu_busy");

        assert_eq!(features.pid, 1234);
        assert_eq!(features.signal_type, "cpu_busy");
        assert_eq!(features.n, 100);
        assert!(features.anomaly_score >= 0.0 && features.anomaly_score <= 1.0);
    }

    #[test]
    fn test_severity_from_kl() {
        assert_eq!(
            AbnormalitySeverity::from_kl_divergence(0.05),
            AbnormalitySeverity::Normal
        );
        assert_eq!(
            AbnormalitySeverity::from_kl_divergence(0.2),
            AbnormalitySeverity::Mild
        );
        assert_eq!(
            AbnormalitySeverity::from_kl_divergence(0.5),
            AbnormalitySeverity::Moderate
        );
        assert_eq!(
            AbnormalitySeverity::from_kl_divergence(1.0),
            AbnormalitySeverity::Severe
        );
        assert_eq!(
            AbnormalitySeverity::from_kl_divergence(2.0),
            AbnormalitySeverity::Critical
        );
    }

    #[test]
    fn test_severity_from_tail_bound() {
        assert_eq!(
            AbnormalitySeverity::from_tail_bound(0.5),
            AbnormalitySeverity::Normal
        );
        assert_eq!(
            AbnormalitySeverity::from_tail_bound(0.05),
            AbnormalitySeverity::Mild
        );
        assert_eq!(
            AbnormalitySeverity::from_tail_bound(0.005),
            AbnormalitySeverity::Moderate
        );
        assert_eq!(
            AbnormalitySeverity::from_tail_bound(0.0005),
            AbnormalitySeverity::Severe
        );
        assert_eq!(
            AbnormalitySeverity::from_tail_bound(0.00005),
            AbnormalitySeverity::Critical
        );
    }

    #[test]
    fn test_reset() {
        let mut analyzer = KlSurprisalAnalyzer::default();
        for _ in 0..50 {
            analyzer.update_bernoulli(true);
        }

        assert_eq!(analyzer.len(), 50);
        analyzer.reset();
        assert!(analyzer.is_empty());
        assert_eq!(analyzer.successes(), 0);
    }

    #[test]
    fn test_known_analytic_case() {
        // For p=0.8, q=0.2:
        // D_KL(0.8 || 0.2) = 0.8 * ln(0.8/0.2) + 0.2 * ln(0.2/0.8)
        //                  = 0.8 * ln(4) + 0.2 * ln(0.25)
        //                  = 0.8 * 1.386 + 0.2 * (-1.386)
        //                  = 1.109 - 0.277 = 0.832
        let analyzer = KlSurprisalAnalyzer::default();
        let kl = analyzer.kl_divergence_bernoulli(0.8, 0.2).unwrap();
        let expected = 0.8 * 4.0_f64.ln() + 0.2 * 0.25_f64.ln();

        assert!(
            (kl - expected).abs() < 0.001,
            "KL divergence mismatch: got {:.6}, expected {:.6}",
            kl,
            expected
        );
    }

    #[test]
    fn test_cramers_bound() {
        // For n=100, p_hat=0.8, p=0.5:
        // D_KL(0.8 || 0.5) ≈ 0.193
        // Rate bound = exp(-100 * 0.193) = exp(-19.3) ≈ 4e-9
        let mut analyzer = KlSurprisalAnalyzer::new(KlSurprisalConfig {
            n_eff_factor: 1.0,
            smoothing: 0.0, // No smoothing for exact test
            min_samples: 10,
            ..Default::default()
        });

        for _ in 0..80 {
            analyzer.update_bernoulli(true);
        }
        for _ in 0..20 {
            analyzer.update_bernoulli(false);
        }

        let result = analyzer.analyze(0.5).unwrap();

        // With n=100, KL≈0.193, bound should be very small
        assert!(
            result.rate_bound < 1e-6,
            "Rate bound should be very small: got {}",
            result.rate_bound
        );
    }
}
