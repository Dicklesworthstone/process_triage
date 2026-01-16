//! Context Tree Weighting (CTW) prequential predictor.
//!
//! CTW is a universal sequence predictor that achieves optimal redundancy (regret)
//! against the class of finite-memory (tree) sources. It maintains a weighted
//! mixture of context-tree Markov models, providing:
//!
//! - Prequential log-loss for anomaly detection
//! - Regret vs simple baselines for regime-shift evidence
//! - Code-length gaps (surprisal in bits) for the evidence ledger
//!
//! # Mathematical Foundation
//!
//! For a binary alphabet with context depth D, CTW maintains a complete binary
//! tree of depth D. Each node s has:
//!
//! - Krichevsky-Trofimov (KT) estimator: P_KT(s) for symbols seen in context s
//! - Weighted probability: P_w(s) = 0.5 * P_KT(s) + 0.5 * P_w(s0) * P_w(s1)
//!
//! The KT estimator is the Bayesian sequential estimate with Jeffreys prior:
//! ```text
//! P_KT(x_{n+1} = 1 | a zeros, b ones) = (b + 0.5) / (a + b + 1)
//! ```
//!
//! # Discretization
//!
//! Continuous signals (CPU, I/O) are discretized into finite alphabets:
//! - Binary: idle/busy based on threshold
//! - Ternary: low/medium/high
//! - Quaternary: idle/light/moderate/heavy
//!
//! # Usage
//!
//! ```
//! use pt_core::inference::ctw::{CtwPredictor, CtwConfig, Discretizer, DiscretizerConfig};
//!
//! // Create discretizer for CPU occupancy
//! let disc_config = DiscretizerConfig::binary(0.5); // threshold at 50%
//! let discretizer = Discretizer::new(disc_config);
//!
//! // Create CTW predictor
//! let config = CtwConfig::default();
//! let mut ctw = CtwPredictor::new(config);
//!
//! // Process observations
//! let observations = [0.1, 0.2, 0.8, 0.9, 0.1]; // CPU occupancy values
//! for &obs in &observations {
//!     let symbol = discretizer.discretize(obs);
//!     let result = ctw.update(symbol);
//!     println!("Step {}: log-loss = {:.4}", result.step, result.log_loss);
//! }
//!
//! // Get summary features
//! let features = ctw.features();
//! println!("Total log-loss: {:.4} bits", features.total_logloss_bits);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Errors from CTW predictor.
#[derive(Debug, Error)]
pub enum CtwError {
    #[error("invalid context depth: {0} (must be in 1..12)")]
    InvalidContextDepth(usize),

    #[error("invalid alphabet size: {0} (must be 2, 3, or 4)")]
    InvalidAlphabetSize(usize),

    #[error("invalid threshold: {0}")]
    InvalidThreshold(f64),

    #[error("symbol out of range: {symbol} (alphabet size is {alphabet_size})")]
    SymbolOutOfRange { symbol: usize, alphabet_size: usize },
}

/// Configuration for CTW predictor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtwConfig {
    /// Context depth (tree depth). Higher = more memory, better for complex patterns.
    /// Typically 4-8 for process signals.
    #[serde(default = "default_context_depth")]
    pub context_depth: usize,

    /// Alphabet size: 2 (binary), 3 (ternary), or 4 (quaternary).
    #[serde(default = "default_alphabet_size")]
    pub alphabet_size: usize,

    /// Weighting parameter for KT vs children (0.5 is standard CTW).
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_context_depth() -> usize {
    6
}

fn default_alphabet_size() -> usize {
    2
}

fn default_weight() -> f64 {
    0.5
}

impl Default for CtwConfig {
    fn default() -> Self {
        Self {
            context_depth: default_context_depth(),
            alphabet_size: default_alphabet_size(),
            weight: default_weight(),
        }
    }
}

impl CtwConfig {
    /// Validate configuration.
    pub fn validate(&self) -> Result<(), CtwError> {
        // Limit context depth to 12 to prevent excessive memory usage
        // (4^12 nodes is manageable, 2^32 is not)
        if self.context_depth == 0 || self.context_depth > 12 {
            return Err(CtwError::InvalidContextDepth(self.context_depth));
        }
        if self.alphabet_size < 2 || self.alphabet_size > 4 {
            return Err(CtwError::InvalidAlphabetSize(self.alphabet_size));
        }
        Ok(())
    }

    /// Create config for binary alphabet with given depth.
    pub fn binary(depth: usize) -> Self {
        Self {
            context_depth: depth,
            alphabet_size: 2,
            weight: 0.5,
        }
    }

    /// Create config for ternary alphabet with given depth.
    pub fn ternary(depth: usize) -> Self {
        Self {
            context_depth: depth,
            alphabet_size: 3,
            weight: 0.5,
        }
    }
}

/// Configuration for discretizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscretizerConfig {
    /// Discretization mode.
    pub mode: DiscretizationMode,

    /// Thresholds for discretization (mode-dependent).
    pub thresholds: Vec<f64>,
}

/// Discretization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscretizationMode {
    /// Binary: below/above single threshold
    Binary,
    /// Ternary: low/medium/high with two thresholds
    Ternary,
    /// Quaternary: idle/light/moderate/heavy with three thresholds
    Quaternary,
}

impl DiscretizerConfig {
    /// Create binary discretizer with single threshold.
    pub fn binary(threshold: f64) -> Self {
        Self {
            mode: DiscretizationMode::Binary,
            thresholds: vec![threshold],
        }
    }

    /// Create ternary discretizer with two thresholds.
    pub fn ternary(low_high: f64, high_low: f64) -> Self {
        Self {
            mode: DiscretizationMode::Ternary,
            thresholds: vec![low_high, high_low],
        }
    }

    /// Create quaternary discretizer with three thresholds.
    pub fn quaternary(t1: f64, t2: f64, t3: f64) -> Self {
        Self {
            mode: DiscretizationMode::Quaternary,
            thresholds: vec![t1, t2, t3],
        }
    }

    /// Default binary discretizer for CPU occupancy.
    pub fn cpu_binary() -> Self {
        Self::binary(0.10) // 10% threshold: idle vs active
    }

    /// Default ternary discretizer for CPU occupancy.
    pub fn cpu_ternary() -> Self {
        Self::ternary(0.10, 0.50) // idle < 10% < active < 50% < busy
    }

    /// Default quaternary discretizer for CPU occupancy.
    pub fn cpu_quaternary() -> Self {
        Self::quaternary(0.05, 0.20, 0.60) // idle < 5% < light < 20% < moderate < 60% < heavy
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), CtwError> {
        let required_thresholds = match self.mode {
            DiscretizationMode::Binary => 1,
            DiscretizationMode::Ternary => 2,
            DiscretizationMode::Quaternary => 3,
        };

        if self.thresholds.len() != required_thresholds {
            return Err(CtwError::InvalidThreshold(self.thresholds.len() as f64));
        }

        for (i, &t) in self.thresholds.iter().enumerate() {
            if !t.is_finite() {
                return Err(CtwError::InvalidThreshold(t));
            }
            // Check monotonicity
            if i > 0 && t <= self.thresholds[i - 1] {
                return Err(CtwError::InvalidThreshold(t));
            }
        }

        Ok(())
    }

    /// Get the alphabet size for this mode.
    pub fn alphabet_size(&self) -> usize {
        match self.mode {
            DiscretizationMode::Binary => 2,
            DiscretizationMode::Ternary => 3,
            DiscretizationMode::Quaternary => 4,
        }
    }
}

/// Discretizer converts continuous values to discrete symbols.
#[derive(Debug, Clone)]
pub struct Discretizer {
    config: DiscretizerConfig,
}

impl Discretizer {
    /// Create a new discretizer.
    pub fn new(config: DiscretizerConfig) -> Self {
        Self { config }
    }

    /// Get the alphabet size.
    pub fn alphabet_size(&self) -> usize {
        self.config.alphabet_size()
    }

    /// Discretize a continuous value to a symbol.
    pub fn discretize(&self, value: f64) -> usize {
        match self.config.mode {
            DiscretizationMode::Binary => {
                if value < self.config.thresholds[0] {
                    0
                } else {
                    1
                }
            }
            DiscretizationMode::Ternary => {
                if value < self.config.thresholds[0] {
                    0
                } else if value < self.config.thresholds[1] {
                    1
                } else {
                    2
                }
            }
            DiscretizationMode::Quaternary => {
                if value < self.config.thresholds[0] {
                    0
                } else if value < self.config.thresholds[1] {
                    1
                } else if value < self.config.thresholds[2] {
                    2
                } else {
                    3
                }
            }
        }
    }

    /// Get the symbol label for a given symbol.
    pub fn symbol_label(&self, symbol: usize) -> &'static str {
        match self.config.mode {
            DiscretizationMode::Binary => match symbol {
                0 => "idle",
                _ => "busy",
            },
            DiscretizationMode::Ternary => match symbol {
                0 => "low",
                1 => "medium",
                _ => "high",
            },
            DiscretizationMode::Quaternary => match symbol {
                0 => "idle",
                1 => "light",
                2 => "moderate",
                _ => "heavy",
            },
        }
    }
}

/// Krichevsky-Trofimov estimator for sequential probability assignment.
///
/// For an alphabet of size k, maintains counts for each symbol and computes
/// the predictive probability using Jeffreys prior (1/2k for each symbol).
#[derive(Debug, Clone)]
struct KtEstimator {
    /// Symbol counts.
    counts: Vec<u64>,
    /// Total count.
    total: u64,
    /// Alphabet size.
    alphabet_size: usize,
}

impl KtEstimator {
    fn new(alphabet_size: usize) -> Self {
        Self {
            counts: vec![0; alphabet_size],
            total: 0,
            alphabet_size,
        }
    }

    /// Predictive probability P(symbol | history).
    /// Uses KT estimator: (count + 0.5) / (total + k/2)
    fn predict(&self, symbol: usize) -> f64 {
        let count = self.counts.get(symbol).copied().unwrap_or(0) as f64;
        let pseudo_count = 0.5; // Jeffreys prior
        let total_pseudo = self.alphabet_size as f64 * 0.5;
        (count + pseudo_count) / (self.total as f64 + total_pseudo)
    }

    /// Log predictive probability.
    fn log_predict(&self, symbol: usize) -> f64 {
        self.predict(symbol).ln()
    }

    /// Update with observed symbol.
    fn update(&mut self, symbol: usize) {
        if symbol < self.alphabet_size {
            self.counts[symbol] += 1;
            self.total += 1;
        }
    }
}

/// Node in the context tree.
#[derive(Debug, Clone)]
struct CtwNode {
    /// KT estimator for this context.
    kt: KtEstimator,
    /// Children nodes (indexed by symbol).
    children: Vec<Option<Box<CtwNode>>>,
}

impl CtwNode {
    fn new(alphabet_size: usize) -> Self {
        Self {
            kt: KtEstimator::new(alphabet_size),
            children: vec![None; alphabet_size],
        }
    }

    /// Get or create child node for symbol.
    fn get_or_create_child(&mut self, symbol: usize, alphabet_size: usize) -> &mut CtwNode {
        if self.children[symbol].is_none() {
            self.children[symbol] = Some(Box::new(CtwNode::new(alphabet_size)));
        }
        self.children[symbol].as_mut().unwrap()
    }

    /// Check if child exists (for future tree statistics).
    #[allow(dead_code)]
    fn has_child(&self, symbol: usize) -> bool {
        self.children
            .get(symbol)
            .map(|c| c.is_some())
            .unwrap_or(false)
    }

    /// Get child reference.
    fn child(&self, symbol: usize) -> Option<&CtwNode> {
        self.children
            .get(symbol)
            .and_then(|c| c.as_ref().map(|b| b.as_ref()))
    }

    /// Get mutable child reference (for future tree pruning).
    #[allow(dead_code)]
    fn child_mut(&mut self, symbol: usize) -> Option<&mut CtwNode> {
        self.children
            .get_mut(symbol)
            .and_then(|c| c.as_mut().map(|b| b.as_mut()))
    }
}

/// CTW predictor maintaining a context tree.
pub struct CtwPredictor {
    config: CtwConfig,
    /// Root of the context tree.
    root: CtwNode,
    /// Current context (most recent symbols).
    context: VecDeque<usize>,
    /// Step counter.
    step: usize,
    /// Cumulative log-loss.
    cum_log_loss: f64,
    /// Cumulative log-loss for baseline predictor (marginal frequencies).
    baseline_cum_log_loss: f64,
    /// Marginal symbol counts for baseline.
    marginal_counts: Vec<u64>,
    /// Total symbols seen.
    total_symbols: u64,
}

impl CtwPredictor {
    /// Create a new CTW predictor.
    pub fn new(config: CtwConfig) -> Self {
        let alphabet_size = config.alphabet_size;
        Self {
            config,
            root: CtwNode::new(alphabet_size),
            context: VecDeque::new(),
            step: 0,
            cum_log_loss: 0.0,
            baseline_cum_log_loss: 0.0,
            marginal_counts: vec![0; alphabet_size],
            total_symbols: 0,
        }
    }

    /// Create with default configuration.
    pub fn default_predictor() -> Self {
        Self::new(CtwConfig::default())
    }

    /// Reset the predictor.
    pub fn reset(&mut self) {
        let alphabet_size = self.config.alphabet_size;
        self.root = CtwNode::new(alphabet_size);
        self.context.clear();
        self.step = 0;
        self.cum_log_loss = 0.0;
        self.baseline_cum_log_loss = 0.0;
        self.marginal_counts = vec![0; alphabet_size];
        self.total_symbols = 0;
    }

    /// Get configuration.
    pub fn config(&self) -> &CtwConfig {
        &self.config
    }

    /// Compute log weighted probability for a symbol using CTW.
    ///
    /// This traverses the context tree from the current context to the root,
    /// combining KT estimates at each level.
    fn log_weighted_prob(&self, symbol: usize) -> f64 {
        let weight = self.config.weight;
        let log_weight = weight.ln();
        let log_1_minus_weight = (1.0 - weight).ln();

        // Build path from root to context
        let mut path: Vec<usize> = Vec::with_capacity(self.context.len());
        for &s in self.context.iter().rev().take(self.config.context_depth) {
            path.push(s);
        }

        // Traverse from deepest context back to root
        self.log_weighted_prob_recursive(
            &self.root,
            &path,
            0,
            symbol,
            log_weight,
            log_1_minus_weight,
        )
    }

    /// Recursive helper for log weighted probability.
    fn log_weighted_prob_recursive(
        &self,
        node: &CtwNode,
        path: &[usize],
        depth: usize,
        symbol: usize,
        log_weight: f64,
        log_1_minus_weight: f64,
    ) -> f64 {
        let log_kt = node.kt.log_predict(symbol);

        // At max depth or no more context, use KT directly
        if depth >= self.config.context_depth || depth >= path.len() {
            return log_kt;
        }

        // Get child for next context symbol
        let next_symbol = path[depth];
        if let Some(child) = node.child(next_symbol) {
            let log_child = self.log_weighted_prob_recursive(
                child,
                path,
                depth + 1,
                symbol,
                log_weight,
                log_1_minus_weight,
            );

            // CTW weighting: 0.5 * P_kt + 0.5 * P_child (in log space)
            log_sum_exp_pair(log_weight + log_kt, log_1_minus_weight + log_child)
        } else {
            // No child exists, use KT only
            log_kt
        }
    }

    /// Update the context tree with an observed symbol.
    fn update_tree(&mut self, symbol: usize) {
        let depth = self.config.context_depth;
        let alphabet_size = self.config.alphabet_size;

        // Build context path
        let mut path: Vec<usize> = Vec::with_capacity(self.context.len());
        for &s in self.context.iter().rev().take(depth) {
            path.push(s);
        }

        // Update nodes along path using static method to avoid borrow issues
        Self::update_node_recursive(&mut self.root, &path, 0, symbol, alphabet_size, depth);
    }

    /// Static recursive helper to update tree nodes.
    fn update_node_recursive(
        node: &mut CtwNode,
        path: &[usize],
        depth: usize,
        symbol: usize,
        alphabet_size: usize,
        max_depth: usize,
    ) {
        // Update KT estimator at this node
        node.kt.update(symbol);

        // Continue down the path if not at max depth
        if depth < max_depth && depth < path.len() {
            let next_symbol = path[depth];
            let child = node.get_or_create_child(next_symbol, alphabet_size);
            Self::update_node_recursive(child, path, depth + 1, symbol, alphabet_size, max_depth);
        }
    }

    /// Compute baseline (marginal) log probability.
    fn baseline_log_prob(&self, symbol: usize) -> f64 {
        let count = self.marginal_counts.get(symbol).copied().unwrap_or(0) as f64;
        let pseudo = 0.5;
        let total_pseudo = self.config.alphabet_size as f64 * 0.5;
        let prob = (count + pseudo) / (self.total_symbols as f64 + total_pseudo);
        prob.ln()
    }

    /// Update with a new symbol and return result.
    pub fn update(&mut self, symbol: usize) -> CtwUpdateResult {
        // Compute predictive probability before update
        let log_prob = self.log_weighted_prob(symbol);
        let log_loss = -log_prob;
        let log_loss_bits = log_loss / std::f64::consts::LN_2;

        // Baseline prediction
        let baseline_log_prob = self.baseline_log_prob(symbol);
        let baseline_log_loss = -baseline_log_prob;

        // Update cumulative losses
        self.cum_log_loss += log_loss;
        self.baseline_cum_log_loss += baseline_log_loss;

        // Update tree
        self.update_tree(symbol);

        // Update context
        self.context.push_back(symbol);
        if self.context.len() > self.config.context_depth {
            self.context.pop_front();
        }

        // Update marginal counts
        if symbol < self.config.alphabet_size {
            self.marginal_counts[symbol] += 1;
        }
        self.total_symbols += 1;

        self.step += 1;

        // Compute regret (excess loss over baseline)
        let regret = self.cum_log_loss - self.baseline_cum_log_loss;
        let regret_bits = regret / std::f64::consts::LN_2;

        CtwUpdateResult {
            step: self.step - 1,
            symbol,
            log_prob,
            log_loss,
            log_loss_bits,
            cumulative_log_loss: self.cum_log_loss,
            cumulative_log_loss_bits: self.cum_log_loss / std::f64::consts::LN_2,
            regret,
            regret_bits,
        }
    }

    /// Process a batch of symbols.
    pub fn process_batch(&mut self, symbols: &[usize]) -> CtwBatchResult {
        let mut results = Vec::with_capacity(symbols.len());

        for &symbol in symbols {
            results.push(self.update(symbol));
        }

        let final_log_loss = self.cum_log_loss;
        let final_regret = self.cum_log_loss - self.baseline_cum_log_loss;

        CtwBatchResult {
            results,
            total_log_loss: final_log_loss,
            total_log_loss_bits: final_log_loss / std::f64::consts::LN_2,
            total_regret: final_regret,
            total_regret_bits: final_regret / std::f64::consts::LN_2,
            step_count: self.step,
        }
    }

    /// Get current feature summary.
    pub fn features(&self) -> CtwFeatures {
        let total_logloss = self.cum_log_loss;
        let total_logloss_bits = total_logloss / std::f64::consts::LN_2;
        let baseline_logloss = self.baseline_cum_log_loss;
        let baseline_logloss_bits = baseline_logloss / std::f64::consts::LN_2;
        let regret = total_logloss - baseline_logloss;
        let regret_bits = regret / std::f64::consts::LN_2;

        // Average log-loss per symbol
        let avg_logloss = if self.step > 0 {
            total_logloss / self.step as f64
        } else {
            0.0
        };
        let avg_logloss_bits = avg_logloss / std::f64::consts::LN_2;

        // Normalized regret (per symbol)
        let normalized_regret = if self.step > 0 {
            regret / self.step as f64
        } else {
            0.0
        };
        let normalized_regret_bits = normalized_regret / std::f64::consts::LN_2;

        CtwFeatures {
            total_logloss,
            total_logloss_bits,
            baseline_logloss,
            baseline_logloss_bits,
            regret,
            regret_bits,
            avg_logloss,
            avg_logloss_bits,
            normalized_regret,
            normalized_regret_bits,
            step_count: self.step,
            provenance: CtwProvenance {
                context_depth: self.config.context_depth,
                alphabet_size: self.config.alphabet_size,
                weight: self.config.weight,
            },
        }
    }

    /// Get the current context as a slice.
    pub fn current_context(&self) -> Vec<usize> {
        self.context.iter().copied().collect()
    }

    /// Get step count.
    pub fn step_count(&self) -> usize {
        self.step
    }
}

/// Result of a single CTW update.
#[derive(Debug, Clone, Serialize)]
pub struct CtwUpdateResult {
    /// Step number (0-indexed).
    pub step: usize,
    /// Symbol that was observed.
    pub symbol: usize,
    /// Log probability assigned to the symbol before update.
    pub log_prob: f64,
    /// Log-loss for this step (-log_prob).
    pub log_loss: f64,
    /// Log-loss in bits.
    pub log_loss_bits: f64,
    /// Cumulative log-loss so far.
    pub cumulative_log_loss: f64,
    /// Cumulative log-loss in bits.
    pub cumulative_log_loss_bits: f64,
    /// Regret vs baseline (cumulative).
    pub regret: f64,
    /// Regret in bits.
    pub regret_bits: f64,
}

/// Result of batch processing.
#[derive(Debug, Clone, Serialize)]
pub struct CtwBatchResult {
    /// Per-step results.
    pub results: Vec<CtwUpdateResult>,
    /// Total log-loss.
    pub total_log_loss: f64,
    /// Total log-loss in bits.
    pub total_log_loss_bits: f64,
    /// Total regret vs baseline.
    pub total_regret: f64,
    /// Total regret in bits.
    pub total_regret_bits: f64,
    /// Number of steps processed.
    pub step_count: usize,
}

/// CTW feature summary for the evidence ledger.
#[derive(Debug, Clone, Serialize)]
pub struct CtwFeatures {
    /// Total prequential log-loss (nats).
    pub total_logloss: f64,
    /// Total prequential log-loss (bits).
    pub total_logloss_bits: f64,
    /// Baseline (marginal) log-loss (nats).
    pub baseline_logloss: f64,
    /// Baseline log-loss (bits).
    pub baseline_logloss_bits: f64,
    /// Regret = CTW loss - baseline loss (nats).
    pub regret: f64,
    /// Regret in bits.
    pub regret_bits: f64,
    /// Average log-loss per symbol (nats).
    pub avg_logloss: f64,
    /// Average log-loss per symbol (bits).
    pub avg_logloss_bits: f64,
    /// Normalized regret per symbol (nats).
    pub normalized_regret: f64,
    /// Normalized regret per symbol (bits).
    pub normalized_regret_bits: f64,
    /// Number of symbols processed.
    pub step_count: usize,
    /// Provenance metadata.
    pub provenance: CtwProvenance,
}

/// Provenance for CTW features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtwProvenance {
    /// Context depth used.
    pub context_depth: usize,
    /// Alphabet size.
    pub alphabet_size: usize,
    /// CTW weighting parameter.
    pub weight: f64,
}

/// Evidence for the inference core from CTW.
#[derive(Debug, Clone, Serialize)]
pub struct CtwEvidence {
    /// Average log-loss per symbol (lower = more predictable).
    pub avg_logloss_bits: f64,
    /// Normalized regret (positive = harder than baseline to predict).
    pub normalized_regret_bits: f64,
    /// Is behavior highly predictable? (low log-loss)
    pub is_predictable: bool,
    /// Is behavior anomalous? (high regret)
    pub is_anomalous: bool,
    /// Confidence in the assessment.
    pub confidence: f64,
    /// Number of observations.
    pub observation_count: usize,
}

impl CtwEvidence {
    /// Create evidence from CTW features.
    ///
    /// # Arguments
    /// * `features` - CTW features
    /// * `predictable_threshold` - Average bits below which behavior is predictable
    /// * `anomaly_threshold` - Regret bits above which behavior is anomalous
    pub fn from_features(
        features: &CtwFeatures,
        predictable_threshold: f64,
        anomaly_threshold: f64,
    ) -> Self {
        let is_predictable = features.avg_logloss_bits < predictable_threshold;
        let is_anomalous = features.normalized_regret_bits > anomaly_threshold;

        // Confidence increases with more observations
        let confidence = if features.step_count == 0 {
            0.0
        } else {
            (1.0 - 1.0 / (features.step_count as f64 + 1.0)).min(0.95)
        };

        CtwEvidence {
            avg_logloss_bits: features.avg_logloss_bits,
            normalized_regret_bits: features.normalized_regret_bits,
            is_predictable,
            is_anomalous,
            confidence,
            observation_count: features.step_count,
        }
    }

    /// Create with default thresholds.
    pub fn from_features_default(features: &CtwFeatures) -> Self {
        Self::from_features(
            features, 0.5, // Less than 0.5 bits per symbol is predictable
            0.1, // More than 0.1 bits regret per symbol is anomalous
        )
    }
}

// Helper functions

/// Log-sum-exp for two values: log(exp(a) + exp(b)).
fn log_sum_exp_pair(a: f64, b: f64) -> f64 {
    if a > b {
        a + (1.0 + (b - a).exp()).ln()
    } else {
        b + (1.0 + (a - b).exp()).ln()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_config_validation() {
        let valid = CtwConfig::default();
        assert!(valid.validate().is_ok());

        let invalid_depth = CtwConfig {
            context_depth: 0,
            ..Default::default()
        };
        assert!(invalid_depth.validate().is_err());

        let invalid_alphabet = CtwConfig {
            alphabet_size: 1,
            ..Default::default()
        };
        assert!(invalid_alphabet.validate().is_err());
    }

    #[test]
    fn test_discretizer_binary() {
        let disc = Discretizer::new(DiscretizerConfig::binary(0.5));
        assert_eq!(disc.discretize(0.0), 0);
        assert_eq!(disc.discretize(0.49), 0);
        assert_eq!(disc.discretize(0.5), 1);
        assert_eq!(disc.discretize(1.0), 1);
        assert_eq!(disc.alphabet_size(), 2);
    }

    #[test]
    fn test_discretizer_ternary() {
        let disc = Discretizer::new(DiscretizerConfig::ternary(0.3, 0.7));
        assert_eq!(disc.discretize(0.0), 0);
        assert_eq!(disc.discretize(0.3), 1);
        assert_eq!(disc.discretize(0.5), 1);
        assert_eq!(disc.discretize(0.7), 2);
        assert_eq!(disc.discretize(1.0), 2);
        assert_eq!(disc.alphabet_size(), 3);
    }

    #[test]
    fn test_discretizer_quaternary() {
        let disc = Discretizer::new(DiscretizerConfig::quaternary(0.25, 0.5, 0.75));
        assert_eq!(disc.discretize(0.0), 0);
        assert_eq!(disc.discretize(0.25), 1);
        assert_eq!(disc.discretize(0.5), 2);
        assert_eq!(disc.discretize(0.75), 3);
        assert_eq!(disc.alphabet_size(), 4);
    }

    #[test]
    fn test_kt_estimator() {
        let mut kt = KtEstimator::new(2);

        // Initial prediction with Jeffreys prior: 0.5 / 1.0 = 0.5
        assert!(approx_eq(kt.predict(0), 0.5, 1e-10));
        assert!(approx_eq(kt.predict(1), 0.5, 1e-10));

        // After seeing symbol 0: (1 + 0.5) / (1 + 1.0) = 0.75 for 0, 0.25 for 1
        kt.update(0);
        assert!(approx_eq(kt.predict(0), 0.75, 1e-10));
        assert!(approx_eq(kt.predict(1), 0.25, 1e-10));

        // After seeing symbol 0 again: (2 + 0.5) / (2 + 1.0) = 0.833... for 0
        kt.update(0);
        assert!(approx_eq(kt.predict(0), 2.5 / 3.0, 1e-10));
    }

    #[test]
    fn test_ctw_basic_update() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // First symbol: CTW assigns probability via KT
        let result = ctw.update(0);
        assert_eq!(result.step, 0);
        assert_eq!(result.symbol, 0);
        assert!(result.log_loss >= 0.0); // Log-loss is always non-negative
        assert!(result.log_prob <= 0.0); // Log probability is always <= 0

        // Second symbol
        let result2 = ctw.update(1);
        assert_eq!(result2.step, 1);
        assert!(result2.cumulative_log_loss > result.cumulative_log_loss);
    }

    #[test]
    fn test_ctw_predictable_sequence() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // Feed a predictable sequence: all zeros
        let sequence = vec![0; 20];
        let batch = ctw.process_batch(&sequence);

        // After many zeros, predicting zero should have low log-loss
        let last = batch.results.last().unwrap();
        assert!(
            last.log_loss_bits < 0.5,
            "Predictable sequence should have low log-loss"
        );

        let features = ctw.features();
        assert!(features.avg_logloss_bits < 0.5);
    }

    #[test]
    fn test_ctw_alternating_sequence() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // Feed an alternating sequence: 0, 1, 0, 1, ...
        // CTW should learn this pattern
        let sequence: Vec<usize> = (0..20).map(|i| i % 2).collect();
        let batch = ctw.process_batch(&sequence);

        // After learning the pattern, log-loss should decrease
        let early_loss = batch.results[5].log_loss_bits;
        let late_loss = batch.results[19].log_loss_bits;

        // Late predictions should be better (lower loss) than early ones
        assert!(
            late_loss < early_loss + 0.5,
            "CTW should learn alternating pattern, early={} late={}",
            early_loss,
            late_loss
        );
    }

    #[test]
    fn test_ctw_regret() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // A sequence with changing regime
        let sequence: Vec<usize> = (0..20).map(|i| if i < 10 { 0 } else { 1 }).collect();
        let _ = ctw.process_batch(&sequence);

        let features = ctw.features();

        // Regret should be finite
        assert!(features.regret_bits.is_finite(), "Regret should be finite");
    }

    #[test]
    fn test_ctw_reset() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        ctw.update(0);
        ctw.update(1);
        assert_eq!(ctw.step_count(), 2);

        ctw.reset();
        assert_eq!(ctw.step_count(), 0);
        assert!(ctw.current_context().is_empty());
    }

    #[test]
    fn test_ctw_features() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // Process some symbols
        for _ in 0..10 {
            ctw.update(0);
        }

        let features = ctw.features();

        assert_eq!(features.step_count, 10);
        assert!(features.total_logloss >= 0.0);
        assert!(features.total_logloss_bits >= 0.0);
        assert_eq!(features.provenance.context_depth, 4);
        assert_eq!(features.provenance.alphabet_size, 2);
    }

    #[test]
    fn test_ctw_evidence() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // Predictable sequence
        for _ in 0..20 {
            ctw.update(0);
        }

        let features = ctw.features();
        let evidence = CtwEvidence::from_features_default(&features);

        assert!(
            evidence.is_predictable,
            "Constant sequence should be predictable"
        );
        assert!(evidence.confidence > 0.0);
        assert_eq!(evidence.observation_count, 20);
    }

    #[test]
    fn test_ctw_evidence_anomalous() {
        let config = CtwConfig::binary(4);
        let mut ctw = CtwPredictor::new(config);

        // Unpredictable sequence (random-ish)
        let sequence = [0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0];
        for &s in &sequence {
            ctw.update(s);
        }

        let features = ctw.features();
        let evidence = CtwEvidence::from_features(&features, 0.3, 0.0);

        // Random sequence should not be highly predictable
        assert!(!evidence.is_predictable || evidence.avg_logloss_bits > 0.3);
    }

    #[test]
    fn test_log_sum_exp_pair() {
        // log(exp(0) + exp(0)) = log(2)
        assert!(approx_eq(log_sum_exp_pair(0.0, 0.0), 2.0_f64.ln(), 1e-10));

        // log(exp(-1000) + exp(-1000)) = -1000 + log(2)
        assert!(approx_eq(
            log_sum_exp_pair(-1000.0, -1000.0),
            -1000.0 + 2.0_f64.ln(),
            1e-10
        ));

        // log(exp(0) + exp(-inf)) ≈ 0
        assert!(approx_eq(
            log_sum_exp_pair(0.0, f64::NEG_INFINITY),
            0.0,
            1e-10
        ));
    }

    #[test]
    fn test_discretizer_cpu_presets() {
        let binary = Discretizer::new(DiscretizerConfig::cpu_binary());
        assert_eq!(binary.alphabet_size(), 2);
        assert_eq!(binary.discretize(0.05), 0); // idle
        assert_eq!(binary.discretize(0.20), 1); // active

        let ternary = Discretizer::new(DiscretizerConfig::cpu_ternary());
        assert_eq!(ternary.alphabet_size(), 3);
        assert_eq!(ternary.discretize(0.05), 0); // idle
        assert_eq!(ternary.discretize(0.30), 1); // active
        assert_eq!(ternary.discretize(0.80), 2); // busy
    }

    #[test]
    fn test_symbol_labels() {
        let binary = Discretizer::new(DiscretizerConfig::cpu_binary());
        assert_eq!(binary.symbol_label(0), "idle");
        assert_eq!(binary.symbol_label(1), "busy");

        let ternary = Discretizer::new(DiscretizerConfig::cpu_ternary());
        assert_eq!(ternary.symbol_label(0), "low");
        assert_eq!(ternary.symbol_label(1), "medium");
        assert_eq!(ternary.symbol_label(2), "high");
    }

    #[test]
    fn test_ternary_ctw() {
        let config = CtwConfig::ternary(4);
        let mut ctw = CtwPredictor::new(config);

        // Sequence with three symbols
        let sequence = [0, 1, 2, 0, 1, 2, 0, 1, 2, 0];
        let batch = ctw.process_batch(&sequence);

        assert_eq!(batch.step_count, 10);
        assert!(batch.total_log_loss > 0.0);
    }

    #[test]
    fn test_discretizer_config_validation() {
        let valid = DiscretizerConfig::binary(0.5);
        assert!(valid.validate().is_ok());

        let valid_ternary = DiscretizerConfig::ternary(0.3, 0.7);
        assert!(valid_ternary.validate().is_ok());

        // Invalid: non-monotonic thresholds
        let invalid = DiscretizerConfig {
            mode: DiscretizationMode::Ternary,
            thresholds: vec![0.7, 0.3], // Wrong order
        };
        assert!(invalid.validate().is_err());
    }
}
