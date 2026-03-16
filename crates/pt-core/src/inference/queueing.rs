//! Queueing-theoretic stall detection for the Useful-Bad class.
//!
//! Applies M/M/1 queueing theory to socket queue sizes to detect processes
//! that are effectively stalled or deadlocked: the service rate (mu) has
//! dropped below the arrival rate (lambda).
//!
//! # Model
//!
//! We model each process's network I/O as an M/M/1 queue:
//! - **lambda** (arrival rate): rate at which data arrives in rx/tx queues
//! - **mu** (service rate): rate at which the process drains queues
//!
//! When `rho = lambda / mu >= 1`, the queue is unstable and grows without
//! bound — a hallmark of a stalled or deadlocked process.
//!
//! # EWMA Estimation
//!
//! Since we sample queue depths at discrete intervals, we use EWMA
//! (Exponentially Weighted Moving Average) to estimate the smoothed queue
//! depth trend. A rising trend with high absolute depth signals stall.
//!
//! # Stall Probability
//!
//! For an M/M/1 queue in steady state: `P(N >= L) = rho^L`.
//! When mu → 0, this probability approaches 1.

use serde::{Deserialize, Serialize};

/// Configuration for the queueing stall detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStallConfig {
    /// EWMA smoothing factor in (0, 1]. Smaller = smoother / slower response.
    /// Default: 0.3
    pub alpha: f64,
    /// Queue depth threshold (bytes) above which a socket is considered
    /// potentially saturated. Default: 4096
    pub saturation_threshold: u32,
    /// Minimum number of samples before the detector emits a stall signal.
    /// Default: 2
    pub min_samples: usize,
    /// Rho threshold above which a queue is declared stalled.
    /// Default: 0.9
    pub rho_threshold: f64,
    /// Queue length parameter L for the M/M/1 probability P(N > L) = rho^L.
    /// This is an abstract queue-length unit (not bytes). Kept small so the
    /// probability remains informative. Default: 8
    pub probability_queue_length: u32,
}

impl Default for QueueStallConfig {
    fn default() -> Self {
        Self {
            alpha: 0.3,
            saturation_threshold: 4096,
            min_samples: 2,
            rho_threshold: 0.9,
            probability_queue_length: 8,
        }
    }
}

/// EWMA estimator for queue depth time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EwmaEstimator {
    /// Current smoothed value.
    value: f64,
    /// Smoothing factor.
    alpha: f64,
    /// Number of samples observed.
    count: usize,
}

impl EwmaEstimator {
    /// Create a new EWMA estimator with the given smoothing factor.
    ///
    /// # Panics
    /// Panics if alpha is not in (0, 1].
    pub fn new(alpha: f64) -> Self {
        assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0, 1]");
        Self {
            value: 0.0,
            alpha,
            count: 0,
        }
    }

    /// Feed a new observation into the estimator.
    pub fn update(&mut self, observation: f64) {
        if self.count == 0 {
            self.value = observation;
        } else {
            self.value = self.alpha * observation + (1.0 - self.alpha) * self.value;
        }
        self.count += 1;
    }

    /// Current smoothed estimate.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Number of samples observed.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether enough samples have been collected for a reliable estimate.
    pub fn is_ready(&self, min_samples: usize) -> bool {
        self.count >= min_samples
    }
}

/// Per-process queueing stall detector state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStallDetector {
    config: QueueStallConfig,
    /// EWMA of total rx_queue depth across all sockets.
    rx_ewma: EwmaEstimator,
    /// EWMA of total tx_queue depth across all sockets.
    tx_ewma: EwmaEstimator,
    /// Previous total rx_queue (for delta / service rate estimation).
    prev_rx_total: Option<u64>,
    /// Previous total tx_queue.
    prev_tx_total: Option<u64>,
    /// EWMA of queue depth deltas (positive = growing, negative = draining).
    delta_ewma: EwmaEstimator,
}

impl QueueStallDetector {
    /// Create a new detector with default config.
    pub fn new() -> Self {
        Self::with_config(QueueStallConfig::default())
    }

    /// Create a new detector with custom config.
    pub fn with_config(config: QueueStallConfig) -> Self {
        let alpha = config.alpha;
        Self {
            config,
            rx_ewma: EwmaEstimator::new(alpha),
            tx_ewma: EwmaEstimator::new(alpha),
            prev_rx_total: None,
            prev_tx_total: None,
            delta_ewma: EwmaEstimator::new(alpha),
        }
    }

    /// Feed a new queue depth observation and return stall analysis.
    pub fn observe(&mut self, total_rx: u64, total_tx: u64) -> QueueStallResult {
        let rx_f = total_rx as f64;
        let tx_f = total_tx as f64;

        self.rx_ewma.update(rx_f);
        self.tx_ewma.update(tx_f);

        // Compute queue depth delta (positive = growing).
        let delta = if let Some(prev_rx) = self.prev_rx_total {
            let prev_total = prev_rx + self.prev_tx_total.unwrap_or(0);
            let curr_total = total_rx + total_tx;
            curr_total as f64 - prev_total as f64
        } else {
            0.0
        };
        self.delta_ewma.update(delta);

        self.prev_rx_total = Some(total_rx);
        self.prev_tx_total = Some(total_tx);

        let smoothed_depth = self.rx_ewma.value() + self.tx_ewma.value();
        let smoothed_delta = self.delta_ewma.value();
        let sample_count = self.rx_ewma.count();

        // Estimate rho from queue dynamics:
        // If queue is growing (delta > 0) and depth is high, rho > 1.
        // Use a sigmoid mapping: rho = sigmoid(depth / threshold + delta_sign).
        let rho = estimate_rho(
            smoothed_depth,
            smoothed_delta,
            self.config.saturation_threshold as f64,
        );

        let threshold = u64::from(self.config.saturation_threshold);
        let is_saturated = total_rx > threshold || total_tx > threshold;

        // Use max of the two smoothed depths (not sum) for stall check,
        // matching is_saturated semantics: either queue individually deep.
        let max_smoothed = self.rx_ewma.value().max(self.tx_ewma.value());
        let is_stalled = sample_count >= self.config.min_samples
            && rho >= self.config.rho_threshold
            && max_smoothed > self.config.saturation_threshold as f64;

        // M/M/1 steady-state: P(N >= L) = rho^L.
        // L is an abstract queue-length parameter (not bytes) kept small
        // so the probability remains informative.
        let l = self.config.probability_queue_length.min(1024);
        let stall_probability = if rho < 1.0 && l > 0 {
            rho.powi(l as i32)
        } else if rho >= 1.0 {
            1.0
        } else {
            0.0
        };

        QueueStallResult {
            smoothed_rx_depth: self.rx_ewma.value(),
            smoothed_tx_depth: self.tx_ewma.value(),
            smoothed_delta,
            rho,
            is_saturated,
            is_stalled,
            stall_probability,
            sample_count,
        }
    }
}

impl Default for QueueStallDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single queue stall observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStallResult {
    /// EWMA-smoothed receive queue depth.
    pub smoothed_rx_depth: f64,
    /// EWMA-smoothed transmit queue depth.
    pub smoothed_tx_depth: f64,
    /// EWMA-smoothed delta (positive = queue growing).
    pub smoothed_delta: f64,
    /// Estimated traffic intensity rho = lambda / mu.
    pub rho: f64,
    /// Whether any individual socket exceeds the saturation threshold.
    pub is_saturated: bool,
    /// Whether the detector declares a stall (high rho + deep queue + enough samples).
    pub is_stalled: bool,
    /// M/M/1 steady-state probability P(N >= L).
    pub stall_probability: f64,
    /// Number of observations processed.
    pub sample_count: usize,
}

/// Estimate traffic intensity rho from smoothed queue depth and growth rate.
///
/// Uses a logistic mapping: depth well above the threshold with positive
/// growth drives rho toward 1.0; depth near zero drives rho toward 0.0.
fn estimate_rho(smoothed_depth: f64, smoothed_delta: f64, threshold: f64) -> f64 {
    if threshold <= 0.0 {
        return 0.0;
    }
    // Normalize depth to threshold and add growth signal.
    let x = (smoothed_depth / threshold) + (smoothed_delta / threshold).clamp(-2.0, 2.0);
    // Logistic sigmoid: 1 / (1 + exp(-k*(x - midpoint)))
    // k=3.0 gives a reasonable transition curve; midpoint at 1.0 means
    // rho ≈ 0.5 when depth ≈ threshold.
    let k = 3.0;
    let midpoint = 1.0;
    1.0 / (1.0 + (-k * (x - midpoint)).exp())
}

/// Single-shot queue saturation check (no EWMA state needed).
///
/// Returns `true` if the process has at least one TCP socket whose rx_queue
/// or tx_queue exceeds the given byte threshold. This is the simplest signal
/// suitable for a Beta-Bernoulli evidence term.
pub fn is_queue_saturated(total_rx: u64, total_tx: u64, threshold: u32) -> bool {
    total_rx > u64::from(threshold) || total_tx > u64::from(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── EWMA ──────────────────────────────────────────────────────────

    #[test]
    fn ewma_first_sample_is_identity() {
        let mut e = EwmaEstimator::new(0.3);
        e.update(100.0);
        assert_eq!(e.value(), 100.0);
        assert_eq!(e.count(), 1);
    }

    #[test]
    fn ewma_converges_to_constant() {
        let mut e = EwmaEstimator::new(0.5);
        for _ in 0..100 {
            e.update(42.0);
        }
        assert!((e.value() - 42.0).abs() < 1e-10);
    }

    #[test]
    fn ewma_smaller_alpha_is_smoother() {
        let mut fast = EwmaEstimator::new(0.9);
        let mut slow = EwmaEstimator::new(0.1);
        fast.update(0.0);
        slow.update(0.0);
        fast.update(100.0);
        slow.update(100.0);
        // Fast should be closer to 100 than slow.
        assert!(fast.value() > slow.value());
    }

    #[test]
    fn ewma_is_ready_respects_min() {
        let mut e = EwmaEstimator::new(0.5);
        assert!(!e.is_ready(2));
        e.update(1.0);
        assert!(!e.is_ready(2));
        e.update(2.0);
        assert!(e.is_ready(2));
    }

    #[test]
    #[should_panic]
    fn ewma_zero_alpha_panics() {
        EwmaEstimator::new(0.0);
    }

    #[test]
    #[should_panic]
    fn ewma_negative_alpha_panics() {
        EwmaEstimator::new(-0.1);
    }

    // ── estimate_rho ──────────────────────────────────────────────────

    #[test]
    fn rho_zero_depth_is_low() {
        let rho = estimate_rho(0.0, 0.0, 4096.0);
        assert!(rho < 0.1, "rho={rho}");
    }

    #[test]
    fn rho_high_depth_growing_is_high() {
        let rho = estimate_rho(20000.0, 5000.0, 4096.0);
        assert!(rho > 0.95, "rho={rho}");
    }

    #[test]
    fn rho_at_threshold_is_moderate() {
        let rho = estimate_rho(4096.0, 0.0, 4096.0);
        // At exactly the threshold with zero delta, rho should be near 0.5.
        assert!(rho > 0.3 && rho < 0.7, "rho={rho}");
    }

    #[test]
    fn rho_zero_threshold_returns_zero() {
        assert_eq!(estimate_rho(1000.0, 100.0, 0.0), 0.0);
    }

    // ── QueueStallDetector ────────────────────────────────────────────

    #[test]
    fn detector_not_stalled_with_empty_queues() {
        let mut det = QueueStallDetector::new();
        let r = det.observe(0, 0);
        assert!(!r.is_stalled);
        assert!(!r.is_saturated);
    }

    #[test]
    fn detector_saturated_with_deep_queue() {
        let mut det = QueueStallDetector::new();
        let r = det.observe(10000, 0);
        assert!(r.is_saturated);
    }

    #[test]
    fn detector_stalls_after_sustained_growth() {
        let mut det = QueueStallDetector::with_config(QueueStallConfig {
            alpha: 0.5,
            saturation_threshold: 1000,
            min_samples: 2,
            rho_threshold: 0.8,
            ..Default::default()
        });
        // Simulate queue growing over several observations.
        det.observe(500, 500);
        det.observe(2000, 2000);
        det.observe(5000, 5000);
        let r = det.observe(10000, 10000);
        assert!(r.is_stalled, "expected stall, rho={}", r.rho);
    }

    #[test]
    fn detector_not_stalled_when_draining() {
        let mut det = QueueStallDetector::with_config(QueueStallConfig {
            alpha: 0.5,
            saturation_threshold: 4096,
            min_samples: 2,
            rho_threshold: 0.9,
            ..Default::default()
        });
        // Queue starts high but drains.
        det.observe(10000, 0);
        det.observe(5000, 0);
        det.observe(1000, 0);
        let r = det.observe(100, 0);
        assert!(!r.is_stalled);
    }

    #[test]
    fn stall_probability_grows_with_rho() {
        let p_low = {
            let mut d = QueueStallDetector::new();
            d.observe(0, 0);
            d.observe(0, 0);
            d.observe(0, 0).stall_probability
        };
        let p_high = {
            let mut d = QueueStallDetector::with_config(QueueStallConfig {
                alpha: 0.9,
                saturation_threshold: 100,
                min_samples: 1,
                rho_threshold: 0.5,
                ..Default::default()
            });
            d.observe(50000, 50000);
            d.observe(100000, 100000);
            d.observe(200000, 200000).stall_probability
        };
        assert!(p_high > p_low, "p_high={p_high}, p_low={p_low}");
    }

    // ── is_queue_saturated ────────────────────────────────────────────

    #[test]
    fn saturated_when_rx_exceeds_threshold() {
        assert!(is_queue_saturated(5000, 0, 4096));
    }

    #[test]
    fn saturated_when_tx_exceeds_threshold() {
        assert!(is_queue_saturated(0, 5000, 4096));
    }

    #[test]
    fn not_saturated_below_threshold() {
        assert!(!is_queue_saturated(1000, 1000, 4096));
    }

    #[test]
    fn not_saturated_at_exact_threshold() {
        assert!(!is_queue_saturated(4096, 4096, 4096));
    }
}
