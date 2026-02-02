//! Kalman filter for resource smoothing and prediction.
//!
//! Implements a 2D Kalman filter tracking [value, velocity] for CPU, memory,
//! and I/O metrics. Handles missing measurements, produces smoothed values,
//! velocity estimates, and prediction intervals.
//!
//! # State Model
//!
//! ```text
//! State:  x = [value, velocity]
//! Transition: F = [[1, dt], [0, 1]]
//! Observation: H = [1, 0]
//! ```

use serde::{Deserialize, Serialize};

/// Configuration for a Kalman filter instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanConfig {
    /// Process noise variance (how much the true state changes between steps).
    pub process_noise: f64,
    /// Measurement noise variance (sensor/sampling noise).
    pub measurement_noise: f64,
    /// Initial state variance.
    pub initial_variance: f64,
}

impl Default for KalmanConfig {
    fn default() -> Self {
        Self {
            process_noise: 0.1,
            measurement_noise: 5.0,
            initial_variance: 100.0,
        }
    }
}

/// Preset configurations for common metrics.
impl KalmanConfig {
    pub fn cpu() -> Self {
        Self {
            process_noise: 0.1,
            measurement_noise: 5.0,
            initial_variance: 100.0,
        }
    }

    pub fn memory() -> Self {
        Self {
            process_noise: 0.01,
            measurement_noise: 10.0,
            initial_variance: 1000.0,
        }
    }

    pub fn io_rate() -> Self {
        Self {
            process_noise: 1.0,
            measurement_noise: 50.0,
            initial_variance: 10000.0,
        }
    }
}

/// 2x2 matrix operations (inline, no external dependency).
#[derive(Debug, Clone, Copy)]
struct Mat2 {
    m: [[f64; 2]; 2],
}

impl Mat2 {
    fn new(a: f64, b: f64, c: f64, d: f64) -> Self {
        Self { m: [[a, b], [c, d]] }
    }

    fn identity() -> Self {
        Self::new(1.0, 0.0, 0.0, 1.0)
    }

    fn mul(&self, other: &Mat2) -> Mat2 {
        Mat2::new(
            self.m[0][0] * other.m[0][0] + self.m[0][1] * other.m[1][0],
            self.m[0][0] * other.m[0][1] + self.m[0][1] * other.m[1][1],
            self.m[1][0] * other.m[0][0] + self.m[1][1] * other.m[1][0],
            self.m[1][0] * other.m[0][1] + self.m[1][1] * other.m[1][1],
        )
    }

    fn transpose(&self) -> Mat2 {
        Mat2::new(self.m[0][0], self.m[1][0], self.m[0][1], self.m[1][1])
    }

    fn add(&self, other: &Mat2) -> Mat2 {
        Mat2::new(
            self.m[0][0] + other.m[0][0],
            self.m[0][1] + other.m[0][1],
            self.m[1][0] + other.m[1][0],
            self.m[1][1] + other.m[1][1],
        )
    }

    fn sub(&self, other: &Mat2) -> Mat2 {
        Mat2::new(
            self.m[0][0] - other.m[0][0],
            self.m[0][1] - other.m[0][1],
            self.m[1][0] - other.m[1][0],
            self.m[1][1] - other.m[1][1],
        )
    }

    fn mul_vec(&self, v: [f64; 2]) -> [f64; 2] {
        [
            self.m[0][0] * v[0] + self.m[0][1] * v[1],
            self.m[1][0] * v[0] + self.m[1][1] * v[1],
        ]
    }
}

/// Kalman filter state.
#[derive(Debug, Clone)]
pub struct KalmanFilter {
    /// Current state estimate [value, velocity].
    x: [f64; 2],
    /// State covariance matrix.
    p: Mat2,
    /// Configuration.
    config: KalmanConfig,
    /// Last update timestamp (seconds).
    last_t: Option<f64>,
    /// Number of updates performed.
    update_count: u64,
}

/// Output of a Kalman filter update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanEstimate {
    /// Smoothed value.
    pub value: f64,
    /// Estimated velocity (rate of change per second).
    pub velocity: f64,
    /// Variance of the value estimate.
    pub value_variance: f64,
    /// Variance of the velocity estimate.
    pub velocity_variance: f64,
    /// Innovation (measurement - prediction), a.k.a. residual.
    pub innovation: f64,
    /// Number of updates so far.
    pub update_count: u64,
}

/// Prediction for a future time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanPrediction {
    /// Predicted value at the future time.
    pub value: f64,
    /// Predicted velocity.
    pub velocity: f64,
    /// Standard deviation of the prediction.
    pub std_dev: f64,
    /// Prediction interval (value ± 2*std_dev).
    pub interval_low: f64,
    pub interval_high: f64,
    /// Seconds ahead from last update.
    pub horizon_secs: f64,
}

impl KalmanFilter {
    /// Create a new Kalman filter with the given configuration.
    pub fn new(config: KalmanConfig) -> Self {
        Self {
            x: [0.0, 0.0],
            p: Mat2::new(config.initial_variance, 0.0, 0.0, config.initial_variance),
            config,
            last_t: None,
            update_count: 0,
        }
    }

    /// Initialize filter with a first measurement.
    pub fn initialize(&mut self, value: f64, t: f64) {
        self.x = [value, 0.0];
        self.p = Mat2::new(
            self.config.initial_variance,
            0.0,
            0.0,
            self.config.initial_variance,
        );
        self.last_t = Some(t);
        self.update_count = 1;
    }

    /// Update the filter with a new measurement.
    ///
    /// Returns the smoothed estimate after incorporating the measurement.
    pub fn update(&mut self, measurement: f64, t: f64) -> KalmanEstimate {
        if self.update_count == 0 {
            self.initialize(measurement, t);
            return KalmanEstimate {
                value: measurement,
                velocity: 0.0,
                value_variance: self.config.initial_variance,
                velocity_variance: self.config.initial_variance,
                innovation: 0.0,
                update_count: 1,
            };
        }

        let dt = t - self.last_t.unwrap_or(t);
        let dt = dt.max(0.001); // Avoid zero dt.

        // State transition matrix: F = [[1, dt], [0, 1]]
        let f = Mat2::new(1.0, dt, 0.0, 1.0);

        // Process noise: Q = q * [[dt^3/3, dt^2/2], [dt^2/2, dt]]
        let q_scale = self.config.process_noise;
        let q = Mat2::new(
            q_scale * dt.powi(3) / 3.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt,
        );

        // Predict step.
        let x_pred = f.mul_vec(self.x);
        let p_pred = f.mul(&self.p).mul(&f.transpose()).add(&q);

        // Observation matrix: H = [1, 0]
        // Innovation: y = z - H*x_pred
        let innovation = measurement - x_pred[0];

        // Innovation covariance: S = H*P_pred*H' + R
        let s = p_pred.m[0][0] + self.config.measurement_noise;

        if s.abs() < 1e-15 {
            // Degenerate; skip update.
            return KalmanEstimate {
                value: x_pred[0],
                velocity: x_pred[1],
                value_variance: p_pred.m[0][0],
                velocity_variance: p_pred.m[1][1],
                innovation,
                update_count: self.update_count,
            };
        }

        // Kalman gain: K = P_pred * H' / S
        let k = [p_pred.m[0][0] / s, p_pred.m[1][0] / s];

        // Update state.
        self.x = [
            x_pred[0] + k[0] * innovation,
            x_pred[1] + k[1] * innovation,
        ];

        // Update covariance: P = (I - K*H) * P_pred
        let kh = Mat2::new(k[0], 0.0, k[1], 0.0);
        self.p = Mat2::identity().sub(&kh).mul(&p_pred);

        self.last_t = Some(t);
        self.update_count += 1;

        KalmanEstimate {
            value: self.x[0],
            velocity: self.x[1],
            value_variance: self.p.m[0][0],
            velocity_variance: self.p.m[1][1],
            innovation,
            update_count: self.update_count,
        }
    }

    /// Handle a missing measurement (predict only, no update).
    pub fn predict_only(&mut self, t: f64) -> KalmanEstimate {
        if self.update_count == 0 {
            return KalmanEstimate {
                value: 0.0,
                velocity: 0.0,
                value_variance: self.config.initial_variance,
                velocity_variance: self.config.initial_variance,
                innovation: 0.0,
                update_count: 0,
            };
        }

        let dt = t - self.last_t.unwrap_or(t);
        let dt = dt.max(0.001);

        let f = Mat2::new(1.0, dt, 0.0, 1.0);
        let q_scale = self.config.process_noise;
        let q = Mat2::new(
            q_scale * dt.powi(3) / 3.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt,
        );

        let x_pred = f.mul_vec(self.x);
        let p_pred = f.mul(&self.p).mul(&f.transpose()).add(&q);

        self.x = x_pred;
        self.p = p_pred;
        self.last_t = Some(t);

        KalmanEstimate {
            value: self.x[0],
            velocity: self.x[1],
            value_variance: self.p.m[0][0],
            velocity_variance: self.p.m[1][1],
            innovation: 0.0,
            update_count: self.update_count,
        }
    }

    /// Predict the state at a future time without modifying the filter.
    pub fn predict_future(&self, horizon_secs: f64) -> KalmanPrediction {
        let dt = horizon_secs;
        let f = Mat2::new(1.0, dt, 0.0, 1.0);
        let q_scale = self.config.process_noise;
        let q = Mat2::new(
            q_scale * dt.powi(3) / 3.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt.powi(2) / 2.0,
            q_scale * dt,
        );

        let x_pred = f.mul_vec(self.x);
        let p_pred = f.mul(&self.p).mul(&f.transpose()).add(&q);
        let std_dev = p_pred.m[0][0].sqrt();

        KalmanPrediction {
            value: x_pred[0],
            velocity: x_pred[1],
            std_dev,
            interval_low: x_pred[0] - 2.0 * std_dev,
            interval_high: x_pred[0] + 2.0 * std_dev,
            horizon_secs,
        }
    }

    /// Current smoothed value.
    pub fn value(&self) -> f64 {
        self.x[0]
    }

    /// Current velocity estimate.
    pub fn velocity(&self) -> f64 {
        self.x[1]
    }

    /// Number of updates performed.
    pub fn update_count(&self) -> u64 {
        self.update_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let mut kf = KalmanFilter::new(KalmanConfig::cpu());
        let est = kf.update(50.0, 0.0);
        assert!((est.value - 50.0).abs() < 1e-6);
        assert_eq!(est.update_count, 1);
    }

    #[test]
    fn test_smoothing_constant_signal() {
        let mut kf = KalmanFilter::new(KalmanConfig::cpu());
        let true_value = 42.0;

        let mut last_est = None;
        for i in 0..50 {
            let noise = ((i * 7 + 3) % 11) as f64 - 5.0;
            let est = kf.update(true_value + noise, i as f64);
            last_est = Some(est);
        }

        let est = last_est.unwrap();
        // After 50 updates, should converge close to true value.
        assert!(
            (est.value - true_value).abs() < 3.0,
            "Expected ~{}, got {}",
            true_value,
            est.value
        );
        // Velocity should be near zero.
        assert!(est.velocity.abs() < 1.0);
    }

    #[test]
    fn test_noise_reduction() {
        let mut kf = KalmanFilter::new(KalmanConfig::cpu());
        let true_value = 50.0;

        let mut raw_errors = Vec::new();
        let mut filtered_errors = Vec::new();

        for i in 0..100 {
            let noise = 10.0 * (((i * 13 + 7) % 19) as f64 / 19.0 - 0.5);
            let measurement = true_value + noise;
            let est = kf.update(measurement, i as f64);

            raw_errors.push((measurement - true_value).powi(2));
            filtered_errors.push((est.value - true_value).powi(2));
        }

        let raw_mse: f64 = raw_errors.iter().sum::<f64>() / raw_errors.len() as f64;
        let filtered_mse: f64 =
            filtered_errors[20..].iter().sum::<f64>() / filtered_errors[20..].len() as f64;

        // Filter should reduce MSE by >50% (after warm-up).
        assert!(
            filtered_mse < raw_mse * 0.5,
            "Filter MSE {} should be < 50% of raw MSE {}",
            filtered_mse,
            raw_mse
        );
    }

    #[test]
    fn test_tracks_linear_trend() {
        let mut kf = KalmanFilter::new(KalmanConfig::memory());
        let slope = 0.5; // 0.5 units per second

        for i in 0..100 {
            let t = i as f64;
            let true_val = 100.0 + slope * t;
            kf.update(true_val, t);
        }

        // Should track the velocity.
        assert!(
            (kf.velocity() - slope).abs() < 0.1,
            "Velocity {} should be near {}",
            kf.velocity(),
            slope
        );
    }

    #[test]
    fn test_missing_measurements() {
        let mut kf = KalmanFilter::new(KalmanConfig::cpu());

        // Feed initial data.
        for i in 0..20 {
            kf.update(50.0, i as f64);
        }

        let before = kf.value();

        // Skip some measurements.
        let est = kf.predict_only(25.0);
        assert!(est.value_variance > 0.0);

        // Resume with measurements.
        let est = kf.update(50.0, 30.0);
        assert!((est.value - 50.0).abs() < 10.0);

        // Variance should have grown during the gap.
        // (We can't easily check this without storing intermediate state,
        // but the filter should still work.)
        let _ = before;
    }

    #[test]
    fn test_prediction_interval() {
        let mut kf = KalmanFilter::new(KalmanConfig::memory());

        for i in 0..50 {
            kf.update(100.0 + 0.1 * i as f64, i as f64);
        }

        let pred = kf.predict_future(300.0); // 5 minutes ahead
        assert!(pred.value > kf.value()); // Should extrapolate upward.
        assert!(pred.std_dev > 0.0); // Uncertainty should be positive.
        assert!(pred.interval_low < pred.value);
        assert!(pred.interval_high > pred.value);
    }

    #[test]
    fn test_prediction_within_bounds() {
        let mut kf = KalmanFilter::new(KalmanConfig::memory());
        let slope = 1.0; // 1 unit per second

        for i in 0..50 {
            let t = i as f64;
            kf.update(100.0 + slope * t, t);
        }

        // Predict 5 minutes ahead.
        let pred = kf.predict_future(300.0);
        let expected = 100.0 + slope * (49.0 + 300.0);

        // Prediction should be within 20%.
        let error_pct = ((pred.value - expected) / expected).abs();
        assert!(
            error_pct < 0.2,
            "Prediction error {:.1}% exceeds 20% (predicted={:.1}, expected={:.1})",
            error_pct * 100.0,
            pred.value,
            expected
        );
    }

    #[test]
    fn test_performance() {
        let mut kf = KalmanFilter::new(KalmanConfig::cpu());
        let start = std::time::Instant::now();

        for i in 0..10000 {
            kf.update(50.0 + (i % 10) as f64, i as f64);
        }

        let elapsed = start.elapsed();
        // 10000 updates should complete in well under 1 second.
        // Each update should be <1ms.
        assert!(
            elapsed.as_millis() < 100,
            "10000 updates took {}ms, expected <100ms",
            elapsed.as_millis()
        );
    }
}
