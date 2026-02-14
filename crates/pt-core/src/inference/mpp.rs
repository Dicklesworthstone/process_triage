//! Marked Point Process (MPP) summary features for process event streams.
//!
//! This module provides deterministic summary features extracted from marked point
//! processes - event streams where each event has a timestamp and a magnitude (mark).
//!
//! # Overview
//!
//! A marked point process consists of:
//! - Event times: monotonic timestamps when events occur
//! - Marks: magnitude/attribute associated with each event (e.g., bytes read, syscall cost)
//!
//! # Features Extracted
//!
//! - Event rate estimates over configurable windows
//! - Mark distribution summaries (mean, median, p95, p99, POT exceedance stats)
//! - Burstiness indices (Fano factor, coefficient of variation of inter-arrival times)
//! - Severity scalars suitable for evidence ledger
//!
//! # Integration
//!
//! Designed to work with streaming sketch inputs:
//! - [`TDigest`] for quantile estimation
//! - [`SpaceSaving`](super::sketches::SpaceSaving) for heavy-hitter marks
//! - Reservoir samples for exact statistics on bounded subsets
//!
//! # Example
//!
//! ```
//! use pt_core::inference::mpp::{MarkedPointProcess, MppConfig, MarkedEvent};
//!
//! // Create processor with default config
//! let config = MppConfig::default();
//! let mut mpp = MarkedPointProcess::new(config);
//!
//! // Add events (timestamp in seconds, mark/magnitude)
//! mpp.add_event(0.0, 1024.0);  // e.g., 1KB read
//! mpp.add_event(0.1, 512.0);   // e.g., 512B read
//! mpp.add_event(0.15, 2048.0); // e.g., 2KB read
//! mpp.add_event(0.5, 256.0);   // e.g., 256B read
//!
//! // Compute summary at window end
//! let summary = mpp.summarize(1.0);
//! println!("Event rate: {:.2}/s", summary.event_rate);
//! println!("Fano factor: {:.3}", summary.fano_factor);
//! ```

use serde::{Deserialize, Serialize};

use super::sketches::{PercentileSummary, TDigest, TDigestConfig};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for marked point process analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppConfig {
    /// TDigest configuration for mark distribution.
    pub tdigest_config: TDigestConfig,

    /// Minimum number of events required for meaningful statistics.
    pub min_events: usize,

    /// Minimum time span required for rate estimation (seconds).
    pub min_time_span: f64,

    /// Maximum number of events to store for exact inter-arrival computation.
    /// Events beyond this use streaming approximation.
    pub max_stored_events: usize,

    /// Threshold for "high" Fano factor (indicates overdispersion/burstiness).
    pub fano_high_threshold: f64,

    /// Threshold for "very high" Fano factor (indicates severe clustering).
    pub fano_very_high_threshold: f64,

    /// Threshold for "high" coefficient of variation of inter-arrivals.
    pub cv_high_threshold: f64,
}

impl Default for MppConfig {
    fn default() -> Self {
        Self {
            tdigest_config: TDigestConfig::default(),
            min_events: 3,
            min_time_span: 0.1, // 100ms minimum
            max_stored_events: 10_000,
            fano_high_threshold: 2.0,      // > 2x Poisson variance
            fano_very_high_threshold: 5.0, // > 5x Poisson variance
            cv_high_threshold: 1.5,        // > 1.5x mean inter-arrival
        }
    }
}

// ============================================================================
// Burstiness Classification
// ============================================================================

/// Classification of burstiness based on statistical indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurstinessLevel {
    /// Regular arrival pattern (Poisson-like).
    Regular,
    /// Mild clustering/burstiness.
    Mild,
    /// Moderate burstiness.
    Moderate,
    /// High burstiness with clear clustering.
    High,
    /// Very high burstiness (pathological).
    VeryHigh,
}

impl std::fmt::Display for BurstinessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BurstinessLevel::Regular => write!(f, "regular"),
            BurstinessLevel::Mild => write!(f, "mild"),
            BurstinessLevel::Moderate => write!(f, "moderate"),
            BurstinessLevel::High => write!(f, "high"),
            BurstinessLevel::VeryHigh => write!(f, "very_high"),
        }
    }
}

impl BurstinessLevel {
    /// Determine burstiness level from Fano factor and CV.
    pub fn from_indices(fano: f64, cv: f64, config: &MppConfig) -> Self {
        // For Poisson process: Fano = 1, CV of inter-arrivals = 1
        // Values above 1 indicate overdispersion/burstiness
        if fano >= config.fano_very_high_threshold || cv >= config.cv_high_threshold * 2.0 {
            BurstinessLevel::VeryHigh
        } else if fano >= config.fano_high_threshold || cv >= config.cv_high_threshold {
            BurstinessLevel::High
        } else if fano >= 1.5 || cv > 1.2 {
            BurstinessLevel::Moderate
        } else if fano > 1.1 || cv > 1.0 {
            // Only above Poisson baseline triggers Mild
            BurstinessLevel::Mild
        } else {
            // Fano <= 1.1 and CV <= 1.0 is Poisson-like (Regular)
            BurstinessLevel::Regular
        }
    }

    /// Map burstiness level to log-odds contribution.
    ///
    /// High burstiness suggests abnormal behavior (tight loops, cascading failures).
    pub fn log_odds_contribution(&self) -> f64 {
        match self {
            BurstinessLevel::Regular => -0.3, // Supports normal behavior
            BurstinessLevel::Mild => 0.0,     // Neutral
            BurstinessLevel::Moderate => 0.3, // Mild concern
            BurstinessLevel::High => 0.8,     // Strong signal
            BurstinessLevel::VeryHigh => 1.5, // Very strong signal
        }
    }
}

// ============================================================================
// Event and Summary Types
// ============================================================================

/// A single marked event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MarkedEvent {
    /// Monotonic timestamp (seconds from reference).
    pub timestamp: f64,
    /// Mark/magnitude associated with the event.
    pub mark: f64,
}

impl MarkedEvent {
    /// Create a new marked event.
    pub fn new(timestamp: f64, mark: f64) -> Self {
        Self { timestamp, mark }
    }
}

/// Summary statistics for mark distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkDistribution {
    /// Number of marks observed.
    pub count: usize,
    /// Sum of all marks.
    pub sum: f64,
    /// Mean of marks.
    pub mean: f64,
    /// Variance of marks.
    pub variance: f64,
    /// Standard deviation of marks.
    pub std_dev: f64,
    /// Percentile summary from TDigest.
    pub percentiles: Option<PercentileSummary>,
    /// Minimum mark value.
    pub min: f64,
    /// Maximum mark value.
    pub max: f64,
}

impl Default for MarkDistribution {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            mean: 0.0,
            variance: 0.0,
            std_dev: 0.0,
            percentiles: None,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }
}

/// Summary of inter-arrival time statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterArrivalStats {
    /// Number of inter-arrival intervals.
    pub count: usize,
    /// Mean inter-arrival time.
    pub mean: f64,
    /// Variance of inter-arrival times.
    pub variance: f64,
    /// Standard deviation of inter-arrival times.
    pub std_dev: f64,
    /// Coefficient of variation (std_dev / mean).
    pub cv: f64,
    /// Minimum inter-arrival time.
    pub min: f64,
    /// Maximum inter-arrival time.
    pub max: f64,
    /// Percentile summary of inter-arrival times.
    pub percentiles: Option<PercentileSummary>,
}

impl Default for InterArrivalStats {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            variance: 0.0,
            std_dev: 0.0,
            cv: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            percentiles: None,
        }
    }
}

/// Complete summary of a marked point process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppSummary {
    /// Number of events in the window.
    pub event_count: usize,

    /// Time span of the observation window (seconds).
    pub time_span: f64,

    /// Event rate (events per second).
    pub event_rate: f64,

    /// Mark/magnitude distribution statistics.
    pub mark_distribution: MarkDistribution,

    /// Inter-arrival time statistics.
    pub inter_arrival: InterArrivalStats,

    /// Fano factor (variance / mean of counts in bins).
    /// = 1 for Poisson, > 1 for overdispersed/bursty.
    pub fano_factor: f64,

    /// Coefficient of variation of inter-arrival times.
    /// = 1 for exponential (Poisson), > 1 for bursty.
    pub cv_inter_arrival: f64,

    /// Index of dispersion (variance of counts / mean of counts).
    pub index_of_dispersion: f64,

    /// Classified burstiness level.
    pub burstiness_level: BurstinessLevel,

    /// Marked intensity proxy (rate * mean_mark).
    pub marked_intensity: f64,

    /// Whether the summary is based on sufficient data.
    pub is_valid: bool,

    /// Reason if invalid.
    pub invalid_reason: Option<String>,
}

impl MppSummary {
    /// Create an invalid summary with a reason.
    pub fn invalid(reason: &str) -> Self {
        Self {
            event_count: 0,
            time_span: 0.0,
            event_rate: 0.0,
            mark_distribution: MarkDistribution::default(),
            inter_arrival: InterArrivalStats::default(),
            fano_factor: 1.0,
            cv_inter_arrival: 1.0,
            index_of_dispersion: 1.0,
            burstiness_level: BurstinessLevel::Regular,
            marked_intensity: 0.0,
            is_valid: false,
            invalid_reason: Some(reason.to_string()),
        }
    }
}

// ============================================================================
// Evidence for Ledger
// ============================================================================

/// Evidence derived from marked point process analysis.
///
/// This structure provides the interface to the evidence ledger system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppEvidence {
    /// Full MPP summary.
    pub summary: MppSummary,

    /// Log-odds contribution (positive supports "abnormal" classification).
    pub log_odds: f64,

    /// Display glyph for the ledger.
    pub glyph: char,

    /// Human-readable description for the ledger.
    pub description: String,

    /// Severity scalar (0.0-1.0) for ranking.
    pub severity: f64,
}

impl MppEvidence {
    /// Create evidence from a summary.
    pub fn from_summary(summary: MppSummary) -> Self {
        let log_odds = summary.burstiness_level.log_odds_contribution();

        let severity = compute_severity(&summary);

        let description = format_description(&summary);

        Self {
            summary,
            log_odds,
            glyph: '\u{1F4C8}', // 📈 chart
            description,
            severity,
        }
    }
}

/// Compute a severity scalar from the summary.
fn compute_severity(summary: &MppSummary) -> f64 {
    if !summary.is_valid {
        return 0.0;
    }

    // Combine multiple signals into a severity score
    let mut severity = 0.0;

    // Fano factor contribution (normalized to 0-0.4)
    let fano_contrib = ((summary.fano_factor - 1.0).max(0.0) / 10.0).min(0.4);
    severity += fano_contrib;

    // CV contribution (normalized to 0-0.3)
    let cv_contrib = ((summary.cv_inter_arrival - 1.0).max(0.0) / 5.0).min(0.3);
    severity += cv_contrib;

    // Burstiness level contribution (0-0.3)
    let burst_contrib = match summary.burstiness_level {
        BurstinessLevel::Regular => 0.0,
        BurstinessLevel::Mild => 0.05,
        BurstinessLevel::Moderate => 0.1,
        BurstinessLevel::High => 0.2,
        BurstinessLevel::VeryHigh => 0.3,
    };
    severity += burst_contrib;

    severity.min(1.0)
}

/// Format a human-readable description from the summary.
fn format_description(summary: &MppSummary) -> String {
    if !summary.is_valid {
        return summary
            .invalid_reason
            .clone()
            .unwrap_or_else(|| "insufficient data".to_string());
    }

    let rate_desc = if summary.event_rate < 0.1 {
        "low"
    } else if summary.event_rate < 1.0 {
        "moderate"
    } else if summary.event_rate < 10.0 {
        "high"
    } else {
        "very high"
    };

    format!(
        "{} event rate ({:.1}/s), {} burstiness (Fano={:.2}, CV={:.2})",
        rate_desc,
        summary.event_rate,
        summary.burstiness_level,
        summary.fano_factor,
        summary.cv_inter_arrival
    )
}

// ============================================================================
// Marked Point Process Processor
// ============================================================================

/// Processor for marked point process event streams.
///
/// Accepts events with timestamps and marks, computing streaming summaries
/// with bounded memory usage.
#[derive(Debug)]
pub struct MarkedPointProcess {
    config: MppConfig,

    /// Stored events for exact computation (up to max_stored_events).
    events: Vec<MarkedEvent>,

    /// TDigest for mark distribution.
    mark_digest: TDigest,

    /// TDigest for inter-arrival time distribution.
    inter_arrival_digest: TDigest,

    /// Running statistics for marks (Welford's algorithm).
    mark_count: usize,
    mark_sum: f64,
    mark_mean: f64,
    mark_m2: f64, // Sum of squared deviations
    mark_min: f64,
    mark_max: f64,

    /// Running statistics for inter-arrival times.
    ia_count: usize,
    ia_sum: f64,
    ia_mean: f64,
    ia_m2: f64,
    ia_min: f64,
    ia_max: f64,

    /// Last event timestamp for inter-arrival computation.
    last_timestamp: Option<f64>,

    /// Window start timestamp.
    window_start: Option<f64>,
}

impl MarkedPointProcess {
    /// Create a new marked point process processor.
    pub fn new(config: MppConfig) -> Self {
        let mark_digest =
            TDigest::new(config.tdigest_config.clone()).expect("TDigest config is valid");
        let inter_arrival_digest =
            TDigest::new(config.tdigest_config.clone()).expect("TDigest config is valid");

        Self {
            config,
            events: Vec::new(),
            mark_digest,
            inter_arrival_digest,
            mark_count: 0,
            mark_sum: 0.0,
            mark_mean: 0.0,
            mark_m2: 0.0,
            mark_min: f64::INFINITY,
            mark_max: f64::NEG_INFINITY,
            ia_count: 0,
            ia_sum: 0.0,
            ia_mean: 0.0,
            ia_m2: 0.0,
            ia_min: f64::INFINITY,
            ia_max: f64::NEG_INFINITY,
            last_timestamp: None,
            window_start: None,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MppConfig::default())
    }

    /// Reset the processor to initial state.
    pub fn reset(&mut self) {
        self.events.clear();
        self.mark_digest =
            TDigest::new(self.config.tdigest_config.clone()).expect("TDigest config is valid");
        self.inter_arrival_digest =
            TDigest::new(self.config.tdigest_config.clone()).expect("TDigest config is valid");
        self.mark_count = 0;
        self.mark_sum = 0.0;
        self.mark_mean = 0.0;
        self.mark_m2 = 0.0;
        self.mark_min = f64::INFINITY;
        self.mark_max = f64::NEG_INFINITY;
        self.ia_count = 0;
        self.ia_sum = 0.0;
        self.ia_mean = 0.0;
        self.ia_m2 = 0.0;
        self.ia_min = f64::INFINITY;
        self.ia_max = f64::NEG_INFINITY;
        self.last_timestamp = None;
        self.window_start = None;
    }

    /// Add an event with timestamp and mark.
    pub fn add_event(&mut self, timestamp: f64, mark: f64) {
        // Update window start
        if self.window_start.is_none() || timestamp < self.window_start.unwrap_or(f64::INFINITY) {
            self.window_start = Some(timestamp);
        }

        // Store event if within capacity
        if self.events.len() < self.config.max_stored_events {
            self.events.push(MarkedEvent::new(timestamp, mark));
        }

        // Update mark statistics (Welford's online algorithm)
        self.mark_count += 1;
        self.mark_sum += mark;
        let delta = mark - self.mark_mean;
        self.mark_mean += delta / self.mark_count as f64;
        let delta2 = mark - self.mark_mean;
        self.mark_m2 += delta * delta2;
        self.mark_min = self.mark_min.min(mark);
        self.mark_max = self.mark_max.max(mark);

        // Add to mark digest
        self.mark_digest.add(mark);

        // Compute inter-arrival time if we have a previous event
        if let Some(last_ts) = self.last_timestamp {
            let ia = timestamp - last_ts;
            if ia >= 0.0 {
                // Update IA statistics (Welford's online algorithm)
                self.ia_count += 1;
                self.ia_sum += ia;
                let delta = ia - self.ia_mean;
                self.ia_mean += delta / self.ia_count as f64;
                let delta2 = ia - self.ia_mean;
                self.ia_m2 += delta * delta2;
                self.ia_min = self.ia_min.min(ia);
                self.ia_max = self.ia_max.max(ia);

                // Add to IA digest
                self.inter_arrival_digest.add(ia);
            }
        }

        self.last_timestamp = Some(timestamp);
    }

    /// Add a marked event.
    pub fn add(&mut self, event: MarkedEvent) {
        self.add_event(event.timestamp, event.mark);
    }

    /// Add multiple events from a batch.
    ///
    /// Events are sorted by timestamp before processing. NaN timestamps are
    /// treated as greater than all other values (sorted to the end).
    pub fn add_batch(&mut self, events: &[MarkedEvent]) {
        if events.is_empty() {
            return;
        }
        // Sort by timestamp if not already sorted
        // Use total_cmp to handle NaN safely (NaN sorts to the end)
        let mut sorted: Vec<_> = events.to_vec();
        sorted.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));

        for event in sorted {
            self.add(event);
        }
    }

    /// Add events from timestamp and mark arrays.
    pub fn add_arrays(&mut self, timestamps: &[f64], marks: &[f64]) {
        debug_assert_eq!(timestamps.len(), marks.len());
        for (&ts, &mark) in timestamps.iter().zip(marks.iter()) {
            self.add_event(ts, mark);
        }
    }

    /// Get current event count.
    pub fn event_count(&self) -> usize {
        self.mark_count
    }

    /// Compute the Fano factor from stored events.
    ///
    /// The Fano factor measures overdispersion:
    /// F = Var(N) / E[N] where N is the count in fixed-size bins.
    /// F = 1 for Poisson, F > 1 for overdispersed/bursty.
    fn compute_fano_factor(&self, window_end: f64) -> f64 {
        if self.events.len() < 3 {
            return 1.0; // Default to Poisson
        }

        let window_start = self.window_start.unwrap_or(0.0);
        let time_span = window_end - window_start;
        if time_span <= 0.0 {
            return 1.0;
        }

        // Choose bin size to get reasonable number of bins
        // Aim for ~10-100 bins with at least a few events each
        let n_events = self.events.len();
        let target_bins = (n_events as f64).sqrt().clamp(5.0, 50.0);
        let bin_size = time_span / target_bins;

        if bin_size <= 0.0 {
            return 1.0;
        }

        // Count events per bin
        let n_bins = (time_span / bin_size).ceil() as usize;
        let mut bin_counts: Vec<usize> = vec![0; n_bins];

        for event in &self.events {
            // Ensure non-negative index
            let offset = (event.timestamp - window_start).max(0.0);
            let bin_idx = (offset / bin_size).floor() as usize;
            if bin_idx < n_bins {
                bin_counts[bin_idx] += 1;
            }
        }

        // Compute mean and variance of bin counts
        let mean: f64 = bin_counts.iter().sum::<usize>() as f64 / n_bins as f64;
        if mean <= 0.0 {
            return 1.0;
        }

        let variance: f64 = bin_counts
            .iter()
            .map(|&c| (c as f64 - mean).powi(2))
            .sum::<f64>()
            / n_bins as f64;

        variance / mean
    }

    /// Compute the index of dispersion from count variance.
    fn compute_index_of_dispersion(&self, window_end: f64) -> f64 {
        // Index of dispersion is essentially the Fano factor
        self.compute_fano_factor(window_end)
    }

    /// Summarize the marked point process at the given window end time.
    pub fn summarize(&mut self, window_end: f64) -> MppSummary {
        // Check for sufficient data
        if self.mark_count < self.config.min_events {
            return MppSummary::invalid(&format!(
                "insufficient events: {} < {}",
                self.mark_count, self.config.min_events
            ));
        }

        let window_start = self.window_start.unwrap_or(0.0);
        let time_span = window_end - window_start;

        if time_span < self.config.min_time_span {
            return MppSummary::invalid(&format!(
                "time span too short: {:.3}s < {:.3}s",
                time_span, self.config.min_time_span
            ));
        }

        // Event rate
        let event_rate = self.mark_count as f64 / time_span;

        // Mark distribution
        let mark_variance = if self.mark_count > 1 {
            self.mark_m2 / (self.mark_count - 1) as f64
        } else {
            0.0
        };
        let mark_std_dev = mark_variance.sqrt();

        let mark_percentiles = self.mark_digest.common_percentiles().ok();

        // Sanitize infinity values if no marks recorded (shouldn't happen due to min_events check)
        let (mark_min, mark_max) = if self.mark_count > 0 {
            (self.mark_min, self.mark_max)
        } else {
            (0.0, 0.0)
        };

        let mark_distribution = MarkDistribution {
            count: self.mark_count,
            sum: self.mark_sum,
            mean: self.mark_mean,
            variance: mark_variance,
            std_dev: mark_std_dev,
            percentiles: mark_percentiles,
            min: mark_min,
            max: mark_max,
        };

        // Inter-arrival statistics
        let ia_variance = if self.ia_count > 1 {
            self.ia_m2 / (self.ia_count - 1) as f64
        } else {
            0.0
        };
        let ia_std_dev = ia_variance.sqrt();
        let ia_cv = if self.ia_mean > 0.0 {
            ia_std_dev / self.ia_mean
        } else {
            1.0
        };

        let ia_percentiles = self.inter_arrival_digest.common_percentiles().ok();

        // Sanitize infinity values when no inter-arrivals recorded
        let (ia_min, ia_max) = if self.ia_count > 0 {
            (self.ia_min, self.ia_max)
        } else {
            (0.0, 0.0) // No inter-arrivals means no valid min/max
        };

        let inter_arrival = InterArrivalStats {
            count: self.ia_count,
            mean: self.ia_mean,
            variance: ia_variance,
            std_dev: ia_std_dev,
            cv: ia_cv,
            min: ia_min,
            max: ia_max,
            percentiles: ia_percentiles,
        };

        // Burstiness indices
        let fano_factor = self.compute_fano_factor(window_end);
        let cv_inter_arrival = ia_cv;
        let index_of_dispersion = self.compute_index_of_dispersion(window_end);

        // Classify burstiness
        let burstiness_level =
            BurstinessLevel::from_indices(fano_factor, cv_inter_arrival, &self.config);

        // Marked intensity (rate * mean_mark)
        let marked_intensity = event_rate * self.mark_mean;

        MppSummary {
            event_count: self.mark_count,
            time_span,
            event_rate,
            mark_distribution,
            inter_arrival,
            fano_factor,
            cv_inter_arrival,
            index_of_dispersion,
            burstiness_level,
            marked_intensity,
            is_valid: true,
            invalid_reason: None,
        }
    }

    /// Summarize and produce evidence for the ledger.
    pub fn evidence(&mut self, window_end: f64) -> MppEvidence {
        let summary = self.summarize(window_end);
        MppEvidence::from_summary(summary)
    }
}

// ============================================================================
// Batch Analyzer
// ============================================================================

/// Batch analyzer for multiple marked point processes.
///
/// Useful for analyzing multiple metrics (CPU events, IO events, network events)
/// in a single pass.
#[derive(Debug)]
pub struct BatchMppAnalyzer {
    /// Named MPP processors.
    processors: Vec<(String, MarkedPointProcess)>,
    /// Configuration shared across processors.
    config: MppConfig,
}

impl BatchMppAnalyzer {
    /// Create a new batch analyzer.
    pub fn new(config: MppConfig) -> Self {
        Self {
            processors: Vec::new(),
            config,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MppConfig::default())
    }

    /// Add a named processor.
    pub fn add_processor(&mut self, name: &str) {
        self.processors.push((
            name.to_string(),
            MarkedPointProcess::new(self.config.clone()),
        ));
    }

    /// Get or create a processor by name.
    pub fn get_or_create(&mut self, name: &str) -> &mut MarkedPointProcess {
        if let Some(idx) = self.processors.iter().position(|(n, _)| n == name) {
            &mut self.processors[idx].1
        } else {
            self.processors.push((
                name.to_string(),
                MarkedPointProcess::new(self.config.clone()),
            ));
            &mut self.processors.last_mut().unwrap().1
        }
    }

    /// Add an event to a named processor.
    pub fn add_event(&mut self, processor_name: &str, timestamp: f64, mark: f64) {
        self.get_or_create(processor_name)
            .add_event(timestamp, mark);
    }

    /// Summarize all processors.
    pub fn summarize_all(&mut self, window_end: f64) -> Vec<(String, MppSummary)> {
        self.processors
            .iter_mut()
            .map(|(name, proc)| (name.clone(), proc.summarize(window_end)))
            .collect()
    }

    /// Get evidence from all processors.
    pub fn evidence_all(&mut self, window_end: f64) -> Vec<(String, MppEvidence)> {
        self.processors
            .iter_mut()
            .map(|(name, proc)| (name.clone(), proc.evidence(window_end)))
            .collect()
    }

    /// Aggregate severity across all processors.
    pub fn aggregate_severity(&mut self, window_end: f64) -> f64 {
        let evidences = self.evidence_all(window_end);
        if evidences.is_empty() {
            return 0.0;
        }

        let total_severity: f64 = evidences.iter().map(|(_, e)| e.severity).sum();
        (total_severity / evidences.len() as f64).min(1.0)
    }
}

// ============================================================================
// Cross-Excitation Summary (for future multivariate extension)
// ============================================================================

/// Summary of cross-excitation between multiple event streams.
///
/// This is a placeholder for the multivariate Hawkes extension (nao.18).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Placeholder for future multivariate extension
pub struct CrossExcitationSummary {
    /// Names of event streams.
    pub stream_names: Vec<String>,
    /// Excitation matrix (stream_i excites stream_j).
    pub excitation_matrix: Vec<Vec<f64>>,
    /// Total cross-excitation score.
    pub total_cross_excitation: f64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpp_basic() {
        let mut mpp = MarkedPointProcess::with_defaults();

        // Add some events
        mpp.add_event(0.0, 100.0);
        mpp.add_event(0.1, 150.0);
        mpp.add_event(0.2, 120.0);
        mpp.add_event(0.5, 200.0);
        mpp.add_event(1.0, 100.0);

        let summary = mpp.summarize(1.5);

        assert!(summary.is_valid);
        assert_eq!(summary.event_count, 5);
        assert!((summary.time_span - 1.5).abs() < 0.01);
        assert!((summary.event_rate - 5.0 / 1.5).abs() < 0.1);
    }

    #[test]
    fn test_mpp_insufficient_events() {
        let mut mpp = MarkedPointProcess::with_defaults();

        mpp.add_event(0.0, 100.0);
        mpp.add_event(0.1, 150.0);

        let summary = mpp.summarize(1.0);

        assert!(!summary.is_valid);
        assert!(summary.invalid_reason.is_some());
    }

    #[test]
    fn test_mpp_fano_factor() {
        let mut mpp = MarkedPointProcess::with_defaults();

        // Regular arrivals (should have Fano ~ 1)
        for i in 0..100 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }

        let summary = mpp.summarize(10.0);
        assert!(summary.is_valid);
        // Regular arrivals should have Fano close to 1
        assert!(summary.fano_factor < 2.0);
    }

    #[test]
    fn test_mpp_bursty_events() {
        let mut mpp = MarkedPointProcess::with_defaults();

        // Create bursty pattern: clusters of events followed by gaps
        // Cluster 1
        mpp.add_event(0.0, 100.0);
        mpp.add_event(0.01, 100.0);
        mpp.add_event(0.02, 100.0);
        mpp.add_event(0.03, 100.0);
        // Gap
        // Cluster 2
        mpp.add_event(1.0, 100.0);
        mpp.add_event(1.01, 100.0);
        mpp.add_event(1.02, 100.0);
        mpp.add_event(1.03, 100.0);
        // Gap
        // Cluster 3
        mpp.add_event(2.0, 100.0);
        mpp.add_event(2.01, 100.0);
        mpp.add_event(2.02, 100.0);
        mpp.add_event(2.03, 100.0);

        let summary = mpp.summarize(3.0);
        assert!(summary.is_valid);
        // Bursty pattern should have higher CV
        assert!(summary.cv_inter_arrival > 1.0);
    }

    #[test]
    fn test_mpp_mark_distribution() {
        let mut mpp = MarkedPointProcess::with_defaults();

        // Add events with varying marks
        for i in 1..=100 {
            mpp.add_event(i as f64 * 0.01, i as f64);
        }

        let summary = mpp.summarize(1.5);
        assert!(summary.is_valid);

        // Mean should be around 50.5
        assert!((summary.mark_distribution.mean - 50.5).abs() < 1.0);
        assert_eq!(summary.mark_distribution.min, 1.0);
        assert_eq!(summary.mark_distribution.max, 100.0);
    }

    #[test]
    fn test_mpp_evidence() {
        let mut mpp = MarkedPointProcess::with_defaults();

        for i in 0..50 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }

        let evidence = mpp.evidence(5.0);

        assert!(evidence.summary.is_valid);
        assert!(!evidence.description.is_empty());
    }

    #[test]
    fn test_batch_analyzer() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();

        // Add events to different streams
        for i in 0..10 {
            analyzer.add_event("cpu", i as f64 * 0.1, 50.0);
            analyzer.add_event("io", i as f64 * 0.1, 1024.0);
        }

        let summaries = analyzer.summarize_all(1.5);
        assert_eq!(summaries.len(), 2);

        let cpu_summary = summaries.iter().find(|(n, _)| n == "cpu");
        assert!(cpu_summary.is_some());
        assert!(cpu_summary.unwrap().1.is_valid);
    }

    #[test]
    fn test_burstiness_classification() {
        let config = MppConfig::default();

        // Regular
        let level = BurstinessLevel::from_indices(1.0, 1.0, &config);
        assert_eq!(level, BurstinessLevel::Regular);

        // High
        let level = BurstinessLevel::from_indices(3.0, 1.8, &config);
        assert_eq!(level, BurstinessLevel::High);

        // Very high
        let level = BurstinessLevel::from_indices(6.0, 3.5, &config);
        assert_eq!(level, BurstinessLevel::VeryHigh);
    }

    #[test]
    fn test_mpp_reset() {
        let mut mpp = MarkedPointProcess::with_defaults();

        for i in 0..10 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }

        assert_eq!(mpp.event_count(), 10);

        mpp.reset();

        assert_eq!(mpp.event_count(), 0);
    }

    #[test]
    fn test_add_batch_with_nan_timestamps() {
        // Ensure NaN timestamps don't panic (they sort to end and are handled gracefully)
        let mut mpp = MarkedPointProcess::with_defaults();

        let events = vec![
            MarkedEvent::new(0.5, 100.0),
            MarkedEvent::new(f64::NAN, 100.0), // NaN should sort to end
            MarkedEvent::new(0.1, 100.0),
            MarkedEvent::new(0.3, 100.0),
        ];

        // This should not panic
        mpp.add_batch(&events);

        // 4 events added (NaN is processed but won't contribute valid inter-arrivals)
        assert_eq!(mpp.event_count(), 4);
    }

    #[test]
    fn test_add_batch_empty() {
        let mut mpp = MarkedPointProcess::with_defaults();
        mpp.add_batch(&[]); // Should not panic
        assert_eq!(mpp.event_count(), 0);
    }

    #[test]
    fn test_single_event_no_infinity() {
        // With only 1 event, there are no inter-arrivals
        // Ensure we don't serialize infinity values
        let config = MppConfig {
            min_events: 1, // Allow single event for this test
            min_time_span: 0.0,
            ..Default::default()
        };
        let mut mpp = MarkedPointProcess::new(config);

        mpp.add_event(0.0, 100.0);

        let summary = mpp.summarize(1.0);
        assert!(summary.is_valid);

        // Check that we don't have infinity values
        assert!(summary.inter_arrival.min.is_finite());
        assert!(summary.inter_arrival.max.is_finite());
        assert!(summary.mark_distribution.min.is_finite());
        assert!(summary.mark_distribution.max.is_finite());
    }

    // ── MppConfig ──────────────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let cfg = MppConfig::default();
        assert_eq!(cfg.min_events, 3);
        assert!((cfg.min_time_span - 0.1).abs() < f64::EPSILON);
        assert_eq!(cfg.max_stored_events, 10_000);
        assert!((cfg.fano_high_threshold - 2.0).abs() < f64::EPSILON);
        assert!((cfg.fano_very_high_threshold - 5.0).abs() < f64::EPSILON);
        assert!((cfg.cv_high_threshold - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = MppConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_events, 3);
        assert_eq!(back.max_stored_events, 10_000);
    }

    // ── BurstinessLevel ────────────────────────────────────────────

    #[test]
    fn burstiness_display() {
        assert_eq!(BurstinessLevel::Regular.to_string(), "regular");
        assert_eq!(BurstinessLevel::Mild.to_string(), "mild");
        assert_eq!(BurstinessLevel::Moderate.to_string(), "moderate");
        assert_eq!(BurstinessLevel::High.to_string(), "high");
        assert_eq!(BurstinessLevel::VeryHigh.to_string(), "very_high");
    }

    #[test]
    fn burstiness_serde() {
        for level in &[
            BurstinessLevel::Regular,
            BurstinessLevel::Mild,
            BurstinessLevel::Moderate,
            BurstinessLevel::High,
            BurstinessLevel::VeryHigh,
        ] {
            let json = serde_json::to_string(level).unwrap();
            let back: BurstinessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn burstiness_log_odds_ordering() {
        // Regular should be negative, VeryHigh should be most positive
        assert!(BurstinessLevel::Regular.log_odds_contribution() < 0.0);
        assert!((BurstinessLevel::Mild.log_odds_contribution() - 0.0).abs() < f64::EPSILON);
        assert!(BurstinessLevel::Moderate.log_odds_contribution() > 0.0);
        assert!(
            BurstinessLevel::High.log_odds_contribution()
                > BurstinessLevel::Moderate.log_odds_contribution()
        );
        assert!(
            BurstinessLevel::VeryHigh.log_odds_contribution()
                > BurstinessLevel::High.log_odds_contribution()
        );
    }

    #[test]
    fn burstiness_from_indices_mild() {
        let config = MppConfig::default();
        // Fano > 1.1, CV > 1.0 => Mild
        let level = BurstinessLevel::from_indices(1.15, 1.05, &config);
        assert_eq!(level, BurstinessLevel::Mild);
    }

    #[test]
    fn burstiness_from_indices_moderate() {
        let config = MppConfig::default();
        // Fano >= 1.5 or CV > 1.2 => Moderate
        let level = BurstinessLevel::from_indices(1.6, 0.8, &config);
        assert_eq!(level, BurstinessLevel::Moderate);
    }

    // ── MarkedEvent ────────────────────────────────────────────────

    #[test]
    fn marked_event_new() {
        let e = MarkedEvent::new(1.5, 42.0);
        assert!((e.timestamp - 1.5).abs() < f64::EPSILON);
        assert!((e.mark - 42.0).abs() < f64::EPSILON);
    }

    // ── MarkDistribution / InterArrivalStats defaults ──────────────

    #[test]
    fn mark_distribution_default() {
        let md = MarkDistribution::default();
        assert_eq!(md.count, 0);
        assert!((md.sum - 0.0).abs() < f64::EPSILON);
        assert!((md.mean - 0.0).abs() < f64::EPSILON);
        assert!(md.percentiles.is_none());
    }

    #[test]
    fn inter_arrival_default() {
        let ia = InterArrivalStats::default();
        assert_eq!(ia.count, 0);
        assert!((ia.cv - 0.0).abs() < f64::EPSILON);
        assert!(ia.percentiles.is_none());
    }

    // ── MppSummary::invalid ────────────────────────────────────────

    #[test]
    fn summary_invalid() {
        let s = MppSummary::invalid("test reason");
        assert!(!s.is_valid);
        assert_eq!(s.invalid_reason.as_deref(), Some("test reason"));
        assert_eq!(s.event_count, 0);
        assert!((s.fano_factor - 1.0).abs() < f64::EPSILON);
    }

    // ── MppEvidence ────────────────────────────────────────────────

    #[test]
    fn evidence_from_invalid_summary() {
        let summary = MppSummary::invalid("insufficient data");
        let evidence = MppEvidence::from_summary(summary);
        assert!((evidence.severity - 0.0).abs() < f64::EPSILON);
        assert!(evidence.description.contains("insufficient data"));
    }

    #[test]
    fn evidence_severity_bounded() {
        let mut mpp = MarkedPointProcess::with_defaults();
        for i in 0..50 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }
        let evidence = mpp.evidence(5.0);
        assert!(evidence.severity >= 0.0);
        assert!(evidence.severity <= 1.0);
    }

    // ── MarkedPointProcess ─────────────────────────────────────────

    #[test]
    fn mpp_add_arrays() {
        let mut mpp = MarkedPointProcess::with_defaults();
        let ts = vec![0.0, 0.1, 0.2, 0.3, 0.4];
        let marks = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        mpp.add_arrays(&ts, &marks);
        assert_eq!(mpp.event_count(), 5);
    }

    #[test]
    fn mpp_time_span_too_short() {
        let mut mpp = MarkedPointProcess::with_defaults();
        // All events at same time
        for _ in 0..5 {
            mpp.add_event(0.0, 100.0);
        }
        let summary = mpp.summarize(0.01); // Very short window
        assert!(!summary.is_valid);
    }

    #[test]
    fn mpp_mark_variance() {
        let mut mpp = MarkedPointProcess::with_defaults();
        // Constant marks should have zero variance
        for i in 0..10 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }
        let summary = mpp.summarize(1.0);
        assert!(summary.is_valid);
        assert!((summary.mark_distribution.variance - 0.0).abs() < 1e-10);
    }

    #[test]
    fn mpp_inter_arrival_cv() {
        let mut mpp = MarkedPointProcess::with_defaults();
        // Regular inter-arrivals of 0.1s
        for i in 0..20 {
            mpp.add_event(i as f64 * 0.1, 100.0);
        }
        let summary = mpp.summarize(2.0);
        assert!(summary.is_valid);
        // CV should be near 0 for perfectly regular arrivals
        assert!(summary.cv_inter_arrival < 0.1);
    }

    #[test]
    fn mpp_marked_intensity() {
        let mut mpp = MarkedPointProcess::with_defaults();
        for i in 0..10 {
            mpp.add_event(i as f64 * 0.1, 50.0);
        }
        let summary = mpp.summarize(1.0);
        assert!(summary.is_valid);
        // marked_intensity = rate * mean_mark = 10/1.0 * 50.0 = 500
        assert!((summary.marked_intensity - 500.0).abs() < 1.0);
    }

    // ── BatchMppAnalyzer ───────────────────────────────────────────

    #[test]
    fn batch_analyzer_get_or_create() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();
        analyzer.get_or_create("cpu").add_event(0.0, 50.0);
        analyzer.get_or_create("cpu").add_event(0.1, 60.0);
        assert_eq!(analyzer.get_or_create("cpu").event_count(), 2);
    }

    #[test]
    fn batch_analyzer_add_processor() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();
        analyzer.add_processor("net");
        analyzer.add_event("net", 0.0, 1024.0);
        let summaries = analyzer.summarize_all(1.0);
        assert_eq!(summaries.len(), 1);
    }

    #[test]
    fn batch_analyzer_aggregate_severity() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();
        for i in 0..10 {
            analyzer.add_event("cpu", i as f64 * 0.1, 50.0);
            analyzer.add_event("io", i as f64 * 0.1, 100.0);
        }
        let severity = analyzer.aggregate_severity(1.0);
        assert!(severity >= 0.0);
        assert!(severity <= 1.0);
    }

    #[test]
    fn batch_analyzer_empty_severity() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();
        let severity = analyzer.aggregate_severity(1.0);
        assert!((severity - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn batch_analyzer_evidence_all() {
        let mut analyzer = BatchMppAnalyzer::with_defaults();
        for i in 0..5 {
            analyzer.add_event("stream1", i as f64 * 0.1, 100.0);
        }
        let evidences = analyzer.evidence_all(1.0);
        assert_eq!(evidences.len(), 1);
        assert_eq!(evidences[0].0, "stream1");
    }

    // ── format_description ─────────────────────────────────────────

    #[test]
    fn format_description_rate_categories() {
        // Low rate
        let mut mpp = MarkedPointProcess::new(MppConfig {
            min_events: 3,
            min_time_span: 0.0,
            ..Default::default()
        });
        for i in 0..3 {
            mpp.add_event(i as f64 * 10.0, 100.0); // rate = 3/30 = 0.1
        }
        let summary = mpp.summarize(30.0);
        let evidence = MppEvidence::from_summary(summary);
        assert!(evidence.description.contains("moderate") || evidence.description.contains("low"));
    }
}
