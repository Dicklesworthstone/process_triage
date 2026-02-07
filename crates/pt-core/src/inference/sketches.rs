//! Streaming sketches and heavy-hitter summaries for high-rate events.
//!
//! This module provides memory-bounded approximate data structures for
//! summarizing high-volume event streams:
//!
//! - [`CountMinSketch`]: Approximate frequency counting with bounded error
//! - [`SpaceSaving`]: Heavy hitters / top-k frequent items
//! - [`TDigest`]: Quantile estimation with bounded memory
//!
//! # Memory Guarantees
//!
//! All sketches in this module have bounded memory independent of stream length:
//! - CountMinSketch: O(depth × width) = O(d × w)
//! - SpaceSaving: O(k) where k is the desired number of heavy hitters
//! - TDigest: O(compression) where compression controls accuracy vs memory
//!
//! # Accuracy Bounds
//!
//! - CountMinSketch: ε-approximate with δ failure probability
//!   - ε = e/width, δ = (1/2)^depth
//! - SpaceSaving: Exact for items with frequency > n/k, bounded error otherwise
//! - TDigest: Better accuracy at tails (p < 0.01 or p > 0.99)

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Errors from sketch operations.
#[derive(Debug, Error)]
pub enum SketchError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Sketch is empty")]
    Empty,

    #[error("Quantile must be between 0 and 1, got {0}")]
    InvalidQuantile(f64),

    #[error("Merge error: {0}")]
    MergeError(String),
}

/// Result type for sketch operations.
pub type SketchResult<T> = Result<T, SketchError>;

// ============================================================================
// Count-Min Sketch
// ============================================================================

/// Configuration for Count-Min Sketch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountMinConfig {
    /// Width of each hash table row. Higher = lower error.
    /// Error bound: ε ≈ e / width
    pub width: usize,

    /// Number of hash functions / rows. Higher = lower failure probability.
    /// Failure probability: δ ≈ (1/2)^depth
    pub depth: usize,
}

impl Default for CountMinConfig {
    fn default() -> Self {
        Self {
            width: 1024, // ε ≈ 0.27%
            depth: 4,    // δ ≈ 6.25%
        }
    }
}

impl CountMinConfig {
    /// Create config from desired error bounds.
    ///
    /// - `epsilon`: maximum overcount ratio (e.g., 0.01 = 1% error)
    /// - `delta`: failure probability (e.g., 0.01 = 1% chance of exceeding epsilon)
    pub fn from_error_bounds(epsilon: f64, delta: f64) -> SketchResult<Self> {
        if epsilon <= 0.0 || epsilon >= 1.0 {
            return Err(SketchError::InvalidConfig(
                "epsilon must be in (0, 1)".to_string(),
            ));
        }
        if delta <= 0.0 || delta >= 1.0 {
            return Err(SketchError::InvalidConfig(
                "delta must be in (0, 1)".to_string(),
            ));
        }

        let width = (std::f64::consts::E / epsilon).ceil() as usize;
        let depth = (1.0 / delta).ln().ceil() as usize;

        Ok(Self { width, depth })
    }

    /// Memory usage in bytes (approximate).
    pub fn memory_bytes(&self) -> usize {
        self.width * self.depth * std::mem::size_of::<u64>()
    }
}

/// Count-Min Sketch for approximate frequency counting.
///
/// A probabilistic data structure for estimating frequencies of items in a stream.
/// Space-efficient: uses O(depth × width) memory regardless of stream size.
///
/// # Error Bounds
///
/// For an item with true count `c` and total stream size `n`:
/// - Estimated count `ĉ` satisfies: `c ≤ ĉ ≤ c + εn` with probability `1 - δ`
/// - Where ε = e/width and δ = (1/2)^depth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountMinSketch {
    config: CountMinConfig,
    /// 2D array of counters [depth][width].
    counters: Vec<Vec<u64>>,
    /// Total count of all items added.
    total_count: u64,
}

impl CountMinSketch {
    /// Create a new Count-Min Sketch with the given configuration.
    pub fn new(config: CountMinConfig) -> SketchResult<Self> {
        if config.width == 0 || config.depth == 0 {
            return Err(SketchError::InvalidConfig(
                "width and depth must be positive".to_string(),
            ));
        }

        let counters = vec![vec![0u64; config.width]; config.depth];

        Ok(Self {
            config,
            counters,
            total_count: 0,
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CountMinConfig::default()).expect("default config is valid")
    }

    /// Hash a key to a position in a given row.
    fn hash_position<K: Hash>(&self, key: &K, row: usize) -> usize {
        let mut hasher = DefaultHasher::new();
        row.hash(&mut hasher); // Seed with row number for different hash functions
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.config.width
    }

    /// Add an item to the sketch with count 1.
    pub fn add<K: Hash>(&mut self, key: &K) {
        self.add_count(key, 1);
    }

    /// Add an item to the sketch with a specific count.
    pub fn add_count<K: Hash>(&mut self, key: &K, count: u64) {
        for row in 0..self.config.depth {
            let pos = self.hash_position(key, row);
            self.counters[row][pos] = self.counters[row][pos].saturating_add(count);
        }
        self.total_count = self.total_count.saturating_add(count);
    }

    /// Estimate the count of an item.
    ///
    /// Returns the minimum count across all hash positions (conservative estimate).
    pub fn estimate<K: Hash>(&self, key: &K) -> u64 {
        (0..self.config.depth)
            .map(|row| {
                let pos = self.hash_position(key, row);
                self.counters[row][pos]
            })
            .min()
            .unwrap_or(0)
    }

    /// Total count of all items added.
    pub fn total(&self) -> u64 {
        self.total_count
    }

    /// Merge another sketch into this one.
    ///
    /// Both sketches must have the same dimensions.
    pub fn merge(&mut self, other: &Self) -> SketchResult<()> {
        if self.config.width != other.config.width || self.config.depth != other.config.depth {
            return Err(SketchError::MergeError(
                "sketches must have same dimensions".to_string(),
            ));
        }

        for row in 0..self.config.depth {
            for col in 0..self.config.width {
                self.counters[row][col] =
                    self.counters[row][col].saturating_add(other.counters[row][col]);
            }
        }
        self.total_count = self.total_count.saturating_add(other.total_count);

        Ok(())
    }

    /// Clear the sketch.
    pub fn clear(&mut self) {
        for row in &mut self.counters {
            for cell in row {
                *cell = 0;
            }
        }
        self.total_count = 0;
    }

    /// Memory usage in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.config.memory_bytes()
    }
}

// ============================================================================
// Space-Saving Algorithm for Heavy Hitters
// ============================================================================

/// Configuration for Space-Saving heavy hitters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceSavingConfig {
    /// Maximum number of counters to maintain.
    /// This bounds memory usage and determines accuracy.
    /// Items with frequency > n/capacity are guaranteed to be tracked.
    pub capacity: usize,
}

impl Default for SpaceSavingConfig {
    fn default() -> Self {
        Self { capacity: 100 }
    }
}

/// A counter entry in the Space-Saving algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpaceSavingEntry<K> {
    key: K,
    count: u64,
    /// Error bound: how much the count might be overestimated.
    error: u64,
}

/// Space-Saving algorithm for heavy hitters detection.
///
/// Finds the most frequent items (heavy hitters) in a stream using bounded memory.
/// Guarantees finding all items with frequency > n/capacity.
///
/// # Space Complexity
///
/// O(capacity) memory regardless of stream length.
///
/// # Accuracy Guarantees
///
/// For capacity k and stream length n:
/// - Any item with true frequency > n/k is guaranteed to be in the output
/// - For items in the output, count is at most n/k overcounted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceSaving<K: Clone + Eq + Hash> {
    config: SpaceSavingConfig,
    /// Map from key to index in entries.
    key_to_idx: HashMap<K, usize>,
    /// The actual counter entries.
    entries: Vec<SpaceSavingEntry<K>>,
    /// Total items seen.
    total_count: u64,
}

impl<K: Clone + Eq + Hash + std::fmt::Debug> SpaceSaving<K> {
    /// Create a new Space-Saving sketch with the given configuration.
    pub fn new(config: SpaceSavingConfig) -> SketchResult<Self> {
        if config.capacity == 0 {
            return Err(SketchError::InvalidConfig(
                "capacity must be positive".to_string(),
            ));
        }

        Ok(Self {
            config,
            key_to_idx: HashMap::new(),
            entries: Vec::new(),
            total_count: 0,
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SpaceSavingConfig::default()).expect("default config is valid")
    }

    /// Add an item to the sketch.
    pub fn add(&mut self, key: K) {
        self.add_count(key, 1);
    }

    /// Add an item with a specific count.
    pub fn add_count(&mut self, key: K, count: u64) {
        self.total_count = self.total_count.saturating_add(count);

        if let Some(&idx) = self.key_to_idx.get(&key) {
            // Key exists, increment count
            self.entries[idx].count = self.entries[idx].count.saturating_add(count);
        } else if self.entries.len() < self.config.capacity {
            // Space available, add new entry
            let idx = self.entries.len();
            self.entries.push(SpaceSavingEntry {
                key: key.clone(),
                count,
                error: 0,
            });
            self.key_to_idx.insert(key, idx);
        } else {
            // At capacity, replace minimum
            let min_idx = self.find_min_idx();
            let min_count = self.entries[min_idx].count;

            // Remove old key from index
            self.key_to_idx.remove(&self.entries[min_idx].key);

            // Replace with new key, using min_count as error bound
            self.entries[min_idx] = SpaceSavingEntry {
                key: key.clone(),
                count: min_count.saturating_add(count),
                error: min_count,
            };
            self.key_to_idx.insert(key, min_idx);
        }
    }

    /// Find the index of the entry with minimum count.
    fn find_min_idx(&self) -> usize {
        self.entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.count)
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Get the estimated count for a key.
    pub fn estimate(&self, key: &K) -> u64 {
        self.key_to_idx
            .get(key)
            .map(|&idx| self.entries[idx].count)
            .unwrap_or(0)
    }

    /// Get the error bound for a key's count.
    ///
    /// The true count is guaranteed to be in [count - error, count].
    pub fn error_bound(&self, key: &K) -> u64 {
        self.key_to_idx
            .get(key)
            .map(|&idx| self.entries[idx].error)
            .unwrap_or(self.total_count / self.config.capacity as u64)
    }

    /// Get the top-k heavy hitters.
    ///
    /// Returns (key, estimated_count, error_bound) tuples sorted by count descending.
    pub fn top_k(&self, k: usize) -> Vec<HeavyHitter<K>> {
        let mut results: Vec<_> = self
            .entries
            .iter()
            .map(|e| HeavyHitter {
                key: e.key.clone(),
                count: e.count,
                error: e.error,
                frequency: if self.total_count > 0 {
                    e.count as f64 / self.total_count as f64
                } else {
                    0.0
                },
            })
            .collect();

        results.sort_by_key(|b| std::cmp::Reverse(b.count));
        results.truncate(k);
        results
    }

    /// Get all tracked items.
    pub fn all(&self) -> Vec<HeavyHitter<K>> {
        self.top_k(self.entries.len())
    }

    /// Total items seen.
    pub fn total(&self) -> u64 {
        self.total_count
    }

    /// Number of distinct items being tracked.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Memory usage in bytes (approximate).
    pub fn memory_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.entries.capacity() * std::mem::size_of::<SpaceSavingEntry<K>>()
            + self.key_to_idx.capacity() * (std::mem::size_of::<K>() + std::mem::size_of::<usize>())
    }

    /// Clear the sketch.
    pub fn clear(&mut self) {
        self.key_to_idx.clear();
        self.entries.clear();
        self.total_count = 0;
    }
}

/// A heavy hitter result from Space-Saving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeavyHitter<K> {
    /// The item key.
    pub key: K,
    /// Estimated count (may be overestimate).
    pub count: u64,
    /// Error bound: true count is in [count - error, count].
    pub error: u64,
    /// Estimated frequency (count / total).
    pub frequency: f64,
}

// ============================================================================
// T-Digest for Quantile Estimation
// ============================================================================

/// Configuration for T-Digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TDigestConfig {
    /// Compression parameter. Higher = more accurate but more memory.
    /// Typical values: 100-1000.
    pub compression: f64,
}

impl Default for TDigestConfig {
    fn default() -> Self {
        Self { compression: 200.0 }
    }
}

/// A centroid in the T-Digest.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct Centroid {
    mean: f64,
    weight: f64,
}

impl Centroid {
    fn new(mean: f64, weight: f64) -> Self {
        Self { mean, weight }
    }

    /// Merge another centroid into this one.
    fn merge(&mut self, other: &Centroid) {
        let total_weight = self.weight + other.weight;
        if total_weight > 0.0 {
            self.mean = (self.mean * self.weight + other.mean * other.weight) / total_weight;
            self.weight = total_weight;
        }
    }
}

/// T-Digest for quantile estimation.
///
/// A data structure for estimating quantiles from a stream with bounded memory.
/// Particularly accurate at the tails (low and high quantiles).
///
/// # Space Complexity
///
/// O(compression) memory regardless of stream length.
///
/// # Accuracy
///
/// Error is bounded by O(1/compression) at any quantile, with better
/// accuracy at extreme quantiles (near 0 or 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TDigest {
    config: TDigestConfig,
    /// Sorted centroids.
    centroids: Vec<Centroid>,
    /// Unprocessed buffer of (value, weight) pairs.
    buffer: Vec<(f64, f64)>,
    /// Total weight.
    total_weight: f64,
    /// Minimum value seen.
    min: f64,
    /// Maximum value seen.
    max: f64,
}

impl TDigest {
    /// Create a new T-Digest with the given configuration.
    pub fn new(config: TDigestConfig) -> SketchResult<Self> {
        if config.compression <= 0.0 {
            return Err(SketchError::InvalidConfig(
                "compression must be positive".to_string(),
            ));
        }

        Ok(Self {
            config,
            centroids: Vec::new(),
            buffer: Vec::new(),
            total_weight: 0.0,
            min: f64::MAX,
            max: f64::MIN,
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TDigestConfig::default()).expect("default config is valid")
    }

    /// Maximum buffer size before auto-merge.
    fn buffer_capacity(&self) -> usize {
        (self.config.compression * 2.0) as usize
    }

    /// Add a value to the digest.
    pub fn add(&mut self, value: f64) {
        self.add_weighted(value, 1.0);
    }

    /// Add a value with a specific weight.
    pub fn add_weighted(&mut self, value: f64, weight: f64) {
        if !value.is_finite() || !weight.is_finite() || weight <= 0.0 {
            return;
        }

        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.buffer.push((value, weight));
        self.total_weight += weight;

        if self.buffer.len() >= self.buffer_capacity() {
            self.process_buffer();
        }
    }

    /// Process the buffer and merge into centroids.
    fn process_buffer(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        // Sort buffer by value
        self.buffer
            .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Create centroids from buffer
        let new_centroids: Vec<_> = self
            .buffer
            .drain(..)
            .map(|(value, weight)| Centroid::new(value, weight))
            .collect();

        // Merge new centroids with existing
        self.merge_centroids(new_centroids);
    }

    /// Merge a sorted list of new centroids with existing centroids.
    fn merge_centroids(&mut self, new_centroids: Vec<Centroid>) {
        if new_centroids.is_empty() {
            return;
        }

        // Merge all centroids and sort
        let mut all_centroids = std::mem::take(&mut self.centroids);
        all_centroids.extend(new_centroids);
        all_centroids.sort_by(|a, b| {
            a.mean
                .partial_cmp(&b.mean)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Compress using the scale function
        self.centroids = self.compress_centroids(all_centroids);
    }

    /// Compress centroids using the T-Digest scale function.
    fn compress_centroids(&self, centroids: Vec<Centroid>) -> Vec<Centroid> {
        if centroids.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut weight_so_far = 0.0;
        let total = self.total_weight;

        let mut current = centroids[0];

        for centroid in centroids.into_iter().skip(1) {
            let proposed_weight = current.weight + centroid.weight;
            let q = (weight_so_far + proposed_weight / 2.0) / total;

            // Scale function: k = compression * (asin(2*q - 1) / pi + 0.5)
            let k_limit = self.scale_limit(q);

            if proposed_weight <= k_limit {
                // Can merge
                current.merge(&centroid);
            } else {
                // Can't merge, start new centroid
                weight_so_far += current.weight;
                result.push(current);
                current = centroid;
            }
        }

        result.push(current);
        result
    }

    /// Compute the weight limit at a given quantile.
    fn scale_limit(&self, q: f64) -> f64 {
        // Using the k_1 scale function which gives better tail accuracy
        let q = q.clamp(0.0001, 0.9999);
        let k = self.config.compression * (q * (1.0 - q)).sqrt() * 4.0;
        k.max(1.0)
    }

    /// Estimate a quantile (0 to 1).
    pub fn quantile(&mut self, q: f64) -> SketchResult<f64> {
        if !(0.0..=1.0).contains(&q) {
            return Err(SketchError::InvalidQuantile(q));
        }

        // Process any buffered values
        self.process_buffer();

        if self.centroids.is_empty() {
            return Err(SketchError::Empty);
        }

        if q == 0.0 {
            return Ok(self.min);
        }
        if q == 1.0 {
            return Ok(self.max);
        }

        // Use cumulative weight to find the right centroid
        // Each centroid represents a range centered at its mean
        let n = self.centroids.len();
        let target_weight = q * self.total_weight;

        // Build cumulative weight array where each centroid contributes weight/2
        // before and after its mean
        let mut cum_weight = Vec::with_capacity(n + 1);
        cum_weight.push(0.0);
        let mut total = 0.0;
        for c in &self.centroids {
            total += c.weight;
            cum_weight.push(total);
        }

        // Find which centroid contains the target
        let mut idx = 0;
        for i in 0..n {
            let lower = cum_weight[i];
            let upper = cum_weight[i + 1];
            if target_weight >= lower && target_weight <= upper {
                idx = i;
                break;
            }
        }

        let centroid = &self.centroids[idx];
        let lower_cum = cum_weight[idx];
        let upper_cum = cum_weight[idx + 1];

        // Interpolate within centroid's range
        let centroid_frac = if upper_cum > lower_cum {
            (target_weight - lower_cum) / (upper_cum - lower_cum)
        } else {
            0.5
        };

        // Determine the bounds for this centroid's range
        let (range_min, range_max) = if n == 1 {
            (self.min, self.max)
        } else if idx == 0 {
            // First centroid: from min to midpoint with next
            let next = &self.centroids[1];
            (self.min, (centroid.mean + next.mean) / 2.0)
        } else if idx == n - 1 {
            // Last centroid: from midpoint with prev to max
            let prev = &self.centroids[n - 2];
            ((prev.mean + centroid.mean) / 2.0, self.max)
        } else {
            // Middle centroid: midpoints with neighbors
            let prev = &self.centroids[idx - 1];
            let next = &self.centroids[idx + 1];
            (
                (prev.mean + centroid.mean) / 2.0,
                (centroid.mean + next.mean) / 2.0,
            )
        };

        Ok(range_min + centroid_frac * (range_max - range_min))
    }

    /// Estimate multiple quantiles at once (more efficient).
    pub fn quantiles(&mut self, qs: &[f64]) -> SketchResult<Vec<f64>> {
        qs.iter().map(|&q| self.quantile(q)).collect()
    }

    /// Get median (50th percentile).
    pub fn median(&mut self) -> SketchResult<f64> {
        self.quantile(0.5)
    }

    /// Get common percentiles: p50, p90, p95, p99.
    pub fn common_percentiles(&mut self) -> SketchResult<PercentileSummary> {
        Ok(PercentileSummary {
            p50: self.quantile(0.50)?,
            p75: self.quantile(0.75)?,
            p90: self.quantile(0.90)?,
            p95: self.quantile(0.95)?,
            p99: self.quantile(0.99)?,
            p999: self.quantile(0.999)?,
            min: self.min,
            max: self.max,
            count: self.total_weight as u64,
        })
    }

    /// Total number of values added.
    pub fn count(&self) -> f64 {
        self.total_weight
    }

    /// Minimum value seen.
    pub fn min(&self) -> f64 {
        self.min
    }

    /// Maximum value seen.
    pub fn max(&self) -> f64 {
        self.max
    }

    /// Number of centroids (indicates compression quality).
    pub fn centroid_count(&self) -> usize {
        self.centroids.len()
    }

    /// Merge another T-Digest into this one.
    pub fn merge(&mut self, other: &mut Self) -> SketchResult<()> {
        // Process both buffers first
        self.process_buffer();
        other.process_buffer();

        // Update bounds
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
        self.total_weight += other.total_weight;

        // Merge centroids
        let other_centroids = std::mem::take(&mut other.centroids);
        self.merge_centroids(other_centroids);

        Ok(())
    }

    /// Clear the digest.
    pub fn clear(&mut self) {
        self.centroids.clear();
        self.buffer.clear();
        self.total_weight = 0.0;
        self.min = f64::MAX;
        self.max = f64::MIN;
    }

    /// Memory usage in bytes (approximate).
    pub fn memory_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.centroids.capacity() * std::mem::size_of::<Centroid>()
            + self.buffer.capacity() * std::mem::size_of::<(f64, f64)>()
    }
}

/// Summary of common percentiles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PercentileSummary {
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
    pub min: f64,
    pub max: f64,
    pub count: u64,
}

// ============================================================================
// Combined Sketch Manager
// ============================================================================

/// Configuration for a combined sketch manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SketchManagerConfig {
    /// Count-Min Sketch config for frequency estimation.
    pub count_min: CountMinConfig,
    /// Space-Saving config for heavy hitters.
    pub space_saving: SpaceSavingConfig,
    /// T-Digest config for quantile estimation.
    pub tdigest: TDigestConfig,
}


/// Combined sketch manager for tracking multiple metrics.
///
/// Maintains:
/// - Heavy hitters for command patterns/signatures
/// - Quantile sketches for numeric metrics (CPU, memory, duration)
/// - Count-Min sketch for arbitrary key frequencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SketchManager {
    config: SketchManagerConfig,
    /// Heavy hitter tracker for command patterns.
    pub command_hitters: SpaceSaving<String>,
    /// Heavy hitter tracker for process signatures.
    pub signature_hitters: SpaceSaving<String>,
    /// Quantile sketch for CPU usage.
    pub cpu_quantiles: TDigest,
    /// Quantile sketch for memory usage.
    pub memory_quantiles: TDigest,
    /// Quantile sketch for process age.
    pub age_quantiles: TDigest,
    /// Count-Min sketch for general frequency tracking.
    pub frequency_sketch: CountMinSketch,
    /// Total events processed.
    pub total_events: u64,
}

impl SketchManager {
    /// Create a new sketch manager.
    pub fn new(config: SketchManagerConfig) -> SketchResult<Self> {
        Ok(Self {
            command_hitters: SpaceSaving::new(config.space_saving.clone())?,
            signature_hitters: SpaceSaving::new(config.space_saving.clone())?,
            cpu_quantiles: TDigest::new(config.tdigest.clone())?,
            memory_quantiles: TDigest::new(config.tdigest.clone())?,
            age_quantiles: TDigest::new(config.tdigest.clone())?,
            frequency_sketch: CountMinSketch::new(config.count_min.clone())?,
            config,
            total_events: 0,
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SketchManagerConfig::default()).expect("default config is valid")
    }

    /// Record a process event.
    pub fn record_process(
        &mut self,
        command: &str,
        signature: &str,
        cpu_percent: f64,
        memory_mb: f64,
        age_seconds: f64,
    ) {
        self.command_hitters.add(command.to_string());
        self.signature_hitters.add(signature.to_string());
        self.cpu_quantiles.add(cpu_percent);
        self.memory_quantiles.add(memory_mb);
        self.age_quantiles.add(age_seconds);
        self.frequency_sketch.add(&command);
        self.total_events += 1;
    }

    /// Get a summary of current sketch state.
    pub fn summary(&mut self) -> SketchResult<SketchSummary> {
        Ok(SketchSummary {
            total_events: self.total_events,
            top_commands: self.command_hitters.top_k(10),
            top_signatures: self.signature_hitters.top_k(10),
            cpu_percentiles: self.cpu_quantiles.common_percentiles()?,
            memory_percentiles: self.memory_quantiles.common_percentiles()?,
            age_percentiles: self.age_quantiles.common_percentiles()?,
        })
    }

    /// Memory usage in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.command_hitters.memory_bytes()
            + self.signature_hitters.memory_bytes()
            + self.cpu_quantiles.memory_bytes()
            + self.memory_quantiles.memory_bytes()
            + self.age_quantiles.memory_bytes()
            + self.frequency_sketch.memory_bytes()
    }

    /// Clear all sketches.
    pub fn clear(&mut self) {
        self.command_hitters.clear();
        self.signature_hitters.clear();
        self.cpu_quantiles.clear();
        self.memory_quantiles.clear();
        self.age_quantiles.clear();
        self.frequency_sketch.clear();
        self.total_events = 0;
    }
}

/// Summary of sketch manager state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SketchSummary {
    pub total_events: u64,
    pub top_commands: Vec<HeavyHitter<String>>,
    pub top_signatures: Vec<HeavyHitter<String>>,
    pub cpu_percentiles: PercentileSummary,
    pub memory_percentiles: PercentileSummary,
    pub age_percentiles: PercentileSummary,
}

// ============================================================================
// Evidence Integration
// ============================================================================

/// Evidence from sketch analysis for the inference engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SketchEvidence {
    /// Is this a heavy hitter command pattern?
    pub is_heavy_hitter: bool,
    /// Rank among heavy hitters (1 = most frequent).
    pub heavy_hitter_rank: Option<usize>,
    /// Estimated frequency of this command pattern.
    pub pattern_frequency: f64,
    /// CPU percentile for this process.
    pub cpu_percentile: f64,
    /// Memory percentile for this process.
    pub memory_percentile: f64,
    /// Age percentile for this process.
    pub age_percentile: f64,
    /// Description for explainability.
    pub description: String,
}

impl SketchManager {
    /// Get evidence for a specific process.
    pub fn get_evidence(
        &mut self,
        command: &str,
        cpu_percent: f64,
        memory_mb: f64,
        age_seconds: f64,
    ) -> SketchResult<SketchEvidence> {
        let top_commands = self
            .command_hitters
            .top_k(self.config.space_saving.capacity);

        let heavy_hitter_rank = top_commands
            .iter()
            .position(|h| h.key == command)
            .map(|i| i + 1);

        let pattern_frequency = if self.command_hitters.total() > 0 {
            self.command_hitters.estimate(&command.to_string()) as f64
                / self.command_hitters.total() as f64
        } else {
            0.0
        };

        // Estimate percentiles by comparing to quantile sketch
        let cpu_percentile =
            self.estimate_percentile(&mut self.cpu_quantiles.clone(), cpu_percent)?;
        let memory_percentile =
            self.estimate_percentile(&mut self.memory_quantiles.clone(), memory_mb)?;
        let age_percentile =
            self.estimate_percentile(&mut self.age_quantiles.clone(), age_seconds)?;

        let description = if let Some(rank) = heavy_hitter_rank {
            format!(
                "Heavy hitter (rank {}), CPU p{:.0}, mem p{:.0}, age p{:.0}",
                rank,
                cpu_percentile * 100.0,
                memory_percentile * 100.0,
                age_percentile * 100.0
            )
        } else {
            format!(
                "Rare pattern, CPU p{:.0}, mem p{:.0}, age p{:.0}",
                cpu_percentile * 100.0,
                memory_percentile * 100.0,
                age_percentile * 100.0
            )
        };

        Ok(SketchEvidence {
            is_heavy_hitter: heavy_hitter_rank.is_some(),
            heavy_hitter_rank,
            pattern_frequency,
            cpu_percentile,
            memory_percentile,
            age_percentile,
            description,
        })
    }

    /// Estimate what percentile a value falls at.
    fn estimate_percentile(&self, digest: &mut TDigest, value: f64) -> SketchResult<f64> {
        // Binary search to find approximate percentile
        let mut low = 0.0;
        let mut high = 1.0;

        for _ in 0..20 {
            // 20 iterations gives ~1e-6 precision
            let mid = (low + high) / 2.0;
            let mid_value = digest.quantile(mid)?;

            if value < mid_value {
                high = mid;
            } else {
                low = mid;
            }
        }

        Ok((low + high) / 2.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Count-Min Sketch Tests
    // ========================================================================

    #[test]
    fn test_count_min_basic() {
        let mut cms = CountMinSketch::with_defaults();

        cms.add(&"foo");
        cms.add(&"foo");
        cms.add(&"bar");

        assert_eq!(cms.estimate(&"foo"), 2);
        assert_eq!(cms.estimate(&"bar"), 1);
        assert_eq!(cms.estimate(&"baz"), 0);
        assert_eq!(cms.total(), 3);
    }

    #[test]
    fn test_count_min_with_count() {
        let mut cms = CountMinSketch::with_defaults();

        cms.add_count(&"foo", 100);
        cms.add_count(&"bar", 50);

        assert_eq!(cms.estimate(&"foo"), 100);
        assert_eq!(cms.estimate(&"bar"), 50);
        assert_eq!(cms.total(), 150);
    }

    #[test]
    fn test_count_min_merge() {
        let mut cms1 = CountMinSketch::with_defaults();
        let mut cms2 = CountMinSketch::with_defaults();

        cms1.add(&"foo");
        cms1.add(&"foo");

        cms2.add(&"foo");
        cms2.add(&"bar");

        cms1.merge(&cms2).unwrap();

        assert_eq!(cms1.estimate(&"foo"), 3);
        assert_eq!(cms1.estimate(&"bar"), 1);
        assert_eq!(cms1.total(), 4);
    }

    #[test]
    fn test_count_min_from_error_bounds() {
        let config = CountMinConfig::from_error_bounds(0.01, 0.01).unwrap();
        assert!(config.width >= 272); // e / 0.01 ≈ 272
        assert!(config.depth >= 5); // ln(1/0.01) ≈ 4.6
    }

    #[test]
    fn test_count_min_clear() {
        let mut cms = CountMinSketch::with_defaults();
        cms.add(&"foo");
        cms.clear();

        assert_eq!(cms.estimate(&"foo"), 0);
        assert_eq!(cms.total(), 0);
    }

    // ========================================================================
    // Space-Saving Tests
    // ========================================================================

    #[test]
    fn test_space_saving_basic() {
        let mut ss: SpaceSaving<String> = SpaceSaving::with_defaults();

        for _ in 0..100 {
            ss.add("frequent".to_string());
        }
        for _ in 0..10 {
            ss.add("less_frequent".to_string());
        }
        ss.add("rare".to_string());

        let top = ss.top_k(3);
        assert!(!top.is_empty());
        assert_eq!(top[0].key, "frequent");
        assert_eq!(top[0].count, 100);
    }

    #[test]
    fn test_space_saving_eviction() {
        let config = SpaceSavingConfig { capacity: 3 };
        let mut ss: SpaceSaving<String> = SpaceSaving::new(config).unwrap();

        ss.add("a".to_string());
        ss.add("b".to_string());
        ss.add("c".to_string());
        ss.add("d".to_string()); // Should evict minimum

        assert_eq!(ss.tracked_count(), 3);
    }

    #[test]
    fn test_space_saving_frequency() {
        let mut ss: SpaceSaving<String> = SpaceSaving::with_defaults();

        for _ in 0..80 {
            ss.add("a".to_string());
        }
        for _ in 0..20 {
            ss.add("b".to_string());
        }

        let top = ss.top_k(2);
        assert!((top[0].frequency - 0.8).abs() < 0.01);
        assert!((top[1].frequency - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_space_saving_error_bound() {
        let mut ss: SpaceSaving<String> = SpaceSaving::with_defaults();

        ss.add("foo".to_string());
        let error = ss.error_bound(&"foo".to_string());
        assert_eq!(error, 0); // No evictions yet
    }

    // ========================================================================
    // T-Digest Tests
    // ========================================================================

    #[test]
    fn test_tdigest_basic() {
        let mut td = TDigest::with_defaults();

        for i in 1..=100 {
            td.add(i as f64);
        }

        let median = td.median().unwrap();
        assert!((median - 50.0).abs() < 2.0); // Should be close to 50

        let p99 = td.quantile(0.99).unwrap();
        assert!((p99 - 99.0).abs() < 2.0); // Should be close to 99
    }

    #[test]
    fn test_tdigest_min_max() {
        let mut td = TDigest::with_defaults();

        td.add(10.0);
        td.add(20.0);
        td.add(30.0);

        assert_eq!(td.min(), 10.0);
        assert_eq!(td.max(), 30.0);
    }

    #[test]
    fn test_tdigest_common_percentiles() {
        let mut td = TDigest::with_defaults();

        for i in 1..=1000 {
            td.add(i as f64);
        }

        let summary = td.common_percentiles().unwrap();
        assert!((summary.p50 - 500.0).abs() < 20.0);
        assert!((summary.p90 - 900.0).abs() < 20.0);
        assert!((summary.p99 - 990.0).abs() < 20.0);
    }

    #[test]
    fn test_tdigest_empty() {
        let mut td = TDigest::with_defaults();
        assert!(td.median().is_err());
    }

    #[test]
    fn test_tdigest_single_value() {
        let mut td = TDigest::with_defaults();
        td.add(42.0);

        assert_eq!(td.quantile(0.0).unwrap(), 42.0);
        assert_eq!(td.quantile(0.5).unwrap(), 42.0);
        assert_eq!(td.quantile(1.0).unwrap(), 42.0);
    }

    #[test]
    fn test_tdigest_merge() {
        let mut td1 = TDigest::with_defaults();
        let mut td2 = TDigest::with_defaults();

        for i in 1..=50 {
            td1.add(i as f64);
        }
        for i in 51..=100 {
            td2.add(i as f64);
        }

        td1.merge(&mut td2).unwrap();

        assert_eq!(td1.min(), 1.0);
        assert_eq!(td1.max(), 100.0);
        assert!((td1.count() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_tdigest_invalid_quantile() {
        let mut td = TDigest::with_defaults();
        td.add(1.0);

        assert!(td.quantile(-0.1).is_err());
        assert!(td.quantile(1.1).is_err());
    }

    // ========================================================================
    // Sketch Manager Tests
    // ========================================================================

    #[test]
    fn test_sketch_manager_basic() {
        let mut mgr = SketchManager::with_defaults();

        mgr.record_process("python test.py", "python-test", 25.0, 100.0, 3600.0);
        mgr.record_process("python test.py", "python-test", 30.0, 120.0, 3700.0);
        mgr.record_process("node server.js", "node-server", 50.0, 200.0, 86400.0);

        assert_eq!(mgr.total_events, 3);

        let summary = mgr.summary().unwrap();
        assert!(!summary.top_commands.is_empty());
        assert_eq!(summary.top_commands[0].key, "python test.py");
    }

    #[test]
    fn test_sketch_manager_evidence() {
        let mut mgr = SketchManager::with_defaults();

        // Add baseline data
        for _ in 0..100 {
            mgr.record_process("common_cmd", "sig1", 10.0, 50.0, 1000.0);
        }
        mgr.record_process("rare_cmd", "sig2", 90.0, 500.0, 100000.0);

        // Get evidence for heavy hitter
        let ev1 = mgr.get_evidence("common_cmd", 10.0, 50.0, 1000.0).unwrap();
        assert!(ev1.is_heavy_hitter);
        assert_eq!(ev1.heavy_hitter_rank, Some(1));

        // Get evidence for rare command
        let ev2 = mgr.get_evidence("rare_cmd", 90.0, 500.0, 100000.0).unwrap();
        assert!(ev2.cpu_percentile > 0.9); // High CPU compared to baseline
    }

    #[test]
    fn test_sketch_manager_clear() {
        let mut mgr = SketchManager::with_defaults();

        mgr.record_process("test", "sig", 10.0, 50.0, 1000.0);
        mgr.clear();

        assert_eq!(mgr.total_events, 0);
    }

    // ========================================================================
    // Memory Bounds Tests
    // ========================================================================

    #[test]
    fn test_memory_bounded() {
        let mut cms = CountMinSketch::with_defaults();
        let initial_mem = cms.memory_bytes();

        // Add many items
        for i in 0..10_000 {
            cms.add(&format!("key_{}", i));
        }

        // Memory should not have grown significantly
        assert_eq!(cms.memory_bytes(), initial_mem);
    }

    #[test]
    fn test_tdigest_compression() {
        let mut td = TDigest::with_defaults();

        // Add many values
        for i in 0..100_000 {
            td.add(i as f64);
        }

        // Should have bounded centroids
        assert!(td.centroid_count() < 1000);
    }
}
