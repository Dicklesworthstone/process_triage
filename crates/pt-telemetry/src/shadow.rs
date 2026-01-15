//! Shadow mode observation storage.
//!
//! This module provides storage for shadow mode observations with:
//! - Tiered retention (hot, warm, cold, archive)
//! - Efficient queries by PID, identity hash, and time range
//! - Automatic compaction and cleanup
//!
//! # Retention Tiers
//!
//! - **Hot** (< 1 hour): Full resolution, all observations
//! - **Warm** (1 hour - 1 day): Sampled to 1-minute intervals
//! - **Cold** (1 day - 7 days): Sampled to 5-minute intervals, compressed
//! - **Archive** (> 7 days): Summary statistics only, or delete
//!
//! # Example
//!
//! ```no_run
//! use pt_telemetry::shadow::{ShadowStorage, ShadowStorageConfig, Observation};
//!
//! let config = ShadowStorageConfig::default();
//! let mut storage = ShadowStorage::new(config).unwrap();
//!
//! // Record an observation
//! storage.record(Observation {
//!     pid: 1234,
//!     identity_hash: "abc123".to_string(),
//!     // ... other fields
//!     ..Default::default()
//! }).unwrap();
//!
//! // Query current state
//! let state = storage.get_current_state(1234);
//! ```

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::time::Duration;

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from shadow storage operations.
#[derive(Error, Debug)]
pub enum ShadowStorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[error("Arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Storage not initialized")]
    NotInitialized,

    #[error("Observation not found for PID {0}")]
    NotFound(u32),

    #[error("Invalid retention tier: {0}")]
    InvalidTier(String),
}

/// Retention tier for observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionTier {
    /// Full resolution, last hour.
    Hot,
    /// 1-minute intervals, 1 hour to 1 day.
    Warm,
    /// 5-minute intervals, 1 to 7 days.
    Cold,
    /// Summary only, > 7 days.
    Archive,
}

impl RetentionTier {
    /// Get the sample interval for this tier.
    pub fn sample_interval(&self) -> Duration {
        match self {
            RetentionTier::Hot => Duration::from_secs(0), // No sampling
            RetentionTier::Warm => Duration::from_secs(60),
            RetentionTier::Cold => Duration::from_secs(300),
            RetentionTier::Archive => Duration::from_secs(3600),
        }
    }

    /// Get the maximum age for this tier.
    pub fn max_age(&self) -> Duration {
        match self {
            RetentionTier::Hot => Duration::from_secs(3600),         // 1 hour
            RetentionTier::Warm => Duration::from_secs(86400),       // 1 day
            RetentionTier::Cold => Duration::from_secs(604800),      // 7 days
            RetentionTier::Archive => Duration::from_secs(2592000),  // 30 days
        }
    }

    /// Get the tier for a given age.
    pub fn for_age(age: Duration) -> Self {
        if age < Duration::from_secs(3600) {
            RetentionTier::Hot
        } else if age < Duration::from_secs(86400) {
            RetentionTier::Warm
        } else if age < Duration::from_secs(604800) {
            RetentionTier::Cold
        } else {
            RetentionTier::Archive
        }
    }
}

/// Configuration for shadow storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowStorageConfig {
    /// Base directory for storage.
    pub base_dir: PathBuf,

    /// Host ID for partitioning.
    pub host_id: String,

    /// Maximum observations per day (for scaling).
    pub max_observations_per_day: usize,

    /// Enable automatic compaction.
    pub auto_compact: bool,

    /// Compaction check interval in seconds.
    pub compact_interval_secs: u64,

    /// Whether to delete archived observations beyond max_age.
    pub delete_expired: bool,

    /// In-memory cache size (number of recent observations per PID).
    pub cache_size_per_pid: usize,
}

impl Default for ShadowStorageConfig {
    fn default() -> Self {
        ShadowStorageConfig {
            base_dir: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("process_triage")
                .join("shadow"),
            host_id: hostname_or_default(),
            max_observations_per_day: 100_000,
            auto_compact: true,
            compact_interval_secs: 300, // 5 minutes
            delete_expired: true,
            cache_size_per_pid: 10,
        }
    }
}

/// A single observation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// When the observation was made.
    pub timestamp: DateTime<Utc>,

    /// Process ID (may be reused).
    pub pid: u32,

    /// Hash of (exe, args, user) for tracking across PID reuse.
    pub identity_hash: String,

    /// Resource usage snapshot.
    pub state: StateSnapshot,

    /// Events since last observation.
    pub events: Vec<ProcessEvent>,

    /// Current belief state (posterior distribution).
    pub belief: BeliefState,
}

impl Default for Observation {
    fn default() -> Self {
        Observation {
            timestamp: Utc::now(),
            pid: 0,
            identity_hash: String::new(),
            state: StateSnapshot::default(),
            events: Vec::new(),
            belief: BeliefState::default(),
        }
    }
}

/// Resource usage snapshot at observation time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// CPU percentage (0-100+).
    pub cpu_percent: f32,

    /// Memory in bytes.
    pub memory_bytes: u64,

    /// Resident set size in bytes.
    pub rss_bytes: u64,

    /// Number of open file descriptors.
    pub fd_count: u32,

    /// Number of threads.
    pub thread_count: u32,

    /// Process state character (R, S, D, Z, T, etc.).
    pub state_char: char,

    /// I/O read bytes since start.
    pub io_read_bytes: u64,

    /// I/O write bytes since start.
    pub io_write_bytes: u64,

    /// Whether process has a controlling TTY.
    pub has_tty: bool,

    /// Number of child processes.
    pub child_count: u32,
}

/// An event that occurred since the last observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,

    /// Event type.
    pub event_type: EventType,

    /// Event-specific details.
    pub details: Option<String>,
}

/// Types of events that can be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Process spawned a child.
    ChildSpawned,
    /// Process's child exited.
    ChildExited,
    /// CPU spike detected.
    CpuSpike,
    /// Memory spike detected.
    MemorySpike,
    /// I/O spike detected.
    IoSpike,
    /// Process state changed.
    StateChange,
    /// Network activity detected.
    NetworkActivity,
    /// File descriptor count changed significantly.
    FdChange,
    /// Process became orphan.
    BecameOrphan,
    /// Supervisor detected.
    SupervisorDetected,
}

/// Belief state (posterior distribution over process classes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeliefState {
    /// P(abandoned | evidence).
    pub p_abandoned: f32,

    /// P(legitimate | evidence).
    pub p_legitimate: f32,

    /// P(zombie | evidence).
    pub p_zombie: f32,

    /// P(useful_but_bad | evidence).
    pub p_useful_but_bad: f32,

    /// Confidence score (0-1).
    pub confidence: f32,

    /// Score for UI display (0-100).
    pub score: f32,

    /// Recommendation based on belief.
    pub recommendation: String,
}

impl Default for BeliefState {
    fn default() -> Self {
        BeliefState {
            p_abandoned: 0.25,
            p_legitimate: 0.25,
            p_zombie: 0.25,
            p_useful_but_bad: 0.25,
            confidence: 0.0,
            score: 0.0,
            recommendation: "unknown".to_string(),
        }
    }
}

/// Summary statistics for archived observations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationSummary {
    /// Identity hash for the process.
    pub identity_hash: String,

    /// First observation timestamp.
    pub first_seen: DateTime<Utc>,

    /// Last observation timestamp.
    pub last_seen: DateTime<Utc>,

    /// Number of observations.
    pub observation_count: u64,

    /// Average CPU usage.
    pub avg_cpu_percent: f32,

    /// Max CPU usage.
    pub max_cpu_percent: f32,

    /// Average memory usage.
    pub avg_memory_bytes: u64,

    /// Max memory usage.
    pub max_memory_bytes: u64,

    /// Total events recorded.
    pub event_count: u64,

    /// Final belief state.
    pub final_belief: BeliefState,
}

/// Query result for observation history.
#[derive(Debug, Clone)]
pub struct HistoryResult {
    /// Identity hash.
    pub identity_hash: String,

    /// Observations in time order.
    pub observations: Vec<Observation>,

    /// Time range covered.
    pub time_range: (DateTime<Utc>, DateTime<Utc>),

    /// Whether results were truncated.
    pub truncated: bool,
}

/// Query result for events.
#[derive(Debug, Clone)]
pub struct EventsResult {
    /// Events in time order.
    pub events: Vec<(u32, ProcessEvent)>, // (pid, event)

    /// Time range covered.
    pub time_range: (DateTime<Utc>, DateTime<Utc>),

    /// Whether results were truncated.
    pub truncated: bool,
}

/// Query result for processes above score threshold.
#[derive(Debug, Clone)]
pub struct ScoreResult {
    /// PIDs with scores above threshold.
    pub processes: Vec<(u32, f32)>, // (pid, score)

    /// Query timestamp.
    pub query_time: DateTime<Utc>,
}

/// Shadow mode observation storage.
pub struct ShadowStorage {
    config: ShadowStorageConfig,

    /// In-memory cache: PID -> recent observations.
    hot_cache: HashMap<u32, Vec<Observation>>,

    /// Index: identity_hash -> list of PIDs that used this identity.
    identity_index: HashMap<String, Vec<u32>>,

    /// Index: PID -> current identity_hash.
    pid_to_identity: HashMap<u32, String>,

    /// Statistics.
    stats: StorageStats,

    /// Last compaction time.
    last_compact: DateTime<Utc>,
}

/// Storage statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total observations recorded.
    pub total_observations: u64,

    /// Observations in hot tier.
    pub hot_observations: u64,

    /// Observations in warm tier.
    pub warm_observations: u64,

    /// Observations in cold tier.
    pub cold_observations: u64,

    /// Observations in archive tier.
    pub archive_observations: u64,

    /// Unique PIDs tracked.
    pub unique_pids: u64,

    /// Unique identity hashes.
    pub unique_identities: u64,

    /// Total events recorded.
    pub total_events: u64,

    /// Last compaction time.
    pub last_compact: Option<DateTime<Utc>>,

    /// Disk usage in bytes.
    pub disk_usage_bytes: u64,
}

impl ShadowStorage {
    /// Create a new shadow storage instance.
    pub fn new(config: ShadowStorageConfig) -> Result<Self, ShadowStorageError> {
        // Create storage directories
        fs::create_dir_all(&config.base_dir)?;
        fs::create_dir_all(config.base_dir.join("hot"))?;
        fs::create_dir_all(config.base_dir.join("warm"))?;
        fs::create_dir_all(config.base_dir.join("cold"))?;
        fs::create_dir_all(config.base_dir.join("archive"))?;

        let mut storage = ShadowStorage {
            config,
            hot_cache: HashMap::new(),
            identity_index: HashMap::new(),
            pid_to_identity: HashMap::new(),
            stats: StorageStats::default(),
            last_compact: Utc::now(),
        };

        // Load existing stats if available
        storage.load_stats()?;

        Ok(storage)
    }

    /// Record a new observation.
    pub fn record(&mut self, obs: Observation) -> Result<(), ShadowStorageError> {
        let pid = obs.pid;
        let identity = obs.identity_hash.clone();

        // Update indices (only add PID to identity index if not already present)
        self.pid_to_identity.insert(pid, identity.clone());
        let pids = self.identity_index.entry(identity).or_default();
        if !pids.contains(&pid) {
            pids.push(pid);
        }

        // Update stats
        self.stats.total_observations += 1;
        self.stats.hot_observations += 1;
        self.stats.total_events += obs.events.len() as u64;

        // Add to hot cache
        let cache = self.hot_cache.entry(pid).or_default();
        cache.push(obs);

        // Trim cache if needed
        let max_size = self.config.cache_size_per_pid;
        if cache.len() > max_size * 2 {
            cache.drain(0..max_size);
        }

        // Check if compaction is needed
        if self.config.auto_compact {
            let elapsed = Utc::now()
                .signed_duration_since(self.last_compact)
                .num_seconds() as u64;
            if elapsed >= self.config.compact_interval_secs {
                self.compact()?;
            }
        }

        Ok(())
    }

    /// Get current state for a PID.
    pub fn get_current_state(&self, pid: u32) -> Option<&Observation> {
        self.hot_cache.get(&pid).and_then(|obs| obs.last())
    }

    /// Get history for an identity hash within a time range.
    pub fn get_history(
        &self,
        identity_hash: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> HistoryResult {
        let mut observations = Vec::new();
        let mut truncated = false;

        // Check hot cache for matching PIDs
        if let Some(pids) = self.identity_index.get(identity_hash) {
            for &pid in pids {
                if let Some(cache) = self.hot_cache.get(&pid) {
                    for obs in cache {
                        if obs.timestamp >= start && obs.timestamp <= end {
                            observations.push(obs.clone());
                            if observations.len() >= limit {
                                truncated = true;
                                break;
                            }
                        }
                    }
                }
                if truncated {
                    break;
                }
            }
        }

        // Sort by timestamp
        observations.sort_by_key(|o| o.timestamp);

        HistoryResult {
            identity_hash: identity_hash.to_string(),
            observations,
            time_range: (start, end),
            truncated,
        }
    }

    /// Get all events within a time range.
    pub fn get_events(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> EventsResult {
        let mut events = Vec::new();
        let mut truncated = false;

        for (&pid, cache) in &self.hot_cache {
            for obs in cache {
                if obs.timestamp >= start && obs.timestamp <= end {
                    for event in &obs.events {
                        events.push((pid, event.clone()));
                        if events.len() >= limit {
                            truncated = true;
                            break;
                        }
                    }
                }
                if truncated {
                    break;
                }
            }
            if truncated {
                break;
            }
        }

        // Sort by timestamp
        events.sort_by_key(|(_, e)| e.timestamp);

        EventsResult {
            events,
            time_range: (start, end),
            truncated,
        }
    }

    /// Get processes with scores above threshold.
    pub fn get_by_score(&self, threshold: f32) -> ScoreResult {
        let mut processes = Vec::new();

        for (&pid, cache) in &self.hot_cache {
            if let Some(obs) = cache.last() {
                if obs.belief.score >= threshold {
                    processes.push((pid, obs.belief.score));
                }
            }
        }

        // Sort by score descending
        processes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        ScoreResult {
            processes,
            query_time: Utc::now(),
        }
    }

    /// Compact observations according to retention tiers.
    pub fn compact(&mut self) -> Result<(), ShadowStorageError> {
        let now = Utc::now();
        let hot_cutoff = now - chrono::Duration::seconds(3600);
        let warm_cutoff = now - chrono::Duration::seconds(86400);
        let cold_cutoff = now - chrono::Duration::seconds(604800);

        // Collect observations to persist (avoiding borrow checker issues)
        let mut to_persist: Vec<(u32, Vec<Observation>, RetentionTier)> = Vec::new();
        let mut archive_count = 0u64;

        // Process hot cache
        for (pid, cache) in self.hot_cache.iter_mut() {
            // Partition by age
            let (hot, older): (Vec<_>, Vec<_>) = cache
                .drain(..)
                .partition(|o| o.timestamp >= hot_cutoff);

            // Keep hot observations in cache
            *cache = hot;

            // Downsample older observations
            if !older.is_empty() {
                let warm_interval = Duration::from_secs(60);
                let cold_interval = Duration::from_secs(300);

                let mut warm_obs = Vec::new();
                let mut cold_obs = Vec::new();

                let mut last_warm_ts: Option<DateTime<Utc>> = None;
                let mut last_cold_ts: Option<DateTime<Utc>> = None;

                for obs in older {
                    if obs.timestamp >= warm_cutoff {
                        // Warm tier: sample at 1-minute intervals
                        let should_keep = last_warm_ts.map_or(true, |last| {
                            obs.timestamp.signed_duration_since(last).num_seconds()
                                >= warm_interval.as_secs() as i64
                        });
                        if should_keep {
                            last_warm_ts = Some(obs.timestamp);
                            warm_obs.push(obs);
                        }
                    } else if obs.timestamp >= cold_cutoff {
                        // Cold tier: sample at 5-minute intervals
                        let should_keep = last_cold_ts.map_or(true, |last| {
                            obs.timestamp.signed_duration_since(last).num_seconds()
                                >= cold_interval.as_secs() as i64
                        });
                        if should_keep {
                            last_cold_ts = Some(obs.timestamp);
                            cold_obs.push(obs);
                        }
                    } else {
                        // Archive tier: just count, don't keep individual observations
                        archive_count += 1;
                    }
                }

                // Collect for persistence
                if !warm_obs.is_empty() {
                    to_persist.push((*pid, warm_obs, RetentionTier::Warm));
                }
                if !cold_obs.is_empty() {
                    to_persist.push((*pid, cold_obs, RetentionTier::Cold));
                }
            }
        }

        // Now persist collected observations (outside the borrow)
        for (pid, obs, tier) in to_persist {
            let count = obs.len() as u64;
            self.persist_observations(pid, &obs, tier)?;
            match tier {
                RetentionTier::Warm => self.stats.warm_observations += count,
                RetentionTier::Cold => self.stats.cold_observations += count,
                _ => {}
            }
        }
        self.stats.archive_observations += archive_count;

        // Update stats
        self.stats.hot_observations = self
            .hot_cache
            .values()
            .map(|v| v.len() as u64)
            .sum();
        self.stats.unique_pids = self.hot_cache.len() as u64;
        self.stats.unique_identities = self.identity_index.len() as u64;
        self.stats.last_compact = Some(now);
        self.last_compact = now;

        // Save stats
        self.save_stats()?;

        Ok(())
    }

    /// Persist observations to disk.
    fn persist_observations(
        &self,
        pid: u32,
        observations: &[Observation],
        tier: RetentionTier,
    ) -> Result<(), ShadowStorageError> {
        if observations.is_empty() {
            return Ok(());
        }

        let tier_dir = match tier {
            RetentionTier::Hot => "hot",
            RetentionTier::Warm => "warm",
            RetentionTier::Cold => "cold",
            RetentionTier::Archive => "archive",
        };

        let now = Utc::now();
        let path = self
            .config
            .base_dir
            .join(tier_dir)
            .join(format!("pid_{}", pid))
            .join(format!("{}_{}.json", now.format("%Y%m%d_%H%M%S"), pid));

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, observations)?;

        Ok(())
    }

    /// Load storage stats from disk.
    fn load_stats(&mut self) -> Result<(), ShadowStorageError> {
        let stats_path = self.config.base_dir.join("stats.json");
        if stats_path.exists() {
            let file = File::open(&stats_path)?;
            let reader = BufReader::new(file);
            self.stats = serde_json::from_reader(reader)?;
        }
        Ok(())
    }

    /// Save storage stats to disk.
    fn save_stats(&self) -> Result<(), ShadowStorageError> {
        let stats_path = self.config.base_dir.join("stats.json");
        let file = File::create(&stats_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.stats)?;
        Ok(())
    }

    /// Get current storage statistics.
    pub fn stats(&self) -> &StorageStats {
        &self.stats
    }

    /// Get the configuration.
    pub fn config(&self) -> &ShadowStorageConfig {
        &self.config
    }

    /// Get the number of PIDs currently tracked.
    pub fn tracked_pids(&self) -> usize {
        self.hot_cache.len()
    }

    /// Get the number of unique identities.
    pub fn unique_identities(&self) -> usize {
        self.identity_index.len()
    }

    /// Flush all pending writes.
    pub fn flush(&mut self) -> Result<(), ShadowStorageError> {
        self.compact()?;
        self.save_stats()?;
        Ok(())
    }

    /// Clean up expired data.
    pub fn cleanup(&mut self) -> Result<u64, ShadowStorageError> {
        let mut cleaned = 0u64;

        if !self.config.delete_expired {
            return Ok(0);
        }

        let archive_max = RetentionTier::Archive.max_age();
        let cutoff = Utc::now() - chrono::Duration::from_std(archive_max).unwrap_or_default();

        // Clean up archive directory
        let archive_dir = self.config.base_dir.join("archive");
        if archive_dir.exists() {
            for entry in fs::read_dir(&archive_dir)? {
                let entry = entry?;
                let metadata = entry.metadata()?;
                if let Ok(modified) = metadata.modified() {
                    let modified_dt = DateTime::<Utc>::from(modified);
                    if modified_dt < cutoff {
                        if entry.path().is_file() {
                            fs::remove_file(entry.path())?;
                            cleaned += 1;
                        } else if entry.path().is_dir() {
                            fs::remove_dir_all(entry.path())?;
                            cleaned += 1;
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }
}

/// Helper to get hostname or a default value.
fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Arrow schema for shadow observations (for Parquet storage).
pub fn shadow_observations_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("pid", DataType::UInt32, false),
        Field::new("identity_hash", DataType::Utf8, false),
        // State snapshot
        Field::new("cpu_percent", DataType::Float32, false),
        Field::new("memory_bytes", DataType::UInt64, false),
        Field::new("rss_bytes", DataType::UInt64, false),
        Field::new("fd_count", DataType::UInt32, false),
        Field::new("thread_count", DataType::UInt32, false),
        Field::new("state_char", DataType::Utf8, false),
        Field::new("io_read_bytes", DataType::UInt64, false),
        Field::new("io_write_bytes", DataType::UInt64, false),
        Field::new("has_tty", DataType::Boolean, false),
        Field::new("child_count", DataType::UInt32, false),
        // Belief state
        Field::new("p_abandoned", DataType::Float32, false),
        Field::new("p_legitimate", DataType::Float32, false),
        Field::new("p_zombie", DataType::Float32, false),
        Field::new("p_useful_but_bad", DataType::Float32, false),
        Field::new("belief_confidence", DataType::Float32, false),
        Field::new("belief_score", DataType::Float32, false),
        Field::new("recommendation", DataType::Utf8, false),
        // Events (stored as JSON array)
        Field::new("events_json", DataType::Utf8, true),
        // Retention tier
        Field::new("retention_tier", DataType::Utf8, false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_retention_tier_for_age() {
        assert_eq!(
            RetentionTier::for_age(Duration::from_secs(30)),
            RetentionTier::Hot
        );
        assert_eq!(
            RetentionTier::for_age(Duration::from_secs(3601)),
            RetentionTier::Warm
        );
        assert_eq!(
            RetentionTier::for_age(Duration::from_secs(86401)),
            RetentionTier::Cold
        );
        assert_eq!(
            RetentionTier::for_age(Duration::from_secs(604801)),
            RetentionTier::Archive
        );
    }

    #[test]
    fn test_retention_tier_sample_interval() {
        assert_eq!(
            RetentionTier::Hot.sample_interval(),
            Duration::from_secs(0)
        );
        assert_eq!(
            RetentionTier::Warm.sample_interval(),
            Duration::from_secs(60)
        );
        assert_eq!(
            RetentionTier::Cold.sample_interval(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn test_default_config() {
        let config = ShadowStorageConfig::default();
        assert_eq!(config.max_observations_per_day, 100_000);
        assert!(config.auto_compact);
        assert_eq!(config.compact_interval_secs, 300);
    }

    #[test]
    fn test_storage_new() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let storage = ShadowStorage::new(config).unwrap();
        assert_eq!(storage.tracked_pids(), 0);
        assert_eq!(storage.unique_identities(), 0);
    }

    #[test]
    fn test_storage_record_and_query() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            auto_compact: false,
            ..Default::default()
        };

        let mut storage = ShadowStorage::new(config).unwrap();

        // Record an observation
        let obs = Observation {
            timestamp: Utc::now(),
            pid: 1234,
            identity_hash: "test_hash_abc123".to_string(),
            state: StateSnapshot {
                cpu_percent: 50.0,
                memory_bytes: 1_000_000,
                ..Default::default()
            },
            belief: BeliefState {
                score: 75.0,
                ..Default::default()
            },
            ..Default::default()
        };

        storage.record(obs).unwrap();

        // Query current state
        let state = storage.get_current_state(1234);
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.pid, 1234);
        assert_eq!(state.state.cpu_percent, 50.0);

        // Query by score
        let score_result = storage.get_by_score(50.0);
        assert_eq!(score_result.processes.len(), 1);
        assert_eq!(score_result.processes[0].0, 1234);
    }

    #[test]
    fn test_storage_history_query() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            auto_compact: false,
            ..Default::default()
        };

        let mut storage = ShadowStorage::new(config).unwrap();
        let identity = "test_identity_xyz";

        // Record multiple observations
        for i in 0..5 {
            let obs = Observation {
                timestamp: Utc::now() - chrono::Duration::minutes(i),
                pid: 1234,
                identity_hash: identity.to_string(),
                ..Default::default()
            };
            storage.record(obs).unwrap();
        }

        // Query history
        let history = storage.get_history(
            identity,
            Utc::now() - chrono::Duration::hours(1),
            Utc::now(),
            100,
        );

        assert_eq!(history.identity_hash, identity);
        assert_eq!(history.observations.len(), 5);
        assert!(!history.truncated);
    }

    #[test]
    fn test_storage_events_query() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            auto_compact: false,
            ..Default::default()
        };

        let mut storage = ShadowStorage::new(config).unwrap();

        // Record observation with events
        let obs = Observation {
            timestamp: Utc::now(),
            pid: 1234,
            identity_hash: "test".to_string(),
            events: vec![
                ProcessEvent {
                    timestamp: Utc::now(),
                    event_type: EventType::CpuSpike,
                    details: Some("CPU jumped to 100%".to_string()),
                },
                ProcessEvent {
                    timestamp: Utc::now(),
                    event_type: EventType::MemorySpike,
                    details: None,
                },
            ],
            ..Default::default()
        };

        storage.record(obs).unwrap();

        // Query events
        let events = storage.get_events(
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
            100,
        );

        assert_eq!(events.events.len(), 2);
    }

    #[test]
    fn test_shadow_observations_schema() {
        let schema = shadow_observations_schema();
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("pid").is_ok());
        assert!(schema.field_with_name("identity_hash").is_ok());
        assert!(schema.field_with_name("p_abandoned").is_ok());
        assert!(schema.field_with_name("belief_score").is_ok());
        assert!(schema.field_with_name("retention_tier").is_ok());
    }

    #[test]
    fn test_observation_default() {
        let obs = Observation::default();
        assert_eq!(obs.pid, 0);
        assert!(obs.identity_hash.is_empty());
        assert!(obs.events.is_empty());
    }

    #[test]
    fn test_belief_state_default() {
        let belief = BeliefState::default();
        assert_eq!(belief.p_abandoned, 0.25);
        assert_eq!(belief.p_legitimate, 0.25);
        assert_eq!(belief.confidence, 0.0);
    }

    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            auto_compact: false,
            ..Default::default()
        };

        let mut storage = ShadowStorage::new(config).unwrap();

        // Record observations
        for pid in 1..=3 {
            let obs = Observation {
                pid,
                identity_hash: format!("identity_{}", pid),
                events: vec![ProcessEvent {
                    timestamp: Utc::now(),
                    event_type: EventType::CpuSpike,
                    details: None,
                }],
                ..Default::default()
            };
            storage.record(obs).unwrap();
        }

        let stats = storage.stats();
        assert_eq!(stats.total_observations, 3);
        assert_eq!(stats.total_events, 3);
    }

    #[test]
    fn test_storage_flush_and_persist() {
        let temp_dir = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            auto_compact: false,
            ..Default::default()
        };

        let mut storage = ShadowStorage::new(config).unwrap();

        let obs = Observation {
            pid: 999,
            identity_hash: "flush_test".to_string(),
            ..Default::default()
        };
        storage.record(obs).unwrap();

        // Flush should succeed
        storage.flush().unwrap();

        // Stats file should exist
        assert!(temp_dir.path().join("stats.json").exists());
    }
}
