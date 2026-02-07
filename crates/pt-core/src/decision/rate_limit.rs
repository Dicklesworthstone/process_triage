//! Sliding window rate limiter for kill operations.
//!
//! This module implements time-based rate limiting using a sliding window algorithm
//! (sliding log approach) for accurate tracking of kills across minute, hour, and day windows.
//!
//! # Features
//!
//! - Per-minute, per-hour, per-day rate limits
//! - Per-session (run) limits
//! - 80% warning threshold before hitting limits
//! - Force override for emergency situations
//! - Persistent state across sessions via state file
//!
//! # Architecture
//!
//! ```text
//! Kill Request → SlidingWindowRateLimiter → RateLimitResult
//!                       ↓
//!               [timestamp log]
//!                       ↓
//!               [state file] (persistence)
//! ```
//!
//! # Example
//!
//! ```ignore
//! let config = RateLimitConfig::from_policy(&policy);
//! let limiter = SlidingWindowRateLimiter::new(config, Some("/var/lib/pt/rate_limit.json"))?;
//!
//! let result = limiter.check(false)?;
//! if let Some(warning) = &result.warning {
//!     eprintln!("Warning: {}", warning);
//! }
//! if result.allowed {
//!     limiter.record_kill()?;
//! }
//! ```

use crate::config::policy::Guardrails;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Duration constants for windows.
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SECONDS_PER_DAY: u64 = 86400;

/// Warning threshold (80% of limit).
const WARNING_THRESHOLD_PERCENT: f64 = 0.80;

/// Errors during rate limiting operations.
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("failed to load state: {0}")]
    LoadState(String),

    #[error("failed to save state: {0}")]
    SaveState(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Configuration for rate limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum kills per run/session.
    pub max_per_run: u32,
    /// Maximum kills per minute.
    pub max_per_minute: Option<u32>,
    /// Maximum kills per hour.
    pub max_per_hour: Option<u32>,
    /// Maximum kills per day.
    pub max_per_day: Option<u32>,
}

impl RateLimitConfig {
    /// Create configuration from policy guardrails.
    pub fn from_guardrails(guardrails: &Guardrails) -> Self {
        Self {
            max_per_run: guardrails.max_kills_per_run,
            max_per_minute: guardrails.max_kills_per_minute,
            max_per_hour: guardrails.max_kills_per_hour,
            max_per_day: guardrails.max_kills_per_day,
        }
    }

    /// Create a default configuration (conservative).
    pub fn default_conservative() -> Self {
        Self {
            max_per_run: 5,
            max_per_minute: Some(2),
            max_per_hour: Some(20),
            max_per_day: Some(100),
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitResult {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Whether this was a forced override.
    pub forced: bool,
    /// Warning message if approaching limit (80% threshold).
    pub warning: Option<RateLimitWarning>,
    /// Block reason if not allowed.
    pub block_reason: Option<RateLimitBlock>,
    /// Current counts for each window.
    pub counts: RateLimitCounts,
}

/// Warning when approaching a rate limit (80% threshold).
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitWarning {
    /// Which window is approaching limit.
    pub window: RateLimitWindow,
    /// Current count.
    pub current: u32,
    /// Limit for that window.
    pub limit: u32,
    /// Percentage of limit used.
    pub percent_used: f64,
    /// Human-readable message.
    pub message: String,
}

/// Block reason when rate limit exceeded.
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitBlock {
    /// Which window caused the block.
    pub window: RateLimitWindow,
    /// Current count.
    pub current: u32,
    /// Limit for that window.
    pub limit: u32,
    /// Human-readable message.
    pub message: String,
}

/// Time windows for rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitWindow {
    /// Per-session/run limit.
    Run,
    /// Per-minute limit.
    Minute,
    /// Per-hour limit.
    Hour,
    /// Per-day limit.
    Day,
}

impl std::fmt::Display for RateLimitWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitWindow::Run => write!(f, "run"),
            RateLimitWindow::Minute => write!(f, "minute"),
            RateLimitWindow::Hour => write!(f, "hour"),
            RateLimitWindow::Day => write!(f, "day"),
        }
    }
}

/// Current counts for each time window.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RateLimitCounts {
    /// Kills in current run.
    pub run: u32,
    /// Kills in last minute.
    pub minute: u32,
    /// Kills in last hour.
    pub hour: u32,
    /// Kills in last day.
    pub day: u32,
}

/// Persistent state stored to disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistentState {
    /// Unix timestamps of kills (in seconds).
    kill_timestamps: VecDeque<u64>,
    /// When this state was last updated.
    last_updated: u64,
}

impl PersistentState {
    /// Prune timestamps older than 24 hours.
    fn prune_old(&mut self, now: u64) {
        let cutoff = now.saturating_sub(SECONDS_PER_DAY);
        while let Some(&ts) = self.kill_timestamps.front() {
            if ts < cutoff {
                self.kill_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Count kills within a time window.
    fn count_within(&self, now: u64, window_seconds: u64) -> u32 {
        let cutoff = now.saturating_sub(window_seconds);
        self.kill_timestamps
            .iter()
            .filter(|&&ts| ts >= cutoff)
            .count() as u32
    }
}

/// Internal state of the rate limiter.
#[derive(Debug)]
struct RateLimiterState {
    /// Persistent state (timestamps).
    persistent: PersistentState,
    /// Kills in the current run (not persisted, reset on startup).
    kills_this_run: u32,
}

/// Sliding window rate limiter for kill operations.
///
/// Thread-safe implementation using RwLock for concurrent access.
#[derive(Debug, Clone)]
pub struct SlidingWindowRateLimiter {
    /// Configuration.
    config: RateLimitConfig,
    /// Internal state (protected by RwLock).
    state: Arc<RwLock<RateLimiterState>>,
    /// Path to state file for persistence (optional).
    state_path: Option<PathBuf>,
}

impl SlidingWindowRateLimiter {
    /// Create a new rate limiter with the given configuration.
    ///
    /// If `state_path` is provided, the limiter will persist state to disk
    /// for cross-session tracking of hourly and daily limits.
    pub fn new(
        config: RateLimitConfig,
        state_path: Option<impl AsRef<Path>>,
    ) -> Result<Self, RateLimitError> {
        let state_path = state_path.map(|p| p.as_ref().to_path_buf());

        // Try to load existing state
        let persistent = if let Some(ref path) = state_path {
            Self::load_state(path).unwrap_or_default()
        } else {
            PersistentState::default()
        };

        let state = RateLimiterState {
            persistent,
            kills_this_run: 0,
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(state)),
            state_path,
        })
    }

    /// Create a new rate limiter from policy guardrails.
    pub fn from_guardrails(
        guardrails: &Guardrails,
        state_path: Option<impl AsRef<Path>>,
    ) -> Result<Self, RateLimitError> {
        Self::new(RateLimitConfig::from_guardrails(guardrails), state_path)
    }

    /// Load state from disk.
    fn load_state(path: &Path) -> Result<PersistentState, RateLimitError> {
        if !path.exists() {
            return Ok(PersistentState::default());
        }

        let file = File::open(path).map_err(|e| RateLimitError::LoadState(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut state: PersistentState = serde_json::from_reader(reader)
            .map_err(|e| RateLimitError::LoadState(e.to_string()))?;

        // Prune old entries on load
        let now = current_unix_timestamp();
        state.prune_old(now);

        Ok(state)
    }

    /// Save state to disk.
    fn save_state(&self, state: &PersistentState) -> Result<(), RateLimitError> {
        let Some(ref path) = self.state_path else {
            return Ok(());
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write atomically via temp file
        let temp_path = path.with_extension("tmp");
        let file = File::create(&temp_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, state)?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Check if a kill is allowed without recording it.
    ///
    /// If `force` is true, the kill is allowed regardless of limits (for emergency override),
    /// but warnings are still generated.
    pub fn check(&self, force: bool) -> Result<RateLimitResult, RateLimitError> {
        let state = self
            .state
            .read()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;

        self.check_internal(&state, force, None)
    }

    /// Check with an override limit (e.g., robot mode may have lower limits).
    pub fn check_with_override(
        &self,
        force: bool,
        override_per_run: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let state = self
            .state
            .read()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;

        self.check_internal(&state, force, override_per_run)
    }

    fn check_internal(
        &self,
        state: &RateLimiterState,
        force: bool,
        override_per_run: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let now = current_unix_timestamp();
        let counts = self.get_counts_internal(state, now);

        // Determine effective per-run limit
        let effective_per_run = override_per_run
            .map(|l| std::cmp::min(l, self.config.max_per_run))
            .unwrap_or(self.config.max_per_run);

        // Check each limit (starting with strictest window)
        let limits_to_check: Vec<(RateLimitWindow, u32, Option<u32>)> = vec![
            (RateLimitWindow::Run, counts.run, Some(effective_per_run)),
            (
                RateLimitWindow::Minute,
                counts.minute,
                self.config.max_per_minute,
            ),
            (RateLimitWindow::Hour, counts.hour, self.config.max_per_hour),
            (RateLimitWindow::Day, counts.day, self.config.max_per_day),
        ];

        let mut block_reason = None;
        let mut warning = None;

        for (window, count, limit_opt) in limits_to_check {
            if let Some(limit) = limit_opt {
                // Check if blocked
                if count >= limit {
                    block_reason = Some(RateLimitBlock {
                        window,
                        current: count,
                        limit,
                        message: format!(
                            "rate limit exceeded: {} kills already performed this {} (max {})",
                            count, window, limit
                        ),
                    });
                    break;
                }

                // Check warning threshold (80%)
                let threshold = (limit as f64 * WARNING_THRESHOLD_PERCENT).ceil() as u32;
                if count >= threshold && warning.is_none() {
                    let percent = (count as f64 / limit as f64) * 100.0;
                    warning = Some(RateLimitWarning {
                        window,
                        current: count,
                        limit,
                        percent_used: percent,
                        message: format!(
                            "approaching rate limit: {}/{} kills this {} ({:.0}% of limit)",
                            count, limit, window, percent
                        ),
                    });
                }
            }
        }

        let allowed = force || block_reason.is_none();

        Ok(RateLimitResult {
            allowed,
            forced: force && block_reason.is_some(),
            warning,
            block_reason: if allowed { None } else { block_reason },
            counts,
        })
    }

    /// Record a kill and update state.
    ///
    /// Returns the updated counts after recording.
    pub fn record_kill(&self) -> Result<RateLimitCounts, RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| RateLimitError::SaveState(format!("lock poisoned: {}", e)))?;

        let now = current_unix_timestamp();

        // Update persistent state
        state.persistent.kill_timestamps.push_back(now);
        state.persistent.last_updated = now;
        state.persistent.prune_old(now);

        // Update run counter
        state.kills_this_run += 1;

        // Save to disk
        self.save_state(&state.persistent)?;

        Ok(self.get_counts_internal(&state, now))
    }

    /// Check and record in one atomic operation.
    ///
    /// Returns the result including whether the kill was allowed.
    /// If allowed (or forced), the kill is recorded.
    pub fn check_and_record(
        &self,
        force: bool,
        override_per_run: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| RateLimitError::SaveState(format!("lock poisoned: {}", e)))?;

        let result = self.check_internal(&state, force, override_per_run)?;

        if result.allowed {
            let now = current_unix_timestamp();

            // Update persistent state
            state.persistent.kill_timestamps.push_back(now);
            state.persistent.last_updated = now;
            state.persistent.prune_old(now);

            // Update run counter
            state.kills_this_run += 1;

            // Save to disk
            self.save_state(&state.persistent)?;
        }

        Ok(result)
    }

    /// Get current counts without modifying state.
    pub fn get_counts(&self) -> Result<RateLimitCounts, RateLimitError> {
        let state = self
            .state
            .read()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;

        let now = current_unix_timestamp();
        Ok(self.get_counts_internal(&state, now))
    }

    fn get_counts_internal(&self, state: &RateLimiterState, now: u64) -> RateLimitCounts {
        RateLimitCounts {
            run: state.kills_this_run,
            minute: state.persistent.count_within(now, SECONDS_PER_MINUTE),
            hour: state.persistent.count_within(now, SECONDS_PER_HOUR),
            day: state.persistent.count_within(now, SECONDS_PER_DAY),
        }
    }

    /// Reset the per-run counter (call at start of new run).
    pub fn reset_run_counter(&self) -> Result<(), RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| RateLimitError::SaveState(format!("lock poisoned: {}", e)))?;

        state.kills_this_run = 0;
        Ok(())
    }

    /// Get current per-run kill count.
    pub fn current_run_count(&self) -> Result<u32, RateLimitError> {
        let state = self
            .state
            .read()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;

        Ok(state.kills_this_run)
    }

    /// Get the configuration.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// Get current Unix timestamp in seconds.
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            max_per_run: 5,
            max_per_minute: Some(2),
            max_per_hour: Some(10),
            max_per_day: Some(50),
        }
    }

    #[test]
    fn test_basic_rate_limiting() {
        // Use config with no minute limit to avoid interference
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // First kill should be allowed
        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
        assert!(result.block_reason.is_none());

        // Record a few kills
        for _ in 0..4 {
            limiter.record_kill().unwrap();
        }

        // 5th kill should still be allowed
        let result = limiter.check(false).unwrap();
        assert!(result.allowed);

        // Record 5th kill
        limiter.record_kill().unwrap();

        // 6th kill should be blocked (per-run limit)
        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Run
        );
    }

    #[test]
    fn test_per_minute_limit() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: Some(2),
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record 2 kills
        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        // 3rd should be blocked by per-minute limit
        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Minute
        );
    }

    #[test]
    fn test_warning_threshold() {
        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record 7 kills (70% of limit - no warning yet)
        for _ in 0..7 {
            limiter.record_kill().unwrap();
        }

        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
        assert!(result.warning.is_none());

        // Record 8th kill (80% threshold)
        limiter.record_kill().unwrap();

        // Now should get warning
        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
        assert!(result.warning.is_some());
        assert_eq!(
            result.warning.as_ref().unwrap().window,
            RateLimitWindow::Run
        );
    }

    #[test]
    fn test_force_override() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Use up the limit
        limiter.record_kill().unwrap();

        // Should be blocked
        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);

        // With force, should be allowed
        let result = limiter.check(true).unwrap();
        assert!(result.allowed);
        assert!(result.forced);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");

        // Create limiter and record kills
        {
            let config = test_config();
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
            limiter.record_kill().unwrap();
            limiter.record_kill().unwrap();
        }

        // Create new limiter with same path - should load state
        {
            let config = test_config();
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();

            // Per-run should be reset (0), but hour/day should have 2
            let counts = limiter.get_counts().unwrap();
            assert_eq!(counts.run, 0); // Run counter resets
            assert_eq!(counts.hour, 2); // Hour persisted
            assert_eq!(counts.day, 2); // Day persisted
        }
    }

    #[test]
    fn test_reset_run_counter() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();

        // Record some kills
        for _ in 0..3 {
            limiter.record_kill().unwrap();
        }

        assert_eq!(limiter.current_run_count().unwrap(), 3);

        // Reset
        limiter.reset_run_counter().unwrap();
        assert_eq!(limiter.current_run_count().unwrap(), 0);

        // Time-based counts should remain
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 0);
        assert_eq!(counts.minute, 3);
    }

    #[test]
    fn test_check_and_record_atomic() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();

        // Check and record in one operation
        let result = limiter.check_and_record(false, None).unwrap();
        assert!(result.allowed);
        // Result counts reflect state at check time (before increment)
        assert_eq!(result.counts.run, 0);

        // Verify state was updated
        assert_eq!(limiter.current_run_count().unwrap(), 1);
    }

    #[test]
    fn test_override_per_run_limit() {
        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record 3 kills
        for _ in 0..3 {
            limiter.record_kill().unwrap();
        }

        // With override of 3, should be blocked
        let result = limiter.check_with_override(false, Some(3)).unwrap();
        assert!(!result.allowed);

        // Without override, should be allowed
        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_default_conservative_config() {
        let config = RateLimitConfig::default_conservative();
        assert_eq!(config.max_per_run, 5);
        assert_eq!(config.max_per_minute, Some(2));
        assert_eq!(config.max_per_hour, Some(20));
        assert_eq!(config.max_per_day, Some(100));
    }

    #[test]
    fn test_counts_struct() {
        let counts = RateLimitCounts {
            run: 1,
            minute: 2,
            hour: 3,
            day: 4,
        };

        // Test serialization
        let json = serde_json::to_string(&counts).unwrap();
        assert!(json.contains("\"run\":1"));
        assert!(json.contains("\"minute\":2"));
    }

    // ── RateLimitConfig serde ───────────────────────────────────────

    #[test]
    fn rate_limit_config_serde_roundtrip() {
        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: Some(3),
            max_per_hour: Some(30),
            max_per_day: Some(200),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_per_run, 10);
        assert_eq!(back.max_per_minute, Some(3));
        assert_eq!(back.max_per_hour, Some(30));
        assert_eq!(back.max_per_day, Some(200));
    }

    #[test]
    fn rate_limit_config_serde_none_optionals() {
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert!(back.max_per_minute.is_none());
        assert!(back.max_per_hour.is_none());
        assert!(back.max_per_day.is_none());
    }

    // ── RateLimitConfig::from_guardrails ────────────────────────────

    #[test]
    fn rate_limit_config_from_guardrails() {
        use crate::config::policy::Guardrails;
        let guardrails = Guardrails::default();
        let config = RateLimitConfig::from_guardrails(&guardrails);
        assert_eq!(config.max_per_run, guardrails.max_kills_per_run);
        assert_eq!(config.max_per_hour, guardrails.max_kills_per_hour);
        assert_eq!(config.max_per_day, guardrails.max_kills_per_day);
    }

    // ── RateLimitResult serde ───────────────────────────────────────

    #[test]
    fn rate_limit_result_serde() {
        let result = RateLimitResult {
            allowed: true,
            forced: false,
            warning: None,
            block_reason: None,
            counts: RateLimitCounts::default(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""allowed":true"#));
        assert!(json.contains(r#""forced":false"#));
    }

    #[test]
    fn rate_limit_result_serde_with_warning() {
        let result = RateLimitResult {
            allowed: true,
            forced: false,
            warning: Some(RateLimitWarning {
                window: RateLimitWindow::Run,
                current: 4,
                limit: 5,
                percent_used: 80.0,
                message: "approaching limit".to_string(),
            }),
            block_reason: None,
            counts: RateLimitCounts::default(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("approaching limit"));
        assert!(json.contains(r#""window":"run""#));
    }

    #[test]
    fn rate_limit_result_serde_with_block() {
        let result = RateLimitResult {
            allowed: false,
            forced: false,
            warning: None,
            block_reason: Some(RateLimitBlock {
                window: RateLimitWindow::Minute,
                current: 3,
                limit: 2,
                message: "exceeded".to_string(),
            }),
            counts: RateLimitCounts::default(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""allowed":false"#));
        assert!(json.contains(r#""window":"minute""#));
    }

    // ── RateLimitWindow serde + Display ─────────────────────────────

    #[test]
    fn rate_limit_window_serde_all_variants() {
        let variants = [
            (RateLimitWindow::Run, "run"),
            (RateLimitWindow::Minute, "minute"),
            (RateLimitWindow::Hour, "hour"),
            (RateLimitWindow::Day, "day"),
        ];
        for (variant, expected_str) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let raw: String = serde_json::from_str(&json).unwrap();
            assert_eq!(&raw, expected_str, "serde name mismatch for {:?}", variant);

            let back: RateLimitWindow = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant);
        }
    }

    #[test]
    fn rate_limit_window_display_all() {
        assert_eq!(format!("{}", RateLimitWindow::Run), "run");
        assert_eq!(format!("{}", RateLimitWindow::Minute), "minute");
        assert_eq!(format!("{}", RateLimitWindow::Hour), "hour");
        assert_eq!(format!("{}", RateLimitWindow::Day), "day");
    }

    // ── RateLimitCounts default ─────────────────────────────────────

    #[test]
    fn rate_limit_counts_default_all_zero() {
        let counts = RateLimitCounts::default();
        assert_eq!(counts.run, 0);
        assert_eq!(counts.minute, 0);
        assert_eq!(counts.hour, 0);
        assert_eq!(counts.day, 0);
    }

    // ── RateLimitError display ──────────────────────────────────────

    #[test]
    fn rate_limit_error_display_load_state() {
        let err = RateLimitError::LoadState("corrupt json".to_string());
        assert!(format!("{}", err).contains("failed to load state"));
        assert!(format!("{}", err).contains("corrupt json"));
    }

    #[test]
    fn rate_limit_error_display_save_state() {
        let err = RateLimitError::SaveState("disk full".to_string());
        assert!(format!("{}", err).contains("failed to save state"));
    }

    #[test]
    fn rate_limit_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = RateLimitError::Io(io_err);
        assert!(format!("{}", err).contains("io error"));
    }

    #[test]
    fn rate_limit_error_display_json() {
        let json_str = "{invalid";
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let err = RateLimitError::Json(json_err);
        assert!(format!("{}", err).contains("json error"));
    }

    // ── Per-hour limit ──────────────────────────────────────────────

    #[test]
    fn test_per_hour_limit() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: Some(3),
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        for _ in 0..3 {
            limiter.record_kill().unwrap();
        }

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Hour
        );
    }

    // ── Per-day limit ───────────────────────────────────────────────

    #[test]
    fn test_per_day_limit() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: Some(2),
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Day
        );
    }

    // ── override_per_run takes minimum ──────────────────────────────

    #[test]
    fn test_override_per_run_takes_minimum() {
        let config = RateLimitConfig {
            max_per_run: 3,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        // Override with 10 — should still be blocked at config's 3
        let result = limiter.check_with_override(false, Some(10)).unwrap();
        assert!(!result.allowed);
    }

    // ── check_and_record when blocked ───────────────────────────────

    #[test]
    fn test_check_and_record_when_blocked_does_not_record() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // First check_and_record succeeds
        let r1 = limiter.check_and_record(false, None).unwrap();
        assert!(r1.allowed);
        assert_eq!(limiter.current_run_count().unwrap(), 1);

        // Second is blocked — should NOT increment
        let r2 = limiter.check_and_record(false, None).unwrap();
        assert!(!r2.allowed);
        assert_eq!(limiter.current_run_count().unwrap(), 1);
    }

    // ── check_and_record force override records even when blocked ────

    #[test]
    fn test_check_and_record_force_records() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();

        // Force override — should still record
        let result = limiter.check_and_record(true, None).unwrap();
        assert!(result.allowed);
        assert!(result.forced);
        assert_eq!(limiter.current_run_count().unwrap(), 2);
    }

    // ── get_counts reflects state ───────────────────────────────────

    #[test]
    fn test_get_counts_reflects_kills() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 2);
        assert_eq!(counts.minute, 2);
        assert_eq!(counts.hour, 2);
        assert_eq!(counts.day, 2);
    }

    // ── config accessor ─────────────────────────────────────────────

    #[test]
    fn test_config_accessor() {
        let config = test_config();
        let limiter = SlidingWindowRateLimiter::new(config.clone(), None::<&str>).unwrap();

        assert_eq!(limiter.config().max_per_run, 5);
        assert_eq!(limiter.config().max_per_minute, Some(2));
    }

    // ── clone is independent ────────────────────────────────────────

    #[test]
    fn test_limiter_clone_shares_state() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();
        let clone = limiter.clone();

        limiter.record_kill().unwrap();

        // Clone should see the same state (Arc<RwLock> shared)
        assert_eq!(clone.current_run_count().unwrap(), 1);
    }

    // ── warning on per-minute approaching limit ─────────────────────

    #[test]
    fn test_per_minute_warning() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: Some(5),
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // 80% of 5 = 4, so after 4 kills we should get a warning
        for _ in 0..4 {
            limiter.record_kill().unwrap();
        }

        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
        assert!(
            result.warning.is_some(),
            "should warn at 80% of per-minute limit"
        );
        assert_eq!(
            result.warning.as_ref().unwrap().window,
            RateLimitWindow::Minute
        );
    }

    // ── block message format ────────────────────────────────────────

    #[test]
    fn test_block_message_contains_counts() {
        let config = RateLimitConfig {
            max_per_run: 2,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        let block = result.block_reason.unwrap();
        assert!(block.message.contains("2 kills already performed"));
        assert!(block.message.contains("run"));
        assert!(block.message.contains("max 2"));
    }

    // ── persistence with corrupt state file ─────────────────────────

    #[test]
    fn test_persistence_corrupt_state_uses_default() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");

        // Write corrupt JSON
        std::fs::write(&state_path, "not valid json").unwrap();

        // Should fall back to default state
        let config = test_config();
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();

        assert_eq!(limiter.current_run_count().unwrap(), 0);
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.day, 0);
    }

    // ── SlidingWindowRateLimiter debug ──────────────────────────────

    #[test]
    fn test_limiter_debug() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();
        let dbg = format!("{:?}", limiter);
        assert!(dbg.contains("SlidingWindowRateLimiter"));
    }
}
