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
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
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

    #[error("kill accounting refused: {0}")]
    KillAccounting(String),

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
    /// An action was authorized but its delivery result has not been durably saved.
    #[serde(default)]
    pending_kill_intent: bool,
    /// The process that wrote `pending_kill_intent`, so a later run can settle an
    /// intent whose writer died (Ctrl-C, a timeout) instead of refusing forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_kill_owner: Option<IntentOwner>,
}

/// A process identity that survives pid reuse: pid plus birth (Linux start ticks,
/// macOS start microseconds), and on Linux the pid namespace the pid belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntentOwner {
    pid: u32,
    birth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid_namespace: Option<u64>,
}

impl IntentOwner {
    fn current() -> Option<Self> {
        let pid = std::process::id();
        process_birth(pid).ok().flatten().map(|birth| Self {
            pid,
            birth,
            pid_namespace: current_pid_namespace(),
        })
    }

    /// Only a confirmed absence counts: no such pid, or the pid now belongs to a
    /// process with a different birth. An unreadable identity, or an owner in
    /// another pid namespace (its pid means a different process here), is not "gone".
    fn is_gone(&self) -> bool {
        if self.pid_namespace.is_some() && self.pid_namespace != current_pid_namespace() {
            return false;
        }
        match process_birth(self.pid) {
            Ok(Some(birth)) => birth != self.birth,
            Ok(None) => true,
            Err(()) => false,
        }
    }
}

/// Whether `pid` may exist: only ESRCH from kill(pid, 0) says it does not.
#[cfg(unix)]
fn pid_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    if pid <= 0 {
        return true;
    }
    // SAFETY: signal 0 performs only the existence and permission check.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Inode of this process's pid namespace (`/proc/self/ns/pid` -> `pid:[N]`).
fn current_pid_namespace() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let link = std::fs::read_link("/proc/self/ns/pid").ok()?;
        let link = link.to_str()?;
        link.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Birth of `pid`: `Ok(None)` if no such process exists, `Err` if it exists (or
/// may exist) but its identity cannot be read.
fn process_birth(pid: u32) -> Result<Option<u64>, ()> {
    #[cfg(target_os = "linux")]
    {
        use crate::collect::proc_parsers::{read_required_proc_stat, StatReadError};
        match read_required_proc_stat(pid) {
            Ok(stat) => Ok(Some(stat.starttime)),
            // /proc can hide a live process (hidepid, no /proc mounted): only
            // ESRCH from kill(pid, 0) proves it does not exist.
            Err(StatReadError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound && !pid_exists(pid) =>
            {
                Ok(None)
            }
            Err(_) => Err(()),
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(info) = crate::collect::macos::read_bsd_info(pid) {
            return Ok(Some(info.start_us));
        }
        if pid_exists(pid) {
            Err(())
        } else {
            Ok(None)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err(())
    }
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
    /// Only the instance which prepared an intent may finish it.
    owns_kill_intent: bool,
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

        let state = RateLimiterState {
            // Read shared state on each check/update. A corrupt budget blocks
            // kills without preventing read-only commands from constructing us.
            persistent: PersistentState::default(),
            kills_this_run: 0,
            owns_kill_intent: false,
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
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PersistentState::default());
            }
            Err(error) => {
                return Err(RateLimitError::LoadState(format!(
                    "{}: {error}; kills are refused until it is readable",
                    path.display()
                )));
            }
        };
        let reader = BufReader::new(file);
        let mut state: PersistentState = serde_json::from_reader(reader).map_err(|error| {
            RateLimitError::LoadState(format!(
                "{}: {error}; kills are refused until it is repaired",
                path.display()
            ))
        })?;

        // Prune old entries on load
        let now = current_unix_timestamp();
        state.prune_old(now);

        Ok(state)
    }

    /// Save state to disk.
    fn save_state(path: &Path, state: &PersistentState) -> Result<(), RateLimitError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let temp_path = sibling_with_suffix(path, &format!(".{}.{nanos}.tmp", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, state)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temp_path, path)?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        // On failure retain the temporary data for diagnosis; never discard it.
        Ok(())
    }

    fn refresh(&self, state: &mut RateLimiterState) -> Result<(), RateLimitError> {
        if let Some(path) = &self.state_path {
            {
                let _lock = StateLock::acquire(path, false)?;
                state.persistent = Self::load_state(path)?;
            }
            if Self::holds_abandoned_intent(state) {
                let _lock = StateLock::acquire(path, true)?;
                state.persistent = Self::load_state(path)?;
                Self::settle_abandoned_intent(state, path)?;
            }
        }
        Ok(())
    }

    fn lock_for_update(
        &self,
        state: &mut RateLimiterState,
    ) -> Result<Option<StateLock>, RateLimitError> {
        let Some(path) = &self.state_path else {
            return Ok(None);
        };
        let lock = StateLock::acquire(path, true)?;
        state.persistent = Self::load_state(path)?;
        Self::settle_abandoned_intent(state, path)?;
        Ok(Some(lock))
    }

    fn holds_abandoned_intent(state: &RateLimiterState) -> bool {
        !state.owns_kill_intent
            && state.persistent.pending_kill_intent
            && state
                .persistent
                .pending_kill_owner
                .as_ref()
                .is_some_and(IntentOwner::is_gone)
    }

    /// Settle an intent whose writer is gone: it can never finish it, and its
    /// signal may have been delivered, so charge one kill and clear the intent.
    /// A live or unverifiable owner, or an intent without one, keeps refusing.
    /// The caller holds the exclusive state lock and has just loaded the state.
    fn settle_abandoned_intent(
        state: &mut RateLimiterState,
        path: &Path,
    ) -> Result<(), RateLimitError> {
        if !Self::holds_abandoned_intent(state) {
            return Ok(());
        }
        let now = current_unix_timestamp();
        state.persistent.kill_timestamps.push_back(now);
        state.persistent.pending_kill_intent = false;
        state.persistent.pending_kill_owner = None;
        state.persistent.last_updated = now;
        state.persistent.prune_old(now);
        Self::save_state(path, &state.persistent)
    }

    /// Refusal while an intent is unresolved, naming the file that holds it.
    fn pending_intent_refusal(&self, state: &RateLimiterState) -> RateLimitError {
        let location = self
            .state_path
            .as_ref()
            .map(|path| format!(" in {}", path.display()))
            .unwrap_or_default();
        let holder = match &state.persistent.pending_kill_owner {
            Some(owner)
                if owner.pid_namespace.is_some()
                    && owner.pid_namespace != current_pid_namespace() =>
            {
                format!(
                    " (written by pt PID {} in another pid namespace, which this run cannot \
                     check; if no pt is running there, set pending_kill_intent to false there)",
                    owner.pid
                )
            }
            Some(owner) => format!(
                " (written by pt PID {}, which is still running or cannot be verified)",
                owner.pid
            ),
            None if self.state_path.is_some() => {
                " (it records no owner; if no pt is running, set pending_kill_intent to false there)"
                    .to_string()
            }
            None => String::new(),
        };
        RateLimitError::KillAccounting(format!(
            "an unresolved pending kill intent{location} must be reconciled before another kill{holder}"
        ))
    }

    fn append_kill(&self, state: &mut RateLimiterState) -> Result<(), RateLimitError> {
        let now = current_unix_timestamp();
        state.persistent.kill_timestamps.push_back(now);
        state.persistent.last_updated = now;
        state.persistent.prune_old(now);
        state.kills_this_run = state.kills_this_run.saturating_add(1);
        if let Some(path) = &self.state_path {
            Self::save_state(path, &state.persistent)?;
        }
        Ok(())
    }

    /// Persist a pending intent before signaling. The caller must check policy
    /// first; an unresolved intent refuses another action even under force.
    /// The intent records this process, so a run after it dies settles the intent
    /// (see `settle_abandoned_intent`) rather than refusing forever.
    /// Without a configured state file, this guards only this shared instance.
    pub fn begin_kill_accounting(&self) -> Result<(), RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| RateLimitError::SaveState(format!("lock poisoned: {error}")))?;
        let _lock = self.lock_for_update(&mut state)?;
        if state.persistent.pending_kill_intent || state.owns_kill_intent {
            return Err(self.pending_intent_refusal(&state));
        }
        state.persistent.pending_kill_intent = true;
        state.persistent.pending_kill_owner = IntentOwner::current();
        state.persistent.last_updated = current_unix_timestamp();
        if let Some(path) = &self.state_path {
            Self::save_state(path, &state.persistent)?;
        }
        state.owns_kill_intent = true;
        Ok(())
    }

    /// Resolve this instance's prepared intent after actual signal delivery.
    /// A failure before atomic replacement retains the on-disk intent. A
    /// failure after replacement may leave the counted result on disk; neither
    /// failure removes the actual per-run charge or permits a repeated finish.
    /// A non-delivery clears the intent without spending kill budget.
    pub fn finish_kill_accounting(
        &self,
        delivered: bool,
    ) -> Result<RateLimitCounts, RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| RateLimitError::SaveState(format!("lock poisoned: {error}")))?;
        if !state.owns_kill_intent {
            return Err(RateLimitError::KillAccounting(
                "this limiter did not prepare the pending kill intent".to_string(),
            ));
        }
        // Charge an observed delivery even if reloading or saving the durable
        // state fails. Consume ownership so a repeated finish cannot double-charge.
        state.owns_kill_intent = false;
        if delivered {
            state.kills_this_run = state.kills_this_run.saturating_add(1);
        }
        let _lock = self.lock_for_update(&mut state)?;
        if !state.persistent.pending_kill_intent {
            return Err(RateLimitError::KillAccounting(
                "the prepared kill intent is missing from the saved budget".to_string(),
            ));
        }
        let now = current_unix_timestamp();
        if delivered {
            state.persistent.kill_timestamps.push_back(now);
        }
        state.persistent.pending_kill_intent = false;
        state.persistent.pending_kill_owner = None;
        state.persistent.last_updated = now;
        state.persistent.prune_old(now);
        if let Some(path) = &self.state_path {
            Self::save_state(path, &state.persistent)?;
        }
        Ok(self.get_counts_internal(&state, now))
    }

    /// Check if a kill is allowed without recording it.
    ///
    /// If `force` is true, the kill is allowed regardless of limits (for emergency override),
    /// but warnings are still generated.
    pub fn check(&self, force: bool) -> Result<RateLimitResult, RateLimitError> {
        self.check_with_override(force, None)
    }

    /// Check with an override limit (e.g., robot mode may have lower limits).
    pub fn check_with_override(
        &self,
        force: bool,
        override_per_run: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;
        self.refresh(&mut state)?;

        self.check_internal(&state, force, override_per_run)
    }

    fn check_internal(
        &self,
        state: &RateLimiterState,
        force: bool,
        override_per_run: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        if state.persistent.pending_kill_intent {
            return Err(self.pending_intent_refusal(state));
        }
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

        let _lock = self.lock_for_update(&mut state)?;
        if state.persistent.pending_kill_intent {
            return Err(self.pending_intent_refusal(&state));
        }
        self.append_kill(&mut state)?;
        Ok(self.get_counts_internal(&state, current_unix_timestamp()))
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

        let _lock = self.lock_for_update(&mut state)?;
        let result = self.check_internal(&state, force, override_per_run)?;
        if result.allowed {
            self.append_kill(&mut state)?;
        }

        Ok(result)
    }

    /// Get current counts. Like every read, this settles an intent whose writer
    /// is gone (see `settle_abandoned_intent`), so it may update the state file.
    pub fn get_counts(&self) -> Result<RateLimitCounts, RateLimitError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| RateLimitError::LoadState(format!("lock poisoned: {}", e)))?;
        self.refresh(&mut state)?;

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

/// Lock a stable sibling inode; renaming the state file never changes this lock.
struct StateLock(#[allow(dead_code)] File);

impl StateLock {
    fn acquire(path: &Path, exclusive: bool) -> Result<Self, RateLimitError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(sibling_with_suffix(path, ".lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let operation = if exclusive {
                libc::LOCK_EX
            } else {
                libc::LOCK_SH
            };
            // SAFETY: flock operates only on the descriptor owned by this guard;
            // closing it releases the lock, including error returns.
            if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(not(unix))]
        let _ = exclusive;
        Ok(Self(file))
    }
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
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

    fn retained_accounting_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from("target/test-logs/e2e/rate_limit")
            .join(format!("{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[cfg(target_os = "linux")]
    struct AccountingTarget {
        child: std::process::Child,
        pidfd: std::os::fd::OwnedFd,
    }

    #[cfg(target_os = "linux")]
    impl AccountingTarget {
        fn spawn() -> Self {
            use std::os::fd::FromRawFd;
            let mut child = std::process::Command::new("sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap();
            // SAFETY: the unreaped child belongs to this test, so its PID cannot
            // be recycled while we open its identity-bound descriptor.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("cannot bind owned accounting target: {error}");
            }
            Self {
                child,
                // SAFETY: pidfd_open returned a new descriptor owned by us.
                pidfd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) },
            }
        }

        fn deliver_term(&mut self) -> bool {
            use std::os::fd::AsRawFd;
            use std::os::unix::process::ExitStatusExt;
            // SAFETY: signaling uses only this test's original owned pidfd.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
            let status = self.child.wait().unwrap();
            assert_eq!(status.signal(), Some(libc::SIGTERM));
            result == 0
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for AccountingTarget {
        fn drop(&mut self) {
            use std::os::fd::AsRawFd;
            // SAFETY: this cannot signal a reused PID or an unrelated target.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            let _ = self.child.wait();
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn durable_accounting_records_actual_delivery_for_a_fresh_limiter() {
        let dir = retained_accounting_dir("delivered");
        let state_path = dir.join("rate_limit.json");
        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let mut target = AccountingTarget::spawn();

        assert!(limiter.check(false).unwrap().allowed);
        limiter.begin_kill_accounting().unwrap();
        let pending: PersistentState =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert!(pending.pending_kill_intent);
        assert!(pending.kill_timestamps.is_empty());
        assert_eq!(limiter.current_run_count().unwrap(), 0);
        assert!(limiter.check(true).is_err());

        let counts = limiter
            .finish_kill_accounting(target.deliver_term())
            .unwrap();
        assert_eq!(
            (counts.run, counts.minute, counts.hour, counts.day),
            (1, 1, 1, 1)
        );
        let saved: PersistentState =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert!(!saved.pending_kill_intent);
        assert_eq!(saved.kill_timestamps.len(), 1);

        let fresh = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let counts = fresh.get_counts().unwrap();
        assert_eq!(
            (counts.run, counts.minute, counts.hour, counts.day),
            (0, 1, 1, 1)
        );
        assert!(fresh.check(false).unwrap().allowed);
        assert!(limiter.finish_kill_accounting(true).is_err());
        assert_eq!(limiter.current_run_count().unwrap(), 1);
        assert_eq!(fresh.get_counts().unwrap().day, 1);
    }

    /// A pending intent as a writer leaves it on disk, written as raw JSON.
    fn write_pending_intent(path: &Path, owner: serde_json::Value) {
        let state = serde_json::json!({
            "kill_timestamps": [],
            "last_updated": current_unix_timestamp(),
            "pending_kill_intent": true,
            "pending_kill_owner": owner,
        });
        fs::write(path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    }

    fn saved_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    /// The writer died during the kill window (Ctrl-C, an agent's timeout): the
    /// next run charges the possibly delivered kill and clears the intent instead
    /// of refusing every kill from then on.
    #[test]
    fn abandoned_intent_of_a_dead_owner_is_charged_and_cleared() {
        let dir = retained_accounting_dir("dead-owner");
        let state_path = dir.join("rate_limit.json");
        let mut exited = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = exited.id();
        exited.wait().unwrap();
        write_pending_intent(
            &state_path,
            serde_json::json!({ "pid": dead_pid, "birth": 1 }),
        );

        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        assert!(limiter.check(false).unwrap().allowed);
        let saved = saved_json(&state_path);
        assert_eq!(saved["pending_kill_intent"], false);
        assert!(saved.get("pending_kill_owner").is_none(), "{saved}");
        assert_eq!(saved["kill_timestamps"].as_array().unwrap().len(), 1);
        let counts = limiter.get_counts().unwrap();
        assert_eq!((counts.run, counts.day), (0, 1));
        limiter.begin_kill_accounting().unwrap();
        limiter.finish_kill_accounting(false).unwrap();
    }

    /// A reused pid is not the owner: a different birth settles the intent too.
    #[test]
    fn intent_of_a_reused_pid_is_settled() {
        let dir = retained_accounting_dir("reused-pid");
        let state_path = dir.join("rate_limit.json");
        let own = IntentOwner::current().expect("own identity");
        write_pending_intent(
            &state_path,
            serde_json::json!({ "pid": own.pid, "birth": own.birth.wrapping_add(1) }),
        );
        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        assert!(limiter.check_and_record(false, None).unwrap().allowed);
        assert_eq!(limiter.get_counts().unwrap().day, 2);
        assert_eq!(saved_json(&state_path)["pending_kill_intent"], false);
    }

    /// A pid recorded in another pid namespace names a different process here, so
    /// its absence proves nothing: the intent keeps refusing.
    #[test]
    fn intent_from_another_pid_namespace_is_not_settled() {
        let dir = retained_accounting_dir("other-namespace");
        let state_path = dir.join("rate_limit.json");
        let mut exited = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = exited.id();
        exited.wait().unwrap();
        write_pending_intent(
            &state_path,
            serde_json::json!({ "pid": dead_pid, "birth": 1, "pid_namespace": 1 }),
        );
        let pending_bytes = fs::read(&state_path).unwrap();
        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let error = limiter.check(false).unwrap_err().to_string();
        assert!(error.contains("another pid namespace"), "{error}");
        assert!(limiter.begin_kill_accounting().is_err());
        assert_eq!(fs::read(&state_path).unwrap(), pending_bytes);
    }

    /// A live owner still blocks other runs, and the refusal names the file.
    #[test]
    fn live_owner_intent_keeps_refusing_and_names_the_file() {
        let dir = retained_accounting_dir("live-owner");
        let state_path = dir.join("rate_limit.json");
        let owner = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        owner.begin_kill_accounting().unwrap();
        let recorded = saved_json(&state_path);
        assert_eq!(recorded["pending_kill_owner"]["pid"], std::process::id());
        let pending_bytes = fs::read(&state_path).unwrap();

        let other = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let error = other.check(false).unwrap_err().to_string();
        assert!(error.contains(&state_path.display().to_string()), "{error}");
        assert!(error.contains("still running"), "{error}");
        assert_eq!(fs::read(&state_path).unwrap(), pending_bytes);
        owner.finish_kill_accounting(false).unwrap();
        assert!(other.check(false).unwrap().allowed);
    }

    #[test]
    fn durable_accounting_non_delivery_releases_intent_without_spending_budget() {
        let dir = retained_accounting_dir("not-delivered");
        let state_path = dir.join("rate_limit.json");
        let owner = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let other = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        owner.begin_kill_accounting().unwrap();
        let pending_bytes = fs::read(&state_path).unwrap();

        assert!(other.begin_kill_accounting().is_err());
        assert!(other.finish_kill_accounting(false).is_err());
        assert!(other.finish_kill_accounting(true).is_err());
        assert!(other.check(false).is_err());
        assert!(other.check(true).is_err());
        assert!(other.check_and_record(true, None).is_err());
        assert!(other.record_kill().is_err());
        assert_eq!(fs::read(&state_path).unwrap(), pending_bytes);
        assert_eq!(other.current_run_count().unwrap(), 0);

        let counts = owner.finish_kill_accounting(false).unwrap();
        assert_eq!(
            (counts.run, counts.minute, counts.hour, counts.day),
            (0, 0, 0, 0)
        );
        let saved: PersistentState =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert!(!saved.pending_kill_intent);
        assert!(saved.kill_timestamps.is_empty());
        assert!(owner.check(false).unwrap().allowed);
        assert!(other.check(false).unwrap().allowed);
        other.begin_kill_accounting().unwrap();
        assert!(owner.check(true).is_err());
        other.finish_kill_accounting(false).unwrap();
        assert!(owner.check(false).unwrap().allowed);
        assert_eq!(owner.current_run_count().unwrap(), 0);
        assert_eq!(other.get_counts().unwrap().day, 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn durable_accounting_failed_final_save_retains_pending_and_actual_run_charge() {
        let dir = retained_accounting_dir("final-save-failure");
        let state_path = dir.join("rate_limit.json");
        let mut limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        let mut target = AccountingTarget::spawn();
        limiter.begin_kill_accounting().unwrap();
        let pending_bytes = fs::read(&state_path).unwrap();
        let alias = dir.join("x".repeat(240));
        fs::hard_link(&state_path, &alias).unwrap();

        // The real pending file and its .lock remain readable. The unique
        // .PID.NANOS.tmp basename exceeds Linux NAME_MAX at the temporary-open
        // boundary, including on root workers. No file is removed or replaced.
        limiter.state_path = Some(alias.clone());
        let error = limiter
            .finish_kill_accounting(target.deliver_term())
            .unwrap_err();
        assert!(
            matches!(&error, RateLimitError::Io(io) if io.raw_os_error() == Some(libc::ENAMETOOLONG)),
            "{error}"
        );
        assert_eq!(limiter.current_run_count().unwrap(), 1);
        assert_eq!(fs::read(&alias).unwrap(), pending_bytes);
        assert_eq!(fs::read(&state_path).unwrap(), pending_bytes);
        let saved: PersistentState = serde_json::from_slice(&pending_bytes).unwrap();
        assert!(saved.pending_kill_intent);
        assert!(saved.kill_timestamps.is_empty());

        for path in [&state_path, &alias] {
            let fresh = SlidingWindowRateLimiter::new(test_config(), Some(path)).unwrap();
            assert!(fresh.check(false).is_err());
            assert!(fresh.check(true).is_err());
            assert!(fresh.check_with_override(true, Some(u32::MAX)).is_err());
            assert!(fresh.check_and_record(false, None).is_err());
            assert!(fresh.check_and_record(true, None).is_err());
            assert!(fresh.begin_kill_accounting().is_err());
            assert!(fresh.finish_kill_accounting(false).is_err());
            assert!(fresh.record_kill().is_err());
            assert_eq!(fresh.current_run_count().unwrap(), 0);
        }
        assert!(limiter.finish_kill_accounting(true).is_err());
        assert_eq!(limiter.current_run_count().unwrap(), 1);
        assert!(limiter.check(true).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn durable_accounting_failed_prepare_never_authorizes_delivery() {
        let dir = retained_accounting_dir("prepare-failure");
        let state_path = dir.join("rate_limit.json");
        SlidingWindowRateLimiter::save_state(&state_path, &PersistentState::default()).unwrap();
        let saved_bytes = fs::read(&state_path).unwrap();
        let alias = dir.join("x".repeat(240));
        fs::hard_link(&state_path, &alias).unwrap();
        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&alias)).unwrap();
        assert!(limiter.check(false).unwrap().allowed);

        let error = limiter.begin_kill_accounting().unwrap_err();
        assert!(
            matches!(&error, RateLimitError::Io(io) if io.raw_os_error() == Some(libc::ENAMETOOLONG)),
            "{error}"
        );
        assert!(limiter.finish_kill_accounting(true).is_err());
        assert_eq!(limiter.current_run_count().unwrap(), 0);
        assert_eq!(fs::read(&state_path).unwrap(), saved_bytes);
        assert_eq!(fs::read(&alias).unwrap(), saved_bytes);
        let saved: PersistentState = serde_json::from_slice(&saved_bytes).unwrap();
        assert!(!saved.pending_kill_intent);
        assert!(saved.kill_timestamps.is_empty());
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
    fn corrupt_persistent_state_refuses_kills_without_resetting_the_budget() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");

        // Write corrupt JSON
        std::fs::write(&state_path, "not valid json").unwrap();

        // Construction permits read-only consumers, but no kill may use a
        // corrupt budget, including an emergency override.
        let config = test_config();
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();

        assert_eq!(limiter.current_run_count().unwrap(), 0);
        assert!(limiter.check(false).is_err());
        assert!(limiter.check(true).is_err());
        assert!(limiter.check_and_record(false, None).is_err());
        assert!(limiter.record_kill().is_err());
        assert!(limiter.begin_kill_accounting().is_err());
        assert!(limiter.finish_kill_accounting(true).is_err());
        assert!(limiter.get_counts().is_err());
        assert_eq!(limiter.current_run_count().unwrap(), 0);
        assert_eq!(fs::read_to_string(&state_path).unwrap(), "not valid json");
    }

    #[test]
    fn unreadable_persistent_state_refuses_kills() {
        // A directory produces a genuine read error even on root workers;
        // permission-bit fixtures alone cannot establish this boundary there.
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");
        fs::create_dir(&state_path).unwrap();
        let limiter = SlidingWindowRateLimiter::new(test_config(), Some(&state_path)).unwrap();
        assert!(limiter.check(false).is_err());
        assert!(limiter.check_and_record(false, None).is_err());
        assert!(limiter.record_kill().is_err());
        assert!(limiter.begin_kill_accounting().is_err());
        assert!(limiter.finish_kill_accounting(true).is_err());
        assert!(state_path.is_dir());
    }

    #[test]
    fn a_running_limiter_sees_another_runs_persisted_kills() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: Some(3),
            max_per_day: None,
        };
        let first = SlidingWindowRateLimiter::new(config.clone(), Some(&state_path)).unwrap();
        let second = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        assert!(second.check(false).unwrap().allowed);
        for _ in 0..3 {
            first.record_kill().unwrap();
        }
        let result = second.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.block_reason.unwrap().window, RateLimitWindow::Hour);
        assert_eq!(second.get_counts().unwrap().hour, 3);
        assert_eq!(second.current_run_count().unwrap(), 0);
        second.check_and_record(true, None).unwrap();
        assert_eq!(first.get_counts().unwrap().hour, 4);
    }

    #[test]
    fn independent_concurrent_writers_lose_no_kills() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");
        let config = RateLimitConfig {
            max_per_run: u32::MAX,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let state_path = state_path.clone();
                let config = config.clone();
                std::thread::spawn(move || {
                    let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
                    for _ in 0..10 {
                        limiter.record_kill().unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let fresh = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        assert_eq!(fresh.get_counts().unwrap().day, 40);
    }

    #[test]
    fn concurrent_atomic_checks_never_exceed_the_shared_budget() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit.json");
        let config = RateLimitConfig {
            max_per_run: u32::MAX,
            max_per_minute: None,
            max_per_hour: Some(10),
            max_per_day: None,
        };
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let state_path = state_path.clone();
                let config = config.clone();
                std::thread::spawn(move || {
                    let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
                    (0..5)
                        .filter(|_| limiter.check_and_record(false, None).unwrap().allowed)
                        .count()
                })
            })
            .collect();
        let accepted: usize = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert_eq!(accepted, 10);
        let fresh = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        assert_eq!(fresh.get_counts().unwrap().hour, 10);
    }

    // ── SlidingWindowRateLimiter debug ──────────────────────────────

    #[test]
    fn test_limiter_debug() {
        let limiter = SlidingWindowRateLimiter::new(test_config(), None::<&str>).unwrap();
        let dbg = format!("{:?}", limiter);
        assert!(dbg.contains("SlidingWindowRateLimiter"));
    }
}
