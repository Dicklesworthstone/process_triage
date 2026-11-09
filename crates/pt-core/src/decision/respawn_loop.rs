//! Respawn loop detection and event persistence.
//!
//! Detects repeated kill→respawn cycles for process identities across sessions
//! and provides planning adjustments: down-weight kill contribution for processes
//! that always respawn, and recommend supervisor-level actions instead.

use crate::collect::ProcessRecord;
use crate::plan::PlanAction;
use crate::verify::{detect_respawn, SavedActionOutcome};
use chrono::{DateTime, Utc};
use pt_common::{IdentityQuality, ProcessIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A record of a kill→respawn event for a process identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnEvent {
    /// Fingerprint matching the process (e.g., command pattern hash).
    pub identity_key: String,
    /// Optional supervisor unit (e.g., systemd service name).
    pub supervisor_unit: Option<String>,
    /// Optional cgroup path.
    pub cgroup: Option<String>,
    /// Timestamp of the kill action (epoch seconds).
    pub kill_ts: f64,
    /// Timestamp when respawn was detected (epoch seconds).
    pub respawn_ts: f64,
    /// Delay between kill and respawn in seconds.
    pub respawn_delay_secs: f64,
    /// Session ID where the kill was issued.
    pub session_id: Option<String>,
}

/// Configuration for respawn loop detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnLoopConfig {
    /// Minimum repeated respawns to declare a loop.
    pub min_respawns: usize,
    /// Maximum time window (seconds) within which respawns count as a loop.
    pub window_secs: f64,
    /// Maximum delay (seconds) between kill and respawn to consider as respawn.
    pub max_respawn_delay_secs: f64,
    /// Kill utility discount factor for respawning processes (0.0 to 1.0).
    /// Applied as: effective_kill_utility *= (1 - discount * loop_count / max_loops)
    pub kill_discount_factor: f64,
    /// Maximum loop count for discount saturation.
    pub max_loops_for_discount: usize,
}

impl Default for RespawnLoopConfig {
    fn default() -> Self {
        Self {
            min_respawns: 2,
            window_secs: 3600.0,
            max_respawn_delay_secs: 30.0,
            kill_discount_factor: 0.8,
            max_loops_for_discount: 5,
        }
    }
}

/// Summary of detected respawn loop for a process identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnLoopDetection {
    /// Process identity key.
    pub identity_key: String,
    /// Number of kill→respawn cycles in the window.
    pub loop_count: usize,
    /// Whether this qualifies as a loop (count >= min_respawns).
    pub is_loop: bool,
    /// Average respawn delay (seconds).
    pub avg_respawn_delay_secs: f64,
    /// Recommended action.
    pub recommendation: RespawnRecommendation,
    /// Kill utility discount (0.0 = full discount, 1.0 = no discount).
    pub kill_utility_multiplier: f64,
}

/// Recommended action for a respawn loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RespawnRecommendation {
    /// Normal kill is fine (no loop detected).
    KillOk,
    /// Warn about respawn pattern but proceed with kill.
    WarnRespawn,
    /// Suggest supervisor stop instead of kill.
    SupervisorStop,
    /// Suggest disabling the supervisor unit entirely.
    SupervisorDisable,
}

impl std::fmt::Display for RespawnRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillOk => write!(f, "kill_ok"),
            Self::WarnRespawn => write!(f, "warn_respawn"),
            Self::SupervisorStop => write!(f, "supervisor_stop"),
            Self::SupervisorDisable => write!(f, "supervisor_disable"),
        }
    }
}

/// Tracks respawn events and detects loops.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RespawnTracker {
    /// All recorded respawn events, keyed by identity_key.
    events: HashMap<String, Vec<RespawnEvent>>,
}

impl RespawnTracker {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
        }
    }

    /// Record a respawn event.
    pub fn record_event(&mut self, event: RespawnEvent) {
        self.events
            .entry(event.identity_key.clone())
            .or_default()
            .push(event);
    }

    /// Record a kill→respawn pair.
    pub fn record_respawn(
        &mut self,
        identity_key: String,
        supervisor_unit: Option<String>,
        cgroup: Option<String>,
        kill_ts: f64,
        respawn_ts: f64,
        session_id: Option<String>,
    ) {
        let delay = respawn_ts - kill_ts;
        self.record_event(RespawnEvent {
            identity_key,
            supervisor_unit,
            cgroup,
            kill_ts,
            respawn_ts,
            respawn_delay_secs: delay,
            session_id,
        });
    }

    /// Detect respawn loop for a given identity.
    pub fn detect_loop(
        &self,
        identity_key: &str,
        config: &RespawnLoopConfig,
        now: f64,
    ) -> RespawnLoopDetection {
        let events = match self
            .events
            .get(identity_key)
            .filter(|_| valid_loop_config(config) && now.is_finite())
        {
            Some(evts) => evts,
            None => {
                return RespawnLoopDetection {
                    identity_key: identity_key.to_string(),
                    loop_count: 0,
                    is_loop: false,
                    avg_respawn_delay_secs: 0.0,
                    recommendation: RespawnRecommendation::KillOk,
                    kill_utility_multiplier: 1.0,
                };
            }
        };

        // Filter events within the time window and with acceptable delay.
        let recent: Vec<&RespawnEvent> = events
            .iter()
            .filter(|e| {
                current_event(e, config, now)
                    && e.respawn_delay_secs <= config.max_respawn_delay_secs
            })
            .collect();

        let loop_count = recent.len();
        let is_loop = loop_count >= config.min_respawns;

        let avg_delay = if recent.is_empty() {
            0.0
        } else {
            recent.iter().map(|e| e.respawn_delay_secs).sum::<f64>() / recent.len() as f64
        };

        let has_supervisor = recent.iter().any(|e| {
            e.supervisor_unit
                .as_deref()
                .is_some_and(|unit| !unit.trim().is_empty())
        });

        let recommendation = if !is_loop {
            RespawnRecommendation::KillOk
        } else if loop_count >= config.max_loops_for_discount && has_supervisor {
            RespawnRecommendation::SupervisorDisable
        } else if has_supervisor {
            RespawnRecommendation::SupervisorStop
        } else {
            RespawnRecommendation::WarnRespawn
        };

        let discount = if is_loop {
            let ratio = (loop_count as f64 / config.max_loops_for_discount as f64).min(1.0);
            1.0 - config.kill_discount_factor * ratio
        } else {
            1.0
        };

        RespawnLoopDetection {
            identity_key: identity_key.to_string(),
            loop_count,
            is_loop,
            avg_respawn_delay_secs: avg_delay,
            recommendation,
            kill_utility_multiplier: discount,
        }
    }

    /// Get all identities with detected loops.
    pub fn all_loops(&self, config: &RespawnLoopConfig, now: f64) -> Vec<RespawnLoopDetection> {
        self.events
            .keys()
            .map(|key| self.detect_loop(key, config, now))
            .filter(|d| d.is_loop)
            .collect()
    }

    /// Number of tracked identities.
    pub fn identity_count(&self) -> usize {
        self.events.len()
    }

    /// Total event count.
    pub fn event_count(&self) -> usize {
        self.events.values().map(|v| v.len()).sum()
    }

    /// Prune events older than the window.
    pub fn prune(&mut self, config: &RespawnLoopConfig, now: f64) {
        for events in self.events.values_mut() {
            events.retain(|e| current_event(e, config, now));
        }
        self.events.retain(|_, v| !v.is_empty());
    }
}

fn valid_loop_config(config: &RespawnLoopConfig) -> bool {
    config.min_respawns > 0
        && config.max_loops_for_discount > 0
        && config.window_secs.is_finite()
        && config.window_secs > 0.0
        && config.max_respawn_delay_secs.is_finite()
        && config.max_respawn_delay_secs >= 0.0
        && config.kill_discount_factor.is_finite()
        && (0.0..=1.0).contains(&config.kill_discount_factor)
}

fn current_event(event: &RespawnEvent, config: &RespawnLoopConfig, now: f64) -> bool {
    valid_loop_config(config)
        && now.is_finite()
        && event.kill_ts.is_finite()
        && event.respawn_ts.is_finite()
        && event.respawn_delay_secs.is_finite()
        && event.kill_ts <= event.respawn_ts
        && event.respawn_ts <= now
        && event.respawn_delay_secs >= 0.0
        && ((event.respawn_ts - event.kill_ts) - event.respawn_delay_secs).abs() < 0.000_001
        && (now - event.kill_ts) <= config.window_secs
}

/// Apply respawn loop discount to a kill utility score.
pub fn discount_kill_utility(base_utility: f64, detection: &RespawnLoopDetection) -> f64 {
    base_utility * detection.kill_utility_multiplier
}

const HISTORY_FILE: &str = "respawn_history.json";
const HISTORY_SCHEMA_VERSION: u32 = 1;
const MAX_HISTORY_EVENTS: usize = 4096;
const MAX_EVENTS_PER_IDENTITY: usize = 64;
const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;

/// A current, incarnation-bound explanation for repeated child replacement.
///
/// This is evidence for reviewing the spawner, never permission to kill it or
/// disable a service. Supervisor actions still require their own fresh binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnLoopSummary {
    pub identity_key: String,
    pub uid: u32,
    pub command: String,
    pub parent: ProcessIdentity,
    pub parent_command: String,
    pub latest_replacement_pid: u32,
    pub last_observed_at: DateTime<Utc>,
    pub detection: RespawnLoopDetection,
    pub review_message: String,
}

/// Result of persisting an observation. Replaying a saved execution returns
/// `inserted = false`, so callers can avoid emitting duplicate inbox items.
#[derive(Debug, Clone, Serialize)]
pub struct RecordedRespawn {
    pub inserted: bool,
    pub summary: RespawnLoopSummary,
}

#[derive(Debug, thiserror::Error)]
pub enum RespawnHistoryError {
    #[error("unable to resolve the process_triage data directory")]
    DataDirUnavailable,
    #[error("respawn history I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid respawn history JSON at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid respawn history: {0}")]
    InvalidHistory(String),
    #[error("durable respawn history requires an operating-system file lock")]
    LockUnavailable,
}

/// Host-local history shared by apply, verify, and later planning sessions.
/// Reads observe an atomic file version. Writers lock a stable sibling inode,
/// reread and merge, then atomically replace the history while holding the lock.
#[derive(Debug, Clone)]
pub struct RespawnHistoryStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableRespawnEvent {
    attempt_id: String,
    identity_key: String,
    session_id: String,
    action_id: String,
    target: ProcessIdentity,
    command: String,
    parent: ProcessIdentity,
    parent_command: String,
    replacement: ProcessIdentity,
    executed_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    respawn_delay_secs: f64,
}

impl DurableRespawnEvent {
    fn tracker_event(&self) -> RespawnEvent {
        let kill_ts = epoch_seconds(self.executed_at);
        RespawnEvent {
            identity_key: self.identity_key.clone(),
            // A parent command is not proof of a supervisor unit or cgroup.
            supervisor_unit: None,
            cgroup: None,
            kill_ts,
            respawn_ts: kill_ts + self.respawn_delay_secs,
            respawn_delay_secs: self.respawn_delay_secs,
            session_id: Some(self.session_id.clone()),
        }
    }

    fn is_current(&self, now: DateTime<Utc>) -> bool {
        self.observed_at <= now
            && current_event(
                &self.tracker_event(),
                &RespawnLoopConfig::default(),
                epoch_seconds(now),
            )
    }

    fn valid(&self) -> bool {
        let config = RespawnLoopConfig::default();
        !self.session_id.trim().is_empty()
            && !self.action_id.trim().is_empty()
            && !self.command.is_empty()
            && normalize_command(&self.command) == self.command
            && full_identity_parts(&self.target).is_some()
            && full_identity_parts(&self.parent).is_some()
            && full_identity_parts(&self.replacement).is_some()
            && same_boot(&self.target, &self.parent)
            && same_boot(&self.target, &self.replacement)
            && self.target.uid == self.replacement.uid
            && self.target.pid != self.parent.pid
            && self.replacement.pid != self.parent.pid
            && self.target.start_id != self.replacement.start_id
            && self.attempt_id
                == attempt_key(
                    &self.session_id,
                    &self.action_id,
                    self.executed_at,
                    &self.target,
                )
            && self.identity_key
                == respawn_identity_key(self.target.uid, &self.command, &self.parent)
            && self.respawn_delay_secs > 0.0
            && self.respawn_delay_secs <= config.max_respawn_delay_secs
            && current_event(
                &self.tracker_event(),
                &config,
                epoch_seconds(self.observed_at),
            )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RespawnHistoryFile {
    schema_version: u32,
    events: Vec<DurableRespawnEvent>,
}

impl Default for RespawnHistoryFile {
    fn default() -> Self {
        Self {
            schema_version: HISTORY_SCHEMA_VERSION,
            events: Vec::new(),
        }
    }
}

/// One read of the shared history, indexed for a whole process census. Loading
/// this snapshot does not write files or acquire an execution lock.
#[derive(Debug, Clone, Default)]
pub struct RespawnHistorySnapshot {
    events: HashMap<String, Vec<DurableRespawnEvent>>,
}

impl RespawnHistorySnapshot {
    fn from_history(history: RespawnHistoryFile) -> Self {
        let mut snapshot = Self::default();
        for event in history.events {
            snapshot
                .events
                .entry(event.identity_key.clone())
                .or_default()
                .push(event);
        }
        snapshot
    }

    pub fn event_count(&self) -> usize {
        self.events.values().map(Vec::len).sum()
    }

    pub fn identity_count(&self) -> usize {
        self.events.len()
    }

    pub fn for_process(
        &self,
        process: &ProcessRecord,
        current: &[ProcessRecord],
        now: DateTime<Utc>,
    ) -> Option<RespawnLoopSummary> {
        self.for_process_with_parent(process, unique_process(process.ppid.0, current), now)
    }

    /// Use a caller's census index to avoid searching the full population for
    /// every candidate. A missing parent or reused PID cannot inherit history.
    pub fn for_process_with_parent(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
        now: DateTime<Utc>,
    ) -> Option<RespawnLoopSummary> {
        let parent = parent?;
        if process.ppid != parent.pid || process.state.is_zombie() || parent.state.is_zombie() {
            return None;
        }
        let parent_identity = full_process_identity(parent)?;
        let child_identity = full_process_identity(process)?;
        if !same_boot(&child_identity, &parent_identity) {
            return None;
        }
        let command = normalize_command(&process.cmd);
        let key = respawn_identity_key(process.uid, &command, &parent_identity);
        self.summarize(&key, now, Some(&parent.cmd))
    }

    fn summarize(
        &self,
        key: &str,
        now: DateTime<Utc>,
        parent_command: Option<&str>,
    ) -> Option<RespawnLoopSummary> {
        let events = self.events.get(key)?;
        let mut tracker = RespawnTracker::new();
        let mut latest: Option<&DurableRespawnEvent> = None;
        for event in events.iter().filter(|event| event.is_current(now)) {
            tracker.record_event(event.tracker_event());
            if latest.is_none_or(|old| {
                (event.executed_at, event.observed_at) > (old.executed_at, old.observed_at)
            }) {
                latest = Some(event);
            }
        }
        let latest = latest?;
        let detection = tracker.detect_loop(key, &RespawnLoopConfig::default(), epoch_seconds(now));
        if detection.loop_count == 0 {
            return None;
        }
        let parent_command = normalize_command(parent_command.unwrap_or(&latest.parent_command));
        let review_message = format!(
            "Spawner PID {} ({:?}) has replaced {:?} after {} verified kill(s). Review this spawner and its supervisor before repeating a child kill; no parent action has been authorized.",
            latest.parent.pid.0, parent_command, latest.command, detection.loop_count,
        );
        Some(RespawnLoopSummary {
            identity_key: key.to_string(),
            uid: latest.target.uid,
            command: latest.command.clone(),
            parent: latest.parent.clone(),
            parent_command,
            latest_replacement_pid: latest.replacement.pid.0,
            last_observed_at: events
                .iter()
                .filter(|event| event.is_current(now))
                .map(|event| event.observed_at)
                .max()?,
            detection,
            review_message,
        })
    }
}

impl RespawnHistoryStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn from_data_dir(data_dir: &Path) -> Self {
        Self::new(data_dir.join(HISTORY_FILE))
    }

    /// Match the session and inbox data-directory resolution order.
    pub fn from_env() -> Result<Self, RespawnHistoryError> {
        let data_dir = if let Ok(dir) = std::env::var("PROCESS_TRIAGE_DATA") {
            PathBuf::from(dir)
        } else if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(dir).join("process_triage")
        } else {
            dirs::data_dir()
                .ok_or(RespawnHistoryError::DataDirUnavailable)?
                .join("process_triage")
        };
        Ok(Self::from_data_dir(&data_dir))
    }

    pub fn load(&self, now: DateTime<Utc>) -> Result<RespawnHistorySnapshot, RespawnHistoryError> {
        let mut history = self.read_history()?;
        self.prune_history(&mut history, now)?;
        Ok(RespawnHistorySnapshot::from_history(history))
    }

    /// Learn only from the shared verifier's positive replacement match, plus a
    /// full, live parent incarnation. The attempt key includes session, action,
    /// execution timestamp, and target incarnation: apply and verify can safely
    /// replay the same successful execution without manufacturing another loop.
    pub fn ingest_verified_respawn(
        &self,
        action: &PlanAction,
        execution: &SavedActionOutcome,
        current: &[ProcessRecord],
        session_id: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<Option<RecordedRespawn>, RespawnHistoryError> {
        let Some(event) =
            verified_respawn_event(action, execution, current, session_id, observed_at)
        else {
            return Ok(None);
        };
        let _lock = HistoryLock::acquire(&self.path)?;
        let mut history = self.read_history()?;
        self.prune_history(&mut history, observed_at)?;
        let already_recorded = history
            .events
            .iter()
            .any(|saved| saved.attempt_id == event.attempt_id);
        let key = event.identity_key.clone();
        let attempt_id = event.attempt_id.clone();
        if !already_recorded {
            history.events.push(event);
            self.prune_history(&mut history, observed_at)?;
        }
        let inserted = !already_recorded
            && history
                .events
                .iter()
                .any(|saved| saved.attempt_id == attempt_id);
        if inserted {
            self.write_history(&history)?;
        }
        let snapshot = RespawnHistorySnapshot::from_history(history);
        Ok(snapshot
            .summarize(&key, observed_at, None)
            .map(|summary| RecordedRespawn { inserted, summary }))
    }

    fn read_history(&self) -> Result<RespawnHistoryFile, RespawnHistoryError> {
        let mut options = OpenOptions::new();
        options.read(true);
        history_file_options(&mut options);
        let file = match options.open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RespawnHistoryFile::default());
            }
            Err(source) => return Err(history_io(&self.path, source)),
        };
        if !file
            .metadata()
            .map_err(|source| history_io(&self.path, source))?
            .is_file()
        {
            return Err(RespawnHistoryError::InvalidHistory(
                "history must be a regular file".to_string(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_HISTORY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| history_io(&self.path, source))?;
        if bytes.len() > MAX_HISTORY_BYTES {
            return Err(RespawnHistoryError::InvalidHistory(
                "history exceeds its size bound".to_string(),
            ));
        }
        let history: RespawnHistoryFile =
            serde_json::from_slice(&bytes).map_err(|source| RespawnHistoryError::Json {
                path: self.path.clone(),
                source,
            })?;
        if history.schema_version != HISTORY_SCHEMA_VERSION
            || history.events.iter().any(|event| !event.valid())
        {
            return Err(RespawnHistoryError::InvalidHistory(
                "unsupported schema or inconsistent execution/parent evidence".to_string(),
            ));
        }
        Ok(history)
    }

    fn prune_history(
        &self,
        history: &mut RespawnHistoryFile,
        now: DateTime<Utc>,
    ) -> Result<(), RespawnHistoryError> {
        history.events.retain(|event| event.is_current(now));
        history.events.sort_by(|left, right| {
            (right.executed_at, right.observed_at, &right.attempt_id).cmp(&(
                left.executed_at,
                left.observed_at,
                &left.attempt_id,
            ))
        });
        let mut attempts = HashSet::new();
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut retained = Vec::new();
        // Leave space for the schema envelope and array punctuation.
        let mut total_bytes = 128usize;
        for event in history.events.drain(..) {
            if retained.len() >= MAX_HISTORY_EVENTS || !attempts.insert(event.attempt_id.clone()) {
                continue;
            }
            let count = counts.entry(event.identity_key.clone()).or_default();
            if *count >= MAX_EVENTS_PER_IDENTITY {
                continue;
            }
            let bytes = serde_json::to_vec(&event).map_err(|source| RespawnHistoryError::Json {
                path: self.path.clone(),
                source,
            })?;
            if total_bytes.saturating_add(bytes.len() + 1) > MAX_HISTORY_BYTES {
                continue;
            }
            total_bytes += bytes.len() + 1;
            *count += 1;
            retained.push(event);
        }
        history.events = retained;
        Ok(())
    }

    fn write_history(&self, history: &RespawnHistoryFile) -> Result<(), RespawnHistoryError> {
        let temporary = history_sibling(
            &self.path,
            &format!(".{}.{}.tmp", std::process::id(), uuid::Uuid::new_v4()),
        );
        let bytes = serde_json::to_vec(history).map_err(|source| RespawnHistoryError::Json {
            path: self.path.clone(),
            source,
        })?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        history_file_options(&mut options);
        let mut file = options
            .open(&temporary)
            .map_err(|source| history_io(&temporary, source))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| history_io(&temporary, source))?;
        fs::rename(&temporary, &self.path).map_err(|source| history_io(&self.path, source))?;
        #[cfg(unix)]
        {
            let parent = history_parent(&self.path);
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| history_io(parent, source))?;
        }
        Ok(())
    }
}

fn verified_respawn_event(
    action: &PlanAction,
    execution: &SavedActionOutcome,
    current: &[ProcessRecord],
    session_id: &str,
    observed_at: DateTime<Utc>,
) -> Option<DurableRespawnEvent> {
    let parent_identity = execution.parent_identity.as_ref()?;
    full_identity_parts(parent_identity)?;
    full_identity_parts(&action.target)?;
    full_identity_parts(execution.target.as_ref()?)?;
    let parent = unique_process(parent_identity.pid.0, current)?;
    if parent.state.is_zombie()
        || current.iter().any(|process| {
            process.pid == action.target.pid
                && process.uid == action.target.uid
                && process.start_id == action.target.start_id
                && !process.state.is_zombie()
        })
    {
        return None;
    }
    let detected = detect_respawn(action, execution, current)?;
    let replacement = unique_process(detected.pid, current)?;
    if replacement.start_time_unix > observed_at.timestamp() {
        return None;
    }
    let executed_at = execution.executed_at?;
    let command = normalize_command(execution.command.as_deref()?);
    let delay = replacement_delay(execution, replacement)?;
    let event = DurableRespawnEvent {
        attempt_id: attempt_key(session_id, &action.action_id, executed_at, &action.target),
        identity_key: respawn_identity_key(action.target.uid, &command, parent_identity),
        session_id: session_id.to_string(),
        action_id: action.action_id.clone(),
        target: action.target.clone(),
        command,
        parent: parent_identity.clone(),
        parent_command: normalize_command(&parent.cmd),
        replacement: full_process_identity(replacement)?,
        executed_at,
        observed_at,
        respawn_delay_secs: delay,
    };
    (event.valid() && event.is_current(observed_at)).then_some(event)
}

fn replacement_delay(execution: &SavedActionOutcome, replacement: &ProcessRecord) -> Option<f64> {
    if let Some(clock) = &execution.execution_clock {
        let (boot, ticks) = start_parts(&replacement.start_id.0, replacement.pid.0)?;
        if boot != clock.boot_id {
            return None;
        }
        #[cfg(unix)]
        {
            // SAFETY: sysconf reads the host's clock-tick rate without modifying state.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            if hz <= 0 {
                return None;
            }
            return Some(ticks.checked_sub(clock.ticks)? as f64 / hz as f64);
        }
        #[cfg(not(unix))]
        {
            let _ = ticks;
            return None;
        }
    }
    Some(replacement.start_time_unix as f64 - epoch_seconds(execution.executed_at?))
}

fn epoch_seconds(at: DateTime<Utc>) -> f64 {
    at.timestamp() as f64 + f64::from(at.timestamp_subsec_nanos()) / 1_000_000_000.0
}

fn normalize_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn unique_process(pid: u32, current: &[ProcessRecord]) -> Option<&ProcessRecord> {
    let mut matches = current.iter().filter(|process| process.pid.0 == pid);
    let process = matches.next()?;
    matches.next().is_none().then_some(process)
}

fn start_parts(start_id: &str, pid: u32) -> Option<(&str, u64)> {
    let mut parts = start_id.split(':');
    let boot = parts.next()?;
    let start = parts.next()?.parse::<u64>().ok()?;
    let recorded_pid = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none()
        && !boot.is_empty()
        && !matches!(boot, "unknown" | "synthetic")
        && start > 0
        && pid > 0
        && recorded_pid == pid)
        .then_some((boot, start))
}

fn full_identity_parts(identity: &ProcessIdentity) -> Option<(&str, u64)> {
    (identity.quality == IdentityQuality::Full)
        .then(|| start_parts(&identity.start_id.0, identity.pid.0))?
}

fn full_process_identity(process: &ProcessRecord) -> Option<ProcessIdentity> {
    start_parts(&process.start_id.0, process.pid.0)?;
    Some(ProcessIdentity::full(
        process.pid.0,
        process.start_id.clone(),
        process.uid,
        process.pgid,
        process.sid,
        IdentityQuality::Full,
    ))
}

fn same_boot(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    full_identity_parts(left)
        .zip(full_identity_parts(right))
        .is_some_and(|((left_boot, _), (right_boot, _))| left_boot == right_boot)
}

fn hash_field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value.as_bytes());
}

fn hash_identity(hash: &mut Sha256, identity: &ProcessIdentity) {
    hash.update(identity.pid.0.to_le_bytes());
    hash.update(identity.uid.to_le_bytes());
    hash_field(hash, &identity.start_id.0);
}

fn respawn_identity_key(uid: u32, command: &str, parent: &ProcessIdentity) -> String {
    let mut hash = Sha256::new();
    hash.update(b"process_triage.respawn.identity.v1");
    hash.update(uid.to_le_bytes());
    hash_field(&mut hash, command);
    hash_identity(&mut hash, parent);
    hex::encode(hash.finalize())
}

fn attempt_key(
    session_id: &str,
    action_id: &str,
    executed_at: DateTime<Utc>,
    target: &ProcessIdentity,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"process_triage.respawn.attempt.v1");
    hash_field(&mut hash, session_id);
    hash_field(&mut hash, action_id);
    hash.update(executed_at.timestamp().to_le_bytes());
    hash.update(executed_at.timestamp_subsec_nanos().to_le_bytes());
    hash_identity(&mut hash, target);
    hex::encode(hash.finalize())
}

fn history_io(path: &Path, source: std::io::Error) -> RespawnHistoryError {
    RespawnHistoryError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn history_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn history_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn history_file_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(not(unix))]
    let _ = options;
}

struct HistoryLock {
    _file: File,
}

impl HistoryLock {
    fn acquire(path: &Path) -> Result<Self, RespawnHistoryError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let parent = history_parent(path);
            fs::create_dir_all(parent).map_err(|source| history_io(parent, source))?;
            let lock_path = history_sibling(path, ".lock");
            let mut options = OpenOptions::new();
            options.create(true).truncate(false).write(true);
            history_file_options(&mut options);
            let file = options
                .open(&lock_path)
                .map_err(|source| history_io(&lock_path, source))?;
            if !file
                .metadata()
                .map_err(|source| history_io(&lock_path, source))?
                .is_file()
            {
                return Err(RespawnHistoryError::InvalidHistory(
                    "history lock must be a regular file".to_string(),
                ));
            }
            loop {
                // SAFETY: the guard owns this descriptor; closing it releases
                // the advisory lock even when a subsequent write fails.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let source = std::io::Error::last_os_error();
                if source.kind() != std::io::ErrorKind::Interrupted {
                    return Err(history_io(&lock_path, source));
                }
            }
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(RespawnHistoryError::LockUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker_with_respawns(n: usize, delay: f64) -> (RespawnTracker, f64) {
        let mut tracker = RespawnTracker::new();
        let base_ts = 1000.0;
        for i in 0..n {
            let kill_ts = base_ts + i as f64 * 60.0;
            tracker.record_respawn(
                "nginx".to_string(),
                Some("nginx.service".to_string()),
                None,
                kill_ts,
                kill_ts + delay,
                Some("pt-session-1".to_string()),
            );
        }
        let now = base_ts + n as f64 * 60.0;
        (tracker, now)
    }

    #[test]
    fn test_no_events() {
        let tracker = RespawnTracker::new();
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("unknown", &config, 1000.0);
        assert!(!det.is_loop);
        assert_eq!(det.loop_count, 0);
        assert_eq!(det.recommendation, RespawnRecommendation::KillOk);
        assert_eq!(det.kill_utility_multiplier, 1.0);
    }

    #[test]
    fn test_single_respawn_no_loop() {
        let (tracker, now) = make_tracker_with_respawns(1, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(!det.is_loop);
        assert_eq!(det.loop_count, 1);
        assert_eq!(det.recommendation, RespawnRecommendation::KillOk);
    }

    #[test]
    fn test_detects_loop() {
        let (tracker, now) = make_tracker_with_respawns(3, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(det.is_loop);
        assert_eq!(det.loop_count, 3);
        assert_eq!(det.recommendation, RespawnRecommendation::SupervisorStop);
        assert!(det.kill_utility_multiplier < 1.0);
    }

    #[test]
    fn test_supervisor_disable_at_max() {
        let (tracker, now) = make_tracker_with_respawns(5, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(det.is_loop);
        assert_eq!(det.recommendation, RespawnRecommendation::SupervisorDisable);
        // At max loops, discount should be at maximum.
        let expected = 1.0 - 0.8; // kill_discount_factor
        assert!((det.kill_utility_multiplier - expected).abs() < 0.01);
    }

    #[test]
    fn test_warn_without_supervisor() {
        let mut tracker = RespawnTracker::new();
        for i in 0..3 {
            tracker.record_respawn(
                "rogue_process".to_string(),
                None, // No supervisor
                None,
                1000.0 + i as f64 * 60.0,
                1002.0 + i as f64 * 60.0,
                None,
            );
        }
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("rogue_process", &config, 1200.0);
        assert!(det.is_loop);
        assert_eq!(det.recommendation, RespawnRecommendation::WarnRespawn);
    }

    #[test]
    fn test_slow_respawn_ignored() {
        let (tracker, now) = make_tracker_with_respawns(3, 60.0); // 60s delay
        let config = RespawnLoopConfig {
            max_respawn_delay_secs: 30.0,
            ..Default::default()
        };
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(!det.is_loop); // Delays too long
        assert_eq!(det.loop_count, 0);
    }

    #[test]
    fn test_old_events_outside_window() {
        let mut tracker = RespawnTracker::new();
        // Events from long ago.
        for i in 0..5 {
            tracker.record_respawn(
                "old_proc".to_string(),
                Some("old.service".to_string()),
                None,
                100.0 + i as f64 * 60.0,
                102.0 + i as f64 * 60.0,
                None,
            );
        }
        let config = RespawnLoopConfig {
            window_secs: 3600.0,
            ..Default::default()
        };
        let det = tracker.detect_loop("old_proc", &config, 100000.0);
        assert!(!det.is_loop); // All events outside window.
    }

    #[test]
    fn test_prune_removes_old() {
        let (mut tracker, _) = make_tracker_with_respawns(5, 2.0);
        assert_eq!(tracker.event_count(), 5);
        let config = RespawnLoopConfig {
            window_secs: 60.0,
            ..Default::default()
        };
        tracker.prune(&config, 100000.0);
        assert_eq!(tracker.event_count(), 0);
        assert_eq!(tracker.identity_count(), 0);
    }

    #[test]
    fn test_discount_kill_utility() {
        let det = RespawnLoopDetection {
            identity_key: "test".to_string(),
            loop_count: 3,
            is_loop: true,
            avg_respawn_delay_secs: 2.0,
            recommendation: RespawnRecommendation::SupervisorStop,
            kill_utility_multiplier: 0.52,
        };
        let discounted = discount_kill_utility(100.0, &det);
        assert!((discounted - 52.0).abs() < 0.1);
    }

    #[test]
    fn test_all_loops() {
        let mut tracker = RespawnTracker::new();
        // nginx loops
        for i in 0..3 {
            tracker.record_respawn(
                "nginx".to_string(),
                Some("nginx.service".to_string()),
                None,
                1000.0 + i as f64 * 60.0,
                1002.0 + i as f64 * 60.0,
                None,
            );
        }
        // single event for redis (no loop)
        tracker.record_respawn(
            "redis".to_string(),
            Some("redis.service".to_string()),
            None,
            1000.0,
            1002.0,
            None,
        );
        let config = RespawnLoopConfig::default();
        let loops = tracker.all_loops(&config, 1200.0);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].identity_key, "nginx");
    }

    #[test]
    fn test_avg_delay() {
        let mut tracker = RespawnTracker::new();
        tracker.record_respawn("svc".to_string(), None, None, 100.0, 102.0, None);
        tracker.record_respawn("svc".to_string(), None, None, 200.0, 206.0, None);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("svc", &config, 300.0);
        assert!((det.avg_respawn_delay_secs - 4.0).abs() < 0.01); // (2+6)/2
    }

    #[test]
    fn invalid_or_future_events_do_not_create_a_loop() {
        let mut tracker = RespawnTracker::new();
        for (kill, replacement) in [
            (1001.0, 1002.0),
            (999.0, 1001.0),
            (900.0, 899.0),
            (f64::NAN, 950.0),
            (950.0, f64::INFINITY),
        ] {
            tracker.record_respawn("svc".to_string(), None, None, kill, replacement, None);
        }
        let config = RespawnLoopConfig::default();
        let detection = tracker.detect_loop("svc", &config, 1000.0);
        assert_eq!(detection.loop_count, 0);
        assert!(!detection.is_loop);
        assert_eq!(detection.kill_utility_multiplier, 1.0);
        tracker.prune(&config, 1000.0);
        assert_eq!(tracker.event_count(), 0);
    }

    #[test]
    fn stale_supervisor_evidence_does_not_escalate_current_events() {
        let mut tracker = RespawnTracker::new();
        tracker.record_respawn(
            "svc".to_string(),
            Some("old.service".to_string()),
            None,
            10.0,
            11.0,
            None,
        );
        tracker.record_respawn("svc".to_string(), None, None, 4000.0, 4001.0, None);
        tracker.record_respawn("svc".to_string(), None, None, 4100.0, 4101.0, None);
        let detection = tracker.detect_loop("svc", &RespawnLoopConfig::default(), 4200.0);
        assert_eq!(detection.loop_count, 2);
        assert_eq!(detection.recommendation, RespawnRecommendation::WarnRespawn);
    }

    #[test]
    fn invalid_discount_config_never_generates_nan_or_invented_loops() {
        let (tracker, now) = make_tracker_with_respawns(3, 2.0);
        for config in [
            RespawnLoopConfig {
                min_respawns: 0,
                ..Default::default()
            },
            RespawnLoopConfig {
                max_loops_for_discount: 0,
                ..Default::default()
            },
            RespawnLoopConfig {
                window_secs: f64::INFINITY,
                ..Default::default()
            },
            RespawnLoopConfig {
                kill_discount_factor: 1.5,
                ..Default::default()
            },
        ] {
            let detection = tracker.detect_loop("nginx", &config, now);
            assert!(!detection.is_loop);
            assert_eq!(detection.kill_utility_multiplier, 1.0);
        }
    }

    #[cfg(unix)]
    mod persistence {
        use super::*;
        use crate::collect::ProcessState;
        use crate::decision::Action;
        use crate::verify::ExecutionClock;
        use pt_common::{ProcessId, StartId};
        use std::sync::{Arc, Barrier};
        use std::time::Duration;

        fn at(seconds: i64) -> DateTime<Utc> {
            DateTime::from_timestamp(seconds, 0).unwrap()
        }

        fn clock_hz() -> u64 {
            // SAFETY: sysconf only reads the host clock configuration.
            u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap()
        }

        fn process(pid: u32, parent: u32, command: &str, started: i64) -> ProcessRecord {
            ProcessRecord {
                pid: ProcessId(pid),
                ppid: ProcessId(parent),
                uid: 1000,
                user: "fixture".to_string(),
                pgid: Some(10),
                sid: Some(10),
                start_id: StartId::from_linux("boot", started as u64 * clock_hz(), pid),
                comm: command.split_whitespace().next().unwrap_or("").to_string(),
                cmd: command.to_string(),
                state: ProcessState::Sleeping,
                cpu_percent: 0.0,
                rss_bytes: 0,
                vsz_bytes: 0,
                tty: None,
                start_time_unix: started,
                elapsed: Duration::from_secs(1),
                source: "respawn history fixture".to_string(),
                container_info: None,
            }
        }

        // These are canonical execution/census fixtures, not live signal proof.
        fn fixture(
            attempt: u32,
        ) -> (
            PlanAction,
            SavedActionOutcome,
            Vec<ProcessRecord>,
            DateTime<Utc>,
        ) {
            let pid = 100 + attempt * 2;
            let killed_at = 1000 + i64::from(attempt) * 2;
            let target = process(pid, 10, "sleep 1000", killed_at - 1);
            let parent = process(10, 1, "bash respawner.sh", 1);
            let replacement = process(pid + 1, 10, " sleep   1000 ", killed_at + 1);
            let action: PlanAction = serde_json::from_value(serde_json::json!({
                "action_id": format!("kill-{attempt}"),
                "target": full_process_identity(&target).unwrap(),
                "action": "kill",
                "order": 0,
                "stage": 0,
                "timeouts": {"preflight_ms": 2000, "execute_ms": 10000, "verify_ms": 5000},
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
            }))
            .unwrap();
            let execution = SavedActionOutcome {
                action_id: action.action_id.clone(),
                pid,
                status: "success".to_string(),
                action: Some(Action::Kill),
                target: Some(action.target.clone()),
                command: Some(target.cmd),
                parent_pid: Some(10),
                parent_identity: full_process_identity(&parent),
                executed_at: Some(at(killed_at)),
                execution_clock: Some(ExecutionClock {
                    boot_id: "boot".to_string(),
                    ticks: killed_at as u64 * clock_hz(),
                }),
                time_ms: Some(50),
                supervisor_restart: None,
            };
            (
                action,
                execution,
                vec![replacement, parent],
                at(killed_at + 2),
            )
        }

        #[test]
        fn persistence_survives_sessions_and_deduplicates_apply_verify_replay() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            assert_eq!(store.load(at(1000)).unwrap().event_count(), 0);
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
            let (action, execution, current, observed) = fixture(0);
            let first = store
                .ingest_verified_respawn(&action, &execution, &current, "session-a", observed)
                .unwrap()
                .unwrap();
            assert!(first.inserted);
            assert_eq!(first.summary.detection.loop_count, 1);
            assert!(!first.summary.detection.is_loop);
            let replay = RespawnHistoryStore::from_data_dir(dir.path())
                .ingest_verified_respawn(&action, &execution, &current, "session-a", at(1100))
                .unwrap()
                .unwrap();
            assert!(!replay.inserted);
            assert_eq!(replay.summary.detection.loop_count, 1);
            assert_eq!(replay.summary.last_observed_at, observed);

            let (action, execution, current, _) = fixture(1);
            let second = RespawnHistoryStore::from_data_dir(dir.path())
                .ingest_verified_respawn(&action, &execution, &current, "session-b", at(1101))
                .unwrap()
                .unwrap();
            assert!(second.inserted);
            assert!(second.summary.detection.is_loop);
            assert_eq!(second.summary.detection.loop_count, 2);
            assert!((second.summary.detection.kill_utility_multiplier - 0.68).abs() < 0.000_001);
            assert!(second.summary.review_message.contains("Spawner PID 10"));
            assert!(second.summary.review_message.contains("bash respawner.sh"));
            assert_eq!(second.summary.parent.start_id, current[1].start_id);

            let snapshot = RespawnHistoryStore::from_data_dir(dir.path())
                .load(at(1101))
                .unwrap();
            let summary = snapshot
                .for_process(&current[0], &current, at(1101))
                .unwrap();
            assert_eq!(snapshot.event_count(), 2);
            assert_eq!(snapshot.identity_count(), 1);
            let json = serde_json::to_value(&summary).unwrap();
            assert_eq!(json["detection"]["loop_count"], 2);
            assert_eq!(json["parent"]["pid"], 10);
            assert_eq!(json["latest_replacement_pid"], current[0].pid.0);
        }

        #[test]
        fn next_plan_requires_the_same_owner_command_and_parent_incarnation() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            let (action, execution, current, observed) = fixture(0);
            store
                .ingest_verified_respawn(&action, &execution, &current, "session", observed)
                .unwrap()
                .unwrap();
            let snapshot = store.load(observed).unwrap();
            assert!(snapshot
                .for_process_with_parent(&current[0], Some(&current[1]), observed)
                .is_some());
            assert!(snapshot
                .for_process_with_parent(&current[0], None, observed)
                .is_none());
            for change in [
                "parent_pid",
                "parent_birth",
                "parent_uid",
                "boot",
                "child_uid",
                "command",
            ] {
                let mut child = current[0].clone();
                let mut parent = current[1].clone();
                match change {
                    "parent_pid" => {
                        parent.pid = ProcessId(11);
                        parent.start_id = StartId::from_linux("boot", clock_hz(), 11);
                        child.ppid = parent.pid;
                    }
                    "parent_birth" => {
                        parent.start_id = StartId::from_linux("boot", 2 * clock_hz(), 10)
                    }
                    "parent_uid" => parent.uid = 1001,
                    "boot" => {
                        parent.start_id = StartId::from_linux("another-boot", clock_hz(), 10);
                        child.start_id =
                            StartId::from_linux("another-boot", 1001 * clock_hz(), child.pid.0);
                    }
                    "child_uid" => child.uid = 1001,
                    "command" => child.cmd = "sleep 10000".to_string(),
                    _ => unreachable!(),
                }
                assert!(
                    snapshot
                        .for_process_with_parent(&child, Some(&parent), observed)
                        .is_none(),
                    "{change}"
                );
            }
            let mut child = current[0].clone();
            child.pid = ProcessId(999);
            child.start_id = StartId::from_linux("boot", 1001 * clock_hz(), 999);
            child.cmd = "\tsleep\t1000\n".to_string();
            assert!(snapshot
                .for_process_with_parent(&child, Some(&current[1]), observed)
                .is_some());
        }

        #[test]
        fn incomplete_or_unbound_execution_evidence_never_creates_history() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            for change in [
                "missing_parent",
                "weak_parent",
                "synthetic_parent",
                "parent_reused",
                "parent_missing",
                "parent_zombie",
                "failed",
                "not_kill",
                "blocked",
                "wrong_parent",
                "original_alive",
                "duplicate_parent",
                "future",
                "preexisting",
                "different_command",
            ] {
                let (mut action, mut execution, mut current, mut observed) = fixture(0);
                match change {
                    "missing_parent" => execution.parent_identity = None,
                    "weak_parent" => {
                        execution.parent_identity.as_mut().unwrap().quality =
                            IdentityQuality::NoBootId
                    }
                    "synthetic_parent" => {
                        let start = StartId::from_linux("synthetic", clock_hz(), 10);
                        execution.parent_identity.as_mut().unwrap().start_id = start.clone();
                        current[1].start_id = start;
                    }
                    "parent_reused" => {
                        current[1].start_id = StartId::from_linux("boot", 2 * clock_hz(), 10)
                    }
                    "parent_missing" => current.truncate(1),
                    "parent_zombie" => current[1].state = ProcessState::Zombie,
                    "failed" => execution.status = "failed".to_string(),
                    "not_kill" => {
                        action.action = Action::Pause;
                        execution.action = Some(Action::Pause);
                    }
                    "blocked" => action.blocked = true,
                    "wrong_parent" => current[0].ppid = ProcessId(11),
                    "original_alive" => {
                        current.push(process(action.target.pid.0, 10, "sleep 1000", 999))
                    }
                    "duplicate_parent" => current.push(current[1].clone()),
                    "future" => observed = at(999),
                    "preexisting" => {
                        current[0].start_id =
                            StartId::from_linux("boot", 1000 * clock_hz(), current[0].pid.0)
                    }
                    "different_command" => current[0].cmd = "sleep 10000".to_string(),
                    _ => unreachable!(),
                }
                assert!(
                    store
                        .ingest_verified_respawn(&action, &execution, &current, "session", observed)
                        .unwrap()
                        .is_none(),
                    "{change}"
                );
            }
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }

        #[test]
        fn replacement_birth_controls_delay_even_when_verification_is_late() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            let (action, execution, mut current, _) = fixture(0);
            let record = store
                .ingest_verified_respawn(&action, &execution, &current, "late-verify", at(1200))
                .unwrap()
                .unwrap();
            assert_eq!(record.summary.detection.avg_respawn_delay_secs, 1.0);

            // Linux birth ticks can establish a replacement within the same
            // wall-clock second; whole-second timestamps must not round it away.
            let same_second_dir = tempfile::tempdir().unwrap();
            let same_second = RespawnHistoryStore::from_data_dir(same_second_dir.path());
            current[0].start_time_unix = 1000;
            current[0].start_id =
                StartId::from_linux("boot", 1000 * clock_hz() + 1, current[0].pid.0);
            let record = same_second
                .ingest_verified_respawn(&action, &execution, &current, "same-second", at(1002))
                .unwrap()
                .unwrap();
            assert!(
                (record.summary.detection.avg_respawn_delay_secs - 1.0 / clock_hz() as f64).abs()
                    < 0.000_001
            );

            let boundary_dir = tempfile::tempdir().unwrap();
            let boundary = RespawnHistoryStore::from_data_dir(boundary_dir.path());
            current[0].start_time_unix = 1030;
            current[0].start_id = StartId::from_linux("boot", 1030 * clock_hz(), current[0].pid.0);
            assert!(boundary
                .ingest_verified_respawn(&action, &execution, &current, "boundary", at(1031))
                .unwrap()
                .is_some());
            current[0].start_time_unix = 1031;
            current[0].start_id = StartId::from_linux("boot", 1031 * clock_hz(), current[0].pid.0);
            assert!(boundary
                .ingest_verified_respawn(&action, &execution, &current, "too-slow", at(1032))
                .unwrap()
                .is_none());
        }

        #[test]
        fn concurrent_writers_merge_distinct_attempts_and_deduplicate_replays() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            let barrier = Arc::new(Barrier::new(8));
            let workers: Vec<_> = (0..8)
                .map(|index| {
                    let store = store.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let (action, execution, current, _) = fixture(index / 2);
                        barrier.wait();
                        store
                            .ingest_verified_respawn(
                                &action,
                                &execution,
                                &current,
                                "concurrent",
                                at(1100),
                            )
                            .unwrap()
                            .unwrap()
                            .inserted
                    })
                })
                .collect();
            let inserted = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|inserted| *inserted)
                .count();
            assert_eq!(inserted, 4);
            let snapshot = store.load(at(1100)).unwrap();
            assert_eq!(snapshot.event_count(), 4);
            let (_, _, current, _) = fixture(3);
            let summary = snapshot
                .for_process(&current[0], &current, at(1100))
                .unwrap();
            assert_eq!(summary.detection.loop_count, 4);
            assert!((summary.detection.kill_utility_multiplier - 0.36).abs() < 0.000_001);
        }

        #[test]
        fn corrupt_history_is_reported_and_never_replaced_by_new_learning() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            let invalid = b"{truncated history";
            fs::write(&store.path, invalid).unwrap();
            assert!(store.load(at(1002)).is_err());
            let (action, execution, current, observed) = fixture(0);
            assert!(store
                .ingest_verified_respawn(&action, &execution, &current, "session", observed)
                .is_err());
            assert_eq!(fs::read(&store.path).unwrap(), invalid);

            let event =
                verified_respawn_event(&action, &execution, &current, "session", observed).unwrap();
            let mut history = RespawnHistoryFile {
                schema_version: HISTORY_SCHEMA_VERSION,
                events: vec![event],
            };
            history.events[0].parent.start_id = StartId::from_linux("boot", 999, 10);
            let inconsistent = serde_json::to_vec(&history).unwrap();
            fs::write(&store.path, &inconsistent).unwrap();
            assert!(matches!(
                store.load(observed),
                Err(RespawnHistoryError::InvalidHistory(_))
            ));
            assert!(store
                .ingest_verified_respawn(&action, &execution, &current, "session", observed)
                .is_err());
            assert_eq!(fs::read(&store.path).unwrap(), inconsistent);
        }

        #[test]
        fn retention_and_capacity_bounds_preserve_recent_distinct_attempts() {
            let dir = tempfile::tempdir().unwrap();
            let store = RespawnHistoryStore::from_data_dir(dir.path());
            let (action, execution, current, observed) = fixture(0);
            store
                .ingest_verified_respawn(&action, &execution, &current, "first", observed)
                .unwrap()
                .unwrap();
            assert_eq!(store.load(at(4600)).unwrap().event_count(), 1);
            assert_eq!(store.load(at(4601)).unwrap().event_count(), 0);
            assert_eq!(store.load(at(999)).unwrap().event_count(), 0);

            let base =
                verified_respawn_event(&action, &execution, &current, "first", observed).unwrap();
            let mut history = RespawnHistoryFile::default();
            for index in 0..MAX_EVENTS_PER_IDENTITY + 3 {
                let mut event = base.clone();
                event.session_id = format!("session-{index}");
                event.attempt_id = attempt_key(
                    &event.session_id,
                    &event.action_id,
                    event.executed_at,
                    &event.target,
                );
                history.events.push(event);
            }
            store.prune_history(&mut history, observed).unwrap();
            assert_eq!(history.events.len(), MAX_EVENTS_PER_IDENTITY);
            store.write_history(&history).unwrap();
            let loaded = store.load(observed).unwrap();
            assert_eq!(loaded.event_count(), MAX_EVENTS_PER_IDENTITY);
            assert!(fs::metadata(&store.path).unwrap().len() <= MAX_HISTORY_BYTES as u64);
            let summary = loaded.for_process(&current[0], &current, observed).unwrap();
            assert!((summary.detection.kill_utility_multiplier - 0.2).abs() < 0.000_001);
        }
    }
}
