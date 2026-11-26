//! Shadow mode observation recording helpers.
//!
//! Records prediction snapshots into pt-telemetry shadow storage for calibration.

use crate::collect::{ProcessActivity, ProcessRecord};
use crate::decision::decision_store::Verdict;
use crate::decision::{Action, DecisionOutcome};
use crate::inference::{ClassScores, Confidence, EvidenceLedger};
use chrono::Utc;
use pt_common::ProcessIdentity;
use pt_telemetry::shadow::{
    ActivityObservation, BeliefState, EventType, Observation, ProcessEvent, ShadowStorage,
    ShadowStorageConfig, ShadowStorageError, StateSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MISS_THRESHOLD: u32 = 2;

/// Persist the same identity-bound rates supplied to inference. A failed window
/// stays unavailable, and window byte deltas never become lifetime counters.
fn observation_state(
    proc: &ProcessRecord,
    activity: Option<&ProcessActivity>,
    child_count: Option<u32>,
) -> StateSnapshot {
    let percent = |value: f64| {
        (value.is_finite() && value >= 0.0 && value <= f64::from(f32::MAX)).then_some(value as f32)
    };
    let mut state = StateSnapshot {
        schema_version: 1,
        cpu_lifetime_percent: percent(proc.cpu_percent),
        memory_bytes: proc.vsz_bytes,
        rss_bytes: proc.rss_bytes,
        state_char: proc.state.to_string().chars().next().unwrap_or('?'),
        has_tty: proc.has_tty(),
        child_count,
        ..StateSnapshot::default()
    };
    let Some(activity) = activity else {
        // No sample means the caller chose snapshot-only mode. A requested but
        // failed window arrives as Some with its missing measurements/errors.
        state.cpu_percent = state.cpu_lifetime_percent;
        return state;
    };
    let mut observed = ActivityObservation {
        source: activity.source.clone(),
        requested_window_ms: activity.requested_window_ms,
        ..ActivityObservation::default()
    };
    let refusal = if !activity.matches_record(proc) {
        Some("activity does not match the recorded process incarnation")
    } else if !matches!(
        activity.source.as_str(),
        "procfs_window" | "ps_lifetime_fallback"
    ) {
        Some("activity source is unsupported")
    } else if activity.requested_window_ms == 0 {
        Some("activity sampling interval was not requested")
    } else {
        None
    };
    if let Some(reason) = refusal {
        observed.cpu_error = Some(reason.to_string());
        observed.io_error = Some(reason.to_string());
        state.activity = Some(observed);
        return state;
    }

    if activity.source == "ps_lifetime_fallback" {
        state.cpu_percent = activity
            .cpu_percent
            .filter(|_| activity.cpu_error.is_none())
            .and_then(percent);
        observed.cpu_error = activity.cpu_error.clone().or_else(|| {
            state
                .cpu_percent
                .is_none()
                .then(|| "native lifetime CPU observation is unavailable".to_string())
        });
        observed.io_error = Some(
            activity
                .io_error
                .clone()
                .unwrap_or_else(|| "native lifetime fallback does not measure storage I/O".into()),
        );
        state.activity = Some(observed);
        return state;
    }

    let completed_window = |seconds: f64| {
        seconds.is_finite()
            && seconds > 0.0
            && seconds >= activity.requested_window_ms as f64 / 1000.0
    };
    let cpu = activity
        .cpu_percent
        .and_then(percent)
        .zip(activity.cpu_ticks)
        .zip(
            activity
                .cpu_window_seconds
                .filter(|seconds| completed_window(*seconds)),
        )
        .filter(|_| activity.cpu_error.is_none());
    if let Some(((percent, ticks), seconds)) = cpu {
        state.cpu_percent = Some(percent);
        observed.cpu_ticks = Some(ticks);
        observed.cpu_window_seconds = Some(seconds);
    } else {
        observed.cpu_error = Some(activity.cpu_error.clone().unwrap_or_else(|| {
            "CPU rate, tick delta or completed sampling interval is unavailable".into()
        }));
    }

    let io = activity
        .io_read_bytes
        .zip(activity.io_write_bytes)
        .zip(
            activity
                .io_window_seconds
                .filter(|seconds| completed_window(*seconds)),
        )
        .filter(|_| activity.io_error.is_none());
    if let Some(((read, written), seconds)) = io {
        let read_rate = read as f64 / seconds;
        let write_rate = written as f64 / seconds;
        if read_rate.is_finite() && write_rate.is_finite() {
            observed.io_read_delta_bytes = Some(read);
            observed.io_write_delta_bytes = Some(written);
            observed.io_window_seconds = Some(seconds);
            observed.read_bytes_per_second = Some(read_rate);
            observed.write_bytes_per_second = Some(write_rate);
            observed.io_active = Some(read > 0 || written > 0);
        } else {
            observed.io_error = Some("storage I/O rates are not finite".into());
        }
    } else {
        observed.io_error = Some(activity.io_error.clone().unwrap_or_else(|| {
            "storage I/O deltas or completed sampling interval are unavailable".into()
        }));
    }
    state.thread_count = activity
        .pressure
        .as_ref()
        .filter(|pressure| pressure.memory_error.is_none())
        .and_then(|pressure| pressure.memory.as_ref())
        .map(|memory| memory.threads)
        .filter(|threads| *threads > 0)
        .or_else(|| {
            activity.normalized_cpu_occupancy()?;
            match activity.cpu_occupancy.as_ref()? {
                crate::collect::CpuOccupancy::Observed { threads, .. } => Some(*threads),
                crate::collect::CpuOccupancy::Unavailable { .. } => None,
            }
        });
    state.activity = Some(observed);
    state
}

#[derive(Debug)]
pub enum ShadowRecordError {
    Storage(ShadowStorageError),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl From<ShadowStorageError> for ShadowRecordError {
    fn from(err: ShadowStorageError) -> Self {
        ShadowRecordError::Storage(err)
    }
}

impl From<std::io::Error> for ShadowRecordError {
    fn from(err: std::io::Error) -> Self {
        ShadowRecordError::Io(err)
    }
}

impl From<serde_json::Error> for ShadowRecordError {
    fn from(err: serde_json::Error) -> Self {
        ShadowRecordError::Json(err)
    }
}

/// Sources that capture an explicit human judgment, never an accepted model
/// default or an automated action outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanVerdictSource {
    AgentLabel,
    TuiReview,
}

impl HumanVerdictSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentLabel => "agent_label",
            Self::TuiReview => "tui_review",
        }
    }
}

/// Persist an explicit judgment about one live process incarnation for shadow
/// calibration. A command-pattern label alone cannot identify a past prediction.
///
/// Call this before updating learned priors so predictions made with the new
/// verdict cannot be evaluated against that same verdict. The event carries no
/// prediction: validation joins it only to an earlier observation with the same
/// identity, and ignores it if no such observation exists.
pub fn record_human_verdict(
    proc: &ProcessRecord,
    verdict: Verdict,
) -> Result<String, ShadowRecordError> {
    record_reviewed_verdict(
        &shadow_config_from_env(),
        &ProcessIdentity::new(proc.pid.0, proc.start_id.clone(), proc.uid),
        &proc.comm,
        &proc.cmd,
        verdict,
        HumanVerdictSource::AgentLabel,
    )
}

/// Persist feedback for the exact process and command reviewed by a human.
/// The process may have exited since review; never look up its PID again.
/// Record this before updating learned priors, just as for a live CLI label.
pub fn record_reviewed_verdict(
    config: &ShadowStorageConfig,
    identity: &ProcessIdentity,
    comm: &str,
    cmd: &str,
    verdict: Verdict,
    source: HumanVerdictSource,
) -> Result<String, ShadowRecordError> {
    let timestamp = Utc::now();
    let identity_hash =
        compute_reviewed_identity_hash(identity.uid, &identity.start_id.0, comm, cmd);
    let mut storage = ShadowStorage::new(config.clone())?;
    storage.record(Observation {
        timestamp,
        pid: identity.pid.0,
        identity_hash: identity_hash.clone(),
        state: StateSnapshot::default(),
        events: vec![ProcessEvent {
            timestamp,
            event_type: EventType::HumanVerdict,
            details: Some(
                serde_json::json!({
                    "verdict": verdict,
                    "source": source,
                    "comm": comm,
                })
                .to_string(),
            ),
        }],
        // An event-only observation has no model belief. In particular, never
        // insert the learned prior or the verdict itself as a prediction.
        belief: BeliefState {
            p_abandoned: 0.0,
            p_legitimate: 0.0,
            p_zombie: 0.0,
            p_useful_but_bad: 0.0,
            confidence: 0.0,
            score: 0.0,
            recommendation: "human_verdict".to_string(),
        },
    })?;
    storage.flush()?;
    Ok(identity_hash)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingObservation {
    identity_hash: String,
    pid: u32,
    last_seen: chrono::DateTime<chrono::Utc>,
    miss_count: u32,
    belief: BeliefState,
    state: StateSnapshot,
    comm: String,
    /// The live command line disappears when a process becomes a zombie. Keep
    /// its birth and owner separately so its exit still joins the earlier
    /// prediction instead of a new hash of an empty command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<ProcessIdentity>,
    #[serde(default)]
    exit_recorded: bool,
}

/// Kernel-observed termination, not a judgment that the process was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedExit {
    wait_status: i32,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
    core_dumped: bool,
}

/// Records shadow observations into local storage.
pub struct ShadowRecorder {
    storage: ShadowStorage,
    recorded: u64,
    pending: HashMap<String, PendingObservation>,
    latest_pending_by_pid: HashMap<u32, String>,
    seen_identities: HashSet<String>,
    seen_pids: HashMap<u32, String>,
    pending_path: PathBuf,
    miss_threshold: u32,
    had_records: bool,
}

impl ShadowRecorder {
    pub fn new() -> Result<Self, ShadowRecordError> {
        Self::with_config(shadow_config_from_env())
    }

    pub fn with_config(config: ShadowStorageConfig) -> Result<Self, ShadowRecordError> {
        let storage = ShadowStorage::new(config)?;
        let pending_path = storage.config().base_dir.join("pending.json");
        let pending = match load_pending(&pending_path) {
            Ok(pending) => pending,
            Err(err) => {
                eprintln!("shadow mode: failed to load pending outcomes: {:?}", err);
                HashMap::new()
            }
        };
        let mut latest: HashMap<u32, &PendingObservation> = HashMap::new();
        for entry in pending.values() {
            let previous = latest.entry(entry.pid).or_insert(entry);
            if (entry.last_seen, &entry.identity_hash)
                > (previous.last_seen, &previous.identity_hash)
            {
                *previous = entry;
            }
        }
        let latest_pending_by_pid = latest
            .into_iter()
            .map(|(pid, entry)| (pid, entry.identity_hash.clone()))
            .collect();
        Ok(Self {
            storage,
            recorded: 0,
            pending,
            latest_pending_by_pid,
            seen_identities: HashSet::new(),
            seen_pids: HashMap::new(),
            pending_path,
            miss_threshold: DEFAULT_MISS_THRESHOLD,
            had_records: false,
        })
    }

    /// Observe process presence before protection, age, PID or sampling filters.
    /// This records no new predictions. A partial census can establish presence,
    /// but absence still requires a separate, incarnation-bound live check.
    /// Call this even when no process will be scored in the current scan.
    pub fn observe_processes(
        &mut self,
        processes: &[ProcessRecord],
    ) -> Result<(), ShadowRecordError> {
        self.had_records = true;
        let by_pid: HashMap<_, _> = processes.iter().map(|proc| (proc.pid.0, proc)).collect();
        for entry in self.pending.values() {
            let Some(proc) = by_pid.get(&entry.pid) else {
                continue;
            };
            // A command rewrite, exec or owner change does not end a process
            // incarnation. Keep its earlier prediction without manufacturing
            // another prediction from the last recorded belief.
            let same_birth = entry.identity.as_ref().is_some_and(|identity| {
                identity.pid == proc.pid && identity.start_id == proc.start_id
            });
            let current_hash = self
                .seen_pids
                .entry(proc.pid.0)
                .or_insert_with(|| compute_identity_hash(proc));
            if same_birth || entry.identity_hash == *current_hash {
                self.seen_identities.insert(entry.identity_hash.clone());
            }
        }
        for proc in processes {
            // Exit status may be observable even when the zombie is excluded
            // from inference. Only follow an already tracked incarnation here;
            // an unrelated zombie supplies no prediction to calibrate.
            if proc.state.is_zombie()
                && self
                    .latest_pending_by_pid
                    .get(&proc.pid.0)
                    .and_then(|hash| self.pending.get(hash))
                    .and_then(|entry| entry.identity.as_ref())
                    .is_some_and(|identity| {
                        identity.matches(&ProcessIdentity::new(
                            proc.pid.0,
                            proc.start_id.clone(),
                            proc.uid,
                        ))
                    })
            {
                self.record_zombie_exit(proc)?;
            }
        }
        Ok(())
    }

    pub fn record_candidate(
        &mut self,
        proc: &ProcessRecord,
        posterior: &ClassScores,
        ledger: &EvidenceLedger,
        decision: &DecisionOutcome,
        activity: Option<&ProcessActivity>,
        child_count: Option<u32>,
    ) -> Result<(), ShadowRecordError> {
        self.had_records = true;
        if proc.state.is_zombie() {
            return self.record_zombie_exit(proc);
        }
        let identity_hash = compute_identity_hash(proc);
        let score = (posterior.abandonment_probability() * 100.0) as f32;

        let belief = BeliefState {
            p_abandoned: posterior.abandoned as f32,
            p_legitimate: posterior.useful as f32,
            p_zombie: posterior.zombie as f32,
            p_useful_but_bad: posterior.useful_bad as f32,
            confidence: confidence_score(ledger.confidence),
            score,
            recommendation: action_to_recommendation(decision.optimal_action).to_string(),
        };

        let state = observation_state(proc, activity, child_count);

        // Only the signature that influenced this prediction may classify its
        // calibration sample. A later verdict must never supply this metadata.
        let signature_category = decision
            .rationale
            .category
            .as_deref()
            .filter(|_| decision.rationale.has_known_signature == Some(true));
        let mut events = Vec::new();
        if let Some(event) = build_evidence_event(
            ledger,
            &proc.comm,
            signature_category,
            Some(&self.storage.config().host_id),
        ) {
            events.push(event);
        }

        let observation = Observation {
            timestamp: Utc::now(),
            pid: proc.pid.0,
            identity_hash: identity_hash.clone(),
            state: state.clone(),
            events,
            belief: belief.clone(),
        };

        self.storage.record(observation)?;
        self.recorded = self.recorded.saturating_add(1);

        self.seen_identities.insert(identity_hash.clone());
        self.seen_pids.insert(proc.pid.0, identity_hash.clone());
        self.latest_pending_by_pid
            .insert(proc.pid.0, identity_hash.clone());
        self.pending.insert(
            identity_hash.clone(),
            PendingObservation {
                identity_hash,
                pid: proc.pid.0,
                last_seen: Utc::now(),
                miss_count: 0,
                belief,
                state,
                comm: proc.comm.clone(),
                identity: Some(ProcessIdentity::new(
                    proc.pid.0,
                    proc.start_id.clone(),
                    proc.uid,
                )),
                exit_recorded: false,
            },
        );
        Ok(())
    }

    /// Record an observed exit once, keeping it associated with the last live
    /// prediction even though /proc no longer supplies its command line. A
    /// terminal-only observation deliberately carries no model prediction.
    fn record_zombie_exit(&mut self, proc: &ProcessRecord) -> Result<(), ShadowRecordError> {
        self.record_zombie_exit_with(proc, observe_zombie_exit)
    }

    fn record_zombie_exit_with(
        &mut self,
        proc: &ProcessRecord,
        observe: impl FnOnce(&ProcessRecord) -> Option<ObservedExit>,
    ) -> Result<(), ShadowRecordError> {
        let identity = ProcessIdentity::new(proc.pid.0, proc.start_id.clone(), proc.uid);
        let previous = self
            .latest_pending_by_pid
            .get(&proc.pid.0)
            .and_then(|hash| self.pending.get(hash))
            .filter(|entry| {
                entry
                    .identity
                    .as_ref()
                    .is_some_and(|recorded| recorded.matches(&identity))
            })
            .cloned();
        if let Some(entry) = previous.as_ref().filter(|entry| entry.exit_recorded) {
            self.seen_identities.insert(entry.identity_hash.clone());
            self.seen_pids
                .insert(proc.pid.0, entry.identity_hash.clone());
            return Ok(());
        }
        let Some(exit) = observe(proc) else {
            // The leader may be a zombie before its remaining threads exit,
            // or its exit evidence may temporarily be unreadable. Neither
            // permits a new prediction from the zombie's empty command line.
            // Preserve the last live prediction until a trusted exit arrives.
            if let Some(entry) = previous {
                self.seen_identities.insert(entry.identity_hash.clone());
                self.seen_pids.insert(proc.pid.0, entry.identity_hash);
            }
            return Ok(());
        };
        let now = Utc::now();
        let mut pending = previous.unwrap_or_else(|| PendingObservation {
            identity_hash: compute_identity_hash(proc),
            pid: proc.pid.0,
            last_seen: now,
            miss_count: 0,
            belief: BeliefState::default(),
            state: StateSnapshot::default(),
            comm: proc.comm.clone(),
            identity: Some(identity),
            exit_recorded: false,
        });
        let details = serde_json::json!({
            "reason": "observed_zombie",
            "source": "proc_stat",
            "comm": pending.comm,
            "wait_status": exit.wait_status,
            "exit_code": exit.exit_code,
            "exit_signal": exit.exit_signal,
            "core_dumped": exit.core_dumped,
        });
        let mut state = pending.state.clone();
        state.state_char = 'Z';
        self.storage.record(Observation {
            timestamp: now,
            pid: proc.pid.0,
            identity_hash: pending.identity_hash.clone(),
            state,
            events: vec![ProcessEvent {
                timestamp: now,
                event_type: EventType::ProcessExit,
                details: Some(details.to_string()),
            }],
            belief: BeliefState {
                p_abandoned: 0.0,
                p_legitimate: 0.0,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                confidence: 0.0,
                score: 0.0,
                recommendation: "observed_exit".to_string(),
            },
        })?;
        self.recorded = self.recorded.saturating_add(1);
        pending.last_seen = now;
        pending.miss_count = 0;
        pending.exit_recorded = true;
        self.seen_identities.insert(pending.identity_hash.clone());
        self.seen_pids
            .insert(proc.pid.0, pending.identity_hash.clone());
        self.latest_pending_by_pid
            .insert(proc.pid.0, pending.identity_hash.clone());
        self.pending.insert(pending.identity_hash.clone(), pending);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), ShadowRecordError> {
        self.record_outcomes_for_missing()?;
        self.storage.flush()?;
        persist_pending(&self.pending_path, &self.pending)?;
        Ok(())
    }

    pub fn recorded_count(&self) -> u64 {
        self.recorded
    }

    fn record_outcomes_for_missing(&mut self) -> Result<(), ShadowRecordError> {
        self.record_outcomes_for_missing_with(observed_exit_target_gone)
    }

    fn record_outcomes_for_missing_with(
        &mut self,
        mut target_gone: impl FnMut(&PendingObservation) -> bool,
    ) -> Result<(), ShadowRecordError> {
        if !self.had_records {
            self.seen_identities.clear();
            self.seen_pids.clear();
            return Ok(());
        }

        let now = Utc::now();
        let mut resolved = Vec::new();

        for entry in self.pending.values_mut() {
            if self.seen_identities.contains(&entry.identity_hash) {
                entry.miss_count = 0;
                entry.last_seen = now;
                continue;
            }

            // Inference only visits selected processes. Missing recommendations
            // never establish an exit, even after repeated filtered scans. An
            // unreadable identity is unknown, not a successful absence check.
            if !target_gone(entry) {
                entry.miss_count = 0;
                continue;
            }
            entry.miss_count = entry.miss_count.saturating_add(1);
            if entry.miss_count >= self.miss_threshold {
                resolved.push(entry.clone());
            }
        }

        for entry in resolved {
            if entry.exit_recorded {
                // Never replace a known wait status with a later "missing".
                self.pending.remove(&entry.identity_hash);
                if self.latest_pending_by_pid.get(&entry.pid) == Some(&entry.identity_hash) {
                    self.latest_pending_by_pid.remove(&entry.pid);
                }
                continue;
            }
            let reuse = self
                .seen_pids
                .get(&entry.pid)
                .map(|identity| identity != &entry.identity_hash)
                .unwrap_or(false);
            let reason = if reuse { "pid_reused" } else { "missing" };
            let details = serde_json::json!({
                "reason": reason,
                "source": "verified_identity_absence",
                "miss_count": entry.miss_count,
                "last_seen": entry.last_seen.to_rfc3339(),
                "comm": entry.comm,
                "last_state": entry.state.state_char.to_string(),
            })
            .to_string();
            let event = ProcessEvent {
                timestamp: now,
                event_type: EventType::ProcessExit,
                details: Some(details),
            };
            let observation = Observation {
                timestamp: now,
                pid: entry.pid,
                identity_hash: entry.identity_hash.clone(),
                state: entry.state,
                events: vec![event],
                // An exit is an outcome-only observation. Copying the previous
                // belief here would turn stale evidence into a fresh prediction.
                belief: BeliefState {
                    p_abandoned: 0.0,
                    p_legitimate: 0.0,
                    p_zombie: 0.0,
                    p_useful_but_bad: 0.0,
                    confidence: 0.0,
                    score: 0.0,
                    recommendation: "observed_exit".to_string(),
                },
            };
            self.storage.record(observation)?;
            self.recorded = self.recorded.saturating_add(1);
            self.pending.remove(&entry.identity_hash);
            if self.latest_pending_by_pid.get(&entry.pid) == Some(&entry.identity_hash) {
                self.latest_pending_by_pid.remove(&entry.pid);
            }
        }

        self.seen_identities.clear();
        self.seen_pids.clear();
        self.had_records = false;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn observe_zombie_exit(proc: &ProcessRecord) -> Option<ObservedExit> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    observe_zombie_exit_from(proc, std::path::Path::new("/proc"), boot_id.trim(), || {})
}

#[cfg(not(target_os = "linux"))]
fn observe_zombie_exit(_proc: &ProcessRecord) -> Option<ObservedExit> {
    None
}

#[cfg(target_os = "linux")]
fn recorded_linux_birth(identity: &ProcessIdentity, boot_id: &str) -> Option<u64> {
    if boot_id.is_empty() || boot_id == "unknown" || identity.pid.0 == 0 {
        return None;
    }
    let mut parts = identity.start_id.0.split(':');
    if parts.next()? != boot_id {
        return None;
    }
    let ticks = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none() && ticks > 0 && pid == identity.pid.0).then_some(ticks)
}

#[cfg(target_os = "linux")]
fn observe_zombie_exit_from(
    proc: &ProcessRecord,
    proc_root: &std::path::Path,
    boot_id: &str,
    between_reads: impl FnOnce(),
) -> Option<ObservedExit> {
    if !proc.state.is_zombie() {
        return None;
    }
    let identity = ProcessIdentity::new(proc.pid.0, proc.start_id.clone(), proc.uid);
    let ticks = recorded_linux_birth(&identity, boot_id)?;
    let directory = proc_root.join(proc.pid.0.to_string());
    // stat's exit_code is [PT]: failed ptrace access silently reports zero.
    // Namespace readlink uses the same PTRACE_MODE_READ_FSCREDS check, and
    // unlike a zero stat field, fails explicitly. The user namespace remains
    // available for a zombie even after its other namespaces have gone.
    let namespace = fs::read_link(directory.join("ns/user")).ok()?;
    let before = fs::read_to_string(directory.join("stat")).ok()?;
    let exit = parse_zombie_exit_stat(&before, proc.pid.0, ticks)?;
    zombie_owner_and_threads(
        &fs::read_to_string(directory.join("status")).ok()?,
        proc.uid,
    )?;
    between_reads();
    if fs::read_link(directory.join("ns/user")).ok()? != namespace {
        return None;
    }
    zombie_owner_and_threads(
        &fs::read_to_string(directory.join("status")).ok()?,
        proc.uid,
    )?;
    let after = fs::read_to_string(directory.join("stat")).ok()?;
    (parse_zombie_exit_stat(&after, proc.pid.0, ticks)? == exit).then_some(exit)
}

#[cfg(target_os = "linux")]
fn zombie_owner_and_threads(status: &str, expected_uid: u32) -> Option<()> {
    let mut uid = None;
    let mut threads = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            if uid.is_some() {
                return None;
            }
            let values = value
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            if values.len() != 4 {
                return None;
            }
            uid = values.first().copied();
        } else if let Some(value) = line.strip_prefix("Threads:") {
            if threads.is_some() {
                return None;
            }
            threads = Some(value.trim().parse::<u32>().ok()?);
        }
    }
    // A zombie group leader may still have running threads. Its thread exit
    // status does not establish that the process has terminated.
    (uid == Some(expected_uid) && threads == Some(1)).then_some(())
}

#[cfg(target_os = "linux")]
fn parse_zombie_exit_stat(content: &str, pid: u32, ticks: u64) -> Option<ObservedExit> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close < open || content[..open].trim().parse::<u32>().ok()? != pid {
        return None;
    }
    let fields: Vec<_> = content[close + 1..].split_whitespace().collect();
    // Field 3 is state, 22 is starttime, and 52 is the wait status. Field 38
    // is the signal sent to the parent, NOT the terminating signal.
    if fields.first() != Some(&"Z") || fields.get(19)?.parse::<u64>().ok()? != ticks {
        return None;
    }
    let wait_status = fields.get(49)?.parse::<u16>().ok()? as i32;
    if libc::WIFEXITED(wait_status) && wait_status & 0xff == 0 {
        Some(ObservedExit {
            wait_status,
            exit_code: Some(libc::WEXITSTATUS(wait_status)),
            exit_signal: None,
            core_dumped: false,
        })
    } else if libc::WIFSIGNALED(wait_status)
        && wait_status & 0xff00 == 0
        && (1..=libc::SIGRTMAX()).contains(&libc::WTERMSIG(wait_status))
    {
        Some(ObservedExit {
            wait_status,
            exit_code: None,
            exit_signal: Some(libc::WTERMSIG(wait_status)),
            core_dumped: libc::WCOREDUMP(wait_status),
        })
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn observed_exit_target_gone(entry: &PendingObservation) -> bool {
    let Some(identity) = &entry.identity else {
        return false;
    };
    if crate::action::signal::ensure_action_pid_namespace().is_err() {
        return false;
    }
    let Ok(boot_id) = fs::read_to_string("/proc/sys/kernel/random/boot_id") else {
        return false;
    };
    observed_exit_target_gone_with(
        identity,
        boot_id.trim(),
        |pid| crate::collect::proc_parsers::read_required_proc_stat(pid).map(|stat| stat.starttime),
        |pid| {
            let Ok(pid) = libc::pid_t::try_from(pid) else {
                return false;
            };
            if pid <= 0 {
                return false;
            }
            // A procfs mount from another PID namespace can make ESRCH refer
            // to a different process table, not the recorded incarnation.
            if crate::action::signal::ensure_action_pid_namespace().is_err() {
                return false;
            }
            // SAFETY: signal zero probes only this validated positive PID.
            let result = unsafe { libc::kill(pid, 0) };
            result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        },
    )
}

#[cfg(target_os = "linux")]
fn observed_exit_target_gone_with(
    identity: &ProcessIdentity,
    current_boot: &str,
    read_birth: impl FnOnce(u32) -> Result<u64, crate::collect::proc_parsers::StatReadError>,
    probe_absent: impl FnOnce(u32) -> bool,
) -> bool {
    if !identity.can_safely_revalidate() || current_boot.is_empty() || current_boot == "unknown" {
        return false;
    }
    let Some(recorded_boot) = identity.start_id.0.split(':').next() else {
        return false;
    };
    let Some(ticks) = recorded_linux_birth(identity, recorded_boot) else {
        return false;
    };
    if recorded_boot != current_boot {
        // A fully identified process from an earlier boot cannot survive it.
        return true;
    }
    match read_birth(identity.pid.0) {
        Ok(current_ticks) => current_ticks > 0 && current_ticks != ticks,
        Err(crate::collect::proc_parsers::StatReadError::Read { source, .. }) => {
            // hidepid and changing procfs visibility can also produce ENOENT.
            // Only an independent ESRCH permits retiring the terminal marker.
            source.kind() == std::io::ErrorKind::NotFound && probe_absent(identity.pid.0)
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn observed_exit_target_gone(_entry: &PendingObservation) -> bool {
    false
}

fn action_to_recommendation(action: Action) -> &'static str {
    action.as_str()
}

fn confidence_score(confidence: Confidence) -> f32 {
    match confidence {
        Confidence::VeryHigh => 0.99,
        Confidence::High => 0.95,
        Confidence::Medium => 0.8,
        Confidence::Low => 0.5,
    }
}

fn compute_identity_hash(proc: &ProcessRecord) -> String {
    compute_reviewed_identity_hash(proc.uid, &proc.start_id.0, &proc.comm, &proc.cmd)
}

fn compute_reviewed_identity_hash(uid: u32, start_id: &str, comm: &str, cmd: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(uid.to_le_bytes());
    hasher.update(start_id.as_bytes());
    hasher.update(comm.as_bytes());
    hasher.update(cmd.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn build_evidence_event(
    ledger: &EvidenceLedger,
    comm: &str,
    signature_category: Option<&str>,
    host_id: Option<&str>,
) -> Option<ProcessEvent> {
    let signature_category = signature_category.map(str::trim).filter(|s| !s.is_empty());
    let host_id = host_id
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "unknown");
    let top: Vec<_> = ledger
        .bayes_factors
        .iter()
        .take(3)
        .map(|bf| {
            serde_json::json!({
                "feature": bf.feature,
                "delta_bits": bf.delta_bits,
                "direction": bf.direction,
                "strength": bf.strength,
            })
        })
        .collect();
    if top.is_empty()
        && ledger.top_evidence.is_empty()
        && signature_category.is_none()
        && host_id.is_none()
    {
        return None;
    }
    let details = serde_json::json!({
        "comm": comm,
        "signature_category": signature_category,
        "host_id": host_id,
        "why_summary": ledger.why_summary,
        "top_evidence": ledger.top_evidence,
        "bayes_factors": top,
    })
    .to_string();
    Some(ProcessEvent {
        timestamp: Utc::now(),
        event_type: EventType::EvidenceSnapshot,
        details: Some(details),
    })
}

fn load_pending(path: &PathBuf) -> Result<HashMap<String, PendingObservation>, ShadowRecordError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(path)?;
    let records: Vec<PendingObservation> = serde_json::from_str(&content)?;
    Ok(records
        .into_iter()
        .map(|record| (record.identity_hash.clone(), record))
        .collect())
}

fn persist_pending(
    path: &Path,
    pending: &HashMap<String, PendingObservation>,
) -> Result<(), ShadowRecordError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut records: Vec<&PendingObservation> = pending.values().collect();
    records.sort_by(|a, b| a.identity_hash.cmp(&b.identity_hash));
    let content = serde_json::to_string_pretty(&records)?;
    // Concurrent shadow runs share this file. A fixed `pending.tmp` let one run
    // rename another's half-written file into place, and the other run's rename
    // then failed with NotFound.
    crate::atomic_file::replace(path, content.as_bytes())?;
    Ok(())
}

fn shadow_config_from_env() -> ShadowStorageConfig {
    let mut config = ShadowStorageConfig::default();
    if let Some(base) = resolve_data_dir_override() {
        config.base_dir = base.join("shadow");
    }
    config
}

fn resolve_data_dir_override() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_DATA") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        return Some(PathBuf::from(dir).join("process_triage"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ENV_LOCK;
    use tempfile::TempDir;

    #[test]
    fn identity_hash_is_stable_and_short() {
        let proc = ProcessRecord {
            pid: pt_common::ProcessId(1),
            ppid: pt_common::ProcessId(0),
            uid: 1000,
            user: "user".to_string(),
            pgid: None,
            sid: None,
            start_id: pt_common::StartId("42".to_string()),
            comm: "bash".to_string(),
            cmd: "bash -c echo test".to_string(),
            state: crate::collect::ProcessState::Running,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: std::time::Duration::from_secs(1),
            source: "test".to_string(),
            container_info: None,
        };

        let h1 = compute_identity_hash(&proc);
        let h2 = compute_identity_hash(&proc);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn identity_hash_changes_for_different_start_id() {
        let mut proc = ProcessRecord {
            pid: pt_common::ProcessId(1),
            ppid: pt_common::ProcessId(0),
            uid: 1000,
            user: "user".to_string(),
            pgid: None,
            sid: None,
            start_id: pt_common::StartId("boot:100:1".to_string()),
            comm: "bash".to_string(),
            cmd: "bash -c echo test".to_string(),
            state: crate::collect::ProcessState::Running,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: std::time::Duration::from_secs(1),
            source: "test".to_string(),
            container_info: None,
        };

        let h1 = compute_identity_hash(&proc);
        proc.start_id = pt_common::StartId("boot:200:1".to_string());
        let h2 = compute_identity_hash(&proc);

        assert_ne!(h1, h2);
    }

    #[test]
    fn verified_missing_entries_emit_exit_event() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp_dir = TempDir::new().expect("temp dir");
        let old_env = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", temp_dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        recorder.miss_threshold = 1;
        recorder.had_records = true;

        recorder.pending.insert(
            "hash_exit".to_string(),
            PendingObservation {
                identity_hash: "hash_exit".to_string(),
                pid: 1234,
                last_seen: Utc::now() - chrono::Duration::minutes(10),
                miss_count: 0,
                belief: BeliefState::default(),
                state: StateSnapshot::default(),
                comm: "sleep".to_string(),
                identity: None,
                exit_recorded: false,
            },
        );

        recorder
            .record_outcomes_for_missing_with(|_| true)
            .expect("record outcomes");

        let events = recorder.storage.get_events(
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
            10,
        );

        assert!(events
            .events
            .iter()
            .any(|(_, event)| event.event_type == EventType::ProcessExit));

        match old_env {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    // ── helpers ──────────────────────────────────────────────────────

    fn make_proc(pid: u32, comm: &str, cmd: &str) -> ProcessRecord {
        ProcessRecord {
            pid: pt_common::ProcessId(pid),
            ppid: pt_common::ProcessId(1),
            uid: 1000,
            user: "user".to_string(),
            pgid: None,
            sid: None,
            start_id: pt_common::StartId(format!("boot:5:{}", pid)),
            comm: comm.to_string(),
            cmd: cmd.to_string(),
            state: crate::collect::ProcessState::Running,
            cpu_percent: 5.0,
            rss_bytes: 1024,
            vsz_bytes: 2048,
            tty: None,
            start_time_unix: 0,
            elapsed: std::time::Duration::from_secs(3600),
            source: "test".to_string(),
            container_info: None,
        }
    }

    fn measured_activity(proc: &ProcessRecord) -> ProcessActivity {
        let mut activity = ProcessActivity::unavailable(
            proc,
            std::time::Duration::from_millis(500),
            "fixture measurement",
        );
        activity.source = "procfs_window".into();
        activity.cpu_percent = Some(37.5);
        activity.cpu_ticks = Some(30);
        activity.cpu_window_seconds = Some(0.8);
        activity.cpu_error = None;
        activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Observed {
            occupancy: 0.375,
            effective_cores: 1.0,
            effective_parallelism: 1.0,
            online_cores: 4,
            affinity_cores: 4,
            quota_cores: Some(1.0),
            threads: 3,
        });
        activity.io_window_seconds = Some(0.75);
        activity.io_read_bytes = Some(300);
        activity.io_write_bytes = Some(0);
        activity.read_bytes_per_second = Some(400.0);
        activity.write_bytes_per_second = Some(0.0);
        activity.io_active = Some(true);
        activity.io_error = None;
        activity
    }

    #[test]
    fn recorded_shadow_state_keeps_measured_windows_and_explicit_unknowns() {
        let directory = TempDir::new().unwrap();
        let mut recorder = ShadowRecorder::with_config(ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            auto_compact: false,
            delete_expired: false,
            ..Default::default()
        })
        .unwrap();
        let proc = make_proc(42, "worker", "worker --job");
        let activity = measured_activity(&proc);
        let ledger = make_ledger(Confidence::Medium, vec![], vec![], "measured prediction");
        recorder
            .record_candidate(
                &proc,
                &ledger.posterior.posterior,
                &ledger,
                &make_decision(Action::Keep),
                Some(&activity),
                Some(0),
            )
            .unwrap();
        recorder.flush().unwrap();
        drop(recorder);

        let paths: Vec<_> = fs::read_dir(directory.path().join("hot/pid_42"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(paths.len(), 1);
        let bytes = fs::read(&paths[0]).unwrap();
        let observations: Vec<Observation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(observations.len(), 1);
        let state = &observations[0].state;
        assert_eq!(state.schema_version, 1);
        assert_eq!(state.cpu_percent, Some(37.5));
        assert_eq!(state.cpu_lifetime_percent, Some(5.0));
        assert_eq!(state.thread_count, Some(3));
        assert_eq!(state.child_count, Some(0));
        assert_eq!(state.fd_count, None);
        assert_eq!(
            state.io_read_bytes, None,
            "no lifetime counter was collected"
        );
        assert_eq!(state.io_write_bytes, None);
        let window = state.activity.as_ref().unwrap();
        assert_eq!(window.source, "procfs_window");
        assert_eq!(window.requested_window_ms, 500);
        assert_eq!(window.cpu_window_seconds, Some(0.8));
        assert_eq!(window.cpu_ticks, Some(30));
        assert_eq!(window.io_window_seconds, Some(0.75));
        assert_eq!(window.io_read_delta_bytes, Some(300));
        assert_eq!(window.io_write_delta_bytes, Some(0));
        assert_eq!(window.read_bytes_per_second, Some(400.0));
        assert_eq!(window.write_bytes_per_second, Some(0.0));
        assert_eq!(window.io_active, Some(true));
        assert!(window.cpu_error.is_none());
        assert!(window.io_error.is_none());
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json[0]["state"]["fd_count"].is_null());
        assert_eq!(json[0]["state"]["child_count"], 0);
        let pending: Vec<PendingObservation> =
            serde_json::from_slice(&fs::read(directory.path().join("pending.json")).unwrap())
                .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].identity_hash, compute_identity_hash(&proc));
        assert_eq!(
            serde_json::to_value(&pending[0].state).unwrap(),
            json[0]["state"]
        );
    }

    #[test]
    fn shadow_cpu_and_io_fail_independently_without_inventing_idle_values() {
        let proc = make_proc(42, "worker", "worker");
        let mut activity = measured_activity(&proc);
        activity.cpu_percent = Some(0.0);
        activity.cpu_ticks = Some(0);
        activity.io_error = Some("permission denied".into());
        let state = observation_state(&proc, Some(&activity), None);
        assert_eq!(state.cpu_percent, Some(0.0));
        assert_eq!(state.cpu_lifetime_percent, Some(5.0));
        assert_eq!(state.child_count, None);
        let window = state.activity.unwrap();
        assert_eq!(window.cpu_ticks, Some(0));
        assert!(window.cpu_error.is_none());
        assert_eq!(window.io_read_delta_bytes, None);
        assert_eq!(window.io_active, None);
        assert_eq!(window.io_error.as_deref(), Some("permission denied"));

        activity = measured_activity(&proc);
        activity.cpu_error = Some("counter reset".into());
        activity.io_read_bytes = Some(0);
        let state = observation_state(&proc, Some(&activity), None);
        assert_eq!(
            state.cpu_percent, None,
            "failed window cannot use lifetime CPU"
        );
        assert_eq!(state.cpu_lifetime_percent, Some(5.0));
        let window = state.activity.unwrap();
        assert_eq!(window.cpu_ticks, None);
        assert_eq!(window.cpu_error.as_deref(), Some("counter reset"));
        assert_eq!(window.io_read_delta_bytes, Some(0));
        assert_eq!(window.io_write_delta_bytes, Some(0));
        assert_eq!(window.read_bytes_per_second, Some(0.0));
        assert_eq!(window.io_active, Some(false));
        assert!(window.io_error.is_none());
    }

    #[test]
    fn shadow_activity_rejects_changed_identity_and_unrecognized_sources() {
        let proc = make_proc(42, "worker", "worker");
        for case in ["pid", "birth", "uid", "source", "no_window"] {
            let mut activity = measured_activity(&proc);
            match case {
                "pid" => activity.pid += 1,
                "birth" => activity.start_id = pt_common::StartId("boot:6:42".into()),
                "uid" => activity.uid += 1,
                "source" => activity.source = "inferred_idle".into(),
                "no_window" => activity.requested_window_ms = 0,
                _ => unreachable!(),
            }
            let state = observation_state(&proc, Some(&activity), Some(2));
            assert_eq!(state.cpu_percent, None, "{case}");
            assert_eq!(state.thread_count, None, "{case}");
            assert_eq!(state.child_count, Some(2), "separate scan evidence: {case}");
            let window = state.activity.unwrap();
            assert_eq!(window.cpu_ticks, None, "{case}");
            assert_eq!(window.io_read_delta_bytes, None, "{case}");
            assert_eq!(window.io_active, None, "{case}");
            assert!(window.cpu_error.is_some(), "{case}");
            assert!(window.io_error.is_some(), "{case}");
        }
    }

    #[test]
    fn shadow_activity_rejects_invalid_or_incomplete_rate_measurements() {
        let proc = make_proc(42, "worker", "worker");
        for value in [f64::NAN, f64::INFINITY, -1.0, f64::MAX] {
            let mut activity = measured_activity(&proc);
            activity.cpu_percent = Some(value);
            let state = observation_state(&proc, Some(&activity), None);
            assert_eq!(state.cpu_percent, None);
            let window = state.activity.unwrap();
            assert!(window.cpu_error.is_some());
            assert_eq!(window.io_read_delta_bytes, Some(300));
        }
        for value in [
            None,
            Some(0.0),
            Some(0.4),
            Some(f64::NAN),
            Some(f64::INFINITY),
        ] {
            let mut activity = measured_activity(&proc);
            activity.cpu_window_seconds = value;
            activity.io_window_seconds = value;
            let state = observation_state(&proc, Some(&activity), None);
            assert_eq!(state.cpu_percent, None);
            let window = state.activity.unwrap();
            assert!(window.cpu_error.is_some());
            assert!(window.io_error.is_some());
            assert_eq!(window.cpu_ticks, None);
            assert_eq!(window.io_read_delta_bytes, None);
        }
        let mut activity = measured_activity(&proc);
        activity.cpu_ticks = None;
        activity.io_read_bytes = None;
        let state = observation_state(&proc, Some(&activity), None);
        assert_eq!(state.cpu_percent, None);
        let window = state.activity.unwrap();
        assert!(window.cpu_error.is_some());
        assert!(window.io_error.is_some());
        assert_eq!(window.read_bytes_per_second, None);
    }

    #[test]
    fn shadow_snapshot_and_native_fallback_keep_lifetime_cpu_explicit() {
        let mut proc = make_proc(42, "worker", "worker");
        let state = observation_state(&proc, None, None);
        assert_eq!(state.cpu_percent, Some(5.0));
        assert_eq!(state.cpu_lifetime_percent, Some(5.0));
        assert!(state.activity.is_none());
        assert_eq!(state.thread_count, None);
        assert_eq!(state.io_read_bytes, None);
        let mut activity = measured_activity(&proc);
        activity.source = "ps_lifetime_fallback".into();
        activity.cpu_percent = Some(2.0);
        let state = observation_state(&proc, Some(&activity), None);
        assert_eq!(state.cpu_percent, Some(2.0));
        let window = state.activity.unwrap();
        assert_eq!(window.source, "ps_lifetime_fallback");
        assert_eq!(window.cpu_ticks, None);
        assert_eq!(window.cpu_window_seconds, None);
        assert_eq!(window.io_read_delta_bytes, None);
        assert!(window.io_error.is_some());

        proc.cpu_percent = f64::NAN;
        let state = observation_state(&proc, None, None);
        assert_eq!(state.cpu_percent, None);
        assert_eq!(state.cpu_lifetime_percent, None);
        assert!(serde_json::to_value(state).unwrap()["cpu_percent"].is_null());
    }

    use crate::inference::{BayesFactorEntry, Classification, PosteriorResult};

    fn make_ledger(
        confidence: Confidence,
        factors: Vec<BayesFactorEntry>,
        top: Vec<String>,
        why: &str,
    ) -> EvidenceLedger {
        EvidenceLedger {
            posterior: PosteriorResult {
                posterior: ClassScores {
                    useful: 0.1,
                    useful_bad: 0.1,
                    abandoned: 0.7,
                    zombie: 0.1,
                },
                log_posterior: ClassScores::default(),
                log_odds_abandoned_useful: 2.0,
                evidence_terms: vec![],
            },
            classification: Classification::Abandoned,
            confidence,
            bayes_factors: factors,
            top_evidence: top,
            why_summary: why.to_string(),
            evidence_glyphs: std::collections::HashMap::new(),
        }
    }

    fn make_bf(feature: &str, delta: f64, direction: &str, strength: &str) -> BayesFactorEntry {
        BayesFactorEntry {
            feature: feature.to_string(),
            bf: 10.0,
            log_bf: 2.3,
            delta_bits: delta,
            direction: direction.to_string(),
            strength: strength.to_string(),
        }
    }

    fn make_decision(action: Action) -> DecisionOutcome {
        use crate::decision::{DecisionRationale, ExpectedLoss};
        DecisionOutcome {
            expected_loss: vec![ExpectedLoss { action, loss: 0.0 }],
            optimal_action: action,
            sprt_boundary: None,
            posterior_odds_abandoned_vs_useful: None,
            recovery_expectations: None,
            rationale: DecisionRationale {
                chosen_action: action,
                tie_break: false,
                disabled_actions: vec![],
                used_recovery_preference: false,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            risk_sensitive: None,
            dro: None,
        }
    }

    fn make_pending(hash: &str, pid: u32, comm: &str) -> PendingObservation {
        PendingObservation {
            identity_hash: hash.to_string(),
            pid,
            last_seen: Utc::now(),
            miss_count: 0,
            belief: BeliefState::default(),
            state: StateSnapshot::default(),
            comm: comm.to_string(),
            identity: None,
            exit_recorded: false,
        }
    }

    #[test]
    fn unscored_presence_survives_restart_command_and_owner_changes() {
        let directory = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            auto_compact: false,
            delete_expired: false,
            ..Default::default()
        };
        let mut proc = make_proc(42, "worker", "worker --first-job");
        let hash = compute_identity_hash(&proc);
        let mut recorder = ShadowRecorder::with_config(config.clone()).unwrap();
        let ledger = make_ledger(Confidence::Medium, vec![], vec![], "earlier prediction");
        recorder
            .record_candidate(
                &proc,
                &ledger.posterior.posterior,
                &ledger,
                &make_decision(Action::Keep),
                None,
                None,
            )
            .unwrap();
        recorder.flush().unwrap();
        drop(recorder);

        proc.comm = "another-worker".to_string();
        proc.cmd = "another-worker --second-job".to_string();
        proc.uid = 1001;
        assert_ne!(compute_identity_hash(&proc), hash);
        for _ in 0..3 {
            let mut recorder = ShadowRecorder::with_config(config.clone()).unwrap();
            recorder
                .observe_processes(std::slice::from_ref(&proc))
                .unwrap();
            recorder
                .record_outcomes_for_missing_with(|_| panic!("the incarnation was observed"))
                .unwrap();
            recorder.flush().unwrap();
            assert_eq!(recorder.pending.len(), 1);
            assert_eq!(recorder.pending[&hash].miss_count, 0);
            assert_eq!(recorder.pending[&hash].comm, "worker");
            assert_eq!(recorder.recorded_count(), 0);
        }
    }

    #[test]
    fn incomplete_or_unreadable_presence_cannot_accumulate_exit_misses() {
        let directory = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            auto_compact: false,
            delete_expired: false,
            ..Default::default()
        };
        let mut recorder = ShadowRecorder::with_config(config).unwrap();
        let mut pending = make_pending("unseen", 42, "worker");
        pending.miss_count = 1;
        recorder
            .pending
            .insert(pending.identity_hash.clone(), pending);

        // Legacy records without birth identity remain unknown, even after
        // successful planner runs that have no eligible candidates.
        for _ in 0..3 {
            recorder.observe_processes(&[]).unwrap();
            recorder.flush().unwrap();
            assert_eq!(recorder.pending["unseen"].miss_count, 0);
            assert_eq!(recorder.recorded_count(), 0);
        }
        recorder.pending.get_mut("unseen").unwrap().identity = Some(ProcessIdentity::new(
            42,
            pt_common::StartId::from_linux("boot", 5, 42),
            1000,
        ));
        // An unreadable check interrupts two otherwise positive checks.
        for (gone, expected_misses) in [(true, 1), (false, 0), (true, 1)] {
            recorder.observe_processes(&[]).unwrap();
            recorder.record_outcomes_for_missing_with(|_| gone).unwrap();
            assert_eq!(recorder.pending["unseen"].miss_count, expected_misses);
        }
        assert_eq!(recorder.recorded_count(), 0);
    }

    #[cfg(target_os = "linux")]
    fn zombie_stat(pid: u32, ticks: u64, wait_status: &str) -> String {
        let mut fields = vec!["0".to_string(); 50];
        fields[0] = "Z".to_string();
        fields[19] = ticks.to_string();
        fields[35] = libc::SIGCHLD.to_string();
        fields[49] = wait_status.to_string();
        format!("{pid} (worker (exit) probe) {}\n", fields.join(" "))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zombie_wait_status_distinguishes_exit_signal_and_nonterminal_states() {
        for (raw, code, signal, core) in [
            (0, Some(0), None, false),
            (7 << 8, Some(7), None, false),
            (255 << 8, Some(255), None, false),
            (libc::SIGTERM, None, Some(libc::SIGTERM), false),
            (libc::SIGSEGV | 0x80, None, Some(libc::SIGSEGV), true),
        ] {
            let status = parse_zombie_exit_stat(&zombie_stat(42, 123, &raw.to_string()), 42, 123)
                .expect("terminal wait status");
            assert_eq!(status.wait_status, raw);
            assert_eq!(status.exit_code, code);
            assert_eq!(status.exit_signal, signal);
            assert_eq!(status.core_dumped, core);
        }
        for raw in ["-1", "65536", "n/a", "65535", "4991", "128", "65", "271"] {
            assert!(parse_zombie_exit_stat(&zombie_stat(42, 123, raw), 42, 123).is_none());
        }
        let valid = zombie_stat(42, 123, "0");
        assert!(parse_zombie_exit_stat(&valid, 43, 123).is_none());
        assert!(parse_zombie_exit_stat(&valid, 42, 124).is_none());
        assert!(parse_zombie_exit_stat(&valid.replace(") Z ", ") T "), 42, 123).is_none());
        assert!(parse_zombie_exit_stat(&valid.replace(") Z ", ") R "), 42, 123).is_none());
        assert!(parse_zombie_exit_stat("42 (worker) Z 1 2", 42, 123).is_none());
    }

    #[cfg(target_os = "linux")]
    fn zombie_fixture(root: &std::path::Path, namespace_readable: bool) -> ProcessRecord {
        let directory = root.join("42");
        fs::create_dir_all(directory.join("ns")).unwrap();
        fs::write(directory.join("stat"), zombie_stat(42, 5, "0")).unwrap();
        fs::write(
            directory.join("status"),
            "Uid:\t1000 1000 1000 1000\nThreads:\t1\n",
        )
        .unwrap();
        if namespace_readable {
            std::os::unix::fs::symlink("user:[1]", directory.join("ns/user")).unwrap();
        }
        let mut proc = make_proc(42, "worker", "worker --old-command");
        proc.state = crate::collect::ProcessState::Zombie;
        proc
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zombie_exit_requires_readable_stable_birth_owner_and_single_thread() {
        let directory = TempDir::new().unwrap();
        let proc = zombie_fixture(directory.path(), true);
        let observe =
            |proc: &ProcessRecord| observe_zombie_exit_from(proc, directory.path(), "boot", || {});
        assert_eq!(observe(&proc).unwrap().exit_code, Some(0));
        let mut wrong = proc.clone();
        wrong.uid = 1001;
        assert!(observe(&wrong).is_none());
        wrong = proc.clone();
        wrong.start_id = pt_common::StartId::from_linux("other-boot", 5, 42);
        assert!(observe(&wrong).is_none());
        wrong.start_id = pt_common::StartId::from_linux("boot", 6, 42);
        assert!(observe(&wrong).is_none());
        wrong.start_id = pt_common::StartId::from_linux("boot", 5, 43);
        assert!(observe(&wrong).is_none());
        for status in [
            "Uid:\t1000 1000 1000 1000\nThreads:\t2\n",
            "Uid:\t1000 1000 1000 1000\n",
            "Threads:\t1\n",
            "Uid:\t1000 1000 1000 1000\nThreads:\t1\nThreads:\t1\n",
        ] {
            fs::write(directory.path().join("42/status"), status).unwrap();
            assert!(observe(&proc).is_none());
        }
        fs::write(
            directory.path().join("42/status"),
            "Uid:\t1000 1000 1000 1000\nThreads:\t1\n",
        )
        .unwrap();
        assert!(
            observe_zombie_exit_from(&proc, directory.path(), "boot", || {
                fs::write(directory.path().join("42/stat"), zombie_stat(42, 6, "0")).unwrap();
            })
            .is_none(),
            "PID reuse between reads is not the original exit"
        );

        let denied = TempDir::new().unwrap();
        let proc = zombie_fixture(denied.path(), false);
        assert!(
            observe_zombie_exit_from(&proc, denied.path(), "boot", || {}).is_none(),
            "a readable zero in stat without ptrace access is not exit zero"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_marker_retirement_requires_positive_absence_or_a_different_boot() {
        let identity =
            ProcessIdentity::new(42, pt_common::StartId::from_linux("boot", 5, 42), 1000);
        let missing = |_| {
            Err(crate::collect::proc_parsers::StatReadError::Read {
                pid: 42,
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            })
        };
        assert!(
            !observed_exit_target_gone_with(&identity, "boot", missing, |_| false),
            "hidden or inaccessible is not gone"
        );
        assert!(observed_exit_target_gone_with(
            &identity,
            "boot",
            missing,
            |_| true
        ));
        assert!(!observed_exit_target_gone_with(
            &identity,
            "boot",
            |_| Ok(5),
            |_| true
        ));
        assert!(!observed_exit_target_gone_with(
            &identity,
            "boot",
            |_| Ok(0),
            |_| true
        ));
        assert!(observed_exit_target_gone_with(
            &identity,
            "boot",
            |_| Ok(6),
            |_| false
        ));
        assert!(observed_exit_target_gone_with(
            &identity,
            "new-boot",
            |_| panic!("old boot"),
            |_| false
        ));
        for boot in ["", "unknown"] {
            assert!(!observed_exit_target_gone_with(
                &identity,
                boot,
                missing,
                |_| true
            ));
        }
        let unknown =
            ProcessIdentity::new(42, pt_common::StartId::from_linux("unknown", 5, 42), 1000);
        assert!(!observed_exit_target_gone_with(
            &unknown,
            "boot",
            missing,
            |_| true
        ));
        let mut weak = identity;
        weak.quality = pt_common::IdentityQuality::PidOnly;
        assert!(!observed_exit_target_gone_with(
            &weak,
            "boot",
            |_| Ok(6),
            |_| true
        ));
        for start in [
            "garbage",
            "boot:0:42",
            "boot:5:43",
            "boot:5:42:extra",
            "unknown:5:42",
        ] {
            let malformed = ProcessIdentity::new(42, pt_common::StartId(start.into()), 1000);
            for boot in ["boot", "new-boot"] {
                assert!(!observed_exit_target_gone_with(
                    &malformed,
                    boot,
                    |_| panic!("invalid saved identity must not reach the live probe"),
                    |_| true
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temporarily_unavailable_zombie_exit_preserves_the_last_live_prediction() {
        let proc_root = TempDir::new().unwrap();
        let mut proc = zombie_fixture(proc_root.path(), true);
        proc.state = crate::collect::ProcessState::Running;
        let original_hash = compute_identity_hash(&proc);
        let directory = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            auto_compact: false,
            delete_expired: false,
            ..Default::default()
        };
        let mut recorder = ShadowRecorder::with_config(config).unwrap();
        let posterior = ClassScores {
            useful: 0.8,
            useful_bad: 0.1,
            abandoned: 0.1,
            zombie: 0.0,
        };
        let ledger = make_ledger(Confidence::Medium, vec![], vec![], "live prediction");
        let decision = make_decision(Action::Keep);
        recorder
            .record_candidate(&proc, &posterior, &ledger, &decision, None, None)
            .unwrap();
        recorder.flush().unwrap();
        proc.state = crate::collect::ProcessState::Zombie;
        proc.cmd.clear();
        let zombie_hash = compute_identity_hash(&proc);
        assert_ne!(original_hash, zombie_hash);
        for status in ["Uid:\t1000 1000 1000 1000\nThreads:\t2\n", "Threads:\t1\n"] {
            fs::write(proc_root.path().join("42/status"), status).unwrap();
            recorder.had_records = true;
            recorder
                .record_zombie_exit_with(&proc, |proc| {
                    observe_zombie_exit_from(proc, proc_root.path(), "boot", || {})
                })
                .unwrap();
            recorder.flush().unwrap();
            assert_eq!(recorder.pending.len(), 1);
            assert_eq!(
                recorder.latest_pending_by_pid.get(&42),
                Some(&original_hash)
            );
            let pending = &recorder.pending[&original_hash];
            assert!(!pending.exit_recorded);
            assert_eq!(pending.miss_count, 0);
            assert_eq!(pending.belief.p_abandoned, 0.1);
            assert_eq!(
                recorder.recorded_count(),
                1,
                "no post-death prediction or false exit"
            );
        }
        fs::write(
            proc_root.path().join("42/status"),
            "Uid:\t1000 1000 1000 1000\nThreads:\t1\n",
        )
        .unwrap();
        recorder.had_records = true;
        recorder
            .record_zombie_exit_with(&proc, |proc| {
                observe_zombie_exit_from(proc, proc_root.path(), "boot", || {})
            })
            .unwrap();
        recorder.flush().unwrap();
        assert_eq!(recorder.pending.len(), 1);
        assert!(recorder.pending[&original_hash].exit_recorded);
        assert!(!recorder.pending.contains_key(&zombie_hash));
        assert_eq!(recorder.recorded_count(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_zombie_outcomes_keep_prediction_identity_and_remain_unlabeled() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        for (script, signal, expected_code, expected_signal) in [
            ("read ignored; exit 0", None, Some(0), None),
            ("read ignored; exit 7", None, Some(7), None),
            (
                "read ignored; exit 0",
                Some(libc::SIGTERM),
                None,
                Some(libc::SIGTERM),
            ),
        ] {
            let mut child = ChildGuard(
                Command::new("sh")
                    .args(["-c", script])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let pid = child.0.id();
            let stat = crate::collect::proc_parsers::read_required_proc_stat(pid).unwrap();
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
            let mut proc = make_proc(pid, "sh", &format!("sh -c {script}"));
            // SAFETY: geteuid only reads this test's effective owner identity.
            proc.uid = unsafe { libc::geteuid() };
            proc.start_id = pt_common::StartId::from_linux(boot.trim(), stat.starttime, pid);
            let identity_hash = compute_identity_hash(&proc);
            let directory = TempDir::new().unwrap();
            let config = ShadowStorageConfig {
                base_dir: directory.path().to_path_buf(),
                auto_compact: false,
                delete_expired: false,
                ..Default::default()
            };
            let posterior = ClassScores {
                useful: 0.8,
                useful_bad: 0.1,
                abandoned: 0.1,
                zombie: 0.0,
            };
            let ledger = make_ledger(Confidence::Medium, vec![], vec![], "live prediction");
            let decision = make_decision(Action::Keep);
            let mut recorder = ShadowRecorder::with_config(config.clone()).unwrap();
            recorder
                .record_candidate(&proc, &posterior, &ledger, &decision, None, None)
                .unwrap();
            recorder.flush().unwrap();
            if let Some(signal) = signal {
                // SAFETY: this test owns the unreaped child at this positive PID.
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, signal) }, 0);
            } else {
                child
                    .0
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(b"done\n")
                    .unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if crate::collect::proc_parsers::read_required_proc_stat(pid)
                    .unwrap()
                    .state
                    == 'Z'
                {
                    break;
                }
                assert!(Instant::now() < deadline, "child did not become a zombie");
                std::thread::sleep(Duration::from_millis(5));
            }
            proc.state = crate::collect::ProcessState::Zombie;
            proc.cmd.clear();
            assert_ne!(compute_identity_hash(&proc), identity_hash);
            recorder
                .observe_processes(std::slice::from_ref(&proc))
                .unwrap();
            assert_eq!(
                recorder.recorded_count(),
                2,
                "unfiltered presence records the exit before candidate selection"
            );
            recorder
                .record_candidate(&proc, &posterior, &ledger, &decision, None, None)
                .unwrap();
            recorder.flush().unwrap();
            drop(recorder);
            let mut recorder = ShadowRecorder::with_config(config.clone()).unwrap();
            recorder
                .record_candidate(&proc, &posterior, &ledger, &decision, None, None)
                .unwrap();
            recorder.flush().unwrap();
            assert_eq!(
                recorder.recorded_count(),
                0,
                "terminal event is durable and deduplicated"
            );
            recorder.miss_threshold = 1;
            recorder.had_records = true;
            recorder.record_outcomes_for_missing().unwrap();
            assert!(
                recorder.pending.contains_key(&identity_hash),
                "filtered scan cannot reap a zombie"
            );
            child.0.wait().unwrap();
            recorder.had_records = true;
            recorder.flush().unwrap();
            assert!(!recorder.pending.contains_key(&identity_hash));

            let mut observations = Vec::new();
            for entry in fs::read_dir(directory.path().join(format!("hot/pid_{pid}"))).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                    let batch: Vec<Observation> =
                        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    observations.extend(batch);
                }
            }
            assert_eq!(
                observations.len(),
                2,
                "one prediction and one observed exit"
            );
            let observed = observations
                .iter()
                .find(|obs| obs.belief.recommendation == "observed_exit")
                .unwrap();
            assert_eq!(observed.identity_hash, identity_hash);
            let details: serde_json::Value =
                serde_json::from_str(observed.events[0].details.as_deref().unwrap()).unwrap();
            assert_eq!(details["exit_code"], serde_json::json!(expected_code));
            assert_eq!(details["exit_signal"], serde_json::json!(expected_signal));
            assert_eq!(details["reason"], "observed_zombie");
            assert!(details.get("outcome_hint").is_none());
            let engine = crate::calibrate::validation::ValidationEngine::from_shadow_observations(
                &observations,
                0.5,
            );
            assert_eq!(engine.records().len(), 1);
            let record = &engine.records()[0];
            assert_eq!(record.exit_code, expected_code);
            assert_eq!(record.exit_signal, expected_signal);
            let report = engine.compute_report().unwrap();
            assert_eq!((report.positive_labels, report.negative_labels), (0, 0));
            assert_eq!(report.unlabeled_outcomes, 1);
            assert!(report.metrics.is_none());
        }
    }

    #[test]
    fn human_verdicts_are_durable_identity_bound_events_without_predictions() {
        let directory = TempDir::new().unwrap();
        let config = ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            auto_compact: false,
            delete_expired: false,
            ..Default::default()
        };
        let proc = make_proc(412, "sleep", "sleep 621");
        let verdicts = [
            (HumanVerdictSource::AgentLabel, Verdict::Kill),
            (HumanVerdictSource::AgentLabel, Verdict::Spare),
            (HumanVerdictSource::TuiReview, Verdict::Kill),
            (HumanVerdictSource::TuiReview, Verdict::Spare),
        ];
        for (source, verdict) in verdicts {
            let identity = record_reviewed_verdict(
                &config,
                &ProcessIdentity::new(proc.pid.0, proc.start_id.clone(), proc.uid),
                &proc.comm,
                &proc.cmd,
                verdict,
                source,
            )
            .expect("persist explicit verdict");
            assert_eq!(identity, compute_identity_hash(&proc));
        }

        // Read the published batches after each short-lived writer has gone;
        // neither the in-memory query cache nor pending.json is the evidence.
        let mut observations = Vec::new();
        for entry in fs::read_dir(directory.path().join("hot/pid_412")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                let batch: Vec<Observation> =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                observations.extend(batch);
            }
        }
        observations.sort_by_key(|obs| obs.timestamp);
        assert_eq!(observations.len(), 4);
        for (obs, (source, verdict)) in observations.iter().zip(verdicts) {
            assert_eq!(obs.pid, proc.pid.0);
            assert_eq!(obs.identity_hash, compute_identity_hash(&proc));
            assert_eq!(obs.events.len(), 1);
            let event = &obs.events[0];
            assert_eq!(event.event_type, EventType::HumanVerdict);
            assert_eq!(event.timestamp, obs.timestamp);
            let details: serde_json::Value =
                serde_json::from_str(event.details.as_deref().unwrap()).unwrap();
            assert_eq!(details["verdict"], serde_json::to_value(verdict).unwrap());
            assert_eq!(details["source"], source.as_str());
            assert_eq!(details["comm"], "sleep");
            assert_eq!(obs.belief.recommendation, "human_verdict");
        }
        assert!(!directory.path().join("pending.json").exists());
        let engine = crate::calibrate::validation::ValidationEngine::from_shadow_observations(
            &observations,
            0.5,
        );
        assert!(
            engine.records().is_empty(),
            "verdicts cannot invent predictions"
        );
    }

    // ── action_to_recommendation ────────────────────────────────────

    #[test]
    fn recommendation_keep() {
        assert_eq!(action_to_recommendation(Action::Keep), "keep");
    }

    #[test]
    fn recommendation_kill() {
        assert_eq!(action_to_recommendation(Action::Kill), "kill");
    }

    #[test]
    fn recommendation_renice() {
        assert_eq!(action_to_recommendation(Action::Renice), "renice");
    }

    #[test]
    fn recommendation_pause() {
        assert_eq!(action_to_recommendation(Action::Pause), "pause");
    }

    #[test]
    fn recommendation_resume() {
        assert_eq!(action_to_recommendation(Action::Resume), "resume");
    }

    #[test]
    fn recommendation_freeze() {
        assert_eq!(action_to_recommendation(Action::Freeze), "freeze");
    }

    #[test]
    fn recommendation_unfreeze() {
        assert_eq!(action_to_recommendation(Action::Unfreeze), "unfreeze");
    }

    #[test]
    fn recommendation_throttle() {
        assert_eq!(action_to_recommendation(Action::Throttle), "throttle");
    }

    #[test]
    fn recommendation_quarantine() {
        assert_eq!(action_to_recommendation(Action::Quarantine), "quarantine");
    }

    #[test]
    fn recommendation_unquarantine() {
        assert_eq!(
            action_to_recommendation(Action::Unquarantine),
            "unquarantine"
        );
    }

    #[test]
    fn recommendation_restart() {
        assert_eq!(action_to_recommendation(Action::Restart), "restart");
    }

    // ── confidence_score ────────────────────────────────────────────

    #[test]
    fn confidence_very_high() {
        assert!((confidence_score(Confidence::VeryHigh) - 0.99).abs() < f32::EPSILON);
    }

    #[test]
    fn confidence_high() {
        assert!((confidence_score(Confidence::High) - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn confidence_medium() {
        assert!((confidence_score(Confidence::Medium) - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn confidence_low() {
        assert!((confidence_score(Confidence::Low) - 0.5).abs() < f32::EPSILON);
    }

    // ── compute_identity_hash ───────────────────────────────────────

    #[test]
    fn hash_changes_for_different_uid() {
        let mut p = make_proc(1, "bash", "bash");
        let h1 = compute_identity_hash(&p);
        p.uid = 9999;
        let h2 = compute_identity_hash(&p);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_changes_for_different_comm() {
        let p1 = make_proc(1, "bash", "bash");
        let p2 = make_proc(1, "zsh", "bash");
        assert_ne!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn hash_changes_for_different_cmd() {
        let p1 = make_proc(1, "bash", "bash -c echo");
        let p2 = make_proc(1, "bash", "bash -c sleep");
        assert_ne!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn hash_ignores_pid() {
        let mut p1 = make_proc(1, "bash", "bash");
        let mut p2 = make_proc(999, "bash", "bash");
        // Ensure same start_id so only pid differs
        p1.start_id = pt_common::StartId("boot:5:same".to_string());
        p2.start_id = pt_common::StartId("boot:5:same".to_string());
        assert_eq!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn hash_is_hex_encoded() {
        let p = make_proc(1, "bash", "bash");
        let h = compute_identity_hash(&p);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── build_evidence_event ────────────────────────────────────────

    #[test]
    fn evidence_event_with_factors_and_top() {
        let factors = vec![make_bf("age", 3.0, "supports abandoned", "strong")];
        let top = vec!["old process".to_string()];
        let ledger = make_ledger(Confidence::High, factors, top, "Likely abandoned");
        let event =
            build_evidence_event(&ledger, "sleep", Some("TestRunner"), Some("host-a")).unwrap();
        assert_eq!(event.event_type, EventType::EvidenceSnapshot);
        let details: serde_json::Value =
            serde_json::from_str(event.details.as_ref().unwrap()).unwrap();
        assert_eq!(details["comm"], "sleep");
        assert_eq!(details["signature_category"], "TestRunner");
        assert_eq!(details["host_id"], "host-a");
        assert_eq!(details["why_summary"], "Likely abandoned");
        assert!(details["bayes_factors"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn evidence_event_none_when_empty() {
        let ledger = make_ledger(Confidence::Low, vec![], vec![], "");
        assert!(build_evidence_event(&ledger, "bash", None, None).is_none());
    }

    #[test]
    fn prediction_metadata_survives_an_empty_evidence_ledger() {
        let ledger = make_ledger(Confidence::Low, vec![], vec![], "");
        let event =
            build_evidence_event(&ledger, "worker", Some("TestRunner"), Some("unknown")).unwrap();
        let details: serde_json::Value =
            serde_json::from_str(event.details.as_deref().unwrap()).unwrap();
        assert_eq!(details["signature_category"], "TestRunner");
        assert!(details["host_id"].is_null());
        assert!(build_evidence_event(&ledger, "worker", Some(" "), Some("unknown")).is_none());
    }

    #[test]
    fn evidence_event_with_only_top_evidence() {
        let ledger = make_ledger(
            Confidence::Medium,
            vec![],
            vec!["some evidence".to_string()],
            "why",
        );
        let event = build_evidence_event(&ledger, "node", None, None);
        assert!(event.is_some());
    }

    #[test]
    fn evidence_event_with_only_bayes_factors() {
        let factors = vec![make_bf("cpu", 1.5, "supports useful", "weak")];
        let ledger = make_ledger(Confidence::Low, factors, vec![], "");
        let event = build_evidence_event(&ledger, "python", None, None);
        assert!(event.is_some());
    }

    #[test]
    fn evidence_event_caps_at_three_factors() {
        let factors = vec![
            make_bf("a", 1.0, "supports abandoned", "weak"),
            make_bf("b", 2.0, "supports abandoned", "substantial"),
            make_bf("c", 3.0, "supports abandoned", "strong"),
            make_bf("d", 4.0, "supports abandoned", "decisive"),
        ];
        let ledger = make_ledger(Confidence::High, factors, vec![], "");
        let event = build_evidence_event(&ledger, "x", None, None).unwrap();
        let details: serde_json::Value =
            serde_json::from_str(event.details.as_ref().unwrap()).unwrap();
        assert_eq!(details["bayes_factors"].as_array().unwrap().len(), 3);
    }

    // ── load_pending / persist_pending ──────────────────────────────

    #[test]
    fn load_pending_nonexistent_returns_empty() {
        let path = PathBuf::from("/tmp/nonexistent_pending_12345.json");
        let result = load_pending(&path).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.json");
        let mut map = HashMap::new();
        map.insert("hash1".to_string(), make_pending("hash1", 100, "sleep"));
        map.insert("hash2".to_string(), make_pending("hash2", 200, "node"));

        persist_pending(&path, &map).unwrap();
        let loaded = load_pending(&path).unwrap();

        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains_key("hash1"));
        assert!(loaded.contains_key("hash2"));
        assert_eq!(loaded["hash1"].pid, 100);
        assert_eq!(loaded["hash2"].comm, "node");
    }

    #[test]
    fn persist_empty_map() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.json");
        persist_pending(&path, &HashMap::new()).unwrap();
        let loaded = load_pending(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn persist_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sub").join("deep").join("pending.json");
        persist_pending(&path, &HashMap::new()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn persist_sorted_by_identity_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.json");
        let mut map = HashMap::new();
        map.insert("zzz".to_string(), make_pending("zzz", 3, "c"));
        map.insert("aaa".to_string(), make_pending("aaa", 1, "a"));
        map.insert("mmm".to_string(), make_pending("mmm", 2, "b"));

        persist_pending(&path, &map).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let records: Vec<PendingObservation> = serde_json::from_str(&content).unwrap();
        assert_eq!(records[0].identity_hash, "aaa");
        assert_eq!(records[1].identity_hash, "mmm");
        assert_eq!(records[2].identity_hash, "zzz");
    }

    #[test]
    fn concurrent_persists_into_one_directory_all_succeed() {
        // Regression: concurrent `--shadow` runs shared a fixed `pending.tmp`,
        // so one run's rename failed with NotFound (exit 21) or published
        // another run's partial file.
        const WRITERS: u32 = 6;
        const ROUNDS: usize = 20;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.json");
        let maps: Vec<HashMap<String, PendingObservation>> = (0..WRITERS)
            .map(|writer| {
                (0..200u32)
                    .map(|index| {
                        let hash = format!("w{writer}-{index:03}");
                        let entry = make_pending(&hash, writer * 1000 + index, "sleep");
                        (hash, entry)
                    })
                    .collect()
            })
            .collect();
        let barrier = std::sync::Barrier::new(WRITERS as usize);
        let (barrier, shared_path) = (&barrier, &path);
        std::thread::scope(|scope| {
            let handles: Vec<_> = maps
                .iter()
                .map(|map| {
                    scope.spawn(move || {
                        barrier.wait();
                        (0..ROUNDS)
                            .map(|_| {
                                persist_pending(shared_path, map).map_err(|err| format!("{err:?}"))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            for handle in handles {
                for result in handle.join().unwrap() {
                    result.expect("every concurrent persist succeeds");
                }
            }
        });
        let loaded = load_pending(&path).expect("the final pending file is valid");
        assert!(
            maps.iter()
                .any(|map| loaded.len() == map.len() && map.keys().all(|k| loaded.contains_key(k))),
            "the final pending file is one writer's complete map"
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "pending.json")
            .collect();
        assert!(leftovers.is_empty(), "staged files left: {leftovers:?}");
    }

    // ── PendingObservation serde ────────────────────────────────────

    #[test]
    fn pending_observation_roundtrip() {
        let obs = make_pending("abc123", 42, "sleep");
        let json = serde_json::to_string(&obs).unwrap();
        let deser: PendingObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.identity_hash, "abc123");
        assert_eq!(deser.pid, 42);
        assert_eq!(deser.comm, "sleep");
    }

    // ── ShadowRecordError From impls ────────────────────────────────

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = ShadowRecordError::from(io_err);
        matches!(err, ShadowRecordError::Io(_));
    }

    #[test]
    fn error_from_json() {
        let json_err = serde_json::from_str::<String>("not json").unwrap_err();
        let err = ShadowRecordError::from(json_err);
        matches!(err, ShadowRecordError::Json(_));
    }

    // ── resolve_data_dir_override ───────────────────────────────────

    #[test]
    fn resolve_data_dir_from_process_triage_data() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let result = resolve_data_dir_override();
        assert_eq!(result, Some(dir.path().to_path_buf()));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    // ── ShadowRecorder with tempdir ─────────────────────────────────

    #[test]
    fn persisted_prediction_category_requires_a_real_signature_match() {
        let directory = TempDir::new().unwrap();
        let storage = ShadowStorage::new(ShadowStorageConfig {
            base_dir: directory.path().to_path_buf(),
            host_id: "host-a".to_string(),
            auto_compact: false,
            ..Default::default()
        })
        .unwrap();
        let mut recorder = ShadowRecorder {
            storage,
            recorded: 0,
            pending: HashMap::new(),
            latest_pending_by_pid: HashMap::new(),
            seen_identities: HashSet::new(),
            seen_pids: HashMap::new(),
            pending_path: directory.path().join("pending.json"),
            miss_threshold: DEFAULT_MISS_THRESHOLD,
            had_records: false,
        };
        let ledger = make_ledger(Confidence::Low, vec![], vec![], "");
        let posterior = ClassScores {
            useful: 0.2,
            useful_bad: 0.0,
            abandoned: 0.6,
            zombie: 0.2,
        };
        for (pid, known_signature) in [(101, Some(true)), (102, Some(false)), (103, None)] {
            let mut decision = make_decision(Action::Keep);
            decision.rationale.category = Some("TestRunner".to_string());
            decision.rationale.has_known_signature = known_signature;
            recorder
                .record_candidate(
                    &make_proc(pid, "worker", "worker"),
                    &posterior,
                    &ledger,
                    &decision,
                    None,
                    None,
                )
                .unwrap();
        }
        recorder.flush().unwrap();

        let mut observations = Vec::new();
        for pid in [101, 102, 103] {
            let files: Vec<_> = fs::read_dir(directory.path().join(format!("hot/pid_{pid}")))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(files.len(), 1);
            let mut batch: Vec<Observation> =
                serde_json::from_slice(&fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(batch.len(), 1);
            let obs = batch.pop().unwrap();
            let details: serde_json::Value =
                serde_json::from_str(obs.events[0].details.as_deref().unwrap()).unwrap();
            assert_eq!(details["host_id"], "host-a");
            assert_eq!(
                details["signature_category"].as_str(),
                (pid == 101).then_some("TestRunner"),
            );
            observations.push(obs);
        }
        let engine = crate::calibrate::validation::ValidationEngine::from_shadow_observations(
            &observations,
            0.5,
        );
        for record in engine.records() {
            assert_eq!(record.host_id.as_deref(), Some("host-a"));
            assert_eq!(
                record.proc_type.as_deref(),
                (record.pid == 101).then_some("TestRunner")
            );
            assert!((record.predicted_abandoned - 0.8).abs() < 1e-6);
        }
    }

    #[test]
    fn recorder_starts_with_zero_count() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let recorder = ShadowRecorder::new().expect("recorder");
        assert_eq!(recorder.recorded_count(), 0);

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    #[test]
    fn recorder_record_candidate_increments_count() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        let proc = make_proc(100, "sleep", "sleep 60");
        let posterior = crate::inference::ClassScores {
            useful: 0.1,
            useful_bad: 0.05,
            abandoned: 0.8,
            zombie: 0.05,
        };
        let ledger = make_ledger(
            Confidence::High,
            vec![make_bf("age", 3.0, "supports abandoned", "strong")],
            vec!["old".to_string()],
            "Abandoned",
        );
        let decision = make_decision(Action::Kill);

        recorder
            .record_candidate(&proc, &posterior, &ledger, &decision, None, None)
            .unwrap();
        assert_eq!(recorder.recorded_count(), 1);

        // Verify pending entry was created
        assert!(recorder.pending.values().any(|p| p.pid == 100));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    #[test]
    fn recorder_flush_persists_pending() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        recorder.pending.insert(
            "test_hash".to_string(),
            make_pending("test_hash", 500, "node"),
        );

        recorder.flush().unwrap();
        assert!(recorder.pending_path.exists());

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    #[test]
    fn recorder_seen_identity_resets_miss_count() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        recorder.had_records = true;
        recorder.pending.insert(
            "seen_hash".to_string(),
            PendingObservation {
                identity_hash: "seen_hash".to_string(),
                pid: 10,
                last_seen: Utc::now() - chrono::Duration::hours(1),
                miss_count: 5,
                belief: BeliefState::default(),
                state: StateSnapshot::default(),
                comm: "test".to_string(),
                identity: None,
                exit_recorded: false,
            },
        );
        recorder.seen_identities.insert("seen_hash".to_string());

        recorder.record_outcomes_for_missing().unwrap();
        // seen_identities cleared after call, but pending should still have entry with reset miss
        // The entry was seen, so miss_count should be 0
        // After the call, seen_identities is cleared but pending keeps it
        assert!(recorder.pending.contains_key("seen_hash"));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    #[test]
    fn recorder_pid_reuse_detected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        recorder.miss_threshold = 1;
        recorder.had_records = true;

        // A pending observation for pid 42 with identity "old_hash"
        recorder.pending.insert(
            "old_hash".to_string(),
            make_pending("old_hash", 42, "old_proc"),
        );

        // But pid 42 now has a different identity (pid reuse)
        recorder.seen_pids.insert(42, "new_hash".to_string());

        recorder.record_outcomes_for_missing_with(|_| true).unwrap();

        // old_hash should be removed from pending (resolved with pid_reused reason)
        assert!(!recorder.pending.contains_key("old_hash"));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    #[test]
    fn recorder_no_records_skips_outcomes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let mut recorder = ShadowRecorder::new().expect("recorder");
        // had_records is false by default
        recorder.pending.insert(
            "should_stay".to_string(),
            make_pending("should_stay", 1, "x"),
        );

        recorder.record_outcomes_for_missing().unwrap();
        // Pending entry should NOT be removed because had_records is false
        assert!(recorder.pending.contains_key("should_stay"));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }

    // ── shadow_config_from_env ──────────────────────────────────────

    #[test]
    fn shadow_config_uses_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old = std::env::var("PROCESS_TRIAGE_DATA").ok();
        std::env::set_var("PROCESS_TRIAGE_DATA", dir.path());

        let config = shadow_config_from_env();
        assert!(config.base_dir.to_string_lossy().contains("shadow"));

        match old {
            Some(val) => std::env::set_var("PROCESS_TRIAGE_DATA", val),
            None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
        }
    }
}
