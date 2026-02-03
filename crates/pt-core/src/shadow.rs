//! Shadow mode observation recording helpers.
//!
//! Records prediction snapshots into pt-telemetry shadow storage for calibration.

use crate::collect::ProcessRecord;
use crate::decision::{Action, DecisionOutcome};
use crate::inference::{ClassScores, Confidence, EvidenceLedger};
use chrono::Utc;
use pt_telemetry::shadow::{
    BeliefState, EventType, Observation, ProcessEvent, ShadowStorage, ShadowStorageConfig,
    ShadowStorageError, StateSnapshot,
};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

const DEFAULT_MISS_THRESHOLD: u32 = 2;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingObservation {
    identity_hash: String,
    pid: u32,
    last_seen: chrono::DateTime<chrono::Utc>,
    miss_count: u32,
    belief: BeliefState,
    state: StateSnapshot,
    comm: String,
}

/// Records shadow observations into local storage.
pub struct ShadowRecorder {
    storage: ShadowStorage,
    recorded: u64,
    pending: HashMap<String, PendingObservation>,
    seen_identities: HashSet<String>,
    seen_pids: HashMap<u32, String>,
    pending_path: PathBuf,
    miss_threshold: u32,
    had_records: bool,
}

impl ShadowRecorder {
    pub fn new() -> Result<Self, ShadowRecordError> {
        let config = shadow_config_from_env();
        let storage = ShadowStorage::new(config)?;
        let pending_path = storage.config().base_dir.join("pending.json");
        let pending = match load_pending(&pending_path) {
            Ok(pending) => pending,
            Err(err) => {
                eprintln!("shadow mode: failed to load pending outcomes: {:?}", err);
                HashMap::new()
            }
        };
        Ok(Self {
            storage,
            recorded: 0,
            pending,
            seen_identities: HashSet::new(),
            seen_pids: HashMap::new(),
            pending_path,
            miss_threshold: DEFAULT_MISS_THRESHOLD,
            had_records: false,
        })
    }

    pub fn record_candidate(
        &mut self,
        proc: &ProcessRecord,
        posterior: &ClassScores,
        ledger: &EvidenceLedger,
        decision: &DecisionOutcome,
    ) -> Result<(), ShadowRecordError> {
        self.had_records = true;
        let identity_hash = compute_identity_hash(proc);
        let state_char = proc.state.to_string().chars().next().unwrap_or('?');
        let max_posterior = posterior
            .useful
            .max(posterior.useful_bad)
            .max(posterior.abandoned)
            .max(posterior.zombie);
        let score = (max_posterior * 100.0) as f32;

        let belief = BeliefState {
            p_abandoned: posterior.abandoned as f32,
            p_legitimate: posterior.useful as f32,
            p_zombie: posterior.zombie as f32,
            p_useful_but_bad: posterior.useful_bad as f32,
            confidence: confidence_score(ledger.confidence),
            score,
            recommendation: action_to_recommendation(decision.optimal_action).to_string(),
        };

        let state = StateSnapshot {
            cpu_percent: proc.cpu_percent as f32,
            memory_bytes: proc.vsz_bytes,
            rss_bytes: proc.rss_bytes,
            fd_count: 0,
            thread_count: 0,
            state_char,
            io_read_bytes: 0,
            io_write_bytes: 0,
            has_tty: proc.has_tty(),
            child_count: 0,
        };

        let mut events = Vec::new();
        if let Some(event) = build_evidence_event(ledger) {
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
        self.seen_pids
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
            },
        );
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

            entry.miss_count = entry.miss_count.saturating_add(1);
            if entry.miss_count >= self.miss_threshold {
                resolved.push(entry.clone());
            }
        }

        for entry in resolved {
            self.pending.remove(&entry.identity_hash);
            let reuse = self
                .seen_pids
                .get(&entry.pid)
                .map(|identity| identity != &entry.identity_hash)
                .unwrap_or(false);
            let reason = if reuse { "pid_reused" } else { "missing" };
            let details = serde_json::json!({
                "reason": reason,
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
                identity_hash: entry.identity_hash,
                state: entry.state,
                events: vec![event],
                belief: entry.belief,
            };
            self.storage.record(observation)?;
        }

        self.seen_identities.clear();
        self.seen_pids.clear();
        self.had_records = false;
        Ok(())
    }
}

fn action_to_recommendation(action: Action) -> &'static str {
    match action {
        Action::Keep => "keep",
        Action::Renice => "renice",
        Action::Pause => "pause",
        Action::Resume => "resume",
        Action::Freeze => "freeze",
        Action::Unfreeze => "unfreeze",
        Action::Throttle => "throttle",
        Action::Quarantine => "quarantine",
        Action::Unquarantine => "unquarantine",
        Action::Restart => "restart",
        Action::Kill => "kill",
    }
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
    let mut hasher = Sha256::new();
    hasher.update(proc.uid.to_le_bytes());
    hasher.update(proc.comm.as_bytes());
    hasher.update(proc.cmd.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn build_evidence_event(ledger: &EvidenceLedger) -> Option<ProcessEvent> {
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
    if top.is_empty() && ledger.top_evidence.is_empty() {
        return None;
    }
    let details = serde_json::json!({
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
    path: &PathBuf,
    pending: &HashMap<String, PendingObservation>,
) -> Result<(), ShadowRecordError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut records: Vec<&PendingObservation> = pending.values().collect();
    records.sort_by(|a, b| a.identity_hash.cmp(&b.identity_hash));
    let content = serde_json::to_string_pretty(&records)?;
    fs::write(path, content)?;
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
    fn missing_entries_emit_exit_event() {
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
            },
        );

        recorder
            .record_outcomes_for_missing()
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
}
