//! Shadow mode observation recording helpers.
//!
//! Records prediction snapshots into pt-telemetry shadow storage for calibration.

use crate::collect::ProcessRecord;
use crate::decision::{Action, DecisionOutcome};
use crate::inference::{ClassScores, Confidence, EvidenceLedger};
use chrono::Utc;
use pt_telemetry::shadow::{
    BeliefState, Observation, ShadowStorage, ShadowStorageConfig, ShadowStorageError, StateSnapshot,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug)]
pub enum ShadowRecordError {
    Storage(ShadowStorageError),
}

impl From<ShadowStorageError> for ShadowRecordError {
    fn from(err: ShadowStorageError) -> Self {
        ShadowRecordError::Storage(err)
    }
}

/// Records shadow observations into local storage.
pub struct ShadowRecorder {
    storage: ShadowStorage,
    recorded: u64,
}

impl ShadowRecorder {
    pub fn new() -> Result<Self, ShadowRecordError> {
        let config = shadow_config_from_env();
        let storage = ShadowStorage::new(config)?;
        Ok(Self {
            storage,
            recorded: 0,
        })
    }

    pub fn record_candidate(
        &mut self,
        proc: &ProcessRecord,
        posterior: &ClassScores,
        ledger: &EvidenceLedger,
        decision: &DecisionOutcome,
    ) -> Result<(), ShadowRecordError> {
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

        let observation = Observation {
            timestamp: Utc::now(),
            pid: proc.pid.0,
            identity_hash,
            state,
            events: Vec::new(),
            belief,
        };

        self.storage.record(observation)?;
        self.recorded = self.recorded.saturating_add(1);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), ShadowRecordError> {
        self.storage.flush()?;
        Ok(())
    }

    pub fn recorded_count(&self) -> u64 {
        self.recorded
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
}
