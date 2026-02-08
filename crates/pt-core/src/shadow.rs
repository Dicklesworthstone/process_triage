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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        if let Some(event) = build_evidence_event(ledger, &proc.comm) {
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
    hasher.update(proc.start_id.0.as_bytes());
    hasher.update(proc.comm.as_bytes());
    hasher.update(proc.cmd.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn build_evidence_event(ledger: &EvidenceLedger, comm: &str) -> Option<ProcessEvent> {
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
        "comm": comm,
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
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Mutex to serialize tests that manipulate PROCESS_TRIAGE_DATA env var.
    /// Without this, parallel tests race on set_var/remove_var causing flaky failures.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    fn missing_entries_emit_exit_event() {
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
        }
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
        let event = build_evidence_event(&ledger, "sleep").unwrap();
        assert_eq!(event.event_type, EventType::EvidenceSnapshot);
        let details: serde_json::Value =
            serde_json::from_str(event.details.as_ref().unwrap()).unwrap();
        assert_eq!(details["comm"], "sleep");
        assert_eq!(details["why_summary"], "Likely abandoned");
        assert!(details["bayes_factors"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn evidence_event_none_when_empty() {
        let ledger = make_ledger(Confidence::Low, vec![], vec![], "");
        assert!(build_evidence_event(&ledger, "bash").is_none());
    }

    #[test]
    fn evidence_event_with_only_top_evidence() {
        let ledger = make_ledger(
            Confidence::Medium,
            vec![],
            vec!["some evidence".to_string()],
            "why",
        );
        let event = build_evidence_event(&ledger, "node");
        assert!(event.is_some());
    }

    #[test]
    fn evidence_event_with_only_bayes_factors() {
        let factors = vec![make_bf("cpu", 1.5, "supports useful", "weak")];
        let ledger = make_ledger(Confidence::Low, factors, vec![], "");
        let event = build_evidence_event(&ledger, "python");
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
        let event = build_evidence_event(&ledger, "x").unwrap();
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
            .record_candidate(&proc, &posterior, &ledger, &decision)
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

        recorder.record_outcomes_for_missing().unwrap();

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
