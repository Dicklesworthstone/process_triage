//! Bounded, identity-bound resource history from saved agent plans.
//!
//! Old plans without explicit measurements are not converted from rounded RSS or
//! lifetime CPU fields. Only observations recorded for the same host and process
//! incarnation can contribute to a new resource prediction.

use super::predictions::ResourceSample;
use pt_common::{schema::SCHEMA_VERSION, SessionId, StartId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

const MAX_HISTORY_SESSIONS: usize = 64;
const MAX_PLAN_BYTES: u64 = 4 * 1024 * 1024;

/// The process incarnation to which resource history belongs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub uid: u32,
    pub start_id: String,
}

impl ProcessIdentity {
    /// History requires a canonical boot UUID and a nonzero process birth time.
    /// Synthetic and unknown boot identifiers cannot safely cross sessions.
    /// Current macOS collectors do not supply a boot UUID, so their history is
    /// conservatively unavailable until that stronger identity is collected.
    pub fn is_valid(&self) -> bool {
        if self.pid == 0 || StartId::parse(&self.start_id).is_none() {
            return false;
        }
        let mut parts = self.start_id.split(':');
        let Some(boot) = parts.next() else {
            return false;
        };
        let Some(start) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            return false;
        };
        let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            return false;
        };
        let Ok(boot_uuid) = uuid::Uuid::parse_str(boot) else {
            return false;
        };
        start > 0
            && pid == self.pid
            && !boot_uuid.is_nil()
            && boot_uuid.hyphenated().to_string() == boot
            && StartId::from_linux(boot, start, pid).0 == self.start_id
    }
}

/// Explicit resource measurements retained inside a saved candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedResourceObservation {
    /// `procfs_window` or `quick_scan`; only the former measures windowed CPU.
    pub source: String,
    pub sample: ResourceSample,
}

/// Accepted observations, chronologically ordered for each process incarnation.
#[derive(Debug, Default)]
pub struct ResourceHistory {
    samples: HashMap<ProcessIdentity, Vec<ResourceSample>>,
    /// Aggregate counts of skipped inputs, bounded by the number of reason types.
    pub warnings: Vec<String>,
}

impl ResourceHistory {
    pub fn samples_for(&self, identity: &ProcessIdentity) -> Vec<ResourceSample> {
        self.samples.get(identity).cloned().unwrap_or_default()
    }
}

#[derive(Deserialize)]
struct RecordedPlan {
    schema_version: Option<String>,
    session_id: String,
    host_id: String,
    #[serde(default)]
    candidates: Vec<serde_json::Value>,
}

type WarningCounts = BTreeMap<&'static str, usize>;

fn note(warnings: &mut WarningCounts, reason: &'static str) {
    let count = warnings.entry(reason).or_default();
    *count = count.saturating_add(1);
}

fn format_warnings(warnings: WarningCounts) -> Vec<String> {
    warnings
        .into_iter()
        .map(|(reason, count)| format!("resource_history_{reason}: {count}"))
        .collect()
}

fn session_timestamp(name: &str) -> Option<i64> {
    // SessionId::parse indexes fixed byte positions; exclude non-ASCII names
    // before using those positions, and validate the date as well as the shape.
    if !name.is_ascii() || SessionId::parse(name).is_none() {
        return None;
    }
    chrono::NaiveDateTime::parse_from_str(&name[3..18], "%Y%m%d-%H%M%S")
        .ok()
        .map(|time| time.and_utc().timestamp_millis())
}

fn read_plan(session_dir: &Path) -> Result<Option<RecordedPlan>, &'static str> {
    let decision_dir = session_dir.join("decision");
    match std::fs::symlink_metadata(&decision_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err("skipped_non_directory_decision_path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("skipped_unreadable_plan"),
    }
    let path = decision_dir.join("plan.json");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Neither a symlink nor a named pipe should turn a bounded history read
        // into an unrelated read or a blocking operation.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file: File = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("skipped_unreadable_plan"),
    };
    let metadata = file.metadata().map_err(|_| "skipped_unreadable_plan")?;
    if !metadata.is_file() {
        return Err("skipped_non_regular_plan");
    }
    if metadata.len() > MAX_PLAN_BYTES {
        return Err("skipped_oversized_plan");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "skipped_unreadable_plan")?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err("skipped_oversized_plan");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "skipped_malformed_plan")
}

fn candidate_identity(candidate: &serde_json::Value) -> Option<ProcessIdentity> {
    Some(ProcessIdentity {
        pid: u32::try_from(candidate.get("pid")?.as_u64()?).ok()?,
        uid: u32::try_from(candidate.get("uid")?.as_u64()?).ok()?,
        start_id: candidate.get("start_id")?.as_str()?.to_string(),
    })
}

fn valid_observation(observation: &RecordedResourceObservation, now_unix_ms: i64) -> bool {
    let sample = &observation.sample;
    matches!(observation.source.as_str(), "procfs_window" | "quick_scan")
        && (observation.source == "procfs_window" || sample.cpu_percent.is_none())
        && sample.observed_at_unix_ms > 0
        && sample.observed_at_unix_ms <= now_unix_ms
        && sample
            .cpu_percent
            .is_none_or(|cpu| cpu.is_finite() && cpu >= 0.0)
        && (sample.rss_bytes.is_some() || sample.cpu_percent.is_some())
}

/// Load measured resource history from at most the 64 newest canonical sessions.
///
/// Each plan read is limited to 4 MiB. Directory enumeration retains only the
/// newest 64 names in memory; it never loads every session manifest. Invalid,
/// future, foreign-host and weak-identity evidence is ignored. Duplicate PIDs
/// within one plan and colliding timestamps across plans contribute no samples.
pub fn load_resource_history(
    sessions_root: &Path,
    host_id: &str,
    wanted: &HashSet<ProcessIdentity>,
    now_unix_ms: i64,
) -> ResourceHistory {
    let mut warnings = WarningCounts::new();
    let mut history = ResourceHistory::default();
    if wanted.is_empty() {
        return history;
    }
    if host_id.is_empty() {
        note(&mut warnings, "invalid_host_id");
        history.warnings = format_warnings(warnings);
        return history;
    }
    let wanted: HashSet<_> = wanted
        .iter()
        .filter(|identity| {
            if identity.is_valid() {
                true
            } else {
                note(&mut warnings, "invalid_requested_identity");
                false
            }
        })
        .cloned()
        .collect();
    if wanted.is_empty() {
        history.warnings = format_warnings(warnings);
        return history;
    }
    let wanted_pids: HashSet<_> = wanted.iter().map(|identity| identity.pid).collect();
    let entries = match std::fs::read_dir(sessions_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            history.warnings = format_warnings(warnings);
            return history;
        }
        Err(_) => {
            note(&mut warnings, "unreadable_sessions_directory");
            history.warnings = format_warnings(warnings);
            return history;
        }
    };
    let mut recent = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                note(&mut warnings, "unreadable_session_entry");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(session_time) = session_timestamp(name) else {
            continue;
        };
        if session_time > now_unix_ms {
            note(&mut warnings, "skipped_future_session");
            continue;
        }
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {}
            Ok(_) => continue,
            Err(_) => {
                note(&mut warnings, "unreadable_session_entry");
                continue;
            }
        }
        recent.insert(name.to_string());
        if recent.len() > MAX_HISTORY_SESSIONS {
            recent.pop_first();
            note(&mut warnings, "sessions_outside_history_limit");
        }
    }

    let mut by_timestamp: HashMap<ProcessIdentity, BTreeMap<i64, Option<ResourceSample>>> =
        HashMap::new();
    for session_name in recent.into_iter().rev() {
        let plan = match read_plan(&sessions_root.join(&session_name)) {
            Ok(Some(plan)) => plan,
            Ok(None) => continue,
            Err(reason) => {
                note(&mut warnings, reason);
                continue;
            }
        };
        if plan.schema_version.as_deref() != Some(SCHEMA_VERSION) {
            note(&mut warnings, "skipped_incompatible_schema");
            continue;
        }
        if plan.host_id != host_id {
            note(&mut warnings, "skipped_foreign_host");
            continue;
        }
        if plan.session_id != session_name {
            note(&mut warnings, "skipped_session_id_mismatch");
            continue;
        }
        let mut seen_pids = HashSet::new();
        let mut duplicate_pids = HashSet::new();
        let mut plan_samples = HashMap::new();
        for candidate in plan.candidates {
            let Some(pid) = candidate
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
            else {
                note(&mut warnings, "skipped_malformed_candidate");
                continue;
            };
            if !wanted_pids.contains(&pid) {
                continue;
            }
            if !seen_pids.insert(pid) && duplicate_pids.insert(pid) {
                note(&mut warnings, "skipped_duplicate_pid_in_plan");
            }
            let Some(identity) = candidate_identity(&candidate) else {
                note(&mut warnings, "skipped_malformed_candidate");
                continue;
            };
            if !identity.is_valid() || !wanted.contains(&identity) {
                note(&mut warnings, "skipped_process_identity_mismatch");
                continue;
            }
            let Some(raw_observation) = candidate.get("resource_observation") else {
                // Older plans' rounded or lifetime fields are not measurements
                // compatible with these trend models.
                continue;
            };
            if raw_observation.is_null() {
                continue;
            }
            let observation: RecordedResourceObservation =
                match serde_json::from_value(raw_observation.clone()) {
                    Ok(observation) => observation,
                    Err(_) => {
                        note(&mut warnings, "skipped_malformed_observation");
                        continue;
                    }
                };
            if !valid_observation(&observation, now_unix_ms) {
                note(&mut warnings, "skipped_invalid_observation");
                continue;
            }
            plan_samples.insert(identity, observation.sample);
        }
        for (identity, sample) in plan_samples {
            if duplicate_pids.contains(&identity.pid) {
                continue;
            }
            match by_timestamp
                .entry(identity)
                .or_default()
                .entry(sample.observed_at_unix_ms)
            {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Some(sample));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    // Keep the collision marker so a third copy cannot restore
                    // an observation that has already been rejected.
                    entry.insert(None);
                    note(&mut warnings, "skipped_colliding_observation_timestamp");
                }
            }
        }
    }
    history.samples = by_timestamp
        .into_iter()
        .map(|(identity, observations)| (identity, observations.into_values().flatten().collect()))
        .collect();
    history.warnings = format_warnings(warnings);
    history
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const BOOT: &str = "7e43f82b-70c4-478a-9b1a-7cc6f38a2a69";
    const NOW: i64 = 1_800_000_000_000;

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            uid: 1000,
            start_id: format!("{BOOT}:100:{pid}"),
        }
    }

    fn session_name(index: usize) -> String {
        format!(
            "pt-20260101-{:02}{:02}{:02}-aaaa",
            index / 3600,
            (index / 60) % 60,
            index % 60
        )
    }

    fn candidate(
        identity: &ProcessIdentity,
        observed_at_unix_ms: i64,
        source: &str,
        cpu_percent: Option<f64>,
    ) -> Value {
        json!({
            "pid": identity.pid,
            "uid": identity.uid,
            "start_id": identity.start_id,
            "resource_observation": {
                "source": source,
                "sample": {
                    "observed_at_unix_ms": observed_at_unix_ms,
                    "rss_bytes": 1024,
                    "cpu_percent": cpu_percent,
                },
            },
        })
    }

    fn write_plan(
        root: &Path,
        index: usize,
        host_id: &str,
        candidates: Vec<Value>,
    ) -> std::path::PathBuf {
        let session_id = session_name(index);
        let decision = root.join(&session_id).join("decision");
        std::fs::create_dir_all(&decision).unwrap();
        let path = decision.join("plan.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id,
                "host_id": host_id,
                "candidates": candidates,
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    #[test]
    fn history_requires_same_host_uid_and_process_birth() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        let other = identity(456);
        let wanted = HashSet::from([current.clone(), other.clone()]);
        write_plan(
            root.path(),
            0,
            "host-a",
            vec![candidate(&current, 1000, "procfs_window", Some(150.0))],
        );
        write_plan(
            root.path(),
            1,
            "host-b",
            vec![candidate(&current, 2000, "procfs_window", Some(50.0))],
        );
        let mut reused = current.clone();
        reused.start_id = format!("{BOOT}:200:123");
        write_plan(
            root.path(),
            2,
            "host-a",
            vec![candidate(&reused, 3000, "quick_scan", None)],
        );
        let mut different_uid = current.clone();
        different_uid.uid = 1001;
        write_plan(
            root.path(),
            3,
            "host-a",
            vec![candidate(&different_uid, 4000, "quick_scan", None)],
        );
        write_plan(
            root.path(),
            4,
            "host-a",
            vec![candidate(&other, 5000, "quick_scan", None)],
        );

        let history = load_resource_history(root.path(), "host-a", &wanted, NOW);
        let samples = history.samples_for(&current);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].observed_at_unix_ms, 1000);
        assert_eq!(samples[0].cpu_percent, Some(150.0));
        assert_eq!(history.samples_for(&other).len(), 1);
        assert!(history.samples_for(&reused).is_empty());
        assert!(history.samples_for(&different_uid).is_empty());
    }

    #[test]
    fn history_refuses_synthetic_noncanonical_and_mismatched_start_ids() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        for (index, start_id) in [
            "unknown:100:123".to_string(),
            "synthetic:100:123".to_string(),
            format!("{BOOT}:0:123"),
            format!("{BOOT}:0100:123"),
            format!("{BOOT}:100:124"),
            "00000000-0000-0000-0000-000000000000:100:123".to_string(),
        ]
        .into_iter()
        .enumerate()
        {
            let invalid = ProcessIdentity {
                start_id,
                ..current.clone()
            };
            assert!(!invalid.is_valid());
            write_plan(
                root.path(),
                index,
                "host-a",
                vec![candidate(&invalid, 1000, "quick_scan", None)],
            );
        }
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        assert!(history.samples_for(&current).is_empty());

        let invalid = ProcessIdentity {
            start_id: "unknown:100:123".into(),
            ..current
        };
        let history = load_resource_history(root.path(), "host-a", &HashSet::from([invalid]), NOW);
        assert_eq!(
            history.warnings,
            ["resource_history_invalid_requested_identity: 1"]
        );
    }

    #[test]
    fn history_uses_explicit_native_measurements_and_never_lifetime_cpu() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        for (index, source, cpu) in [
            (0, "quick_scan", None),
            (1, "quick_scan", Some(80.0)),
            (2, "procfs_window", None),
            (3, "procfs_window", Some(150.0)),
            (4, "lifetime", Some(80.0)),
        ] {
            write_plan(
                root.path(),
                index,
                "host-a",
                vec![candidate(&current, (index as i64 + 1) * 1000, source, cpu)],
            );
        }
        write_plan(
            root.path(),
            5,
            "host-a",
            vec![json!({
                "pid": current.pid, "uid": current.uid, "start_id": current.start_id,
                "cpu_percent": 99.0, "memory_mb": 200,
            })],
        );
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        let samples = history.samples_for(&current);
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.observed_at_unix_ms)
                .collect::<Vec<_>>(),
            [1000, 3000, 4000]
        );
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.cpu_percent)
                .collect::<Vec<_>>(),
            [None, None, Some(150.0)]
        );
        assert!(samples.iter().all(|sample| sample.rss_bytes == Some(1024)));
    }

    #[test]
    fn corrupt_oversized_future_and_mismatched_plans_do_not_poison_valid_history() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        write_plan(
            root.path(),
            0,
            "host-a",
            vec![candidate(&current, 1000, "quick_scan", None)],
        );
        let malformed = write_plan(root.path(), 1, "host-a", vec![]);
        std::fs::write(malformed, b"{").unwrap();
        let oversized = write_plan(root.path(), 2, "host-a", vec![]);
        OpenOptions::new()
            .write(true)
            .open(oversized)
            .unwrap()
            .set_len(MAX_PLAN_BYTES + 1)
            .unwrap();
        write_plan(
            root.path(),
            3,
            "host-a",
            vec![candidate(&current, NOW + 1, "quick_scan", None)],
        );
        let mismatch = write_plan(root.path(), 4, "host-a", vec![]);
        std::fs::write(
            mismatch,
            serde_json::to_vec(&json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_name(0), "host_id": "host-a",
                "candidates": [candidate(&current, 2000, "quick_scan", None)],
            }))
            .unwrap(),
        )
        .unwrap();
        write_plan(
            root.path(),
            5,
            "host-a",
            vec![candidate(&current, 3000, "procfs_window", Some(-1.0))],
        );
        write_plan(
            root.path(),
            6,
            "host-a",
            vec![json!({
                "pid": current.pid, "uid": current.uid, "start_id": current.start_id,
                "resource_observation": {"source": "procfs_window", "sample": "corrupt"},
            })],
        );
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        assert_eq!(history.samples_for(&current).len(), 1);
        assert!(history
            .warnings
            .iter()
            .any(|warning| warning == "resource_history_skipped_oversized_plan: 1"));
        assert!(history
            .warnings
            .iter()
            .any(|warning| warning == "resource_history_skipped_malformed_plan: 1"));
        assert!(history
            .warnings
            .iter()
            .any(|warning| warning == "resource_history_skipped_session_id_mismatch: 1"));
        assert!(history
            .warnings
            .iter()
            .any(|warning| warning == "resource_history_skipped_invalid_observation: 2"));
    }

    #[test]
    fn duplicate_candidates_and_repeated_timestamps_are_excluded_completely() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        write_plan(
            root.path(),
            0,
            "host-a",
            vec![
                candidate(&current, 1000, "quick_scan", None),
                candidate(&current, 2000, "quick_scan", None),
            ],
        );
        for index in 1..=3 {
            write_plan(
                root.path(),
                index,
                "host-a",
                vec![candidate(
                    &current,
                    3000,
                    "procfs_window",
                    Some(index as f64),
                )],
            );
        }
        write_plan(
            root.path(),
            4,
            "host-a",
            vec![candidate(&current, 4000, "quick_scan", None)],
        );
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        let samples = history.samples_for(&current);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].observed_at_unix_ms, 4000);
    }

    #[test]
    fn observations_require_the_current_plan_schema() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        write_plan(
            root.path(),
            0,
            "host-a",
            vec![candidate(&current, 1000, "quick_scan", None)],
        );
        for (index, schema) in [(1, None), (2, Some("999.0.0"))] {
            let path = write_plan(root.path(), index, "host-a", vec![]);
            let mut plan = json!({
                "session_id": session_name(index), "host_id": "host-a",
                "candidates": [candidate(&current, 2000, "quick_scan", None)],
            });
            if let Some(schema) = schema {
                plan["schema_version"] = json!(schema);
            }
            std::fs::write(path, serde_json::to_vec(&plan).unwrap()).unwrap();
        }
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        assert_eq!(history.samples_for(&current).len(), 1);
        assert_eq!(
            history.warnings,
            ["resource_history_skipped_incompatible_schema: 2"]
        );
    }

    #[test]
    fn only_the_newest_64_canonical_nonfuture_sessions_are_read() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        for index in 0..70 {
            let path = write_plan(
                root.path(),
                index,
                "host-a",
                vec![candidate(
                    &current,
                    (index as i64 + 1) * 1000,
                    "quick_scan",
                    None,
                )],
            );
            if index == 0 {
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(MAX_PLAN_BYTES + 1)
                    .unwrap();
            }
        }
        for name in [
            "pt-20990101-000000-aaaa",
            "pt-20260101-000000-0000",
            "pt-20261342-000000-aaaa",
            "pt-2026010é000000-abcd",
        ] {
            std::fs::create_dir_all(root.path().join(name)).unwrap();
        }
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        let samples = history.samples_for(&current);
        assert_eq!(samples.len(), 64);
        assert_eq!(samples.first().unwrap().observed_at_unix_ms, 7000);
        assert_eq!(samples.last().unwrap().observed_at_unix_ms, 70_000);
        assert!(history
            .warnings
            .iter()
            .any(|warning| warning == "resource_history_sessions_outside_history_limit: 6"));
        assert!(!history
            .warnings
            .iter()
            .any(|warning| warning.contains("oversized")));
    }

    #[test]
    fn diagnostics_aggregate_many_bad_records_and_missing_history_is_normal() {
        let root = tempfile::tempdir().unwrap();
        let current = identity(123);
        let wanted = HashSet::from([current]);
        let missing = load_resource_history(&root.path().join("missing"), "host-a", &wanted, NOW);
        assert!(missing.warnings.is_empty());
        write_plan(root.path(), 0, "host-a", vec![Value::Null; 1000]);
        let history = load_resource_history(root.path(), "host-a", &wanted, NOW);
        assert_eq!(
            history.warnings,
            ["resource_history_skipped_malformed_candidate: 1000"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn history_does_not_follow_plan_or_session_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let current = identity(123);
        let outside_plan = write_plan(
            outside.path(),
            0,
            "host-a",
            vec![candidate(&current, 1000, "quick_scan", None)],
        );
        let decision = root.path().join(session_name(0)).join("decision");
        std::fs::create_dir_all(&decision).unwrap();
        symlink(outside_plan, decision.join("plan.json")).unwrap();
        symlink(
            outside.path().join(session_name(0)),
            root.path().join(session_name(1)),
        )
        .unwrap();
        let history = load_resource_history(
            root.path(),
            "host-a",
            &HashSet::from([current.clone()]),
            NOW,
        );
        assert!(history.samples_for(&current).is_empty());
        assert_eq!(
            history.warnings,
            ["resource_history_skipped_unreadable_plan: 1"]
        );
    }
}
