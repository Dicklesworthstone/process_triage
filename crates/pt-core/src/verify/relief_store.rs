//! Append-only storage and replay of host measurements for actual apply runs.
//!
//! Persistence or sensor failures describe missing resource evidence. They never
//! turn a completed action into a failed action, and saved runs never substitute
//! for a fresh observation of an action's current postcondition.

use super::relief::{
    capture_resource_observation, collect_resource_window, replay_resource_artifact,
    summarize_window, ResourceActionBinding, ResourceDelta, ResourceObservation,
    ResourceObservationArtifact, ResourceObservationWindow, MAX_RESOURCE_WINDOW_MS,
    RESOURCE_OBSERVATION_SCHEMA_VERSION,
};
use super::SavedActionOutcome;
use crate::collect::pressure::Unavailable;
use crate::plan::Plan;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const BASELINE_WINDOW_MS: u64 = 500;
pub const MAX_RESOURCE_ARTIFACTS: usize = 64;
pub const MAX_RESOURCE_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_RESOURCE_REPLAY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ACTION_DIRECTORY_ENTRIES: usize = 4096;
const SAMPLE_FILE: &str = "resource_samples.jsonl";
const ARTIFACT_PREFIX: &str = "resource_delta-";
const ARTIFACT_SUFFIX: &str = ".json";

#[derive(Debug)]
pub struct ResourceRun {
    pub run_id: String,
    pub before: Option<ResourceObservationWindow>,
    pub unavailable: Vec<Unavailable>,
    action_dir: PathBuf,
    session_id: String,
    plan_id: String,
    plan_sha256: String,
    settle_ms: u64,
    enabled: bool,
}

impl ResourceRun {
    /// Shorten observation to the remaining apply timeout without changing any
    /// action result. Exhausted budgets retain a point observation, not a rate.
    pub fn cap_settle_ms(&mut self, remaining_ms: u64) {
        if remaining_ms < self.settle_ms {
            let requested_ms = self.settle_ms;
            self.settle_ms = remaining_ms;
            missing(
                &mut self.unavailable,
                "settle_timeout_budget",
                format!(
                    "the remaining apply timeout capped the settle window from {requested_ms} ms to {remaining_ms} ms; the full requested settling opportunity was not observed"
                ),
            );
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ResourceRunResult {
    pub run_id: String,
    /// Raw windows are retained for the caller's goal measurements.
    pub before: Option<ResourceObservationWindow>,
    pub after: Option<ResourceObservationWindow>,
    pub artifact_path: Option<PathBuf>,
    pub resource_delta: Option<ResourceDelta>,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Serialize)]
pub struct RejectedResourceArtifact {
    pub artifact_file: String,
    pub reason: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ResourceReplayReport {
    /// Every valid bounded historical run, with its explicit action-ID binding.
    pub reports: Vec<ResourceDelta>,
    pub rejected: Vec<RejectedResourceArtifact>,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Serialize)]
struct RawSample<'a> {
    schema_version: u32,
    session_id: &'a str,
    plan_id: &'a str,
    plan_sha256: &'a str,
    run_id: &'a str,
    phase: &'a str,
    observation: &'a ResourceObservation,
}

fn missing(errors: &mut Vec<Unavailable>, source: &str, reason: impl Into<String>) {
    let item = Unavailable {
        source: source.to_string(),
        reason: reason.into(),
    };
    if !errors.contains(&item) {
        errors.push(item);
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_run_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == id)
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK also prevents a raced FIFO from blocking before the metadata
        // check; it has no effect on a regular file.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn ensure_action_directory(path: &Path, create: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err("the action evidence path is not a regular directory".into()),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| error.to_string())?;
            ensure_action_directory(path, false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn open_sample_log(run: &ResourceRun) -> Result<(File, bool), String> {
    ensure_action_directory(&run.action_dir, true)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    no_follow(&mut options);
    let mut file = options
        .open(run.action_dir.join(SAMPLE_FILE))
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("raw sample evidence is not a regular file".into());
    }
    let mut preserved_partial_line = false;
    if metadata.len() > 0 {
        file.seek(SeekFrom::End(-1))
            .map_err(|error| error.to_string())?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)
            .map_err(|error| error.to_string())?;
        if last[0] != b'\n' {
            // Preserve a torn previous record and separate the next valid
            // JSONL record without truncating or rewriting any prior bytes.
            file.write_all(b"\n").map_err(|error| error.to_string())?;
            preserved_partial_line = true;
        }
    }
    Ok((file, preserved_partial_line))
}

fn collect_for_run(
    run: &ResourceRun,
    phase: &str,
    duration: Duration,
    errors: &mut Vec<Unavailable>,
    collect: impl FnOnce(
        Duration,
        &mut dyn FnMut(&ResourceObservation),
    ) -> Result<ResourceObservationWindow, String>,
) -> Option<ResourceObservationWindow> {
    let mut writer = match open_sample_log(run) {
        Ok((file, preserved_partial_line)) => {
            if preserved_partial_line {
                missing(errors, "resource_samples", "an incomplete prior raw record was preserved and separated from this run's new records");
            }
            Some(file)
        }
        Err(reason) => {
            missing(errors, "resource_samples", reason);
            None
        }
    };
    let measured = {
        let mut on_sample = |observation: &ResourceObservation| {
            let Some(file) = writer.as_mut() else { return };
            let record = RawSample {
                schema_version: RESOURCE_OBSERVATION_SCHEMA_VERSION,
                session_id: &run.session_id,
                plan_id: &run.plan_id,
                plan_sha256: &run.plan_sha256,
                run_id: &run.run_id,
                phase,
                observation,
            };
            let result = serde_json::to_vec(&record)
                .map_err(|error| error.to_string())
                .and_then(|mut bytes| {
                    bytes.push(b'\n');
                    file.write_all(&bytes).map_err(|error| error.to_string())
                });
            if let Err(reason) = result {
                missing(errors, "resource_samples", reason);
                // Retain all bytes already written, including a partial record.
                // Avoid flooding the report with the same storage failure.
                writer = None;
            }
        };
        collect(duration, &mut on_sample)
    };
    if let Some(file) = writer {
        if let Err(error) = file.sync_data() {
            missing(errors, "resource_samples", error.to_string());
        }
    }
    match measured {
        Ok(window) => {
            for sample in &window.samples {
                for error in sample
                    .unavailable
                    .iter()
                    .chain(&sample.pressure.unavailable)
                {
                    missing(
                        errors,
                        &format!("{phase}.{}", error.source),
                        error.reason.clone(),
                    );
                }
            }
            Some(window)
        }
        Err(reason) => {
            missing(errors, phase, reason);
            None
        }
    }
}

/// Capture the baseline only after execution policy and the action lock have
/// been acquired. The full digest must hash the actual saved canonical plan bytes.
pub fn begin_resource_run(
    action_dir: &Path,
    plan: &Plan,
    plan_sha256: &str,
    settle_ms: u64,
) -> ResourceRun {
    begin_resource_run_with(
        action_dir,
        plan,
        plan_sha256,
        settle_ms,
        |duration, sample| collect_resource_window(duration, sample),
    )
}

fn begin_resource_run_with(
    action_dir: &Path,
    plan: &Plan,
    plan_sha256: &str,
    settle_ms: u64,
    collect: impl FnOnce(
        Duration,
        &mut dyn FnMut(&ResourceObservation),
    ) -> Result<ResourceObservationWindow, String>,
) -> ResourceRun {
    let mut run = ResourceRun {
        run_id: uuid::Uuid::new_v4().to_string(),
        before: None,
        unavailable: Vec::new(),
        action_dir: action_dir.to_path_buf(),
        session_id: plan.session_id.clone(),
        plan_id: plan.plan_id.clone(),
        plan_sha256: plan_sha256.to_string(),
        settle_ms,
        enabled: true,
    };
    if !valid_digest(plan_sha256) || settle_ms > MAX_RESOURCE_WINDOW_MS {
        missing(
            &mut run.unavailable,
            "resource_run",
            "a complete plan SHA-256 and a bounded settle duration are required",
        );
        run.enabled = false;
        return run;
    }
    let duration = if settle_ms == 0 || !cfg!(target_os = "linux") {
        Duration::ZERO
    } else {
        Duration::from_millis(BASELINE_WINDOW_MS.min(settle_ms))
    };
    let mut errors = Vec::new();
    run.before = collect_for_run(&run, "before", duration, &mut errors, collect);
    run.unavailable.extend(errors);
    run
}

fn has_boot_clock(window: &ResourceObservationWindow) -> bool {
    let Some(first) = window.samples.first() else {
        return false;
    };
    let Some(boot) = first.boot_id.as_deref() else {
        return false;
    };
    canonical_run_id(boot)
        && window.samples.iter().all(|sample| {
            sample.boot_id.as_deref() == Some(boot)
                && sample.clock_ticks_per_second.is_some_and(|hz| hz > 0)
                && sample
                    .monotonic_start_ns
                    .zip(sample.monotonic_end_ns)
                    .is_some_and(|(start, end)| end >= start)
        })
}

fn persist_artifact(
    action_dir: &Path,
    artifact: &ResourceObservationArtifact,
) -> Result<PathBuf, String> {
    if !canonical_run_id(&artifact.run_id) {
        return Err("invalid apply-run UUID".into());
    }
    ensure_action_directory(action_dir, true)?;
    let path = action_dir.join(format!(
        "{ARTIFACT_PREFIX}{}{ARTIFACT_SUFFIX}",
        artifact.run_id
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    no_follow(&mut options);
    let mut file = options.open(&path).map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut file, artifact).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(path)
}

/// Call only after actual action outcomes have already been persisted. An
/// unavailable measurement never changes those execution outcomes. No genuine
/// bound execution means no settle wait and no completed resource-run artifact.
pub fn finish_resource_run(
    run: ResourceRun,
    plan: &Plan,
    saved_outcomes: &[SavedActionOutcome],
) -> ResourceRunResult {
    finish_resource_run_with(
        run,
        plan,
        saved_outcomes,
        |duration, sample| collect_resource_window(duration, sample),
        capture_resource_observation,
    )
}

fn finish_resource_run_with(
    run: ResourceRun,
    plan: &Plan,
    saved_outcomes: &[SavedActionOutcome],
    collect: impl FnOnce(
        Duration,
        &mut dyn FnMut(&ResourceObservation),
    ) -> Result<ResourceObservationWindow, String>,
    observe_current: impl FnOnce() -> ResourceObservation,
) -> ResourceRunResult {
    let mut result = ResourceRunResult {
        run_id: run.run_id.clone(),
        before: run.before.clone(),
        after: None,
        artifact_path: None,
        resource_delta: None,
        unavailable: run.unavailable.clone(),
    };
    if !run.enabled || run.session_id != plan.session_id || run.plan_id != plan.plan_id {
        missing(
            &mut result.unavailable,
            "resource_run",
            "the baseline does not bind this apply plan",
        );
        return result;
    }
    let recorded = match super::recorded_plan_actions(plan, saved_outcomes) {
        Ok(recorded) => recorded,
        Err(error) => {
            missing(
                &mut result.unavailable,
                "execution_binding",
                error.to_string(),
            );
            return result;
        }
    };
    let mut actions = Vec::new();
    for (_, outcome) in recorded {
        match ResourceActionBinding::from_saved(outcome) {
            Ok(binding) => actions.push(binding),
            Err(reason) => missing(&mut result.unavailable, "execution_binding", reason),
        }
    }
    if actions.is_empty() {
        missing(&mut result.unavailable, "execution_binding", "no actual executed attempt has complete identity and clock evidence; no settle window was collected");
        return result;
    }
    let Some(before) = run.before.as_ref() else {
        missing(
            &mut result.unavailable,
            "before",
            "the pre-execution resource window is unavailable",
        );
        return result;
    };
    if !has_boot_clock(before) || !summarize_window(before).complete {
        missing(&mut result.unavailable, "resource_run", "boot-bound host measurements are unavailable on this platform or the baseline clock is missing; no settle wait was performed");
        return result;
    }
    let duration = if cfg!(target_os = "linux") {
        Duration::from_millis(run.settle_ms)
    } else {
        Duration::ZERO
    };
    let Some(after) = collect_for_run(&run, "after", duration, &mut result.unavailable, collect)
    else {
        return result;
    };
    result.after = Some(after.clone());
    let artifact = ResourceObservationArtifact {
        schema_version: RESOURCE_OBSERVATION_SCHEMA_VERSION,
        session_id: run.session_id.clone(),
        plan_id: run.plan_id.clone(),
        plan_sha256: run.plan_sha256.clone(),
        run_id: run.run_id.clone(),
        actions,
        before: before.clone(),
        after,
    };
    match persist_artifact(&run.action_dir, &artifact) {
        Ok(path) => result.artifact_path = Some(path),
        Err(reason) => missing(&mut result.unavailable, "resource_artifact", reason),
    }
    match replay_resource_artifact(
        &artifact,
        plan,
        &run.plan_sha256,
        saved_outcomes,
        &observe_current(),
    ) {
        Ok(delta) => result.resource_delta = Some(delta),
        Err(reason) => missing(&mut result.unavailable, "resource_replay", reason),
    }
    result
}

fn artifact_run_id(name: &str) -> Option<&str> {
    let id = name
        .strip_prefix(ARTIFACT_PREFIX)?
        .strip_suffix(ARTIFACT_SUFFIX)?;
    canonical_run_id(id).then_some(id)
}

fn reject(report: &mut ResourceReplayReport, file: &str, reason: impl Into<String>) {
    report.rejected.push(RejectedResourceArtifact {
        artifact_file: file.to_string(),
        reason: reason.into(),
    });
}

/// Load every valid bounded historical run. Files are never selected by mtime,
/// lexical UUID ordering, or a guessed "latest" artifact. The caller supplies a
/// fresh host observation solely for replay identity/time validation; each delta
/// continues to describe its saved apply-time windows and named action IDs.
pub fn load_resource_runs(
    action_dir: &Path,
    plan: &Plan,
    current_plan_sha256: &str,
    saved_outcomes: &[SavedActionOutcome],
    current_observation: &ResourceObservation,
) -> ResourceReplayReport {
    let mut report = ResourceReplayReport::default();
    if !valid_digest(current_plan_sha256) {
        missing(
            &mut report.unavailable,
            "resource_artifacts",
            "the full current canonical plan SHA-256 is unavailable",
        );
        return report;
    }
    if let Err(reason) = ensure_action_directory(action_dir, false) {
        missing(&mut report.unavailable, "resource_artifacts", reason);
        return report;
    }
    let entries = match fs::read_dir(action_dir) {
        Ok(entries) => entries,
        Err(error) => {
            missing(
                &mut report.unavailable,
                "resource_artifacts",
                error.to_string(),
            );
            return report;
        }
    };
    let mut candidates = Vec::new();
    let mut candidate_count = 0;
    let mut declared_bytes = 0u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_ACTION_DIRECTORY_ENTRIES {
            missing(&mut report.unavailable, "resource_artifacts", "the action directory exceeds the bounded inspection count; no partial history was selected");
            return report;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                missing(
                    &mut report.unavailable,
                    "resource_artifacts",
                    error.to_string(),
                );
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(ARTIFACT_PREFIX) {
            continue;
        }
        candidate_count += 1;
        if candidate_count > MAX_RESOURCE_ARTIFACTS {
            missing(&mut report.unavailable, "resource_artifacts", "too many resource artifacts for a complete bounded replay; no partial history was selected");
            return report;
        }
        if artifact_run_id(&name).is_none() {
            reject(
                &mut report,
                &name,
                "artifact filename is not a canonical apply-run UUID",
            );
            continue;
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                reject(
                    &mut report,
                    &name,
                    "artifact is not a regular file; symlinks are not followed",
                );
                continue;
            }
            Err(error) => {
                reject(&mut report, &name, error.to_string());
                continue;
            }
        };
        if metadata.len() > MAX_RESOURCE_ARTIFACT_BYTES {
            reject(
                &mut report,
                &name,
                "artifact exceeds the per-file byte limit",
            );
            continue;
        }
        declared_bytes = declared_bytes.saturating_add(metadata.len());
        if declared_bytes > MAX_RESOURCE_REPLAY_BYTES {
            missing(&mut report.unavailable, "resource_artifacts", "resource history exceeds the total replay byte limit; no partial history was selected");
            return report;
        }
        candidates.push((name, entry.path()));
    }
    // Deterministic output is useful, but every accepted run is retained.
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let mut bytes_read = 0u64;
    for (name, path) in candidates {
        let mut options = OpenOptions::new();
        options.read(true);
        no_follow(&mut options);
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) => {
                reject(&mut report, &name, error.to_string());
                continue;
            }
        };
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            reject(&mut report, &name, "artifact ceased to be a regular file");
            continue;
        }
        let limit =
            MAX_RESOURCE_ARTIFACT_BYTES.min(MAX_RESOURCE_REPLAY_BYTES.saturating_sub(bytes_read));
        let mut bytes = Vec::new();
        let read = file.take(limit + 1).read_to_end(&mut bytes);
        bytes_read = bytes_read.saturating_add(bytes.len() as u64);
        if let Err(error) = read {
            reject(&mut report, &name, error.to_string());
            continue;
        }
        if bytes.len() as u64 > limit {
            reject(
                &mut report,
                &name,
                "artifact grew beyond a bounded replay byte limit",
            );
            continue;
        }
        let artifact: ResourceObservationArtifact = match serde_json::from_slice(&bytes) {
            Ok(artifact) => artifact,
            Err(error) => {
                reject(
                    &mut report,
                    &name,
                    format!("invalid resource artifact: {error}"),
                );
                continue;
            }
        };
        if artifact_run_id(&name) != Some(artifact.run_id.as_str()) {
            reject(
                &mut report,
                &name,
                "artifact run ID does not match its filename",
            );
            continue;
        }
        match replay_resource_artifact(
            &artifact,
            plan,
            current_plan_sha256,
            saved_outcomes,
            current_observation,
        ) {
            Ok(delta) => report.reports.push(delta),
            Err(reason) => reject(&mut report, &name, reason),
        }
    }
    if report.reports.is_empty() && report.rejected.is_empty() && report.unavailable.is_empty() {
        missing(
            &mut report.unavailable,
            "resource_artifacts",
            "no saved resource observations are available for this session",
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::pressure::{MemInfo, PressureSnapshot};
    use pt_common::{ProcessIdentity, StartId};
    use sha2::Digest;

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const RUN_A: &str = "22222222-2222-4222-8222-222222222222";
    const RUN_B: &str = "33333333-3333-4333-8333-333333333333";
    const RUN_C: &str = "44444444-4444-4444-8444-444444444444";

    fn observation(ms: u64) -> ResourceObservation {
        ResourceObservation {
            boot_id: Some(BOOT.into()),
            clock_ticks_per_second: Some(100),
            monotonic_start_ns: Some(ms * 1_000_000),
            monotonic_end_ns: Some(ms * 1_000_000),
            cpu_times: None,
            unavailable: Vec::new(),
            pressure: PressureSnapshot {
                sampled_at_ms: ms,
                cpus: 2,
                cpu: None,
                memory: None,
                io: None,
                irq: None,
                load: None,
                vmstat: None,
                file_handles: None,
                unavailable: Vec::new(),
                meminfo: Some(MemInfo {
                    total: Some(100_000_000),
                    available: Some(ms * 1000),
                    ..MemInfo::default()
                }),
            },
        }
    }

    fn window(ms: u64, duration: Duration) -> ResourceObservationWindow {
        let duration_ms = duration.as_millis() as u64;
        let mut samples = vec![observation(ms)];
        if duration_ms > 0 {
            samples.push(observation(ms + duration_ms));
        }
        ResourceObservationWindow {
            requested_duration_ms: duration_ms,
            sample_interval_ms: 1000,
            samples,
        }
    }

    fn stream(window: &ResourceObservationWindow, callback: &mut dyn FnMut(&ResourceObservation)) {
        for sample in &window.samples {
            callback(sample);
        }
    }

    fn fixture() -> (Plan, SavedActionOutcome, String) {
        let target = ProcessIdentity::new(42, StartId::from_linux(BOOT, 10, 42), 1000);
        let plan: Plan = serde_json::from_value(serde_json::json!({
            "plan_id": "store-plan", "session_id": "store-session", "generated_at": "1970-01-01T00:00:00Z", "policy_version": "test", "pre_toggled": [],
            "gates_summary": {"total_candidates": 1, "blocked_candidates": 0, "pre_toggled_actions": 0},
            "actions": [{"action_id": "renice-42", "target": target, "action": "renice", "order": 0, "stage": 1, "timeouts": crate::plan::ActionTimeouts::default(), "pre_checks": [], "rationale": {}, "on_success": [], "on_failure": [], "blocked": false}]
        })).unwrap();
        let saved: SavedActionOutcome = serde_json::from_value(serde_json::json!({
            "action_id": "renice-42", "pid": 42, "action": "renice", "target": target, "status": "success",
            "executed_at": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(2500).unwrap(), "execution_clock": {"boot_id": BOOT, "ticks": 250},
        })).unwrap();
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&plan).unwrap())
        );
        (plan, saved, digest)
    }

    fn artifact(
        plan: &Plan,
        saved: &SavedActionOutcome,
        digest: &str,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> ResourceObservationArtifact {
        ResourceObservationArtifact {
            schema_version: RESOURCE_OBSERVATION_SCHEMA_VERSION,
            session_id: plan.session_id.clone(),
            plan_id: plan.plan_id.clone(),
            plan_sha256: digest.into(),
            run_id: run_id.into(),
            actions: vec![ResourceActionBinding::from_saved(saved).unwrap()],
            before: window(start, Duration::ZERO),
            after: window(end, Duration::ZERO),
        }
    }

    #[test]
    fn baseline_streams_run_identity_and_appends_without_replacing_previous_samples() {
        let temp = tempfile::tempdir().unwrap();
        let action_dir = temp.path().join("action");
        let (plan, _, digest) = fixture();
        let run =
            begin_resource_run_with(&action_dir, &plan, &digest, 15_000, |duration, callback| {
                assert_eq!(
                    duration,
                    if cfg!(target_os = "linux") {
                        Duration::from_millis(500)
                    } else {
                        Duration::ZERO
                    }
                );
                let measured = window(1000, duration);
                stream(&measured, callback);
                Ok(measured)
            });
        assert!(run.before.is_some());
        assert!(run.unavailable.is_empty());
        let first_bytes = fs::read(action_dir.join(SAMPLE_FILE)).unwrap();
        let first_records: Vec<serde_json::Value> = String::from_utf8(first_bytes.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(!first_records.is_empty());
        for record in first_records {
            assert_eq!(record["run_id"], run.run_id);
            assert_eq!(record["session_id"], plan.session_id);
            assert_eq!(record["plan_sha256"], digest);
            assert_eq!(record["phase"], "before");
        }
        let next = begin_resource_run_with(&action_dir, &plan, &digest, 0, |duration, callback| {
            assert_eq!(duration, Duration::ZERO);
            let measured = window(2000, duration);
            stream(&measured, callback);
            Ok(measured)
        });
        assert_ne!(run.run_id, next.run_id);
        let appended = fs::read(action_dir.join(SAMPLE_FILE)).unwrap();
        assert!(appended.starts_with(&first_bytes));
        assert!(appended.len() > first_bytes.len());
        let invalid =
            begin_resource_run_with(&action_dir, &plan, "not-a-full-digest", 0, |_, _| {
                panic!("invalid binding must not collect")
            });
        assert!(invalid.before.is_none());
        let invalid = begin_resource_run_with(
            &action_dir,
            &plan,
            &digest,
            MAX_RESOURCE_WINDOW_MS + 1,
            |_, _| panic!("unbounded duration must not collect"),
        );
        assert!(invalid.before.is_none());
    }

    #[test]
    fn finish_persists_one_exclusive_artifact_and_replays_the_actual_observations() {
        let temp = tempfile::tempdir().unwrap();
        let action_dir = temp.path().join("action");
        let (plan, saved, digest) = fixture();
        let run = begin_resource_run_with(&action_dir, &plan, &digest, 0, |duration, callback| {
            let measured = window(1000, duration);
            stream(&measured, callback);
            Ok(measured)
        });
        let report = finish_resource_run_with(
            run,
            &plan,
            std::slice::from_ref(&saved),
            |duration, callback| {
                assert_eq!(duration, Duration::ZERO);
                let measured = window(3000, duration);
                stream(&measured, callback);
                Ok(measured)
            },
            || observation(4000),
        );
        assert_eq!(
            report
                .resource_delta
                .as_ref()
                .unwrap()
                .available_memory_bytes
                .delta,
            Some(2_000_000.0)
        );
        let path = report.artifact_path.as_ref().unwrap();
        let persisted = fs::read(path).unwrap();
        let artifact: ResourceObservationArtifact = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(artifact.run_id, report.run_id);
        assert!(persist_artifact(&action_dir, &artifact).is_err());
        assert_eq!(
            fs::read(path).unwrap(),
            persisted,
            "existing runs must not be overwritten"
        );
        let replay = load_resource_runs(&action_dir, &plan, &digest, &[saved], &observation(5000));
        assert_eq!(replay.reports.len(), 1);
        assert!(replay.rejected.is_empty());
        assert_eq!(
            replay.reports[0].binding.as_ref().unwrap().run_id,
            report.run_id
        );
        let samples: Vec<serde_json::Value> = fs::read_to_string(action_dir.join(SAMPLE_FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0]["phase"], "before");
        assert_eq!(samples[1]["phase"], "after");
    }

    #[test]
    fn timeout_budget_shortens_baseline_and_settle_without_changing_execution_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (plan, saved, digest) = fixture();
        for remaining_ms in [0, 50] {
            let mut run =
                begin_resource_run_with(temp.path(), &plan, &digest, 120, |duration, callback| {
                    assert_eq!(
                        duration,
                        if cfg!(target_os = "linux") {
                            Duration::from_millis(120)
                        } else {
                            Duration::ZERO
                        }
                    );
                    let measured = window(1000, duration);
                    stream(&measured, callback);
                    Ok(measured)
                });
            run.cap_settle_ms(500);
            assert_eq!(
                run.settle_ms, 120,
                "a larger remaining budget cannot extend the requested wait"
            );
            assert!(!run
                .unavailable
                .iter()
                .any(|item| item.source == "settle_timeout_budget"));
            run.cap_settle_ms(remaining_ms);
            assert_eq!(run.settle_ms, remaining_ms);
            let expected_ms = if cfg!(target_os = "linux") {
                remaining_ms
            } else {
                0
            };
            let report = finish_resource_run_with(
                run,
                &plan,
                std::slice::from_ref(&saved),
                |duration, callback| {
                    assert_eq!(duration, Duration::from_millis(expected_ms));
                    let measured = window(3000, duration);
                    stream(&measured, callback);
                    Ok(measured)
                },
                || observation(4000),
            );
            assert_eq!(
                report.after.as_ref().unwrap().requested_duration_ms,
                expected_ms
            );
            assert!(report
                .unavailable
                .iter()
                .any(|item| item.source == "settle_timeout_budget"
                    && item
                        .reason
                        .contains(&format!("120 ms to {remaining_ms} ms"))));
            let artifact: ResourceObservationArtifact =
                serde_json::from_slice(&fs::read(report.artifact_path.unwrap()).unwrap()).unwrap();
            assert_eq!(artifact.actions[0].status, "success");
            assert_eq!(artifact.actions[0].executed_at, saved.executed_at.unwrap());
            let delta = report.resource_delta.unwrap();
            assert!(delta.available_memory_bytes.delta.is_some());
            if expected_ms == 0 {
                assert!(delta.after_window.cpu_usage.is_none());
                assert!(delta.after_window.pressure_rates.is_none());
            }
        }
    }

    #[test]
    fn unexecuted_or_unmeasurable_runs_never_spend_a_settle_wait() {
        let temp = tempfile::tempdir().unwrap();
        let (plan, saved, digest) = fixture();
        for status in [
            "none",
            "dry_run",
            "shadow",
            "precheck_blocked",
            "failed_without_execution",
        ] {
            let run = begin_resource_run_with(
                temp.path(),
                &plan,
                &digest,
                15_000,
                |duration, callback| {
                    let measured = window(1000, duration);
                    stream(&measured, callback);
                    Ok(measured)
                },
            );
            let mut outcomes = vec![saved.clone()];
            match status {
                "none" => outcomes.clear(),
                "failed_without_execution" => {
                    outcomes[0].status = "failed".into();
                    outcomes[0].executed_at = None;
                    outcomes[0].execution_clock = None;
                }
                status => outcomes[0].status = status.into(),
            }
            let report = finish_resource_run_with(
                run,
                &plan,
                &outcomes,
                |_, _| panic!("{status} must not settle"),
                || panic!("{status} must not replay"),
            );
            assert!(report.after.is_none());
            assert!(report.artifact_path.is_none());
            assert!(report.resource_delta.is_none());
            assert!(!report.unavailable.is_empty());
        }
        for missing in ["boot", "incomplete"] {
            let run =
                begin_resource_run_with(temp.path(), &plan, &digest, 15_000, |_, callback| {
                    let mut measured = window(1000, Duration::ZERO);
                    if missing == "boot" {
                        measured.samples[0].boot_id = None;
                    } else {
                        measured.requested_duration_ms = 500;
                    }
                    stream(&measured, callback);
                    Ok(measured)
                });
            let report = finish_resource_run_with(
                run,
                &plan,
                std::slice::from_ref(&saved),
                |_, _| panic!("{missing} must not settle"),
                || panic!("{missing} must not replay"),
            );
            assert!(report.after.is_none());
            assert!(!report.unavailable.is_empty());
        }
    }

    #[test]
    fn storage_failure_retains_live_observations_and_preserves_existing_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join(SAMPLE_FILE)).unwrap();
        let (plan, saved, digest) = fixture();
        let run = begin_resource_run_with(temp.path(), &plan, &digest, 0, |duration, callback| {
            let measured = window(1000, duration);
            stream(&measured, callback);
            Ok(measured)
        });
        assert!(run
            .unavailable
            .iter()
            .any(|item| item.source == "resource_samples"));
        let occupied = temp
            .path()
            .join(format!("{ARTIFACT_PREFIX}{}{ARTIFACT_SUFFIX}", run.run_id));
        fs::write(&occupied, b"previous evidence must survive").unwrap();
        let report = finish_resource_run_with(
            run,
            &plan,
            &[saved],
            |duration, callback| {
                let measured = window(3000, duration);
                stream(&measured, callback);
                Ok(measured)
            },
            || observation(4000),
        );
        assert!(report.artifact_path.is_none());
        assert!(
            report.resource_delta.is_some(),
            "valid live observations survive a persistence failure"
        );
        assert!(report
            .unavailable
            .iter()
            .any(|item| item.source == "resource_artifact"));
        assert_eq!(
            fs::read(occupied).unwrap(),
            b"previous evidence must survive"
        );
    }

    #[test]
    fn appending_after_a_torn_sample_preserves_it_and_keeps_new_records_parseable() {
        let temp = tempfile::tempdir().unwrap();
        let sample_path = temp.path().join(SAMPLE_FILE);
        let torn = b"{\"run_id\":\"unfinished";
        fs::write(&sample_path, torn).unwrap();
        let (plan, _, digest) = fixture();
        let run = begin_resource_run_with(temp.path(), &plan, &digest, 0, |duration, callback| {
            let measured = window(1000, duration);
            stream(&measured, callback);
            Ok(measured)
        });
        let bytes = fs::read(&sample_path).unwrap();
        assert!(bytes.starts_with(torn));
        assert_eq!(bytes[torn.len()], b'\n');
        let new: serde_json::Value = serde_json::from_slice(&bytes[torn.len() + 1..]).unwrap();
        assert_eq!(new["run_id"], run.run_id);
        assert!(run
            .unavailable
            .iter()
            .any(|item| item.reason.contains("incomplete prior raw record")));
    }

    #[test]
    fn loader_returns_all_bound_runs_and_explicit_rejections_without_latest_file_guessing() {
        let temp = tempfile::tempdir().unwrap();
        let (mut plan, first, _) = fixture();
        let mut second_action = plan.actions[0].clone();
        second_action.action_id = "renice-43".into();
        second_action.order = 1;
        second_action.target = ProcessIdentity::new(43, StartId::from_linux(BOOT, 10, 43), 1000);
        plan.actions.push(second_action.clone());
        plan.gates_summary.total_candidates = 2;
        let mut second = first.clone();
        second.action_id = second_action.action_id.clone();
        second.pid = 43;
        second.target = Some(second_action.target);
        second.executed_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(6500);
        second.execution_clock.as_mut().unwrap().ticks = 650;
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&plan).unwrap())
        );
        persist_artifact(
            temp.path(),
            &artifact(&plan, &first, &digest, RUN_A, 1000, 3000),
        )
        .unwrap();
        persist_artifact(
            temp.path(),
            &artifact(&plan, &second, &digest, RUN_B, 5000, 7000),
        )
        .unwrap();
        fs::write(
            temp.path()
                .join(format!("{ARTIFACT_PREFIX}{RUN_C}{ARTIFACT_SUFFIX}")),
            b"incomplete-json",
        )
        .unwrap();
        let saved = vec![first.clone(), second];
        let report = load_resource_runs(temp.path(), &plan, &digest, &saved, &observation(8000));
        assert_eq!(report.reports.len(), 2);
        assert_eq!(report.rejected.len(), 1);
        let mut ids: Vec<_> = report
            .reports
            .iter()
            .flat_map(|report| report.binding.as_ref().unwrap().action_ids.clone())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["renice-42", "renice-43"]);

        let mut latest = saved;
        let mut retry = first;
        retry.executed_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(7500);
        retry.execution_clock.as_mut().unwrap().ticks = 750;
        latest.push(retry);
        let stale = load_resource_runs(temp.path(), &plan, &digest, &latest, &observation(8000));
        assert_eq!(stale.reports.len(), 1);
        assert_eq!(
            stale.reports[0].binding.as_ref().unwrap().action_ids,
            vec!["renice-43"]
        );
        assert_eq!(stale.rejected.len(), 2);
    }

    #[test]
    fn loader_enforces_names_sizes_counts_and_filename_identity() {
        let temp = tempfile::tempdir().unwrap();
        let (plan, saved, digest) = fixture();
        let wrong_name = temp
            .path()
            .join(format!("{ARTIFACT_PREFIX}{RUN_B}{ARTIFACT_SUFFIX}"));
        fs::write(
            &wrong_name,
            serde_json::to_vec(&artifact(&plan, &saved, &digest, RUN_A, 1000, 3000)).unwrap(),
        )
        .unwrap();
        let oversized = File::create(
            temp.path()
                .join(format!("{ARTIFACT_PREFIX}{RUN_C}{ARTIFACT_SUFFIX}")),
        )
        .unwrap();
        oversized.set_len(MAX_RESOURCE_ARTIFACT_BYTES + 1).unwrap();
        fs::write(temp.path().join("resource_delta-not-a-uuid.json"), b"{}").unwrap();
        let report = load_resource_runs(
            temp.path(),
            &plan,
            &digest,
            std::slice::from_ref(&saved),
            &observation(4000),
        );
        assert!(report.reports.is_empty());
        assert_eq!(report.rejected.len(), 3);
        assert!(report
            .rejected
            .iter()
            .any(|item| item.reason.contains("does not match its filename")));
        assert!(report
            .rejected
            .iter()
            .any(|item| item.reason.contains("byte limit")));
        assert!(report
            .rejected
            .iter()
            .any(|item| item.reason.contains("canonical apply-run UUID")));
        let many = tempfile::tempdir().unwrap();
        for _ in 0..=MAX_RESOURCE_ARTIFACTS {
            let name = format!("{ARTIFACT_PREFIX}{}{ARTIFACT_SUFFIX}", uuid::Uuid::new_v4());
            fs::write(many.path().join(name), b"{}").unwrap();
        }
        let report = load_resource_runs(many.path(), &plan, &digest, &[saved], &observation(4000));
        assert!(report.reports.is_empty());
        assert!(report
            .unavailable
            .iter()
            .any(|item| item.reason.contains("too many resource artifacts")));
    }

    #[cfg(unix)]
    #[test]
    fn evidence_symlinks_are_not_followed_or_modified() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let action_dir = temp.path().join("action");
        fs::create_dir(&action_dir).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"do not follow or modify").unwrap();
        symlink(&outside, action_dir.join(SAMPLE_FILE)).unwrap();
        symlink(
            &outside,
            action_dir.join(format!("{ARTIFACT_PREFIX}{RUN_A}{ARTIFACT_SUFFIX}")),
        )
        .unwrap();
        let (plan, saved, digest) = fixture();
        let run = begin_resource_run_with(&action_dir, &plan, &digest, 0, |duration, callback| {
            let measured = window(1000, duration);
            stream(&measured, callback);
            Ok(measured)
        });
        assert!(run
            .unavailable
            .iter()
            .any(|item| item.source == "resource_samples"));
        let replay = load_resource_runs(&action_dir, &plan, &digest, &[saved], &observation(4000));
        assert!(replay.reports.is_empty());
        assert_eq!(replay.rejected.len(), 1);
        assert!(replay.rejected[0].reason.contains("symlinks"));
        assert_eq!(fs::read(outside).unwrap(), b"do not follow or modify");
    }
}
