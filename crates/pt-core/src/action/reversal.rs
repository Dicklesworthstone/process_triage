//! Durable, conditional undo for recorded cgroup-v2 and Linux renice actions.
//!
//! A receipt is synchronized before a controller is changed. `Prepared` means
//! that execution may or may not have reached the kernel; it is never a success
//! claim. Undo uses the saved values only after revalidating the original live
//! process, isolated cgroup, boot, namespaces, mount, and directory identity.
//! Callers must hold the same execution-policy lock used for normal actions.

use super::executor::ActionError;
use super::renice::{ReniceReversalMetadata, ReniceThreadReversal};
use crate::decision::Action;
use crate::plan::{ActionRouting, PlanAction};
use pt_common::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt, unix::fs::OpenOptionsExt},
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(target_os = "linux")]
const JOURNAL_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const MAX_RECEIPT_BYTES: u64 = 128 * 1024;
#[cfg(target_os = "linux")]
const MAX_RECEIPTS: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_RESTORATIONS: usize = 64;
#[cfg(target_os = "linux")]
const MAX_RESTORE_VERIFY_MS: u64 = 10_000;

/// Execution status is independent of subsequent undo attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversalStatus {
    Prepared,
    Applied,
    Verified,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorationStatus {
    Prepared,
    Restored,
    Failed,
}

/// Typed controls prevent a receipt from authorizing an arbitrary file write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReversalValue {
    Freeze {
        requested: bool,
    },
    CpuMax {
        quota_us: i64,
        period_us: u64,
    },
    /// Canonical requested CPU list. Empty preserves inheritance from the
    /// parent; effective CPUs are observed afresh and are never written.
    Cpuset {
        cpus: String,
    },
}

#[cfg(target_os = "linux")]
impl ReversalValue {
    fn same_control(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Freeze { .. }, Self::Freeze { .. })
                | (Self::CpuMax { .. }, Self::CpuMax { .. })
                | (Self::Cpuset { .. }, Self::Cpuset { .. })
        )
    }

    fn validate(&self) -> Result<(), ActionError> {
        if let Self::CpuMax {
            quota_us,
            period_us,
        } = self
        {
            if (*quota_us != -1 && *quota_us < 1_000) || !(1_000..=1_000_000).contains(period_us) {
                return Err(failed("invalid saved CPU bandwidth limit"));
            }
        }
        if let Self::Cpuset { cpus } = self {
            if !cpus.is_empty() && super::cpuset_quarantine::CpuSet::parse(cpus)?.as_list() != *cpus
            {
                return Err(failed("saved cpuset is not a canonical CPU list"));
            }
        }
        Ok(())
    }

    fn filename(&self) -> &'static str {
        match self {
            Self::Freeze { .. } => "cgroup.freeze",
            Self::CpuMax { .. } => "cpu.max",
            Self::Cpuset { .. } => "cpuset.cpus",
        }
    }

    fn contents(&self) -> String {
        match self {
            Self::Freeze { requested } => u8::from(*requested).to_string(),
            Self::CpuMax {
                quota_us,
                period_us,
            } => format!(
                "{} {period_us}",
                if *quota_us == -1 {
                    "max".to_string()
                } else {
                    quota_us.to_string()
                }
            ),
            // A zero-byte write cannot clear a kernfs cpuset assignment.
            Self::Cpuset { cpus } => format!("{cpus}\n"),
        }
    }
}

/// A pathname alone is not an identity and is never sufficient for restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversalScope {
    pub cgroup_path: String,
    pub device: u64,
    pub inode: u64,
    pub mount_id: u64,
    pub boot_id: String,
    pub mount_namespace_device: u64,
    pub mount_namespace_inode: u64,
    pub cgroup_namespace_device: u64,
    pub cgroup_namespace_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReversalOperation {
    CgroupV2 {
        scope: ReversalScope,
        before: ReversalValue,
        applied: ReversalValue,
        verify_timeout_ms: u64,
    },
    Renice {
        metadata: ReniceReversalMetadata,
        pid_namespace_device: u64,
        pid_namespace_inode: u64,
    },
    Unsupported {
        reason: String,
    },
}

/// The original state that was observed after an intentional restoration.
/// Thread priorities retain every captured incarnation and value; a leader's
/// priority alone cannot establish that a multithreaded process was restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestorationValue {
    Freeze { requested: bool },
    CpuMax { quota_us: i64, period_us: u64 },
    Cpuset { cpus: String },
    ThreadPriorities { threads: Vec<ReniceThreadReversal> },
}

impl From<ReversalValue> for RestorationValue {
    fn from(value: ReversalValue) -> Self {
        match value {
            ReversalValue::Freeze { requested } => Self::Freeze { requested },
            ReversalValue::CpuMax {
                quota_us,
                period_us,
            } => Self::CpuMax {
                quota_us,
                period_us,
            },
            ReversalValue::Cpuset { cpus } => Self::Cpuset { cpus },
        }
    }
}

/// Every restore attempt is retained separately from the execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversalOutcome {
    pub attempt_id: String,
    pub restore_id: String,
    pub action_id: String,
    pub status: RestorationStatus,
    /// `None` on failure because a write may have preceded the failed check.
    pub changed: Option<bool>,
    pub detail: Option<String>,
    pub timestamp: String,
}

/// Read-only evidence that a successfully executed action was intentionally
/// undone and that its exact original controller state is still present.
/// The original execution and restoration records remain unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorationObservation {
    pub attempt_id: String,
    pub restore_id: String,
    pub action_id: String,
    pub original_value: RestorationValue,
    pub recorded_restored_at: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversalRecord {
    pub version: u32,
    pub attempt_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub plan_sha256: String,
    pub action_id: String,
    pub action: Action,
    pub target: ProcessIdentity,
    pub routing: ActionRouting,
    pub original_zombie_target: Option<ProcessIdentity>,
    pub operation: ReversalOperation,
    pub status: ReversalStatus,
    pub detail: Option<String>,
    pub prepared_at: String,
    pub updated_at: String,
    pub restorations: Vec<ReversalOutcome>,
}

#[cfg(target_os = "linux")]
impl ReversalRecord {
    fn is_restored(&self) -> bool {
        self.restorations
            .iter()
            .any(|outcome| outcome.status == RestorationStatus::Restored)
    }

    fn check_action(&self, action: &PlanAction) -> Result<(), ActionError> {
        if self.action_id != action.action_id
            || self.action != action.action
            || self.target != action.target
            || self.routing != action.routing
            || self.original_zombie_target != action.original_zombie_target
            || action.supervisor_restart.is_some()
        {
            return Err(failed(
                "undo receipt does not match the complete planned target/action",
            ));
        }
        if let ReversalOperation::CgroupV2 {
            verify_timeout_ms, ..
        } = self.operation
        {
            if verify_timeout_ms > action.timeouts.verify_ms {
                return Err(failed(
                    "undo deadline exceeds the saved action's verification budget",
                ));
            }
        }
        Ok(())
    }
}

/// The constructor is read-only. The private directory is created only when an
/// actual supported execution prepares its receipt (or records unsupported v1).
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ReversalJournal {
    directory: PathBuf,
    sessions_root: PathBuf,
    session_id: String,
    plan_sha256: String,
    #[cfg(target_os = "linux")]
    lock: Mutex<()>,
}

impl ReversalJournal {
    pub fn new(
        action_dir: impl Into<PathBuf>,
        session_id: impl Into<String>,
        plan_sha256: impl Into<String>,
        sessions_root: impl Into<PathBuf>,
    ) -> Result<Self, ActionError> {
        let session_id = session_id.into();
        let plan_sha256 = plan_sha256.into();
        let sessions_root = sessions_root.into();
        let action_dir = action_dir.into();
        if session_id.is_empty()
            || session_id.len() > 128
            || !session_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || plan_sha256.len() != 64
            || !plan_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(failed(
                "undo journal requires a session ID and canonical plan SHA-256",
            ));
        }
        if action_dir != sessions_root.join(&session_id).join("action") {
            return Err(failed(
                "undo action directory must belong to its explicit session root and ID",
            ));
        }
        Ok(Self {
            directory: action_dir.join("reversals"),
            sessions_root,
            session_id,
            plan_sha256: plan_sha256.to_ascii_lowercase(),
            #[cfg(target_os = "linux")]
            lock: Mutex::new(()),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Inspect saved facts only. This neither creates files nor promises that a
    /// target is currently eligible for restoration.
    #[cfg(target_os = "linux")]
    pub fn inspect(&self, action: &PlanAction) -> Result<Vec<ReversalRecord>, ActionError> {
        let _lock = self
            .lock
            .lock()
            .map_err(|_| failed("undo journal lock unavailable"))?;
        let Some(directory) = JournalDirectory::open(&self.directory, false)? else {
            return Ok(Vec::new());
        };
        let records = self.read_records(&directory)?;
        let mut selected = Vec::new();
        for record in records {
            if record.action_id == action.action_id {
                record.check_action(action)?;
                selected.push(record);
            }
        }
        Ok(selected)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn inspect(&self, _action: &PlanAction) -> Result<Vec<ReversalRecord>, ActionError> {
        Err(failed("durable undo receipts are supported only on Linux"))
    }

    /// Observe intentional restoration without changing a controller or receipt.
    /// Callers hold the same execution-policy lock as apply and undo. Only the
    /// latest execution receipt can change the expected postcondition; a newer
    /// incomplete attempt or restoration never inherits an older success.
    #[cfg(target_os = "linux")]
    pub fn observe_restoration(
        &self,
        action: &PlanAction,
    ) -> Result<Option<RestorationObservation>, ActionError> {
        if !matches!(
            action.action,
            Action::Freeze
                | Action::Unfreeze
                | Action::Throttle
                | Action::Quarantine
                | Action::Renice
        ) {
            return Ok(None);
        }
        let _lock = self
            .lock
            .lock()
            .map_err(|_| failed("undo journal lock unavailable"))?;
        let Some(directory) = JournalDirectory::open(&self.directory, false)? else {
            return Ok(None);
        };
        let records = self.read_records(&directory)?;
        let Some((record, restored)) = latest_recorded_restoration(&records, action)? else {
            return Ok(None);
        };
        let observed_at = chrono::Utc::now();
        validate_restoration_times(record, restored, observed_at)?;
        refuse_newer_control(&records, record)?;
        refuse_other_session_owner(
            &self.sessions_root,
            &record.operation,
            Some(&self.session_id),
        )?;
        observe_restored_control(record)?;
        directory.revalidate()?;
        let observed_at = chrono::Utc::now();
        validate_restoration_times(record, restored, observed_at)?;
        let original_value = match &record.operation {
            ReversalOperation::CgroupV2 { before, .. } => before.clone().into(),
            ReversalOperation::Renice { metadata, .. } => RestorationValue::ThreadPriorities {
                threads: metadata.threads.clone(),
            },
            ReversalOperation::Unsupported { .. } => {
                return Err(failed("unsupported recorded restoration"))
            }
        };
        Ok(Some(RestorationObservation {
            attempt_id: record.attempt_id.clone(),
            restore_id: restored.restore_id.clone(),
            action_id: record.action_id.clone(),
            original_value,
            recorded_restored_at: restored.timestamp.clone(),
            observed_at: observed_at.to_rfc3339(),
        }))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn observe_restoration(
        &self,
        _action: &PlanAction,
    ) -> Result<Option<RestorationObservation>, ActionError> {
        Err(failed("restoration observation is supported only on Linux"))
    }

    /// Restore one saved attempt. The caller must hold the normal action and
    /// execution-policy locks. A selected attempt's live refusal is persisted
    /// and returned as `Ok(Failed)`; callers must inspect the outcome status.
    #[cfg(target_os = "linux")]
    pub fn restore(
        &self,
        action: &PlanAction,
        attempt_id: Option<&str>,
    ) -> Result<ReversalOutcome, ActionError> {
        let _lock = self
            .lock
            .lock()
            .map_err(|_| failed("undo journal lock unavailable"))?;
        let directory = JournalDirectory::open(&self.directory, false)?
            .ok_or_else(|| failed("no durable undo receipt exists for this action"))?;
        let records = self.read_records(&directory)?;
        let mut record = select_receipt(&records, action, attempt_id)?.clone();
        if matches!(record.operation, ReversalOperation::Unsupported { .. }) {
            return Err(failed(
                "this execution has no supported durable undo operation",
            ));
        }
        if record.restorations.len() >= MAX_RESTORATIONS {
            return Err(failed(
                "undo attempt limit reached; existing receipts are retained",
            ));
        }
        let mut outcome = ReversalOutcome {
            attempt_id: record.attempt_id.clone(),
            restore_id: uuid::Uuid::new_v4().to_string(),
            action_id: record.action_id.clone(),
            status: RestorationStatus::Prepared,
            changed: None,
            detail: None,
            timestamp: now(),
        };
        record.restorations.push(outcome.clone());
        record.updated_at = now();
        self.write_record(&directory, &record, false)?;

        let restored = refuse_newer_control(&records, &record)
            .and_then(|()| {
                refuse_other_session_owner(
                    &self.sessions_root,
                    &record.operation,
                    Some(&self.session_id),
                )
            })
            .and_then(|()| restore_live(&record));
        match restored {
            Ok(changed) => {
                outcome.status = RestorationStatus::Restored;
                outcome.changed = Some(changed);
            }
            Err(error) => {
                outcome.status = RestorationStatus::Failed;
                outcome.detail = Some(error.to_string());
            }
        }
        outcome.timestamp = now();
        *record
            .restorations
            .last_mut()
            .expect("inserted restoration") = outcome.clone();
        record.updated_at = now();
        self.write_record(&directory, &record, false)
            .map_err(|error| {
                failed(format!(
                    "{error}; undo may have changed the target; retained receipt {}",
                    record.attempt_id
                ))
            })?;
        Ok(outcome)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn restore(
        &self,
        _action: &PlanAction,
        _attempt_id: Option<&str>,
    ) -> Result<ReversalOutcome, ActionError> {
        Err(failed("durable undo is supported only on Linux"))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(
        self: &Arc<Self>,
        action: &PlanAction,
        cgroup_path: &str,
        handle: &File,
        before: ReversalValue,
        applied: ReversalValue,
        verify_timeout_ms: u64,
    ) -> Result<PreparedReversal, ActionError> {
        let scope = ReversalScope::capture(cgroup_path, handle)?;
        validate_target(&action.target, &scope.boot_id)?;
        let operation = ReversalOperation::CgroupV2 {
            scope,
            before,
            applied,
            verify_timeout_ms: verify_timeout_ms.min(MAX_RESTORE_VERIFY_MS),
        };
        let record = self.insert(action, operation, ReversalStatus::Prepared)?;
        Ok(PreparedReversal {
            journal: Arc::clone(self),
            attempt_id: record.attempt_id,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_renice(
        self: &Arc<Self>,
        action: &PlanAction,
        metadata: ReniceReversalMetadata,
    ) -> Result<PreparedReversal, ActionError> {
        ensure_renice_target(&action.target)?;
        let namespace = fs::metadata("/proc/self/ns/pid")
            .map_err(|error| failed(format!("cannot bind renice PID namespace: {error}")))?;
        let record = self.insert(
            action,
            ReversalOperation::Renice {
                metadata,
                pid_namespace_device: namespace.dev(),
                pid_namespace_inode: namespace.ino(),
            },
            ReversalStatus::Prepared,
        )?;
        Ok(PreparedReversal {
            journal: Arc::clone(self),
            attempt_id: record.attempt_id,
        })
    }

    /// V1 actuation keeps its existing behavior but must never appear undoable.
    #[cfg(target_os = "linux")]
    pub(crate) fn record_unsupported(
        &self,
        action: &PlanAction,
        reason: &str,
    ) -> Result<(), ActionError> {
        self.insert(
            action,
            ReversalOperation::Unsupported {
                reason: reason.to_string(),
            },
            ReversalStatus::Unsupported,
        )?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn insert(
        &self,
        action: &PlanAction,
        operation: ReversalOperation,
        status: ReversalStatus,
    ) -> Result<ReversalRecord, ActionError> {
        if action.supervisor_restart.is_some() || action.routing == ActionRouting::Supervisor {
            return Err(failed("undo cannot record a supervisor-routed operation"));
        }
        let _lock = self
            .lock
            .lock()
            .map_err(|_| failed("undo journal lock unavailable"))?;
        let directory = JournalDirectory::open(&self.directory, true)?
            .ok_or_else(|| failed("cannot create private undo directory"))?;
        let records = self.read_records(&directory)?;
        if records.iter().any(|record| {
            record.action_id == action.action_id
                && record.status != ReversalStatus::Unsupported
                && !record.is_restored()
        }) {
            return Err(failed(format!(
                "action {} already has an unresolved undo receipt; inspect or undo that attempt before retrying",
                action.action_id
            )));
        }
        if records.len() >= MAX_RECEIPTS {
            return Err(failed("undo receipt limit reached"));
        }
        let sequence = records
            .last()
            .map_or(Some(1), |record| record.sequence.checked_add(1))
            .ok_or_else(|| failed("undo receipt sequence exhausted"))?;
        let timestamp = now();
        let record = ReversalRecord {
            version: JOURNAL_VERSION,
            attempt_id: uuid::Uuid::new_v4().to_string(),
            sequence,
            session_id: self.session_id.clone(),
            plan_sha256: self.plan_sha256.clone(),
            action_id: action.action_id.clone(),
            action: action.action,
            target: action.target.clone(),
            routing: action.routing.clone(),
            original_zombie_target: action.original_zombie_target.clone(),
            operation,
            status,
            detail: None,
            prepared_at: timestamp.clone(),
            updated_at: timestamp,
            restorations: Vec::new(),
        };
        validate_record(&record)?;
        refuse_other_session_owner(
            &self.sessions_root,
            &record.operation,
            Some(&self.session_id),
        )?;
        self.write_record(&directory, &record, true)?;
        Ok(record)
    }

    #[cfg(target_os = "linux")]
    fn read_records(
        &self,
        directory: &JournalDirectory,
    ) -> Result<Vec<ReversalRecord>, ActionError> {
        read_stored_records(directory, &self.session_id, Some(&self.plan_sha256))
    }

    #[cfg(target_os = "linux")]
    fn write_record(
        &self,
        directory: &JournalDirectory,
        record: &ReversalRecord,
        create: bool,
    ) -> Result<(), ActionError> {
        validate_record(record)?;
        let mut bytes = serde_json::to_vec(record)
            .map_err(|error| failed(format!("cannot encode undo receipt: {error}")))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(failed("undo receipt exceeds the bounded record size"));
        }
        let destination = format!("{}.json", record.attempt_id);
        let temporary = (!create).then(|| format!("{}.tmp", uuid::Uuid::new_v4()));
        write_receipt_bytes(directory, &destination, temporary.as_deref(), &bytes)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct PreparedReversal {
    journal: Arc<ReversalJournal>,
    attempt_id: String,
}

#[cfg(target_os = "linux")]
impl PreparedReversal {
    /// Any failure after preparation names the retained receipt. Persistence
    /// failures never erase the original write-before-act record.
    pub(crate) fn finish<T>(
        &self,
        result: Result<T, ActionError>,
        success: ReversalStatus,
    ) -> Result<T, ActionError> {
        let update = || -> Result<(), ActionError> {
            let _lock = self
                .journal
                .lock
                .lock()
                .map_err(|_| failed("undo journal lock unavailable"))?;
            let directory = JournalDirectory::open(&self.journal.directory, false)?
                .ok_or_else(|| failed("prepared undo directory disappeared"))?;
            let mut record = self
                .journal
                .read_records(&directory)?
                .into_iter()
                .find(|record| record.attempt_id == self.attempt_id)
                .ok_or_else(|| failed("prepared undo receipt disappeared"))?;
            if record.is_restored() {
                return Err(failed("cannot update an already restored execution"));
            }
            record.status = if result.is_ok() {
                success
            } else {
                ReversalStatus::Failed
            };
            record.detail = result.as_ref().err().map(ToString::to_string);
            record.updated_at = now();
            self.journal.write_record(&directory, &record, false)
        };
        if let Err(error) = update() {
            return Err(failed(format!(
                "{error}; execution may have changed the target; retained undo receipt {}",
                self.attempt_id
            )));
        }
        result.map_err(|error| {
            failed(format!(
                "{error}; retained undo receipt {}",
                self.attempt_id
            ))
        })
    }
}

fn failed(message: impl Into<String>) -> ActionError {
    ActionError::Failed(message.into())
}

#[cfg(target_os = "linux")]
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(target_os = "linux")]
fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

#[cfg(target_os = "linux")]
fn validate_cgroup_path(path: &str) -> Result<(), ActionError> {
    if !path.starts_with('/')
        || path == "/"
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(failed("undo requires an unambiguous non-root cgroup path"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_target(target: &ProcessIdentity, boot_id: &str) -> Result<(), ActionError> {
    let mut parts = target.start_id.0.split(':');
    if target.quality != pt_common::IdentityQuality::Full
        || target.pid.0 <= 1
        || !canonical_uuid(boot_id)
        || parts.next() != Some(boot_id)
        || !parts
            .next()
            .is_some_and(|value| value.parse::<u64>().is_ok_and(|ticks| ticks > 0))
        || !parts
            .next()
            .is_some_and(|value| value.parse::<u32>() == Ok(target.pid.0))
        || parts.next().is_some()
    {
        return Err(failed(
            "undo requires the original full Linux process identity and boot",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_record(record: &ReversalRecord) -> Result<(), ActionError> {
    if record.version != JOURNAL_VERSION
        || !canonical_uuid(&record.attempt_id)
        || record.sequence == 0
        || record.action_id.is_empty()
        || record.action_id.len() > 256
        || record.plan_sha256.len() != 64
        || !record
            .plan_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || record.restorations.len() > MAX_RESTORATIONS
        || record.routing == ActionRouting::Supervisor
    {
        return Err(failed("invalid or unsupported undo receipt"));
    }
    match &record.operation {
        ReversalOperation::CgroupV2 {
            scope,
            before,
            applied,
            verify_timeout_ms,
        } => {
            validate_cgroup_path(&scope.cgroup_path)?;
            validate_target(&record.target, &scope.boot_id)?;
            before.validate()?;
            applied.validate()?;
            if !before.same_control(applied)
                || *verify_timeout_ms > MAX_RESTORE_VERIFY_MS
                || scope.inode == 0
                || scope.mount_id == 0
                || scope.mount_namespace_inode == 0
                || scope.cgroup_namespace_inode == 0
                || record.status == ReversalStatus::Unsupported
                || !matches!(
                    (record.action, applied),
                    (Action::Freeze, ReversalValue::Freeze { requested: true })
                        | (Action::Unfreeze, ReversalValue::Freeze { requested: false })
                        | (Action::Throttle, ReversalValue::CpuMax { .. })
                        | (Action::Quarantine, ReversalValue::Cpuset { .. })
                )
            {
                return Err(failed(
                    "undo control does not match the recorded action/scope",
                ));
            }
            if let (
                ReversalValue::CpuMax {
                    quota_us: previous_quota,
                    period_us: previous_period,
                },
                ReversalValue::CpuMax {
                    quota_us: applied_quota,
                    period_us: applied_period,
                },
            ) = (before, applied)
            {
                if *applied_quota <= 0
                    || (*previous_quota > 0
                        && (*applied_quota as u128) * u128::from(*previous_period)
                            > (*previous_quota as u128) * u128::from(*applied_period))
                {
                    return Err(failed("saved throttle would increase CPU bandwidth"));
                }
            }
            if let (
                ReversalValue::Cpuset { cpus: previous },
                ReversalValue::Cpuset { cpus: requested },
            ) = (before, applied)
            {
                let requested = super::cpuset_quarantine::CpuSet::parse(requested)?;
                if !previous.is_empty()
                    && !requested.is_subset_of(&super::cpuset_quarantine::CpuSet::parse(previous)?)
                {
                    return Err(failed(
                        "saved quarantine would expand the requested CPU set",
                    ));
                }
            }
        }
        ReversalOperation::Renice {
            metadata,
            pid_namespace_inode,
            ..
        } => {
            let boot_id = record
                .target
                .start_id
                .0
                .split(':')
                .next()
                .unwrap_or_default();
            validate_target(&record.target, boot_id)?;
            super::renice::validate_reversal_metadata(metadata)?;
            if record.action != Action::Renice
                || record.routing != ActionRouting::Direct
                || record.original_zombie_target.is_some()
                || metadata.identity.as_ref() != Some(&record.target)
                || *pid_namespace_inode == 0
                || record.status == ReversalStatus::Unsupported
            {
                return Err(failed(
                    "renice receipt does not match its action, target, or namespace",
                ));
            }
        }
        ReversalOperation::Unsupported { reason } => {
            if record.status != ReversalStatus::Unsupported || reason.is_empty() {
                return Err(failed("malformed unsupported undo receipt"));
            }
        }
    }
    for outcome in &record.restorations {
        if outcome.attempt_id != record.attempt_id
            || outcome.action_id != record.action_id
            || !canonical_uuid(&outcome.restore_id)
            || (outcome.status == RestorationStatus::Restored) != outcome.changed.is_some()
        {
            return Err(failed(
                "restoration outcome does not match its execution receipt",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn select_receipt<'a>(
    records: &'a [ReversalRecord],
    action: &PlanAction,
    attempt_id: Option<&str>,
) -> Result<&'a ReversalRecord, ActionError> {
    let matching: Vec<_> = records
        .iter()
        .filter(|record| record.action_id == action.action_id)
        .collect();
    for record in &matching {
        record.check_action(action)?;
    }
    if let Some(id) = attempt_id {
        if !canonical_uuid(id) {
            return Err(failed("invalid undo attempt ID"));
        }
        return matching
            .into_iter()
            .find(|record| record.attempt_id == id)
            .ok_or_else(|| failed("requested undo attempt does not belong to this action"));
    }
    let unresolved: Vec<_> = matching
        .iter()
        .copied()
        .filter(|record| !record.is_restored() && record.status != ReversalStatus::Unsupported)
        .collect();
    match unresolved.as_slice() {
        [record] => Ok(record),
        [] if matching.len() == 1 => Ok(matching[0]),
        [] if matching.is_empty() => Err(failed("no durable undo receipt exists for this action")),
        _ => Err(failed(
            "multiple undo attempts exist; select an explicit --attempt-id",
        )),
    }
}

#[cfg(target_os = "linux")]
fn refuse_newer_control(
    records: &[ReversalRecord],
    selected: &ReversalRecord,
) -> Result<(), ActionError> {
    for later in records
        .iter()
        .filter(|record| record.sequence > selected.sequence && !record.is_restored())
    {
        if operations_share_control(&selected.operation, &later.operation) {
            return Err(failed(format!(
                "a later recorded action controls this target; undo receipt {} first",
                later.attempt_id
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn latest_recorded_restoration<'a>(
    records: &'a [ReversalRecord],
    action: &PlanAction,
) -> Result<Option<(&'a ReversalRecord, &'a ReversalOutcome)>, ActionError> {
    let mut latest: Option<&ReversalRecord> = None;
    for record in records
        .iter()
        .filter(|record| record.action_id == action.action_id)
    {
        record.check_action(action)?;
        if latest.is_none_or(|previous| previous.sequence < record.sequence) {
            latest = Some(record);
        }
    }
    let Some(record) = latest else {
        return Ok(None);
    };
    if matches!(
        record.status,
        ReversalStatus::Prepared | ReversalStatus::Failed
    ) {
        return Err(failed(
            "latest recorded execution is incomplete or failed; restoration cannot replace its verification",
        ));
    }
    let Some(restored) = record.restorations.last() else {
        return Ok(None);
    };
    if record.status != ReversalStatus::Verified
        || restored.status != RestorationStatus::Restored
        || !matches!(
            record.operation,
            ReversalOperation::CgroupV2 { .. } | ReversalOperation::Renice { .. }
        )
    {
        return Err(failed(
            "latest recorded execution/restoration is not a verified action followed by a completed undo",
        ));
    }
    Ok(Some((record, restored)))
}

#[cfg(target_os = "linux")]
fn validate_restoration_times(
    record: &ReversalRecord,
    restored: &ReversalOutcome,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), ActionError> {
    let parse = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
            .map_err(|_| failed("invalid recorded restoration timestamp"))
    };
    let prepared_at = parse(&record.prepared_at)?;
    let restored_at = parse(&restored.timestamp)?;
    let updated_at = parse(&record.updated_at)?;
    if prepared_at > restored_at || restored_at > updated_at || updated_at > observed_at {
        return Err(failed(
            "recorded restoration timestamps are out of order or in the future",
        ));
    }
    Ok(())
}

/// Ownership follows the physical cgroup across path, bind-mount and namespace
/// aliases. Full mount/namespace provenance remains mandatory during restoration.
#[cfg(target_os = "linux")]
fn operations_share_control(left: &ReversalOperation, right: &ReversalOperation) -> bool {
    match (left, right) {
        (
            ReversalOperation::CgroupV2 {
                scope: a,
                applied: control_a,
                ..
            },
            ReversalOperation::CgroupV2 {
                scope: b,
                applied: control_b,
                ..
            },
        ) => {
            a.boot_id == b.boot_id
                && a.device == b.device
                && a.inode == b.inode
                && control_a.same_control(control_b)
        }
        (
            ReversalOperation::Renice {
                metadata: a,
                pid_namespace_device: device_a,
                pid_namespace_inode: inode_a,
            },
            ReversalOperation::Renice {
                metadata: b,
                pid_namespace_device: device_b,
                pid_namespace_inode: inode_b,
            },
        ) => {
            device_a == device_b
                && inode_a == inode_b
                && a.identity
                    .as_ref()
                    .zip(b.identity.as_ref())
                    .is_some_and(|(a, b)| a.matches(b))
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn read_stored_records(
    directory: &JournalDirectory,
    session_id: &str,
    plan_sha256: Option<&str>,
) -> Result<Vec<ReversalRecord>, ActionError> {
    directory.revalidate()?;
    let mut records = Vec::new();
    for (index, entry) in fs::read_dir(directory.pinned())
        .map_err(|error| failed(format!("cannot enumerate undo receipts: {error}")))?
        .enumerate()
    {
        if index >= MAX_RECEIPTS * 2 {
            return Err(failed("undo journal entry limit exceeded"));
        }
        let entry = entry.map_err(|error| failed(format!("cannot read undo entry: {error}")))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(failed("invalid undo receipt filename"));
        };
        if name.ends_with(".tmp") {
            continue;
        }
        let id = name
            .strip_suffix(".json")
            .filter(|id| canonical_uuid(id))
            .ok_or_else(|| failed("unrecognized file in private undo directory"))?;
        if records.len() >= MAX_RECEIPTS {
            return Err(failed("undo receipt limit exceeded"));
        }
        let bytes = read_bounded(open_private_file(&entry.path())?, MAX_RECEIPT_BYTES)?;
        let record: ReversalRecord = serde_json::from_slice(&bytes)
            .map_err(|error| failed(format!("malformed undo receipt {id}: {error}")))?;
        if record.attempt_id != id
            || record.session_id != session_id
            || plan_sha256.is_some_and(|expected| record.plan_sha256 != expected)
        {
            return Err(failed(
                "undo receipt filename/session/canonical-plan binding differs",
            ));
        }
        validate_record(&record)?;
        records.push(record);
    }
    records.sort_by_key(|record| record.sequence);
    if records
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err(failed("ambiguous duplicate undo receipt sequence"));
    }
    directory.revalidate()?;
    Ok(records)
}

/// All action entry points hold the data directory's execution-policy lock, so
/// another pt action cannot publish an owner between this scan and the write.
/// Refuse cross-session stacking rather than guessing a global undo order.
#[cfg(target_os = "linux")]
fn refuse_other_session_owner(
    sessions_root: &Path,
    operation: &ReversalOperation,
    own_session: Option<&str>,
) -> Result<(), ActionError> {
    if matches!(operation, ReversalOperation::Unsupported { .. }) {
        return Ok(());
    }
    let root = open_directory(sessions_root)?;
    let root_metadata = root.metadata().map_err(|error| failed(error.to_string()))?;
    check_owned_directory(&root_metadata, false)?;
    let mut receipts_read = 0usize;
    for (index, entry) in fs::read_dir(pinned_directory(&root))
        .map_err(|error| failed(format!("cannot inspect shared undo ownership: {error}")))?
        .enumerate()
    {
        if index >= MAX_RECEIPTS {
            return Err(failed(
                "session limit prevents a complete undo ownership check",
            ));
        }
        let entry =
            entry.map_err(|error| failed(format!("cannot inspect session ownership: {error}")))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(failed("ambiguous session directory name"));
        };
        if own_session == Some(name) {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|error| failed(error.to_string()))?;
        if kind.is_symlink() {
            return Err(failed(
                "cannot establish undo ownership through a symlinked session",
            ));
        }
        if !kind.is_dir() {
            continue;
        }
        let session = open_directory(&entry.path())?;
        check_owned_directory(
            &session
                .metadata()
                .map_err(|error| failed(error.to_string()))?,
            false,
        )?;
        let action_path = pinned_directory(&session).join("action");
        let action_directory = match open_directory(&action_path) {
            Ok(handle) => handle,
            Err(_)
                if fs::symlink_metadata(&action_path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        check_owned_directory(
            &action_directory
                .metadata()
                .map_err(|error| failed(error.to_string()))?,
            false,
        )?;
        let journal_path = pinned_directory(&action_directory).join("reversals");
        let Some(directory) = JournalDirectory::open(&journal_path, false)? else {
            continue;
        };
        // Foreign plans may have changed or disappeared. Their unresolved
        // receipts still own a controller; a current plan mismatch must not hide them.
        let records = read_stored_records(&directory, name, None)?;
        receipts_read = receipts_read
            .checked_add(records.len())
            .ok_or_else(|| failed("undo ownership count overflow"))?;
        if receipts_read > MAX_RECEIPTS {
            return Err(failed(
                "receipt limit prevents a complete undo ownership check",
            ));
        }
        for record in records {
            if !record.is_restored() && operations_share_control(operation, &record.operation) {
                return Err(failed(format!(
                    "controller has an unresolved durable owner in session {} (receipt {}); undo that attempt first",
                    record.session_id, record.attempt_id
                )));
            }
        }
    }
    let current = fs::symlink_metadata(sessions_root).map_err(|error| {
        failed(format!(
            "session root changed during ownership check: {error}"
        ))
    })?;
    check_owned_directory(&current, false)?;
    if current.dev() != root_metadata.dev() || current.ino() != root_metadata.ino() {
        return Err(failed(
            "session root identity changed during undo ownership check",
        ));
    }
    Ok(())
}

/// Read-only protection for callers whose plans are mutable (notably the TUI).
/// Such callers do not promise undo, but cannot overwrite a durable owner.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_control_unowned(
    sessions_root: &Path,
    cgroup_path: &str,
    handle: &File,
    control: ReversalValue,
) -> Result<(), ActionError> {
    let scope = ReversalScope::capture(cgroup_path, handle)?;
    refuse_other_session_owner(
        sessions_root,
        &ReversalOperation::CgroupV2 {
            scope,
            before: control.clone(),
            applied: control,
            verify_timeout_ms: 0,
        },
        None,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_renice_unowned(
    sessions_root: &Path,
    metadata: &ReniceReversalMetadata,
) -> Result<(), ActionError> {
    super::renice::validate_reversal_metadata(metadata)?;
    let namespace = fs::metadata("/proc/self/ns/pid")
        .map_err(|error| failed(format!("cannot identify renice PID namespace: {error}")))?;
    refuse_other_session_owner(
        sessions_root,
        &ReversalOperation::Renice {
            metadata: metadata.clone(),
            pid_namespace_device: namespace.dev(),
            pid_namespace_inode: namespace.ino(),
        },
        None,
    )
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct JournalDirectory {
    path: PathBuf,
    handle: File,
}

#[cfg(target_os = "linux")]
impl JournalDirectory {
    fn open(path: &Path, create: bool) -> Result<Option<Self>, ActionError> {
        if create {
            use std::os::unix::fs::DirBuilderExt;
            let parent = path
                .parent()
                .ok_or_else(|| failed("undo directory has no parent"))?;
            let parent_handle = open_directory(parent)?;
            check_owned_directory(
                &parent_handle
                    .metadata()
                    .map_err(|error| failed(error.to_string()))?,
                false,
            )?;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => parent_handle.sync_all().map_err(|error| {
                    failed(format!("cannot sync undo directory creation: {error}"))
                })?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(failed(format!(
                        "cannot create private undo directory: {error}"
                    )));
                }
            }
        }
        let handle = match open_directory(path) {
            Ok(handle) => handle,
            Err(_)
                if !create
                    && fs::symlink_metadata(path)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        check_owned_directory(
            &handle
                .metadata()
                .map_err(|error| failed(error.to_string()))?,
            true,
        )?;
        let directory = Self {
            path: path.to_path_buf(),
            handle,
        };
        directory.revalidate()?;
        Ok(Some(directory))
    }

    fn pinned(&self) -> PathBuf {
        pinned_directory(&self.handle)
    }

    fn revalidate(&self) -> Result<(), ActionError> {
        let saved = self
            .handle
            .metadata()
            .map_err(|error| failed(error.to_string()))?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|error| failed(format!("undo directory changed: {error}")))?;
        check_owned_directory(&current, true)?;
        if saved.dev() != current.dev() || saved.ino() != current.ino() {
            return Err(failed("undo directory identity changed"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn check_owned_directory(metadata: &fs::Metadata, private: bool) -> Result<(), ActionError> {
    // SAFETY: geteuid only reads the caller's effective credentials.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(failed(
            "undo storage requires an owned, non-writable-by-others directory (receipts private)",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> Result<File, ActionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| failed(format!("cannot open directory {}: {error}", path.display())))
}

#[cfg(target_os = "linux")]
fn open_private_file(path: &Path) -> Result<File, ActionError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| failed(format!("cannot open undo receipt: {error}")))?;
    let metadata = file.metadata().map_err(|error| failed(error.to_string()))?;
    // SAFETY: geteuid only reads the caller's effective credentials.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(failed(
            "undo receipt must be a private, owned, singly linked regular file",
        ));
    }
    Ok(file)
}

/// Persist an initial record exclusively, or replace an existing private record
/// only after the complete replacement has been synchronized. Keeping this byte
/// protocol separate from JSON encoding permits real filesystem failure tests.
#[cfg(target_os = "linux")]
fn write_receipt_bytes(
    directory: &JournalDirectory,
    destination_name: &str,
    temporary_name: Option<&str>,
    bytes: &[u8],
) -> Result<(), ActionError> {
    for name in std::iter::once(destination_name).chain(temporary_name) {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || name == "."
            || name == ".."
        {
            return Err(failed("invalid private undo filename"));
        }
    }
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(failed("undo receipt exceeds the bounded record size"));
    }
    directory.revalidate()?;
    let destination = directory.pinned().join(destination_name);
    let path = match temporary_name {
        None => destination.clone(),
        Some(name) => {
            // Refuse a substituted symlink, hard link, nonregular file, or
            // widened permissions before replacing a known receipt.
            open_private_file(&destination)?;
            directory.pinned().join(name)
        }
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| failed(format!("cannot create durable undo receipt: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(format!("cannot synchronize undo receipt: {error}")))?;
    if temporary_name.is_some() {
        fs::rename(&path, &destination)
            .map_err(|error| failed(format!("cannot replace undo receipt: {error}")))?;
    }
    directory
        .handle
        .sync_all()
        .map_err(|error| failed(format!("cannot synchronize undo directory: {error}")))?;
    directory.revalidate()
}

#[cfg(target_os = "linux")]
fn read_bounded(file: File, maximum: u64) -> Result<Vec<u8>, ActionError> {
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| failed(format!("cannot read undo evidence: {error}")))?;
    if bytes.len() as u64 > maximum {
        return Err(failed("undo evidence exceeds its size bound"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn pinned_directory(handle: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn mount_id(handle: &File) -> Result<u64, ActionError> {
    let path = format!("/proc/self/fdinfo/{}", handle.as_raw_fd());
    let contents = fs::read_to_string(path)
        .map_err(|error| failed(format!("cannot read cgroup mount identity: {error}")))?;
    let mut values = contents
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    let id = values
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| failed("missing cgroup mount identity"))?;
    if values.next().is_some() {
        return Err(failed("ambiguous cgroup mount identity"));
    }
    Ok(id)
}

#[cfg(target_os = "linux")]
impl ReversalScope {
    fn capture(cgroup_path: &str, handle: &File) -> Result<Self, ActionError> {
        validate_cgroup_path(cgroup_path)?;
        let metadata = handle
            .metadata()
            .map_err(|error| failed(error.to_string()))?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: handle is a live file descriptor and statfs points to writable storage.
        if unsafe { libc::fstatfs(handle.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(failed(format!(
                "cannot identify cgroup filesystem: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful fstatfs initialized the structure.
        if !metadata.is_dir() || unsafe { filesystem.assume_init() }.f_type as u64 != 0x6367_7270 {
            return Err(failed(
                "durable undo requires the actual cgroup-v2 filesystem",
            ));
        }
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| failed(format!("cannot bind undo to this boot: {error}")))?;
        let boot_id = boot_id.trim().to_string();
        if !canonical_uuid(&boot_id) {
            return Err(failed("invalid kernel boot ID"));
        }
        let mount_namespace = fs::metadata("/proc/self/ns/mnt")
            .map_err(|error| failed(format!("cannot identify mount namespace: {error}")))?;
        let cgroup_namespace = fs::metadata("/proc/self/ns/cgroup")
            .map_err(|error| failed(format!("cannot identify cgroup namespace: {error}")))?;
        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mount_id: mount_id(handle)?,
            boot_id,
            mount_namespace_device: mount_namespace.dev(),
            mount_namespace_inode: mount_namespace.ino(),
            cgroup_namespace_device: cgroup_namespace.dev(),
            cgroup_namespace_inode: cgroup_namespace.ino(),
        })
    }
}

#[cfg(target_os = "linux")]
fn restore_live(record: &ReversalRecord) -> Result<bool, ActionError> {
    if let ReversalOperation::Renice { metadata, .. } = &record.operation {
        validate_renice_scope(record)?;
        let changed = super::renice::ReniceActionRunner::with_defaults()
            .restore_recorded(metadata, !record.is_restored())?;
        validate_renice_scope(record)?;
        return Ok(changed);
    }
    let ReversalOperation::CgroupV2 { scope, .. } = &record.operation else {
        return Err(failed("unsupported recorded undo operation"));
    };
    let current_path = super::dispatch::ensure_cgroup_target(&record.target)?;
    if current_path != scope.cgroup_path {
        return Err(failed("target moved from its recorded cgroup"));
    }
    let directory = PathBuf::from(format!("/sys/fs/cgroup{current_path}"));
    let handle = open_directory(&directory)?;
    let pinned = pinned_directory(&handle);
    let revalidate = || -> Result<(), ActionError> {
        if super::dispatch::ensure_cgroup_target(&record.target)? != scope.cgroup_path {
            return Err(failed("target changed cgroup during undo"));
        }
        let current = open_directory(&directory)?;
        if ReversalScope::capture(&scope.cgroup_path, &current)? != *scope
            || ReversalScope::capture(&scope.cgroup_path, &handle)? != *scope
        {
            return Err(failed(
                "recorded cgroup directory, mount, namespace, or boot changed",
            ));
        }
        super::dispatch::ensure_exclusive_cgroup_path(record.target.pid.0, &pinned)
    };
    restore_record_at(record, &pinned, revalidate)
}

/// The observation path deliberately invokes no restoration writer or journal
/// updater. It proves the same complete live scope before reading old values.
#[cfg(target_os = "linux")]
fn observe_restored_control(record: &ReversalRecord) -> Result<(), ActionError> {
    if let ReversalOperation::Renice { metadata, .. } = &record.operation {
        validate_renice_scope(record)?;
        super::renice::ReniceActionRunner::with_defaults().observe_restored(metadata)?;
        return validate_renice_scope(record);
    }
    let ReversalOperation::CgroupV2 { scope, before, .. } = &record.operation else {
        return Err(failed("unsupported recorded restoration"));
    };
    let current_path = super::dispatch::ensure_cgroup_target(&record.target)?;
    if current_path != scope.cgroup_path {
        return Err(failed("target moved from its recorded restoration cgroup"));
    }
    let directory = PathBuf::from(format!("/sys/fs/cgroup{current_path}"));
    let handle = open_directory(&directory)?;
    let pinned = pinned_directory(&handle);
    let revalidate = || -> Result<(), ActionError> {
        if super::dispatch::ensure_cgroup_target(&record.target)? != scope.cgroup_path {
            return Err(failed(
                "target changed cgroup during restoration observation",
            ));
        }
        let current = open_directory(&directory)?;
        if ReversalScope::capture(&scope.cgroup_path, &current)? != *scope
            || ReversalScope::capture(&scope.cgroup_path, &handle)? != *scope
        {
            return Err(failed(
                "recorded cgroup directory, mount, namespace, or boot changed",
            ));
        }
        super::dispatch::ensure_exclusive_cgroup_path(record.target.pid.0, &pinned)
    };
    observe_original_control_at(&pinned, before, revalidate)
}

#[cfg(target_os = "linux")]
fn ensure_renice_target(target: &ProcessIdentity) -> Result<(), ActionError> {
    use super::executor::IdentityProvider;
    super::signal::ensure_action_pid_namespace()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| failed(format!("cannot revalidate renice boot: {error}")))?;
    validate_target(target, boot.trim())?;
    // SAFETY: geteuid only reads the calling process's credentials.
    if target.uid != unsafe { libc::geteuid() } {
        return Err(ActionError::PermissionDenied);
    }
    if crate::collect::protected::live_invoker_chain_pids().contains(&target.pid.0) {
        return Err(failed(
            "renice undo refuses the invoker and its ancestor chain",
        ));
    }
    if !super::signal::LiveIdentityProvider::new().revalidate(target)? {
        return Err(ActionError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_renice_scope(record: &ReversalRecord) -> Result<(), ActionError> {
    let ReversalOperation::Renice {
        pid_namespace_device,
        pid_namespace_inode,
        ..
    } = &record.operation
    else {
        return Err(failed("receipt is not a renice operation"));
    };
    ensure_renice_target(&record.target)?;
    let namespace = fs::metadata("/proc/self/ns/pid")
        .map_err(|error| failed(format!("cannot revalidate renice PID namespace: {error}")))?;
    if namespace.dev() != *pid_namespace_device || namespace.ino() != *pid_namespace_inode {
        return Err(failed(
            "renice PID namespace differs from the recorded namespace",
        ));
    }
    Ok(())
}

/// Read exact original values twice with scope guards surrounding each sample.
/// Freezer request and completed state must agree; no waiting or repair occurs.
#[cfg(target_os = "linux")]
fn observe_original_control_at(
    directory: &Path,
    original: &ReversalValue,
    revalidate: impl Fn() -> Result<(), ActionError>,
) -> Result<(), ActionError> {
    original.validate()?;
    revalidate()?;
    for _ in 0..2 {
        match original {
            ReversalValue::Freeze { requested } => {
                let state = super::freeze::read_freezer_state(directory)?;
                if state.requested != *requested || state.frozen != *requested {
                    return Err(failed(
                        "original freezer request and completed state are not both present",
                    ));
                }
            }
            ReversalValue::CpuMax { .. } => {
                if read_control(directory, original)? != *original {
                    return Err(failed(
                        "current CPU limit differs from the recorded original",
                    ));
                }
            }
            ReversalValue::Cpuset { cpus } => {
                super::cpuset_quarantine::verify_cpuset_assignment(
                    directory,
                    "cpuset.cpus.effective",
                    cpus,
                )?;
            }
        }
        revalidate()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_record_at(
    record: &ReversalRecord,
    directory: &Path,
    revalidate: impl Fn() -> Result<(), ActionError>,
) -> Result<bool, ActionError> {
    let ReversalOperation::CgroupV2 {
        before,
        applied,
        verify_timeout_ms,
        ..
    } = &record.operation
    else {
        return Err(failed("unsupported recorded undo operation"));
    };
    restore_control_at(
        directory,
        before,
        applied,
        *verify_timeout_ms,
        !record.is_restored(),
        revalidate,
    )
}

#[cfg(target_os = "linux")]
fn needs_restore(
    before: &ReversalValue,
    applied: &ReversalValue,
    current: &ReversalValue,
) -> Result<bool, ActionError> {
    before.validate()?;
    applied.validate()?;
    current.validate()?;
    if !before.same_control(applied) || !before.same_control(current) {
        return Err(failed("undo controller kinds differ"));
    }
    if current == before {
        return Ok(false);
    }
    if current == applied {
        return Ok(true);
    }
    Err(failed(
        "controller changed since the recorded action; refusing to overwrite another value",
    ))
}

#[cfg(target_os = "linux")]
fn read_control(directory: &Path, kind: &ReversalValue) -> Result<ReversalValue, ActionError> {
    if matches!(kind, ReversalValue::Cpuset { .. }) {
        return super::cpuset_quarantine::read_cpuset_assignment(&directory.join("cpuset.cpus"))
            .map(|cpus| ReversalValue::Cpuset { cpus });
    }
    let bytes = read_bounded(
        File::open(directory.join(kind.filename()))
            .map_err(|error| failed(format!("cannot read saved controller: {error}")))?,
        4096,
    )?;
    let contents = std::str::from_utf8(&bytes).map_err(|_| failed("controller is not UTF-8"))?;
    let value = match kind {
        ReversalValue::Freeze { .. } => match contents.trim() {
            "0" => ReversalValue::Freeze { requested: false },
            "1" => ReversalValue::Freeze { requested: true },
            _ => return Err(failed("invalid freezer request")),
        },
        ReversalValue::CpuMax { .. } => {
            let fields: Vec<_> = contents.split_whitespace().collect();
            if fields.len() != 2 || !fields[1].bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(failed("malformed cpu.max during undo"));
            }
            let quota_us = if fields[0] == "max" {
                -1
            } else {
                if !fields[0].bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(failed("malformed CPU quota"));
                }
                fields[0].parse().map_err(|_| failed("invalid CPU quota"))?
            };
            ReversalValue::CpuMax {
                quota_us,
                period_us: fields[1]
                    .parse()
                    .map_err(|_| failed("invalid CPU period"))?,
            }
        }
        ReversalValue::Cpuset { .. } => unreachable!("cpuset uses its bounded CPU-list parser"),
    };
    value.validate()?;
    Ok(value)
}

/// The only low-level undo writer. Production supplies the complete live scope
/// guard; tests exercise its real file and deadline behavior on owned fixtures.
#[cfg(target_os = "linux")]
fn restore_control_at(
    directory: &Path,
    before: &ReversalValue,
    applied: &ReversalValue,
    verify_timeout_ms: u64,
    allow_write: bool,
    revalidate: impl Fn() -> Result<(), ActionError>,
) -> Result<bool, ActionError> {
    revalidate()?;
    let current = read_control(directory, applied)?;
    let changed = needs_restore(before, applied, &current)?;
    if changed && !allow_write {
        return Err(failed(
            "this receipt was already restored; it cannot authorize another controller write",
        ));
    }
    if let ReversalValue::Cpuset { cpus } = &current {
        super::cpuset_quarantine::verify_cpuset_assignment(
            directory,
            "cpuset.cpus.effective",
            cpus,
        )?;
    }
    revalidate()?;
    if read_control(directory, applied)? != current {
        return Err(failed("controller changed immediately before undo"));
    }
    if let ReversalValue::Cpuset { cpus } = &current {
        super::cpuset_quarantine::verify_cpuset_assignment(
            directory,
            "cpuset.cpus.effective",
            cpus,
        )?;
    }
    if changed {
        fs::write(directory.join(before.filename()), before.contents())
            .map_err(|error| failed(format!("cannot restore controller: {error}")))?;
    }
    revalidate()?;
    match before {
        ReversalValue::Freeze { requested } => {
            super::freeze::wait_for_frozen_state(
                *requested,
                Duration::from_millis(verify_timeout_ms.min(MAX_RESTORE_VERIFY_MS)),
                || {
                    revalidate()?;
                    let state = super::freeze::read_freezer_state(directory);
                    revalidate()?;
                    state
                },
            )?;
        }
        ReversalValue::CpuMax { .. } => {
            if read_control(directory, before)? != *before {
                return Err(failed(
                    "restored CPU limit does not match the saved original",
                ));
            }
            revalidate()?;
            if read_control(directory, before)? != *before {
                return Err(failed("restored CPU limit changed during verification"));
            }
        }
        ReversalValue::Cpuset { cpus } => {
            for _ in 0..2 {
                super::cpuset_quarantine::verify_cpuset_assignment(
                    directory,
                    "cpuset.cpus.effective",
                    cpus,
                )?;
                revalidate()?;
            }
        }
    }
    revalidate()?;
    Ok(changed)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const BOOT: &str = "11111111-2222-4333-8444-555555555555";

    fn action(kind: Action) -> PlanAction {
        PlanAction {
            action_id: "recorded-action".to_string(),
            target: ProcessIdentity::new(123, pt_common::StartId::from_linux(BOOT, 456, 123), 1000),
            action: kind,
            order: 0,
            stage: 0,
            timeouts: Default::default(),
            pre_checks: Vec::new(),
            rationale: crate::plan::ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: Vec::new(),
            on_failure: Vec::new(),
            blocked: false,
            routing: Default::default(),
            confidence: Default::default(),
            original_zombie_target: None,
            d_state_diagnostics: None,
            supervisor_restart: None,
        }
    }

    // These are historical record fixtures, not a simulated live cgroup. Live
    // restore deliberately cannot authorize a kernel write from these values.
    fn operation(before: ReversalValue, applied: ReversalValue) -> ReversalOperation {
        ReversalOperation::CgroupV2 {
            scope: ReversalScope {
                cgroup_path: "/owned-leaf".to_string(),
                device: 42,
                inode: 43,
                mount_id: 44,
                boot_id: BOOT.to_string(),
                mount_namespace_device: 45,
                mount_namespace_inode: 46,
                cgroup_namespace_device: 45,
                cgroup_namespace_inode: 47,
            },
            before,
            applied,
            verify_timeout_ms: 0,
        }
    }

    fn journal(directory: &Path) -> Arc<ReversalJournal> {
        journal_in_sessions(&directory.join("sessions"), "pt-20261108-120000-abcd")
    }

    fn journal_in_sessions(sessions_root: &Path, session_id: &str) -> Arc<ReversalJournal> {
        let action_directory = sessions_root.join(session_id).join("action");
        fs::create_dir_all(&action_directory).unwrap();
        Arc::new(
            ReversalJournal::new(action_directory, session_id, "a".repeat(64), sessions_root)
                .unwrap(),
        )
    }

    fn freeze_operation() -> ReversalOperation {
        operation(
            ReversalValue::Freeze { requested: false },
            ReversalValue::Freeze { requested: true },
        )
    }

    fn renice_operation(action: &PlanAction) -> ReversalOperation {
        ReversalOperation::Renice {
            metadata: ReniceReversalMetadata {
                pid: action.target.pid.0,
                previous_nice: 0,
                applied_nice: 10,
                applied_at: now(),
                identity: Some(action.target.clone()),
                threads: vec![ReniceThreadReversal {
                    tid: action.target.pid.0,
                    start_ticks: 456,
                    uid: action.target.uid,
                    previous_nice: 0,
                    applied_nice: 10,
                }],
            },
            pid_namespace_device: 1,
            pid_namespace_inode: 2,
        }
    }

    #[test]
    fn renice_receipts_preserve_exact_identity_and_per_thread_priorities() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let mut action = action(Action::Renice);
        action.target.pgid = Some(101);
        action.target.sid = Some(102);
        let operation = renice_operation(&action);
        let record = journal
            .insert(&action, operation.clone(), ReversalStatus::Prepared)
            .unwrap();
        let reopened = ReversalJournal::new(
            journal.directory().parent().unwrap(),
            &journal.session_id,
            &journal.plan_sha256,
            &journal.sessions_root,
        )
        .unwrap();
        let saved = reopened.inspect(&action).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].operation, operation);
        assert_eq!(saved[0].target, action.target);
        assert_eq!(saved[0].attempt_id, record.attempt_id);
        assert_eq!(saved[0].status, ReversalStatus::Prepared);
        for changed in ["pid", "birth", "uid", "pgid", "sid", "action"] {
            let mut changed_action = action.clone();
            match changed {
                "pid" => changed_action.target.pid.0 += 1,
                "birth" => {
                    changed_action.target.start_id = pt_common::StartId::from_linux(BOOT, 457, 123)
                }
                "uid" => changed_action.target.uid += 1,
                "pgid" => changed_action.target.pgid = Some(999),
                "sid" => changed_action.target.sid = Some(999),
                "action" => changed_action.action = Action::Pause,
                _ => unreachable!(),
            }
            assert!(reopened.inspect(&changed_action).is_err(), "{changed}");
        }
    }

    #[test]
    fn renice_receipts_refuse_unbound_duplicate_and_priority_raising_states() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Renice);
        for changed in [
            "identity",
            "birth",
            "uid",
            "leader",
            "duplicate",
            "raise",
            "namespace",
        ] {
            let mut operation = renice_operation(&action);
            let ReversalOperation::Renice {
                metadata,
                pid_namespace_inode,
                ..
            } = &mut operation
            else {
                unreachable!();
            };
            match changed {
                "identity" => metadata.identity = None,
                "birth" => metadata.threads[0].start_ticks += 1,
                "uid" => metadata.threads[0].uid += 1,
                "leader" => metadata.applied_nice += 1,
                "duplicate" => metadata.threads.push(metadata.threads[0].clone()),
                "raise" => metadata.threads[0].applied_nice = -1,
                "namespace" => *pid_namespace_inode = 0,
                _ => unreachable!(),
            }
            assert!(
                journal
                    .insert(&action, operation, ReversalStatus::Prepared)
                    .is_err(),
                "{changed}"
            );
            assert!(journal.inspect(&action).unwrap().is_empty());
        }
    }

    #[test]
    fn renice_control_ownership_blocks_cross_session_and_unjournaled_changes() {
        let directory = tempfile::tempdir().unwrap();
        let sessions = directory.path().join("sessions");
        let first = journal_in_sessions(&sessions, "session-a");
        let second = journal_in_sessions(&sessions, "session-b");
        let action = action(Action::Renice);
        let operation = renice_operation(&action);
        let mut record = first
            .insert(&action, operation.clone(), ReversalStatus::Verified)
            .unwrap();
        assert!(second
            .insert(&action, operation.clone(), ReversalStatus::Prepared)
            .is_err());
        assert!(refuse_other_session_owner(&sessions, &operation, None).is_err());
        let mut different = operation.clone();
        if let ReversalOperation::Renice { metadata, .. } = &mut different {
            metadata.identity.as_mut().unwrap().start_id =
                pt_common::StartId::from_linux(BOOT, 789, 123);
            metadata.threads[0].start_ticks = 789;
        }
        assert!(!operations_share_control(&operation, &different));
        assert!(!operations_share_control(&operation, &freeze_operation()));
        record.restorations.push(restored_outcome(&record));
        let stored = JournalDirectory::open(first.directory(), false)
            .unwrap()
            .unwrap();
        first.write_record(&stored, &record, false).unwrap();
        assert!(second
            .insert(&action, operation, ReversalStatus::Prepared)
            .is_ok());
    }

    struct OwnedReniceChild(std::process::Child);

    impl Drop for OwnedReniceChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn owned_renice_target() -> (OwnedReniceChild, PlanAction) {
        let child = OwnedReniceChild(
            std::process::Command::new("sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("owned disposable process"),
        );
        let mut action = action(Action::Renice);
        action.target = super::super::dispatch::read_cgroup_identity(child.0.id())
            .expect("owned process full Linux identity");
        (child, action)
    }

    #[test]
    fn durable_renice_owned_child_roundtrips_and_observes_idempotent_restoration() {
        use crate::action::{ActionRunner, ReniceActionRunner, ReniceConfig};
        let (_child, action) = owned_renice_target();
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        // No privilege is needed for this intentionally unchanged priority.
        // Changed-priority restoration and permission failures have separate tests.
        let runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: -20,
            ..Default::default()
        })
        .with_reversal_journal(Arc::clone(&journal));
        runner.execute(&action).unwrap();
        runner.verify(&action).unwrap();
        let saved = journal.inspect(&action).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].status, ReversalStatus::Verified);
        let ReversalOperation::Renice { metadata, .. } = &saved[0].operation else {
            panic!("renice execution must capture its exact original state");
        };
        assert_eq!(metadata.identity.as_ref(), Some(&action.target));
        assert_eq!(metadata.threads.len(), 1);
        assert!(metadata
            .threads
            .iter()
            .all(|thread| thread.previous_nice == thread.applied_nice));
        for _ in 0..2 {
            let restored = journal.restore(&action, None).unwrap();
            assert_eq!(restored.status, RestorationStatus::Restored);
            assert_eq!(restored.changed, Some(false));
        }
        let bytes = fs::read(
            journal
                .directory()
                .join(format!("{}.json", saved[0].attempt_id)),
        )
        .unwrap();
        let observed = journal.observe_restoration(&action).unwrap().unwrap();
        assert_eq!(
            observed.original_value,
            RestorationValue::ThreadPriorities {
                threads: metadata.threads.clone()
            }
        );
        assert_eq!(
            fs::read(
                journal
                    .directory()
                    .join(format!("{}.json", saved[0].attempt_id))
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn durable_renice_never_changes_priority_when_receipt_persistence_is_unavailable() {
        use crate::action::{ActionRunner, ReniceActionRunner};
        let (_child, action) = owned_renice_target();
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        fs::write(journal.directory(), b"not a private receipt directory").unwrap();
        let runner = ReniceActionRunner::with_defaults().with_reversal_journal(journal);
        let before = runner
            .capture_reversal_metadata(action.target.pid.0)
            .unwrap();
        assert!(runner.execute(&action).is_err());
        let after = runner
            .capture_reversal_metadata(action.target.pid.0)
            .unwrap();
        assert_eq!(before.threads, after.threads);
    }

    #[test]
    fn durable_renice_owned_priority_change_preserves_permission_failure_or_exact_undo() {
        use crate::action::{ActionRunner, ReniceActionRunner, ReniceConfig};
        let (_child, action) = owned_renice_target();
        let baseline = ReniceActionRunner::with_defaults()
            .capture_reversal_metadata(action.target.pid.0)
            .unwrap();
        if baseline.previous_nice == 19 {
            eprintln!("SKIP changed-priority live restoration: test runner inherited nice 19; exact mutation/permission behavior is covered by task-state tests");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: baseline.previous_nice + 1,
            ..Default::default()
        })
        .with_reversal_journal(Arc::clone(&journal));
        runner.execute(&action).unwrap();
        runner.verify(&action).unwrap();
        let lowered = runner
            .capture_reversal_metadata(action.target.pid.0)
            .unwrap();
        assert_eq!(lowered.previous_nice, baseline.previous_nice + 1);
        let restored = journal.restore(&action, None).unwrap();
        let current = runner
            .capture_reversal_metadata(action.target.pid.0)
            .unwrap();
        match restored.status {
            RestorationStatus::Restored => {
                assert_eq!(restored.changed, Some(true));
                assert_eq!(current.previous_nice, baseline.previous_nice);
                assert!(journal.observe_restoration(&action).unwrap().is_some());
            }
            RestorationStatus::Failed => {
                assert!(
                    restored
                        .detail
                        .as_deref()
                        .unwrap_or_default()
                        .contains("permission denied"),
                    "{restored:?}"
                );
                assert_eq!(restored.changed, None);
                assert_eq!(current.previous_nice, lowered.previous_nice);
                assert!(journal.observe_restoration(&action).is_err());
                let records = journal.inspect(&action).unwrap();
                assert_eq!(records[0].status, ReversalStatus::Verified);
                assert_eq!(
                    records[0].restorations.last().unwrap().status,
                    RestorationStatus::Failed
                );
            }
            RestorationStatus::Prepared => panic!("a completed restore cannot still be prepared"),
        }
    }

    fn restored_outcome(record: &ReversalRecord) -> ReversalOutcome {
        ReversalOutcome {
            attempt_id: record.attempt_id.clone(),
            restore_id: uuid::Uuid::new_v4().to_string(),
            action_id: record.action_id.clone(),
            status: RestorationStatus::Restored,
            changed: Some(true),
            detail: None,
            timestamp: now(),
        }
    }

    #[test]
    fn preview_is_read_only_and_old_sessions_have_no_invented_state() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        assert!(journal.inspect(&action(Action::Freeze)).unwrap().is_empty());
        assert!(!journal.directory().exists());
        assert_eq!(
            fs::read_dir(journal.directory().parent().unwrap())
                .unwrap()
                .count(),
            0
        );
        assert!(journal.restore(&action(Action::Freeze), None).is_err());
        assert!(!journal.directory().exists());
        assert_eq!(
            fs::read_dir(journal.directory().parent().unwrap())
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn restoration_observation_without_history_is_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        assert!(journal
            .observe_restoration(&action(Action::Freeze))
            .unwrap()
            .is_none());
        assert!(!journal.directory().exists());

        let action = action(Action::Freeze);
        journal
            .insert(&action, freeze_operation(), ReversalStatus::Verified)
            .unwrap();
        let before = fs::read_dir(journal.directory())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        assert!(journal.observe_restoration(&action).unwrap().is_none());
        assert_eq!(
            fs::read_dir(journal.directory()).unwrap().count(),
            before.len()
        );
        for (path, bytes) in before {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn restoration_credit_requires_latest_verified_execution_and_latest_completed_undo() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Freeze);
        let mut earlier = journal
            .insert(&action, freeze_operation(), ReversalStatus::Verified)
            .unwrap();
        earlier.restorations.push(restored_outcome(&earlier));
        assert!(latest_recorded_restoration(&[earlier.clone()], &action)
            .unwrap()
            .is_some());

        for status in [ReversalStatus::Prepared, ReversalStatus::Failed] {
            let mut later = earlier.clone();
            later.attempt_id = uuid::Uuid::new_v4().to_string();
            later.sequence += 1;
            later.status = status;
            later.restorations.clear();
            assert!(latest_recorded_restoration(&[later, earlier.clone()], &action).is_err());
        }
        for status in [ReversalStatus::Applied, ReversalStatus::Verified] {
            let mut later = earlier.clone();
            later.attempt_id = uuid::Uuid::new_v4().to_string();
            later.sequence += 1;
            later.status = status;
            later.restorations.clear();
            assert!(
                latest_recorded_restoration(&[later, earlier.clone()], &action)
                    .unwrap()
                    .is_none()
            );
        }
        for status in [RestorationStatus::Prepared, RestorationStatus::Failed] {
            let mut record = earlier.clone();
            let mut latest = restored_outcome(&record);
            latest.status = status;
            latest.changed = None;
            record.restorations.push(latest);
            assert!(latest_recorded_restoration(&[record], &action).is_err());
        }
        for status in [
            ReversalStatus::Applied,
            ReversalStatus::Prepared,
            ReversalStatus::Failed,
        ] {
            let mut record = earlier.clone();
            record.status = status;
            assert!(latest_recorded_restoration(&[record], &action).is_err());
        }
        let mut foreign_action = action.clone();
        foreign_action.target.uid += 1;
        assert!(latest_recorded_restoration(&[earlier], &foreign_action).is_err());
    }

    #[test]
    fn unsupported_execution_has_no_restoration_credit() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Throttle);
        let mut record = journal
            .insert(
                &action,
                ReversalOperation::Unsupported {
                    reason: "v1 has no durable undo".to_string(),
                },
                ReversalStatus::Unsupported,
            )
            .unwrap();
        assert!(latest_recorded_restoration(&[record.clone()], &action)
            .unwrap()
            .is_none());
        record.restorations.push(restored_outcome(&record));
        assert!(latest_recorded_restoration(&[record], &action).is_err());
    }

    #[test]
    fn restoration_observation_refuses_malformed_future_and_reversed_timestamps() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let mut record = journal
            .insert(
                &action(Action::Freeze),
                freeze_operation(),
                ReversalStatus::Verified,
            )
            .unwrap();
        record.prepared_at = "2020-01-01T00:00:00Z".to_string();
        record.updated_at = "2020-01-01T00:00:02Z".to_string();
        let mut restored = restored_outcome(&record);
        restored.timestamp = "2020-01-01T00:00:01Z".to_string();
        let now = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:03Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(validate_restoration_times(&record, &restored, now).is_ok());
        for timestamp in ["invalid", "2019-12-31T23:59:59Z", "2020-01-01T00:00:04Z"] {
            let mut invalid = restored.clone();
            invalid.timestamp = timestamp.to_string();
            assert!(validate_restoration_times(&record, &invalid, now).is_err());
        }
        record.updated_at = "2020-01-01T00:00:04Z".to_string();
        assert!(validate_restoration_times(&record, &restored, now).is_err());
    }

    #[test]
    fn original_cpu_observation_never_repairs_a_different_or_missing_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cpu.max");
        let original = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        assert!(observe_original_control_at(directory.path(), &original, || Ok(())).is_err());
        assert!(!path.exists());
        for (text, matches) in [
            ("max 100000\n", true),
            ("25000 100000\n", false),
            ("max 50000\n", false),
            ("not-a-limit\n", false),
        ] {
            fs::write(&path, text).unwrap();
            assert_eq!(
                observe_original_control_at(directory.path(), &original, || Ok(())).is_ok(),
                matches
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), text);
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn original_freezer_observation_requires_request_and_completed_state_without_writes() {
        let directory = tempfile::tempdir().unwrap();
        for requested in [false, true] {
            let original = ReversalValue::Freeze { requested };
            for current_request in [false, true] {
                for completed in [false, true] {
                    let request = format!("{}\n", u8::from(current_request));
                    let events = format!("populated 1\nfrozen {}\n", u8::from(completed));
                    fs::write(directory.path().join("cgroup.freeze"), &request).unwrap();
                    fs::write(directory.path().join("cgroup.events"), &events).unwrap();
                    assert_eq!(
                        observe_original_control_at(directory.path(), &original, || Ok(())).is_ok(),
                        current_request == requested && completed == requested,
                    );
                    assert_eq!(
                        fs::read_to_string(directory.path().join("cgroup.freeze")).unwrap(),
                        request
                    );
                    assert_eq!(
                        fs::read_to_string(directory.path().join("cgroup.events")).unwrap(),
                        events
                    );
                }
            }
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn original_control_observation_rechecks_late_controller_and_directory_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cpu.max");
        fs::write(&path, "max 100000").unwrap();
        let checks = Cell::new(0);
        let original = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let result = observe_original_control_at(directory.path(), &original, || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                fs::write(&path, "25000 100000").unwrap();
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "25000 100000");

        let leaf = directory.path().join("leaf");
        let moved = directory.path().join("moved");
        fs::create_dir(&leaf).unwrap();
        fs::write(leaf.join("cpu.max"), "max 100000").unwrap();
        let handle = open_directory(&leaf).unwrap();
        let expected = handle.metadata().unwrap();
        let checks = Cell::new(0);
        let result = observe_original_control_at(&pinned_directory(&handle), &original, || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                fs::rename(&leaf, &moved).unwrap();
                fs::create_dir(&leaf).unwrap();
                fs::write(leaf.join("cpu.max"), "25000 100000").unwrap();
            }
            let current = fs::symlink_metadata(&leaf).unwrap();
            if current.dev() != expected.dev() || current.ino() != expected.ino() {
                Err(failed("directory changed"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(moved.join("cpu.max")).unwrap(),
            "max 100000"
        );
        assert_eq!(
            fs::read_to_string(leaf.join("cpu.max")).unwrap(),
            "25000 100000"
        );
    }

    #[test]
    fn prepared_receipt_is_private_and_survives_failed_execution() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Freeze);
        let saved = journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .unwrap();
        let file = journal
            .directory()
            .join(format!("{}.json", saved.attempt_id));
        assert_eq!(
            fs::metadata(journal.directory()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        let read = journal.inspect(&action).unwrap();
        assert_eq!(read[0].status, ReversalStatus::Prepared);
        assert_eq!(read[0].operation, freeze_operation());
        let receipt = PreparedReversal {
            journal: Arc::clone(&journal),
            attempt_id: saved.attempt_id.clone(),
        };
        let failure = receipt
            .finish::<()>(Err(ActionError::IdentityMismatch), ReversalStatus::Applied)
            .unwrap_err();
        assert!(failure.to_string().contains(&saved.attempt_id));
        let read = journal.inspect(&action).unwrap();
        assert_eq!(read[0].status, ReversalStatus::Failed);
        assert_eq!(read[0].operation, freeze_operation());
        assert!(read[0].restorations.is_empty());
    }

    #[test]
    fn receipt_binding_refuses_plan_session_identity_and_routing_changes() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Freeze);
        journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .unwrap();
        for changed in 0..5 {
            let mut other = action.clone();
            match changed {
                0 => other.target.uid += 1,
                1 => other.target.quality = pt_common::IdentityQuality::PidOnly,
                2 => other.target.pgid = Some(999),
                3 => other.routing = ActionRouting::DStateLowConfidence,
                _ => other.action = Action::Unfreeze,
            }
            assert!(journal.inspect(&other).is_err());
        }
        for (session, digest) in [
            ("another-session", "a".repeat(64)),
            ("pt-20261108-120000-abcd", "b".repeat(64)),
        ] {
            let other = ReversalJournal::new(
                journal.directory().parent().unwrap(),
                session,
                digest,
                &journal.sessions_root,
            );
            match other {
                Ok(other) => assert!(other.inspect(&action).is_err()),
                Err(error) => assert!(error.to_string().contains("explicit session root")),
            }
        }
    }

    #[test]
    fn unresolved_execution_cannot_overwrite_its_original_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Freeze);
        let first = journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .unwrap();
        assert!(journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .is_err());
        let read = journal.inspect(&action).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].attempt_id, first.attempt_id);
        assert_eq!(read[0].status, ReversalStatus::Prepared);
    }

    #[test]
    fn failed_outcome_persistence_retains_the_original_prepared_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Freeze);
        let saved = journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .unwrap();
        let retained = directory.path().join("retained");
        fs::rename(journal.directory(), &retained).unwrap();
        symlink(&retained, journal.directory()).unwrap();
        let receipt = PreparedReversal {
            journal,
            attempt_id: saved.attempt_id.clone(),
        };
        let error = receipt.finish(Ok(()), ReversalStatus::Applied).unwrap_err();
        assert!(error.to_string().contains(&saved.attempt_id));
        let original: ReversalRecord = serde_json::from_slice(
            &fs::read(retained.join(format!("{}.json", saved.attempt_id))).unwrap(),
        )
        .unwrap();
        assert_eq!(original.status, ReversalStatus::Prepared);
    }

    #[test]
    fn receipts_refuse_symlinks_hard_links_and_widened_permissions() {
        for kind in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let journal = journal(directory.path());
            let action = action(Action::Freeze);
            let record = journal
                .insert(&action, freeze_operation(), ReversalStatus::Prepared)
                .unwrap();
            let path = journal
                .directory()
                .join(format!("{}.json", record.attempt_id));
            let retained = directory.path().join("retained.json");
            match kind {
                0 => {
                    fs::rename(&path, &retained).unwrap();
                    symlink(&retained, &path).unwrap();
                }
                1 => fs::hard_link(&path, &retained).unwrap(),
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            assert!(journal.inspect(&action).is_err());
        }
    }

    #[test]
    fn malformed_or_oversized_receipts_are_not_partial_undo_authority() {
        for bytes in [
            b"{\"version\":1".to_vec(),
            vec![b' '; MAX_RECEIPT_BYTES as usize + 1],
        ] {
            let directory = tempfile::tempdir().unwrap();
            let journal = journal(directory.path());
            let action = action(Action::Freeze);
            let record = journal
                .insert(&action, freeze_operation(), ReversalStatus::Prepared)
                .unwrap();
            fs::write(
                journal
                    .directory()
                    .join(format!("{}.json", record.attempt_id)),
                bytes,
            )
            .unwrap();
            assert!(journal.inspect(&action).is_err());
        }
    }

    #[test]
    fn private_directory_identity_replacement_is_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("reversals");
        let pinned = JournalDirectory::open(&path, true).unwrap().unwrap();
        fs::rename(&path, parent.path().join("retained")).unwrap();
        JournalDirectory::open(&path, true).unwrap();
        assert!(pinned.revalidate().is_err());
    }

    #[test]
    fn durable_byte_writer_preserves_prior_record_when_replacement_cannot_be_created() {
        let parent = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(&parent.path().join("reversals"), true)
            .unwrap()
            .unwrap();
        write_receipt_bytes(&directory, "receipt.json", None, b"prepared\n").unwrap();
        assert!(write_receipt_bytes(&directory, "receipt.json", None, b"overwritten\n").is_err());
        fs::write(directory.pinned().join("occupied.tmp"), b"reserved").unwrap();
        assert!(write_receipt_bytes(
            &directory,
            "receipt.json",
            Some("occupied.tmp"),
            b"applied\n"
        )
        .is_err());
        assert_eq!(
            read_bounded(
                open_private_file(&directory.pinned().join("receipt.json")).unwrap(),
                100
            )
            .unwrap(),
            b"prepared\n"
        );
        write_receipt_bytes(
            &directory,
            "receipt.json",
            Some("complete.tmp"),
            b"applied\n",
        )
        .unwrap();
        assert_eq!(
            read_bounded(
                open_private_file(&directory.pinned().join("receipt.json")).unwrap(),
                100
            )
            .unwrap(),
            b"applied\n"
        );
        assert!(!directory.pinned().join("complete.tmp").exists());
        assert_eq!(
            fs::metadata(directory.pinned().join("receipt.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn durable_byte_writer_refuses_symlink_and_out_of_directory_destinations() {
        let parent = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(&parent.path().join("reversals"), true)
            .unwrap()
            .unwrap();
        let outside = parent.path().join("outside");
        fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, directory.pinned().join("receipt.json")).unwrap();
        assert!(write_receipt_bytes(
            &directory,
            "receipt.json",
            Some("replacement.tmp"),
            b"changed"
        )
        .is_err());
        assert!(write_receipt_bytes(&directory, "receipt.json", None, b"changed").is_err());
        assert!(write_receipt_bytes(&directory, "../outside", None, b"changed").is_err());
        assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    }

    #[test]
    fn ordinary_directories_cannot_be_captured_as_cgroup_v2() {
        let directory = tempfile::tempdir().unwrap();
        let handle = open_directory(directory.path()).unwrap();
        let error = ReversalScope::capture("/owned-leaf", &handle).unwrap_err();
        assert!(error.to_string().contains("actual cgroup-v2 filesystem"));
        assert!(mount_id(&handle).unwrap() > 0);
    }

    #[test]
    fn unsupported_v1_execution_is_inspectable_but_not_undoable() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Throttle);
        journal
            .record_unsupported(&action, "v1 CPU controller")
            .unwrap();
        let records = journal.inspect(&action).unwrap();
        assert_eq!(records[0].status, ReversalStatus::Unsupported);
        assert!(matches!(
            records[0].operation,
            ReversalOperation::Unsupported { .. }
        ));
        assert!(journal.restore(&action, None).is_err());
    }

    #[test]
    fn malformed_controls_paths_and_identity_quality_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        for path in ["/", "relative", "/a/../b", "/a/./b", "/a//b", "/a\nb"] {
            assert!(validate_cgroup_path(path).is_err());
        }
        for value in [
            ReversalValue::CpuMax {
                quota_us: 0,
                period_us: 100_000,
            },
            ReversalValue::CpuMax {
                quota_us: 999,
                period_us: 100_000,
            },
            ReversalValue::CpuMax {
                quota_us: 25_000,
                period_us: 1_000_001,
            },
        ] {
            assert!(value.validate().is_err());
        }
        let mut action = action(Action::Freeze);
        action.target.quality = pt_common::IdentityQuality::NoBootId;
        assert!(journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .is_err());
        action.target.quality = pt_common::IdentityQuality::Full;
        action.target.start_id = pt_common::StartId::from_linux(BOOT, 456, 124);
        assert!(journal
            .insert(&action, freeze_operation(), ReversalStatus::Prepared)
            .is_err());
    }

    #[test]
    fn later_control_receipt_must_be_undone_first_and_attempts_stay_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let first_action = action(Action::Freeze);
        let first = journal
            .insert(&first_action, freeze_operation(), ReversalStatus::Prepared)
            .unwrap();
        let mut second_action = action(Action::Unfreeze);
        second_action.action_id = "later-unfreeze".to_string();
        let second = journal
            .insert(
                &second_action,
                operation(
                    ReversalValue::Freeze { requested: true },
                    ReversalValue::Freeze { requested: false },
                ),
                ReversalStatus::Prepared,
            )
            .unwrap();
        assert_ne!(first.attempt_id, second.attempt_id);
        let records = vec![first.clone(), second.clone()];
        assert!(refuse_newer_control(&records, &first).is_err());
        assert!(refuse_newer_control(&records, &second).is_ok());
        let mut completed_second = second.clone();
        completed_second
            .restorations
            .push(restored_outcome(&second));
        assert!(refuse_newer_control(&[first.clone(), completed_second], &first).is_ok());
        let mut duplicate = first.clone();
        duplicate.attempt_id = uuid::Uuid::new_v4().to_string();
        duplicate.sequence = 3;
        let duplicates = [first.clone(), duplicate];
        assert!(select_receipt(&duplicates, &first_action, None).is_err());
        assert_eq!(
            select_receipt(&duplicates, &first_action, Some(&first.attempt_id))
                .unwrap()
                .attempt_id,
            first.attempt_id
        );
    }

    #[test]
    fn control_ownership_follows_physical_cgroup_across_mount_and_namespace_aliases() {
        let original = freeze_operation();
        let mut aliased = original.clone();
        if let ReversalOperation::CgroupV2 { scope, .. } = &mut aliased {
            scope.cgroup_path = "/other-view".to_string();
            scope.mount_id += 1;
            scope.mount_namespace_inode += 1;
            scope.cgroup_namespace_inode += 1;
        }
        assert!(operations_share_control(&original, &aliased));
        let cpu = operation(
            ReversalValue::CpuMax {
                quota_us: -1,
                period_us: 100_000,
            },
            ReversalValue::CpuMax {
                quota_us: 25_000,
                period_us: 100_000,
            },
        );
        assert!(!operations_share_control(&original, &cpu));
        if let ReversalOperation::CgroupV2 { scope, .. } = &mut aliased {
            scope.inode += 1;
        }
        assert!(!operations_share_control(&original, &aliased));
    }

    #[test]
    fn foreign_session_cannot_claim_even_an_unchanged_cap_until_original_is_restored() {
        let directory = tempfile::tempdir().unwrap();
        let sessions = directory.path().join("sessions");
        let first = journal_in_sessions(&sessions, "session-a");
        let second = journal_in_sessions(&sessions, "session-b");
        let action = action(Action::Throttle);
        let unlimited = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let capped = ReversalValue::CpuMax {
            quota_us: 25_000,
            period_us: 100_000,
        };
        let mut original = first
            .insert(
                &action,
                operation(unlimited, capped.clone()),
                ReversalStatus::Applied,
            )
            .unwrap();
        let unchanged_cap = operation(capped.clone(), capped);
        assert!(second
            .insert(&action, unchanged_cap.clone(), ReversalStatus::Prepared)
            .is_err());
        assert!(second.inspect(&action).unwrap().is_empty());
        // A historical completed restoration makes the old claim inactive.
        // This fixture exercises durable ownership state, not kernel actuation.
        original.restorations.push(restored_outcome(&original));
        let stored = JournalDirectory::open(first.directory(), false)
            .unwrap()
            .unwrap();
        first.write_record(&stored, &original, false).unwrap();
        let new_owner = second
            .insert(&action, unchanged_cap, ReversalStatus::Prepared)
            .unwrap();
        let result = first.restore(&action, Some(&original.attempt_id)).unwrap();
        assert_eq!(result.status, RestorationStatus::Failed);
        assert!(result.detail.unwrap().contains("session-b"));
        assert_eq!(result.changed, None);
        assert_eq!(
            second.inspect(&action).unwrap()[0].attempt_id,
            new_owner.attempt_id
        );
    }

    #[test]
    fn unjournaled_guard_refuses_all_live_owners_including_its_own_session() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let operation = freeze_operation();
        assert!(refuse_other_session_owner(&journal.sessions_root, &operation, None).is_ok());
        journal
            .insert(
                &action(Action::Freeze),
                operation.clone(),
                ReversalStatus::Prepared,
            )
            .unwrap();
        assert!(refuse_other_session_owner(&journal.sessions_root, &operation, None).is_err());
        assert!(refuse_other_session_owner(
            &journal.sessions_root,
            &operation,
            Some(&journal.session_id)
        )
        .is_ok());
    }

    #[test]
    fn cpuset_receipts_require_canonical_nonexpanding_assignments() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let record = journal
            .insert(
                &action(Action::Quarantine),
                operation(
                    ReversalValue::Cpuset {
                        cpus: String::new(),
                    },
                    ReversalValue::Cpuset {
                        cpus: "8".to_string(),
                    },
                ),
                ReversalStatus::Applied,
            )
            .unwrap();
        for (previous, requested, valid) in [
            ("", "8", true),
            ("8-11", "8", true),
            ("8-11", "8-11", true),
            ("8-11", "", false),
            ("8-11", "0", false),
            ("8-11", "8-12", false),
            ("8-11", "8,9", false),
            ("8,9", "8", false),
            ("\n", "8", false),
            ("", "8,broken", false),
        ] {
            let mut changed = record.clone();
            changed.operation = operation(
                ReversalValue::Cpuset {
                    cpus: previous.to_string(),
                },
                ReversalValue::Cpuset {
                    cpus: requested.to_string(),
                },
            );
            assert_eq!(
                validate_record(&changed).is_ok(),
                valid,
                "{previous:?} -> {requested:?}"
            );
        }
        let mut wrong_action = record.clone();
        wrong_action.action = Action::Throttle;
        assert!(validate_record(&wrong_action).is_err());
        let mut wrong_controller = record;
        if let ReversalOperation::CgroupV2 { before, .. } = &mut wrong_controller.operation {
            *before = ReversalValue::Freeze { requested: false };
        }
        assert!(validate_record(&wrong_controller).is_err());
    }

    #[test]
    fn cpuset_ownership_survives_new_journal_instances_without_claiming_other_controls() {
        let directory = tempfile::tempdir().unwrap();
        let sessions = directory.path().join("sessions");
        let first = journal_in_sessions(&sessions, "session-a");
        let second = journal_in_sessions(&sessions, "session-b");
        let quarantine = action(Action::Quarantine);
        let restricted = ReversalValue::Cpuset {
            cpus: "8".to_string(),
        };
        let mut original = first
            .insert(
                &quarantine,
                operation(
                    ReversalValue::Cpuset {
                        cpus: String::new(),
                    },
                    restricted.clone(),
                ),
                ReversalStatus::Verified,
            )
            .unwrap();
        drop(first);
        let first = journal_in_sessions(&sessions, "session-a");
        let unchanged = operation(restricted.clone(), restricted);
        assert!(second
            .insert(&quarantine, unchanged.clone(), ReversalStatus::Prepared)
            .is_err());
        assert!(refuse_other_session_owner(&sessions, &unchanged, None).is_err());
        assert!(!operations_share_control(
            &original.operation,
            &freeze_operation()
        ));
        let throttle = operation(
            ReversalValue::CpuMax {
                quota_us: -1,
                period_us: 100_000,
            },
            ReversalValue::CpuMax {
                quota_us: 25_000,
                period_us: 100_000,
            },
        );
        assert!(!operations_share_control(&original.operation, &throttle));
        let mut throttle_action = action(Action::Throttle);
        throttle_action.action_id = "other-controller".to_string();
        second
            .insert(&throttle_action, throttle, ReversalStatus::Prepared)
            .unwrap();

        // Historical journal transition only: this does not stand in for a
        // live kernel restore, which separately proves the full cgroup scope.
        original.restorations.push(restored_outcome(&original));
        let stored = JournalDirectory::open(first.directory(), false)
            .unwrap()
            .unwrap();
        first.write_record(&stored, &original, false).unwrap();
        second
            .insert(&quarantine, unchanged, ReversalStatus::Prepared)
            .unwrap();
        assert_eq!(
            first.inspect(&quarantine).unwrap()[0].operation,
            original.operation
        );
    }

    #[test]
    fn real_file_cpuset_restore_preserves_inherited_and_explicit_intent() {
        for previous in ["", "8-11", "8"] {
            let directory = tempfile::tempdir().unwrap();
            let requested = directory.path().join("cpuset.cpus");
            let effective = directory.path().join("cpuset.cpus.effective");
            let sibling = directory.path().join("sibling.cpus");
            let before = ReversalValue::Cpuset {
                cpus: previous.to_string(),
            };
            let applied = ReversalValue::Cpuset {
                cpus: "8".to_string(),
            };
            fs::write(&requested, "8\n").unwrap();
            fs::write(&effective, "8\n").unwrap();
            fs::write(&sibling, "16-19\n").unwrap();
            let observe_effective = || {
                // Exercise write/read ordering on files; delegated integration
                // tests supply kernel-managed effective CPU evidence.
                if fs::read_to_string(&requested).unwrap() == before.contents() {
                    fs::write(&effective, if previous == "8" { "8\n" } else { "8-11\n" }).unwrap();
                }
                Ok(())
            };
            assert_eq!(
                restore_control_at(
                    directory.path(),
                    &before,
                    &applied,
                    0,
                    true,
                    observe_effective
                )
                .unwrap(),
                previous != "8"
            );
            assert_eq!(
                fs::read_to_string(&requested).unwrap(),
                format!("{previous}\n")
            );
            assert!(
                !restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(()))
                    .unwrap()
            );
            assert!(observe_original_control_at(directory.path(), &before, || Ok(())).is_ok());
            assert_eq!(fs::read_to_string(&sibling).unwrap(), "16-19\n");
        }
    }

    #[test]
    fn cpuset_restore_and_observation_refuse_external_or_missing_evidence_without_writes() {
        let directory = tempfile::tempdir().unwrap();
        let requested = directory.path().join("cpuset.cpus");
        let effective = directory.path().join("cpuset.cpus.effective");
        let before = ReversalValue::Cpuset {
            cpus: "8-11".to_string(),
        };
        let applied = ReversalValue::Cpuset {
            cpus: "8".to_string(),
        };
        fs::write(&requested, "8\n").unwrap();
        assert!(
            restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(())).is_err()
        );
        assert_eq!(fs::read_to_string(&requested).unwrap(), "8\n");
        for (current, available) in [
            ("9\n", "9\n"),
            ("\n", "8-11\n"),
            ("8\n", "\n"),
            ("8\n", "0-15\n"),
            ("8\n", "8,broken\n"),
            ("8-11\n", "0-15\n"),
        ] {
            fs::write(&requested, current).unwrap();
            fs::write(&effective, available).unwrap();
            assert!(
                restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(()))
                    .is_err(),
                "accepted {current:?}/{available:?}"
            );
            assert!(observe_original_control_at(directory.path(), &before, || Ok(())).is_err());
            assert_eq!(fs::read_to_string(&requested).unwrap(), current);
            assert_eq!(fs::read_to_string(&effective).unwrap(), available);
        }
        fs::write(&requested, "8\n").unwrap();
        fs::write(&effective, "8\n").unwrap();
        assert!(
            restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(())).is_err()
        );
        assert_eq!(fs::read_to_string(&requested).unwrap(), "8\n");
    }

    #[test]
    fn real_file_cpu_restore_preserves_exact_prior_limit_and_is_idempotent() {
        for before in [
            ReversalValue::CpuMax {
                quota_us: -1,
                period_us: 50_000,
            },
            ReversalValue::CpuMax {
                quota_us: 50_000,
                period_us: 100_000,
            },
            ReversalValue::CpuMax {
                quota_us: 10_000,
                period_us: 100_000,
            },
        ] {
            let directory = tempfile::tempdir().unwrap();
            let applied = if matches!(
                before,
                ReversalValue::CpuMax {
                    quota_us: 10_000,
                    ..
                }
            ) {
                before.clone()
            } else {
                ReversalValue::CpuMax {
                    quota_us: 25_000,
                    period_us: 100_000,
                }
            };
            fs::write(directory.path().join("cpu.max"), applied.contents()).unwrap();
            assert_eq!(
                restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(()))
                    .unwrap(),
                before != applied
            );
            assert_eq!(
                fs::read_to_string(directory.path().join("cpu.max")).unwrap(),
                before.contents()
            );
            assert!(
                !restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(()))
                    .unwrap()
            );
        }
    }

    #[test]
    fn real_file_restore_refuses_external_values_and_reuse_of_completed_receipts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cpu.max");
        let before = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let applied = ReversalValue::CpuMax {
            quota_us: 25_000,
            period_us: 100_000,
        };
        fs::write(&path, "17000 100000").unwrap();
        assert!(
            restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(())).is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "17000 100000");
        fs::write(&path, applied.contents()).unwrap();
        assert!(
            restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(())).is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), applied.contents());
    }

    #[test]
    fn completed_receipt_stays_non_mutating_after_a_new_prepared_restore_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let action = action(Action::Throttle);
        let before = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let applied = ReversalValue::CpuMax {
            quota_us: 25_000,
            period_us: 100_000,
        };
        let mut record = journal
            .insert(
                &action,
                operation(before.clone(), applied.clone()),
                ReversalStatus::Applied,
            )
            .unwrap();
        record.restorations.push(restored_outcome(&record));
        let mut next = restored_outcome(&record);
        next.status = RestorationStatus::Prepared;
        next.changed = None;
        record.restorations.push(next);
        // Another actor has returned the controller to the former applied cap.
        // The original completed receipt has no authority for another write,
        // even though restore() has appended a new Prepared outcome.
        let path = directory.path().join("cpu.max");
        fs::write(&path, applied.contents()).unwrap();
        assert!(record.is_restored());
        assert!(restore_record_at(&record, directory.path(), || Ok(())).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), applied.contents());
        record.restorations.last_mut().unwrap().status = RestorationStatus::Failed;
        assert!(record.is_restored());
        assert!(restore_record_at(&record, directory.path(), || Ok(())).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), applied.contents());
        fs::write(&path, before.contents()).unwrap();
        assert!(!restore_record_at(&record, directory.path(), || Ok(())).unwrap());
    }

    #[test]
    fn real_file_restore_rechecks_after_prepare_and_refuses_late_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cpu.max");
        let before = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let applied = ReversalValue::CpuMax {
            quota_us: 25_000,
            period_us: 100_000,
        };
        fs::write(&path, applied.contents()).unwrap();
        let calls = Cell::new(0);
        let result = restore_control_at(directory.path(), &before, &applied, 0, true, || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                fs::write(&path, "17000 100000").unwrap();
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "17000 100000");
    }

    #[test]
    fn real_file_freezer_restore_requires_completed_state_even_for_noop() {
        for before_requested in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let before = ReversalValue::Freeze {
                requested: before_requested,
            };
            let applied = ReversalValue::Freeze {
                requested: !before_requested,
            };
            fs::write(directory.path().join("cgroup.freeze"), applied.contents()).unwrap();
            fs::write(
                directory.path().join("cgroup.events"),
                format!("populated 1\nfrozen {}\n", u8::from(before_requested)),
            )
            .unwrap();
            assert!(
                restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(()))
                    .unwrap()
            );
            assert!(
                !restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(()))
                    .unwrap()
            );
            fs::write(
                directory.path().join("cgroup.events"),
                format!("frozen {}\n", u8::from(!before_requested)),
            )
            .unwrap();
            assert!(matches!(
                restore_control_at(directory.path(), &before, &applied, 0, false, || Ok(())),
                Err(ActionError::Timeout)
            ));
        }
    }

    #[test]
    fn malformed_controller_evidence_never_authorizes_restoration() {
        let directory = tempfile::tempdir().unwrap();
        let before = ReversalValue::CpuMax {
            quota_us: -1,
            period_us: 100_000,
        };
        let applied = ReversalValue::CpuMax {
            quota_us: 25_000,
            period_us: 100_000,
        };
        for contents in [
            "",
            "25000",
            "25000 100000 extra",
            "+25000 100000",
            "-1 100000",
            "max 0",
            "999 100000",
        ] {
            fs::write(directory.path().join("cpu.max"), contents).unwrap();
            assert!(
                restore_control_at(directory.path(), &before, &applied, 0, true, || Ok(()))
                    .is_err()
            );
            assert_eq!(
                fs::read_to_string(directory.path().join("cpu.max")).unwrap(),
                contents
            );
        }
    }
}
