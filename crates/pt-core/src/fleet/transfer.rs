//! Fleet learning transfer: bundle, merge, normalize, diff.
//!
//! Provides a combined transfer workflow that packages priors and signatures
//! into a single bundle, supports weighted merging of Beta-distributed
//! hyperparameters, baseline normalization across different host types, and
//! diff preview before applying changes.

use crate::supervision::pattern_persistence::{
    AllPatternStats, ConflictResolution, DisabledPatterns, ImportConflict, PatternLifecycle,
    PersistedPattern, PersistedSchema,
};
use crate::supervision::signature::SupervisorSignature;
use pt_config::priors::{BetaParams, ClassParams, Priors};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────

/// Current transfer bundle schema version.
pub const TRANSFER_SCHEMA_VERSION: &str = "1.0.0";

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("unsupported schema version: {0} (expected {TRANSFER_SCHEMA_VERSION})")]
    UnsupportedSchemaVersion(String),

    #[error("prior probabilities do not sum to 1.0 (sum = {0:.6})")]
    PriorProbSum(f64),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid weight: {0}")]
    InvalidWeight(String),

    #[error("invalid transfer configuration: {0}")]
    InvalidConfiguration(String),

    #[error("transfer contains detected sensitive content; intact configuration transfer refused")]
    SensitiveContent,

    #[error("fleet import publication failed: {0}")]
    Publication(String),
}

// A small state file blocks readers during publication. Exact old and new bytes
// are retained in a separate private journal, including after success: an error
// synchronizing the final state must never discard the only copy of a preimage.
const IMPORT_STATE_FILE: &str = ".fleet-transfer-state.json";
const IMPORT_JOURNAL_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const IMPORT_ARTIFACTS: [&str; 6] = [
    "priors.json",
    "priors.json.bak",
    "patterns/learned.json",
    "patterns/custom.json",
    "patterns/disabled.json",
    "pattern_stats.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportPhase {
    Pending,
    Committed,
    RolledBack,
}

/// Opaque comparison token for one completed publication or rollback. The
/// terminal phase matters: a visible commit marker can precede a failed fsync
/// and subsequent rollback of the same transaction UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationGeneration {
    id: uuid::Uuid,
    phase: ImportPhase,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportState {
    version: u32,
    id: uuid::Uuid,
    journal_sha256: String,
    phase: ImportPhase,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportFile {
    path: String,
    before: Option<String>,
    after: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportJournal {
    version: u32,
    id: uuid::Uuid,
    files: Vec<ImportFile>,
}

/// Durable recovery evidence for one completed import. The private journal
/// contains exact preimages even when the optional priors.json.bak is disabled.
#[derive(Debug, Serialize)]
pub struct ImportPublication {
    pub id: uuid::Uuid,
    pub recovery_journal: PathBuf,
}

/// Serialize fleet writers from before the local configuration is read until
/// every destination is published or recovered. Locking the directory avoids
/// predictable temporary names and does not add a lock file to dry-run output.
pub struct TransferImport {
    config_dir: PathBuf,
    directory: File,
    patterns_directory: RefCell<Option<File>>,
    baseline: BTreeMap<String, Result<Option<String>, String>>,
    recovered_import: Option<uuid::Uuid>,
}

impl TransferImport {
    /// Acquire the writer lock and recover an interrupted import before merging.
    pub fn begin(config_dir: &Path) -> Result<Self, TransferError> {
        Self::begin_locked(config_dir, true)
    }

    /// Hold the configuration writer lock without recovering a pending import.
    /// Ordinary writers acquire this BEFORE reading the values they will edit.
    pub fn begin_writer(config_dir: &Path) -> Result<Self, TransferError> {
        Self::begin_locked(config_dir, false)
    }

    fn begin_locked(config_dir: &Path, recover: bool) -> Result<Self, TransferError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(config_dir)?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(config_dir)?;
            // SAFETY: the directory descriptor remains owned by this guard.
            if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(TransferError::Publication(format!(
                    "cannot lock configuration directory (another import may be running): {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut import = Self {
                config_dir: config_dir.to_path_buf(),
                directory,
                patterns_directory: RefCell::new(None),
                baseline: BTreeMap::new(),
                recovered_import: None,
            };
            import.check_directory()?;
            if let Some(state) = read_import_state(config_dir)? {
                if state.phase == ImportPhase::Pending {
                    if !recover {
                        return Err(TransferError::Publication(
                            "configuration has a pending fleet import; run fleet transfer import to recover before changing configuration".into(),
                        ));
                    }
                    let journal = import.load_journal(&state)?;
                    import.rollback(&state, &journal)?;
                    import.recovered_import = Some(state.id);
                }
            }
            // Capture preimages before the caller reads and merges anything.
            // Errors for unrelated artifacts remain deferred until requested.
            for path in IMPORT_ARTIFACTS {
                let before = import
                    .read_artifact(path)
                    .map_err(|error| error.to_string());
                import.baseline.insert(path.to_string(), before);
            }
            Ok(import)
        }
        #[cfg(not(unix))]
        {
            let _ = (config_dir, recover);
            Err(TransferError::Publication(
                "durable fleet import requires Unix directory locking and synchronization".into(),
            ))
        }
    }

    pub fn recovered_import(&self) -> Option<uuid::Uuid> {
        self.recovered_import
    }

    /// Publish one JSON document while retaining this guard's writer lock and
    /// pinned destination directory. Callers must hold the guard across reads.
    pub fn write_json(&self, relative: &Path, bytes: &[u8]) -> Result<(), TransferError> {
        serde_json::from_slice::<serde::de::IgnoredAny>(bytes)?;
        self.check_directory()?;
        let name = relative
            .to_str()
            .ok_or_else(|| TransferError::Publication("non-UTF-8 artifact path".into()))?;
        let allowed = relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
            && (relative.components().count() == 1 || IMPORT_ARTIFACTS.contains(&name));
        if !allowed {
            return Err(TransferError::Publication(
                "unsupported configuration write path".into(),
            ));
        }
        let parent = self
            .parent_directory(relative, true)?
            .ok_or_else(|| TransferError::Publication("missing artifact directory".into()))?;
        let path = self.config_dir.join(relative);
        // The ordinary priors importer historically replaces a backup symlink
        // without following it. The pinned-parent writer preserves that safe
        // behavior. Transactional imports still validate/snapshot the backup
        // via baseline_for/read_artifact before reaching this publication step.
        if name != "priors.json.bak" {
            read_import_json(&path, MAX_JOURNAL_BYTES)?;
        }
        crate::session::write_serialized_json_at(&path, &parent, bytes)
            .map_err(|error| TransferError::Publication(error.to_string()))
    }

    fn baseline_for(&self, relative: &str) -> Result<Option<String>, TransferError> {
        let before = self
            .baseline
            .get(relative)
            .ok_or_else(|| TransferError::Publication("missing artifact baseline".into()))?
            .as_ref()
            .map_err(|error| TransferError::Publication(error.clone()))?
            .clone();
        if self.read_artifact(relative)? != before {
            return Err(TransferError::Publication(format!(
                "{relative} changed since the import began; reload before merging"
            )));
        }
        Ok(before)
    }

    /// Validate and stage every artifact before touching any destination. A
    /// durable pending state precedes publication; failures restore exact old
    /// bytes, and interruption is recovered by the next non-preview import.
    pub fn publish(
        &self,
        files: Vec<(PathBuf, Vec<u8>)>,
        backup_priors: bool,
    ) -> Result<Option<ImportPublication>, TransferError> {
        self.publish_with(files, backup_priors, |path, bytes| {
            let relative = path.strip_prefix(&self.config_dir).map_err(|_| {
                TransferError::Publication("artifact escaped configuration directory".into())
            })?;
            self.write_json(relative, bytes)
        })
    }

    fn publish_with(
        &self,
        files: Vec<(PathBuf, Vec<u8>)>,
        backup_priors: bool,
        mut publish: impl FnMut(&Path, &[u8]) -> Result<(), TransferError>,
    ) -> Result<Option<ImportPublication>, TransferError> {
        self.check_directory()?;
        configuration_generation(&self.config_dir)?;
        if files.is_empty() {
            return Ok(None);
        }
        let mut journal = ImportJournal {
            version: IMPORT_JOURNAL_VERSION,
            id: uuid::Uuid::new_v4(),
            files: Vec::new(),
        };
        for (relative, bytes) in files {
            let path = relative
                .to_str()
                .ok_or_else(|| TransferError::Publication("non-UTF-8 artifact path".into()))?
                .to_string();
            validate_import_path(&path)?;
            let after = String::from_utf8(bytes)
                .map_err(|_| TransferError::Publication("non-UTF-8 configuration".into()))?;
            validate_import_payload(&path, &after)?;
            let before = self.baseline_for(&path)?;
            journal.files.push(ImportFile {
                path,
                before,
                after,
            });
        }
        if backup_priors {
            if let Some(before) = journal
                .files
                .iter()
                .find(|file| file.path == "priors.json")
                .and_then(|file| file.before.clone())
            {
                journal.files.push(ImportFile {
                    path: "priors.json.bak".into(),
                    before: self.baseline_for("priors.json.bak")?,
                    after: before,
                });
            }
        }
        validate_import_journal(&journal)?;
        let bytes = serde_json::to_vec_pretty(&journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(TransferError::Publication(
                "import journal is too large".into(),
            ));
        }
        let path = self.journal_path(journal.id);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(TransferError::Publication(
                "import journal already exists".into(),
            ));
        }
        self.write_json(
            Path::new(path.file_name().expect("journal has a filename")),
            &bytes,
        )?;
        let mut state = ImportState {
            version: IMPORT_JOURNAL_VERSION,
            id: journal.id,
            journal_sha256: hex::encode(Sha256::digest(&bytes)),
            phase: ImportPhase::Pending,
        };
        // Validate the persisted staging, not only the values in memory.
        self.load_journal(&state)?;
        self.write_state(&state)?;
        for file in &journal.files {
            let result = (|| {
                self.check_directory()?;
                if self.read_artifact(&file.path)? != file.before {
                    return Err(TransferError::Publication(format!(
                        "{} changed after staging; refusing to overwrite it",
                        file.path
                    )));
                }
                publish(&self.config_dir.join(&file.path), file.after.as_bytes())
            })();
            if let Err(error) = result {
                return Err(self.publication_failure(error, &state, &journal));
            }
        }
        state.phase = ImportPhase::Committed;
        if let Err(error) = self.write_state(&state) {
            // A state rename may have succeeded before its fsync failed. Make
            // Pending durable again BEFORE changing any published artifact.
            state.phase = ImportPhase::Pending;
            if let Err(pending_error) = self.write_state(&state) {
                return Err(TransferError::Publication(format!(
                    "all artifacts published, but commit durability could not be confirmed: {error}; \
                     could not persist recovery state: {pending_error}; exact originals retained at {}",
                    path.display()
                )));
            }
            return Err(self.publication_failure(error, &state, &journal));
        }
        Ok(Some(ImportPublication {
            id: state.id,
            recovery_journal: path,
        }))
    }

    fn publication_failure(
        &self,
        error: TransferError,
        state: &ImportState,
        journal: &ImportJournal,
    ) -> TransferError {
        let recovery = match self.rollback(state, journal) {
            Ok(()) => "all original artifacts restored".to_string(),
            Err(rollback) => format!(
                "recovery remains pending: {rollback}; exact originals retained at {}",
                self.journal_path(state.id).display()
            ),
        };
        TransferError::Publication(format!("{error}; {recovery}"))
    }

    fn journal_path(&self, id: uuid::Uuid) -> PathBuf {
        self.config_dir.join(format!(".fleet-transfer-{id}.json"))
    }

    fn write_state(&self, state: &ImportState) -> Result<(), TransferError> {
        self.check_directory()?;
        let path = self.config_dir.join(IMPORT_STATE_FILE);
        // Never replace a substituted symlink or non-regular journal marker.
        read_import_json(&path, MAX_CONFIG_BYTES)?;
        self.write_json(
            Path::new(IMPORT_STATE_FILE),
            &serde_json::to_vec_pretty(state)?,
        )
    }

    fn load_journal(&self, state: &ImportState) -> Result<ImportJournal, TransferError> {
        self.check_directory()?;
        let bytes = read_import_json(&self.journal_path(state.id), MAX_JOURNAL_BYTES)?
            .ok_or_else(|| TransferError::Publication("missing import recovery journal".into()))?;
        if hex::encode(Sha256::digest(bytes.as_bytes())) != state.journal_sha256 {
            return Err(TransferError::Publication(
                "import recovery checksum mismatch".into(),
            ));
        }
        let journal: ImportJournal = serde_json::from_str(&bytes)?;
        if journal.id != state.id {
            return Err(TransferError::Publication(
                "import recovery identity mismatch".into(),
            ));
        }
        validate_import_journal(&journal)?;
        Ok(journal)
    }

    fn read_artifact(&self, relative: &str) -> Result<Option<String>, TransferError> {
        validate_import_path(relative)?;
        self.check_directory()?;
        if self.parent_directory(Path::new(relative), false)?.is_none() {
            return Ok(None);
        }
        read_import_json(&self.config_dir.join(relative), MAX_CONFIG_BYTES)
    }

    fn parent_directory(
        &self,
        relative: &Path,
        create: bool,
    ) -> Result<Option<File>, TransferError> {
        self.check_directory()?;
        if relative
            .parent()
            .is_none_or(|parent| parent.as_os_str().is_empty())
        {
            return Ok(Some(self.directory.try_clone()?));
        }
        if relative.parent() != Some(Path::new("patterns")) {
            return Err(TransferError::Publication(
                "unsupported artifact parent".into(),
            ));
        }
        let path = self.config_dir.join("patterns");
        let mut pinned = self.patterns_directory.borrow_mut();
        if pinned.is_none() {
            *pinned = open_import_subdirectory(&self.directory, "patterns", create, false)?;
        }
        if let Some(directory) = pinned.as_ref() {
            validate_import_directory(&path, directory)?;
            Ok(Some(directory.try_clone()?))
        } else {
            Ok(None)
        }
    }

    fn check_directory(&self) -> Result<(), TransferError> {
        validate_import_directory(&self.config_dir, &self.directory)
    }

    fn rollback(&self, state: &ImportState, journal: &ImportJournal) -> Result<(), TransferError> {
        self.rollback_with_sync(state, journal, File::sync_all)
    }

    fn rollback_with_sync(
        &self,
        state: &ImportState,
        journal: &ImportJournal,
        synchronize: impl Fn(&File) -> std::io::Result<()>,
    ) -> Result<(), TransferError> {
        validate_import_journal(journal)?;
        // Validate every destination before making recovery changes. An unrelated
        // writer's bytes are preserved; a pending marker keeps readers out.
        for file in &journal.files {
            let current = self.read_artifact(&file.path)?;
            if current != file.before && current.as_deref() != Some(file.after.as_str()) {
                return Err(TransferError::Publication(format!(
                    "{} changed independently; refusing recovery overwrite",
                    file.path
                )));
            }
        }
        let mut retained = None;
        for (index, file) in journal.files.iter().enumerate().rev() {
            let current = self.read_artifact(&file.path)?;
            if current == file.before {
                // A previous recovery may have renamed the original into place
                // (or retired a new file) before its parent fsync failed. Visible
                // bytes/absence are not yet proof of durable recovery.
                if let Some(parent) = self.parent_directory(Path::new(&file.path), false)? {
                    synchronize(&parent)?;
                    self.check_directory()?;
                    let path = self.config_dir.join(&file.path);
                    validate_import_directory(
                        path.parent().expect("artifact has a parent"),
                        &parent,
                    )?;
                }
                continue;
            }
            if current.as_deref() != Some(file.after.as_str()) {
                return Err(TransferError::Publication(
                    "artifact changed during recovery".into(),
                ));
            }
            let path = self.config_dir.join(&file.path);
            if let Some(before) = &file.before {
                self.write_json(Path::new(&file.path), before.as_bytes())?;
            } else {
                // A newly created artifact has no original to restore. Retain
                // it outside the active names instead of deleting any file.
                if retained.is_none() {
                    let name = format!(".fleet-transfer-recovered-{}", uuid::Uuid::new_v4());
                    let directory = open_import_subdirectory(&self.directory, &name, true, true)?
                        .ok_or_else(|| {
                        TransferError::Publication("missing recovery directory".into())
                    })?;
                    retained = Some((self.config_dir.join(name), directory));
                }
                let (directory_path, directory) =
                    retained.as_ref().expect("recovery directory was created");
                self.check_directory()?;
                let source_parent = self
                    .parent_directory(Path::new(&file.path), false)?
                    .ok_or_else(|| TransferError::Publication("missing source parent".into()))?;
                crate::session::retire_serialized_json_at(
                    &path,
                    &source_parent,
                    &directory_path.join(format!("{index}.json")),
                    directory,
                    file.after.as_bytes(),
                )
                .map_err(|error| TransferError::Publication(error.to_string()))?;
            }
        }
        self.write_state(&ImportState {
            version: state.version,
            id: state.id,
            journal_sha256: state.journal_sha256.clone(),
            phase: ImportPhase::RolledBack,
        })
    }
}

fn validate_import_directory(path: &Path, directory: &File) -> Result<(), TransferError> {
    let current = fs::symlink_metadata(path)?;
    let saved = directory.metadata()?;
    #[cfg(unix)]
    let same_identity = {
        use std::os::unix::fs::MetadataExt;
        current.dev() == saved.dev() && current.ino() == saved.ino()
    };
    #[cfg(not(unix))]
    let same_identity = saved.is_dir();
    if !current.is_dir() || !same_identity {
        return Err(TransferError::Publication(
            "configuration directory identity changed or became a symlink".into(),
        ));
    }
    Ok(())
}

/// Open one child relative to the already locked root. A replaced path cannot
/// redirect directory creation outside that inode; the caller also checks the
/// public path against this descriptor before publishing through it.
fn open_import_subdirectory(
    root: &File,
    name: &str,
    create: bool,
    exclusive: bool,
) -> Result<Option<File>, TransferError> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        if Path::new(name).components().count() != 1
            || !matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(TransferError::Publication(
                "invalid import directory name".into(),
            ));
        }
        let name = std::ffi::CString::new(name)
            .map_err(|_| TransferError::Publication("invalid import directory name".into()))?;
        if create {
            // SAFETY: the descriptor and single-component C string stay live.
            if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if exclusive || error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
        }
        // SAFETY: openat resolves one child of the held inode and refuses links.
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if !create && error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        // SAFETY: ownership of the new descriptor is transferred exactly once.
        let directory = unsafe { File::from_raw_fd(fd) };
        if create {
            directory.sync_all()?;
            root.sync_all()?;
        }
        Ok(Some(directory))
    }
    #[cfg(not(unix))]
    {
        let _ = (root, name, create, exclusive);
        Err(TransferError::Publication(
            "durable import requires Unix directories".into(),
        ))
    }
}

/// Read guards compare this generation before and after loading related files.
/// Pending or malformed state fails closed; generation changes detect imports
/// that complete between reads. This is not a cross-command snapshot lock.
pub fn configuration_generation(
    config_dir: &Path,
) -> Result<Option<ConfigurationGeneration>, TransferError> {
    match read_import_state(config_dir)? {
        Some(state) if state.phase == ImportPhase::Pending => Err(TransferError::Publication(
            "configuration has an interrupted or active fleet import; retry a non-dry-run fleet transfer import to recover it".into(),
        )),
        state => Ok(state.map(|state| ConfigurationGeneration {
            id: state.id,
            phase: state.phase,
        })),
    }
}

fn read_import_state(config_dir: &Path) -> Result<Option<ImportState>, TransferError> {
    let Some(bytes) = read_import_json(&config_dir.join(IMPORT_STATE_FILE), MAX_CONFIG_BYTES)?
    else {
        return Ok(None);
    };
    let state: ImportState = serde_json::from_str(&bytes)?;
    if state.version != IMPORT_JOURNAL_VERSION
        || state.id.is_nil()
        || state.journal_sha256.len() != 64
        || !state
            .journal_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TransferError::Publication(
            "invalid import recovery state".into(),
        ));
    }
    Ok(Some(state))
}

fn validate_import_path(path: &str) -> Result<(), TransferError> {
    if !matches!(
        path,
        "priors.json"
            | "priors.json.bak"
            | "patterns/learned.json"
            | "patterns/custom.json"
            | "patterns/disabled.json"
            | "pattern_stats.json"
    ) {
        return Err(TransferError::Publication(
            "unsupported import artifact path".into(),
        ));
    }
    Ok(())
}

fn validate_import_payload(path: &str, bytes: &str) -> Result<(), TransferError> {
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(TransferError::Publication(
            "configuration artifact is too large".into(),
        ));
    }
    match path {
        "priors.json" => {
            let priors: Priors = serde_json::from_str(bytes)?;
            pt_config::validate::validate_priors(&priors)
                .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
        }
        "patterns/learned.json" | "patterns/custom.json" => {
            let schema = PersistedSchema::from_json(bytes)
                .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
            for pattern in &schema.patterns {
                pattern
                    .signature
                    .validate_for_activation()
                    .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
            }
        }
        "patterns/disabled.json" => {
            serde_json::from_str::<DisabledPatterns>(bytes)?;
        }
        "pattern_stats.json" => {
            serde_json::from_str::<AllPatternStats>(bytes)?;
        }
        "priors.json.bak" => {
            serde_json::from_str::<serde::de::IgnoredAny>(bytes)?;
        }
        _ => {
            return Err(TransferError::Publication(
                "unsupported import artifact path".into(),
            ));
        }
    }
    Ok(())
}

fn validate_import_journal(journal: &ImportJournal) -> Result<(), TransferError> {
    if journal.version != IMPORT_JOURNAL_VERSION
        || journal.id.is_nil()
        || journal.files.is_empty()
        || journal.files.len() > 6
    {
        return Err(TransferError::Publication(
            "invalid import recovery journal".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for file in &journal.files {
        validate_import_path(&file.path)?;
        if !seen.insert(&file.path) {
            return Err(TransferError::Publication(
                "duplicate import artifact".into(),
            ));
        }
        validate_import_payload(&file.path, &file.after)?;
        if let Some(before) = &file.before {
            if before.len() as u64 > MAX_CONFIG_BYTES {
                return Err(TransferError::Publication(
                    "configuration preimage is too large".into(),
                ));
            }
            serde_json::from_str::<serde::de::IgnoredAny>(before)?;
        }
    }
    Ok(())
}

fn read_import_json(path: &Path, limit: u64) -> Result<Option<String>, TransferError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) if !metadata.is_file() => {
            return Err(TransferError::Publication(format!(
                "{} must be a regular file, not a symlink or special file",
                path.display()
            )));
        }
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(TransferError::Publication(
            "invalid or oversized configuration file".into(),
        ));
    }
    let mut bytes = String::new();
    file.take(limit + 1).read_to_string(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(TransferError::Publication(
            "configuration file exceeds size limit".into(),
        ));
    }
    serde_json::from_str::<serde::de::IgnoredAny>(&bytes)?;
    Ok(Some(bytes))
}

#[cfg(test)]
fn publish_import_json(path: &Path, bytes: &[u8]) -> Result<(), TransferError> {
    crate::session::write_serialized_json(path, bytes)
        .map_err(|error| TransferError::Publication(error.to_string()))
}

#[cfg(all(test, unix))]
mod publication_tests {
    use super::*;
    use crate::config::{load_config, ConfigOptions};
    use crate::supervision::pattern_persistence::PatternLibrary;
    use crate::supervision::SupervisorCategory;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn fixture() -> (PathBuf, String) {
        let root = tempfile::Builder::new()
            .prefix("pt-fleet-import-")
            .tempdir()
            .unwrap()
            .keep();
        let original = format!(
            "{}\n  \n",
            serde_json::to_string(&Priors::default()).unwrap()
        );
        fs::write(root.join("priors.json"), &original).unwrap();
        eprintln!(
            "Fleet import recovery artifacts retained at {}",
            root.display()
        );
        (root, original)
    }

    fn incoming_priors() -> Vec<u8> {
        let mut priors = Priors::default();
        priors.classes.useful.prior_prob = 0.4;
        priors.classes.useful_bad.prior_prob = 0.2;
        priors.classes.abandoned.prior_prob = 0.3;
        priors.classes.zombie.prior_prob = 0.1;
        serde_json::to_vec_pretty(&priors).unwrap()
    }

    fn incoming_patterns() -> Vec<(PathBuf, Vec<u8>)> {
        let mut library = PatternLibrary::new(Path::new("unused-import-source"));
        library
            .add_custom(
                SupervisorSignature::new("imported-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^imported-worker$"])
                    .with_confidence(0.9),
            )
            .unwrap();
        library.pending_files().unwrap()
    }

    fn config_options(root: &Path) -> ConfigOptions {
        ConfigOptions {
            config_dir: Some(root.into()),
            ..ConfigOptions::default()
        }
    }

    #[test]
    fn publication_commits_all_artifacts_with_exact_private_recovery_and_backup() {
        let (root, original) = fixture();
        let import = TransferImport::begin(&root).unwrap();
        let mut files = vec![(PathBuf::from("priors.json"), incoming_priors())];
        files.extend(incoming_patterns());
        let publication = import.publish(files.clone(), true).unwrap().unwrap();
        for (path, expected) in files {
            assert_eq!(fs::read(root.join(path)).unwrap(), expected);
        }
        assert_eq!(
            fs::read_to_string(root.join("priors.json.bak")).unwrap(),
            original
        );
        assert_eq!(
            fs::metadata(&publication.recovery_journal)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join(IMPORT_STATE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let state = read_import_state(&root).unwrap().unwrap();
        assert_eq!(state.phase, ImportPhase::Committed);
        let journal = import.load_journal(&state).unwrap();
        assert_eq!(journal.files.len(), 6);
        assert_eq!(journal.files[0].before.as_deref(), Some(original.as_str()));
        assert_eq!(
            configuration_generation(&root).unwrap(),
            Some(ConfigurationGeneration {
                id: publication.id,
                phase: ImportPhase::Committed,
            })
        );
        assert_eq!(
            load_config(&config_options(&root))
                .unwrap()
                .priors
                .classes
                .useful
                .prior_prob,
            0.4
        );
        let mut library = PatternLibrary::new(&root);
        library.load().unwrap();
        assert!(library.get_pattern("imported-worker").is_some());
        drop(import);
        let import = TransferImport::begin(&root).unwrap();
        let next = import
            .publish(vec![("priors.json".into(), incoming_priors())], false)
            .unwrap()
            .unwrap();
        assert_ne!(publication.id, next.id);
        assert!(publication.recovery_journal.is_file());
        assert!(next.recovery_journal.is_file());
    }

    #[test]
    fn publication_later_write_failure_restores_originals_and_retires_new_artifacts() {
        let (root, original) = fixture();
        fs::create_dir(root.join("patterns")).unwrap();
        let original_custom = format!("{}\n  ", PersistedSchema::new().to_json().unwrap());
        fs::write(root.join("patterns/custom.json"), &original_custom).unwrap();
        let pattern_files = incoming_patterns();
        let custom = pattern_files
            .iter()
            .find(|(path, _)| path == Path::new("patterns/custom.json"))
            .unwrap()
            .1
            .clone();
        let learned = pattern_files
            .iter()
            .find(|(path, _)| path == Path::new("patterns/learned.json"))
            .unwrap()
            .1
            .clone();
        let import = TransferImport::begin(&root).unwrap();
        let mut writes = 0;
        let result = import.publish_with(
            vec![
                ("priors.json".into(), incoming_priors()),
                ("patterns/learned.json".into(), learned.clone()),
                ("patterns/custom.json".into(), custom),
            ],
            true,
            |path, bytes| {
                // Exercise failure AFTER a real later-file atomic rename, as can
                // happen when synchronizing its parent directory fails.
                import.write_json(path.strip_prefix(&root).unwrap(), bytes)?;
                writes += 1;
                if writes == 3 {
                    return Err(
                        std::io::Error::other("later artifact synchronization failed").into(),
                    );
                }
                Ok(())
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("all original artifacts restored"));
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            original
        );
        assert_eq!(
            fs::read_to_string(root.join("patterns/custom.json")).unwrap(),
            original_custom
        );
        assert!(!root.join("patterns/learned.json").exists());
        assert!(!root.join("priors.json.bak").exists());
        let recovered = fs::read_dir(&root)
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".fleet-transfer-recovered-")
            })
            .unwrap()
            .path();
        assert_eq!(fs::read(recovered.join("1.json")).unwrap(), learned);
        assert_eq!(
            read_import_state(&root).unwrap().unwrap().phase,
            ImportPhase::RolledBack
        );
        load_config(&config_options(&root)).unwrap();
    }

    #[test]
    fn publication_same_transaction_rollback_changes_the_reader_generation() {
        let (root, original) = fixture();
        let import = TransferImport::begin(&root).unwrap();
        import
            .publish(vec![("priors.json".into(), incoming_priors())], false)
            .unwrap();
        let committed = configuration_generation(&root).unwrap();
        let mut state = read_import_state(&root).unwrap().unwrap();
        let journal = import.load_journal(&state).unwrap();
        // A successful rename followed by a failed directory fsync can expose
        // Committed before publication has to restore Pending and roll back.
        state.phase = ImportPhase::Pending;
        import.write_state(&state).unwrap();
        assert!(configuration_generation(&root).is_err());
        import.rollback(&state, &journal).unwrap();
        let rolled_back = configuration_generation(&root).unwrap();
        assert_ne!(committed, rolled_back);
        assert_eq!(committed.unwrap().id, rolled_back.unwrap().id);
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            original
        );
    }

    #[test]
    fn publication_recovery_retry_syncs_already_restored_or_retired_pattern_entries() {
        use std::os::unix::fs::MetadataExt;
        for existed in [false, true] {
            let (root, _) = fixture();
            fs::create_dir(root.join("patterns")).unwrap();
            let artifact = root.join("patterns/custom.json");
            let original = PersistedSchema::new().to_json().unwrap();
            if existed {
                fs::write(&artifact, &original).unwrap();
            }
            let import = TransferImport::begin(&root).unwrap();
            let custom = incoming_patterns()
                .into_iter()
                .find(|(path, _)| path == Path::new("patterns/custom.json"))
                .unwrap();
            import.publish(vec![custom], false).unwrap();
            let mut state = read_import_state(&root).unwrap().unwrap();
            let journal = import.load_journal(&state).unwrap();
            state.phase = ImportPhase::Pending;
            import.write_state(&state).unwrap();
            // Leave the real filesystem at the exact rename-before-parent-sync
            // boundary of an interrupted recovery, for either kind of preimage.
            if existed {
                let restore = root.join("patterns/restore.json");
                fs::write(&restore, &original).unwrap();
                File::open(&restore).unwrap().sync_all().unwrap();
                fs::rename(restore, &artifact).unwrap();
            } else {
                fs::rename(&artifact, root.join("retained-new-pattern.json")).unwrap();
            }
            let metadata = fs::metadata(root.join("patterns")).unwrap();
            let attempts = std::cell::Cell::new(0);
            let error = import
                .rollback_with_sync(&state, &journal, |directory| {
                    let current = directory.metadata()?;
                    if (current.dev(), current.ino()) == (metadata.dev(), metadata.ino()) {
                        attempts.set(attempts.get() + 1);
                        Err(std::io::Error::other("forced retry parent sync failure"))
                    } else {
                        directory.sync_all()
                    }
                })
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("forced retry parent sync failure"));
            assert_eq!(attempts.get(), 1);
            assert_eq!(
                read_import_state(&root).unwrap().unwrap().phase,
                ImportPhase::Pending
            );
            assert!(configuration_generation(&root).is_err());
            drop(import);
            let recovered = TransferImport::begin(&root).unwrap();
            assert_eq!(recovered.recovered_import(), Some(state.id));
            assert_eq!(
                read_import_state(&root).unwrap().unwrap().phase,
                ImportPhase::RolledBack
            );
            if existed {
                assert_eq!(fs::read_to_string(&artifact).unwrap(), original);
            } else {
                assert!(!artifact.exists());
                assert!(root.join("retained-new-pattern.json").is_file());
            }
        }
    }

    #[test]
    fn publication_validates_every_staged_artifact_before_creating_a_journal() {
        for (path, payload) in [
            ("patterns/custom.json", b"{not-json".to_vec()),
            ("../outside.json", incoming_priors()),
            ("patterns/../priors.json", incoming_priors()),
            ("priors.json", incoming_priors()),
        ] {
            let (root, original) = fixture();
            let import = TransferImport::begin(&root).unwrap();
            assert!(import
                .publish(
                    vec![
                        ("priors.json".into(), incoming_priors()),
                        (path.into(), payload),
                    ],
                    false
                )
                .is_err());
            assert_eq!(
                fs::read_to_string(root.join("priors.json")).unwrap(),
                original
            );
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        }
    }

    fn interrupt_after_first_publication(root: &Path) -> ImportState {
        let import = TransferImport::begin(root).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let mut files = vec![("priors.json".into(), incoming_priors())];
            files.extend(incoming_patterns());
            let _ = import.publish_with(files, false, |path, bytes| {
                import.write_json(path.strip_prefix(root).unwrap(), bytes)?;
                panic!("interrupt after the first durable publication");
            });
        }))
        .is_err());
        let state = read_import_state(root).unwrap().unwrap();
        assert_eq!(state.phase, ImportPhase::Pending);
        // Dropping the actual directory lock models the writer exiting. Its
        // files remain untouched for the next independent import to recover.
        drop(import);
        state
    }

    #[test]
    fn publication_interruption_blocks_readers_and_next_import_recovers_before_merging() {
        let (root, original) = fixture();
        let pending = interrupt_after_first_publication(&root);
        assert_eq!(
            fs::read(root.join("priors.json")).unwrap(),
            incoming_priors()
        );
        assert!(load_config(&config_options(&root))
            .unwrap_err()
            .to_string()
            .contains("interrupted or active fleet import"));
        assert!(PatternLibrary::new(&root)
            .load()
            .unwrap_err()
            .to_string()
            .contains("interrupted or active fleet import"));
        let import = TransferImport::begin(&root).unwrap();
        assert_eq!(import.recovered_import(), Some(pending.id));
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            original
        );
        assert_eq!(
            read_import_state(&root).unwrap().unwrap().phase,
            ImportPhase::RolledBack
        );
        load_config(&config_options(&root)).unwrap();
        let publication = import
            .publish(vec![("priors.json".into(), incoming_priors())], false)
            .unwrap()
            .unwrap();
        assert_ne!(publication.id, pending.id);
        assert!(!root.join("priors.json.bak").exists());
    }

    #[test]
    fn publication_recovery_preserves_independent_edits_and_keeps_exact_preimages() {
        let (root, original) = fixture();
        let state = interrupt_after_first_publication(&root);
        let external = format!("{}\n", String::from_utf8(incoming_priors()).unwrap());
        fs::write(root.join("priors.json"), &external).unwrap();
        let error = match TransferImport::begin(&root) {
            Ok(_) => panic!("independently changed file must refuse recovery"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("changed independently"));
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            external
        );
        let journal: ImportJournal = serde_json::from_slice(
            &fs::read(root.join(format!(".fleet-transfer-{}.json", state.id))).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.files[0].before.as_deref(), Some(original.as_str()));
        assert!(configuration_generation(&root).is_err());
    }

    #[test]
    fn publication_writer_lock_excludes_concurrent_imports_without_a_lock_file() {
        let (root, original) = fixture();
        let import = TransferImport::begin(&root).unwrap();
        let other_root = root.clone();
        assert!(
            std::thread::spawn(move || TransferImport::begin(&other_root).is_err())
                .join()
                .unwrap()
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            original
        );
        drop(import);
        TransferImport::begin(&root).unwrap();
    }

    #[test]
    fn publication_rejects_edits_since_begin_before_capturing_stale_merge_preimages() {
        let (root, original) = fixture();
        let import = TransferImport::begin(&root).unwrap();
        let independently_edited = format!("{original}\n");
        fs::write(root.join("priors.json"), &independently_edited).unwrap();
        let error = import
            .publish(vec![("priors.json".into(), incoming_priors())], false)
            .unwrap_err();
        assert!(error.to_string().contains("changed since the import began"));
        assert_eq!(
            fs::read_to_string(root.join("priors.json")).unwrap(),
            independently_edited
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    fn publication_existing_writers_cannot_race_and_loaded_libraries_cannot_undo_imports() {
        let (root, _) = fixture();
        let mut library = PatternLibrary::new(&root);
        library
            .add_custom(
                SupervisorSignature::new("local-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^local-worker$"]),
            )
            .unwrap();
        library.save().unwrap();
        let mut stale = PatternLibrary::new(&root);
        stale.load().unwrap();
        stale
            .add_custom(
                SupervisorSignature::new("stale-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^stale-worker$"]),
            )
            .unwrap();
        let import = TransferImport::begin(&root).unwrap();
        let disabled_before = fs::read(root.join("patterns/disabled.json")).unwrap();
        let mut disabled = DisabledPatterns::default();
        disabled.disable("imported-worker", Some("concurrent edit"));
        assert!(crate::signature_cli::save_disabled_patterns(&root, &disabled).is_err());
        assert!(stale.save().is_err());
        assert_eq!(
            fs::read(root.join("patterns/disabled.json")).unwrap(),
            disabled_before
        );
        import.publish(incoming_patterns(), false).unwrap();
        drop(import);
        let imported_bytes = fs::read(root.join("patterns/custom.json")).unwrap();
        assert!(stale.save().unwrap_err().to_string().contains("reload"));
        assert_eq!(
            fs::read(root.join("patterns/custom.json")).unwrap(),
            imported_bytes
        );
        let mut current = PatternLibrary::new(&root);
        current.load().unwrap();
        assert!(current.get_pattern("imported-worker").is_some());
        assert!(current.get_pattern("stale-worker").is_none());

        // Ordinary disabled-pattern edits don't publish a fleet generation;
        // exact file preimages still detect them before an old library saves.
        current
            .add_custom(
                SupervisorSignature::new("another-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^another-worker$"]),
            )
            .unwrap();
        crate::signature_cli::save_disabled_patterns(&root, &disabled).unwrap();
        let edited_bytes = fs::read(root.join("patterns/disabled.json")).unwrap();
        assert!(current.save().unwrap_err().to_string().contains("reload"));
        assert_eq!(
            fs::read(root.join("patterns/disabled.json")).unwrap(),
            edited_bytes
        );
    }

    #[test]
    fn publication_refuses_replaced_root_and_pattern_directories() {
        for replace_root in [false, true] {
            let (root, original) = fixture();
            fs::create_dir(root.join("patterns")).unwrap();
            let custom = PersistedSchema::new().to_json().unwrap();
            fs::write(root.join("patterns/custom.json"), &custom).unwrap();
            let import = TransferImport::begin(&root).unwrap();
            let (path, moved) = if replace_root {
                (
                    root.clone(),
                    root.with_extension(format!("retained-{}", uuid::Uuid::new_v4())),
                )
            } else {
                (root.join("patterns"), root.join("retained-patterns"))
            };
            fs::rename(&path, &moved).unwrap();
            fs::create_dir(&path).unwrap();
            fs::write(path.join("canary.json"), b"{\"keep\":true}").unwrap();
            assert!(import.publish(incoming_patterns(), false).is_err());
            assert_eq!(
                fs::read(path.join("canary.json")).unwrap(),
                b"{\"keep\":true}"
            );
            assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
            let original_root = if replace_root { &moved } else { &root };
            assert_eq!(
                fs::read_to_string(original_root.join("priors.json")).unwrap(),
                original
            );
            let original_custom = if replace_root {
                moved.join("patterns/custom.json")
            } else {
                moved.join("custom.json")
            };
            assert_eq!(fs::read_to_string(original_custom).unwrap(), custom);
        }
    }

    #[test]
    fn publication_library_requires_loading_existing_files_before_save() {
        let (root, _) = fixture();
        let import = TransferImport::begin(&root).unwrap();
        import.publish(incoming_patterns(), false).unwrap();
        drop(import);
        let original = fs::read(root.join("patterns/custom.json")).unwrap();
        let mut unloaded = PatternLibrary::new(&root);
        unloaded
            .add_custom(
                SupervisorSignature::new("new-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^new-worker$"]),
            )
            .unwrap();
        assert!(unloaded.save().unwrap_err().to_string().contains("reload"));
        assert_eq!(
            fs::read(root.join("patterns/custom.json")).unwrap(),
            original
        );
        unloaded.load().unwrap();
        unloaded
            .add_custom(
                SupervisorSignature::new("new-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^new-worker$"]),
            )
            .unwrap();
        unloaded.save().unwrap();
        let mut checked = PatternLibrary::new(&root);
        checked.load().unwrap();
        assert!(checked.get_pattern("new-worker").is_some());
        assert!(checked.get_pattern("imported-worker").is_some());
    }

    #[test]
    fn publication_readers_do_not_create_missing_configuration_directories() {
        let (root, _) = fixture();
        let missing = root.join("missing-config");
        load_config(&config_options(&missing)).unwrap();
        let mut library = PatternLibrary::new(&missing);
        library.load().unwrap();
        assert!(library.all_active_patterns().is_empty());
        assert!(!missing.exists());
    }

    #[test]
    fn publication_rejects_symlink_destinations_and_recovery_markers() {
        for kind in ["artifact", "parent", "state", "journal"] {
            let (root, original) = fixture();
            let outside = root.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(
                outside.join("custom.json"),
                PersistedSchema::new().to_json().unwrap(),
            )
            .unwrap();
            fs::write(outside.join("state.json"), "{}").unwrap();
            match kind {
                "parent" => symlink(&outside, root.join("patterns")).unwrap(),
                "artifact" => {
                    fs::create_dir(root.join("patterns")).unwrap();
                    symlink(
                        outside.join("custom.json"),
                        root.join("patterns/custom.json"),
                    )
                    .unwrap();
                }
                "state" => {
                    symlink(outside.join("state.json"), root.join(IMPORT_STATE_FILE)).unwrap()
                }
                "journal" => {
                    let id = uuid::Uuid::new_v4();
                    symlink(
                        outside.join("state.json"),
                        root.join(format!(".fleet-transfer-{id}.json")),
                    )
                    .unwrap();
                    publish_import_json(
                        &root.join(IMPORT_STATE_FILE),
                        &serde_json::to_vec(&ImportState {
                            version: IMPORT_JOURNAL_VERSION,
                            id,
                            phase: ImportPhase::Pending,
                            journal_sha256: hex::encode(Sha256::digest(b"{}")),
                        })
                        .unwrap(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let before = fs::read(outside.join("custom.json")).unwrap();
            let result = TransferImport::begin(&root)
                .and_then(|import| import.publish(incoming_patterns(), false));
            assert!(result.is_err(), "{kind}");
            assert_eq!(
                fs::read_to_string(root.join("priors.json")).unwrap(),
                original
            );
            assert_eq!(fs::read(outside.join("custom.json")).unwrap(), before);
            assert_eq!(fs::read(outside.join("state.json")).unwrap(), b"{}");
        }
    }

    #[test]
    fn publication_recovery_rejects_forged_paths_versions_and_checksums_before_writes() {
        for corruption in ["path", "version", "checksum", "state"] {
            let (root, original) = fixture();
            let id = uuid::Uuid::new_v4();
            let journal = ImportJournal {
                version: if corruption == "version" {
                    99
                } else {
                    IMPORT_JOURNAL_VERSION
                },
                id,
                files: vec![ImportFile {
                    path: if corruption == "path" {
                        "../outside.json"
                    } else {
                        "priors.json"
                    }
                    .into(),
                    before: Some(original.clone()),
                    after: String::from_utf8(incoming_priors()).unwrap(),
                }],
            };
            let bytes = serde_json::to_vec(&journal).unwrap();
            publish_import_json(&root.join(format!(".fleet-transfer-{id}.json")), &bytes).unwrap();
            let mut state = serde_json::to_value(ImportState {
                version: IMPORT_JOURNAL_VERSION,
                id,
                phase: ImportPhase::Pending,
                journal_sha256: if corruption == "checksum" {
                    "0".repeat(64)
                } else {
                    hex::encode(Sha256::digest(&bytes))
                },
            })
            .unwrap();
            if corruption == "state" {
                state["phase"] = serde_json::json!("trust-me");
            }
            publish_import_json(
                &root.join(IMPORT_STATE_FILE),
                &serde_json::to_vec(&state).unwrap(),
            )
            .unwrap();
            assert!(TransferImport::begin(&root).is_err(), "{corruption}");
            assert_eq!(
                fs::read_to_string(root.join("priors.json")).unwrap(),
                original
            );
            assert!(load_config(&config_options(&root)).is_err());
        }
    }
}

/// Non-fatal warning from bundle validation.
#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

// ── Core Types ────────────────────────────────────────────────────────────

/// A combined transfer bundle containing priors, signatures, and baseline stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferBundle {
    pub schema_version: String,
    pub exported_at: String,
    pub source_host_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priors: Option<Priors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<PersistedSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_stats: Option<BaselineStats>,
    pub checksum: String,
}

/// Summary statistics about the source host, used for baseline normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    pub total_processes_seen: u64,
    pub observation_window_hours: f64,
    /// Empirical class frequencies (class name -> fraction).
    /// BTreeMap ensures deterministic serialisation order for stable checksums.
    #[serde(default)]
    pub class_distribution: BTreeMap<String, f64>,
    pub mean_cpu_utilization: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_type: Option<String>,
}

/// Merge strategy for combining priors from two sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MergeStrategy {
    /// Weighted average of pseudo-observations (default).
    #[default]
    Weighted,
    /// Replace local priors entirely with incoming.
    Replace,
    /// Keep local priors, ignore incoming.
    KeepLocal,
}

impl std::str::FromStr for MergeStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "weighted" => Ok(Self::Weighted),
            "replace" => Ok(Self::Replace),
            "keep-local" => Ok(Self::KeepLocal),
            other => Err(format!(
                "unknown merge strategy '{}' (expected: weighted, replace, keep-local)",
                other
            )),
        }
    }
}

// ── Diff Types ────────────────────────────────────────────────────────────

/// Full diff between local state and an incoming transfer bundle.
#[derive(Debug, Clone, Serialize)]
pub struct TransferDiff {
    pub priors_changes: Vec<PriorChange>,
    pub signature_changes: Vec<SignatureChange>,
    pub baseline_adjustments: Vec<BaselineAdjustment>,
}

/// A source difference or effective change to any prior configuration field.
#[derive(Debug, Clone, Serialize)]
pub struct PriorChange {
    /// Process class, or `configuration` for fields outside `classes`.
    pub class: String,
    pub field: String,
    /// JSON Pointer into the complete priors document, including array indices.
    pub path: String,
    pub local_value: Value,
    pub incoming_value: Value,
    /// The actual strategy result, including JSON null for removed options.
    /// Absent for a source comparison that does not select a merge strategy.
    pub merged_value: Option<Value>,
    /// Whether import changes this field; absent for a source comparison.
    pub applied: Option<bool>,
}

/// The configuration that determines a signature's matching and lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignatureConfiguration {
    pub signature: SupervisorSignature,
    pub lifecycle: PatternLifecycle,
}

impl From<&PersistedPattern> for SignatureConfiguration {
    fn from(pattern: &PersistedPattern) -> Self {
        Self {
            signature: pattern.signature.clone(),
            lifecycle: pattern.lifecycle,
        }
    }
}

/// A signature comparison. With a merged library, `change_type` describes the
/// effective import, not a hypothetical replacement by the incoming bundle.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureChange {
    pub name: String,
    pub change_type: SignatureChangeType,
    pub local_confidence: Option<f64>,
    pub incoming_confidence: Option<f64>,
    pub merged_confidence: Option<f64>,
    pub local: Option<SignatureConfiguration>,
    pub incoming: Option<SignatureConfiguration>,
    pub merged: Option<SignatureConfiguration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureChangeType {
    Added,
    Removed,
    Updated,
    Unchanged,
}

/// An adjustment due to baseline normalization.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineAdjustment {
    pub class: String,
    pub field: String,
    pub original_value: f64,
    pub adjusted_value: f64,
    pub reason: String,
}

// ── Core Functions ────────────────────────────────────────────────────────

/// Create a transfer bundle from local priors, signatures, and baseline stats.
///
/// The `host_id` is expected to already be HMAC-hashed (or a safe identifier).
pub fn export_bundle(
    priors: Option<&Priors>,
    signatures: Option<&PersistedSchema>,
    baseline: Option<&BaselineStats>,
    host_id: &str,
    profile: Option<&str>,
) -> Result<TransferBundle, TransferError> {
    let exported_at = chrono::Utc::now().to_rfc3339();

    // Build the bundle without checksum first, then compute it.
    let mut bundle = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
        exported_at,
        source_host_id: host_id.to_string(),
        source_host_profile: profile.map(|s| s.to_string()),
        priors: priors.cloned(),
        signatures: signatures.cloned(),
        baseline_stats: baseline.cloned(),
        checksum: String::new(),
    };

    bundle.checksum = compute_bundle_checksum(&bundle)?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// Compute the SHA-256 checksum of the bundle content (excluding the checksum field itself).
pub fn compute_bundle_checksum(bundle: &TransferBundle) -> Result<String, TransferError> {
    // Serialize a copy with empty checksum so the hash is stable.
    let mut for_hash = bundle.clone();
    for_hash.checksum = String::new();
    let mut value = serde_json::to_value(&for_hash)?;
    // Reuse the session checksum's canonical object ordering. Nested matcher
    // HashMaps may be reconstructed with a different order after deserialization.
    crate::session::snapshot_persist::canonicalize_json(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Validate a transfer bundle, returning warnings for non-fatal issues.
pub fn validate_bundle(bundle: &TransferBundle) -> Result<Vec<Warning>, TransferError> {
    // Guard before version/checksum diagnostics, which include supplied fields.
    // Intact operational configuration must not bypass content checks just
    // because it is packaged as opaque bytes. Refuse rather than redact its
    // executable matchers or echo detected values in a diagnostic.
    let content = serde_json::to_value(bundle)?;
    if contains_detected_secret(&content, &pt_redact::SecretDetector::new()) {
        return Err(TransferError::SensitiveContent);
    }
    let mut warnings = Vec::new();

    // 1. Check schema version.
    if bundle.schema_version != TRANSFER_SCHEMA_VERSION {
        // Allow forward-compatible reads for minor bumps, but warn.
        let parts: Vec<&str> = bundle.schema_version.split('.').collect();
        let local_parts: Vec<&str> = TRANSFER_SCHEMA_VERSION.split('.').collect();
        if parts.first() != local_parts.first() {
            return Err(TransferError::UnsupportedSchemaVersion(
                bundle.schema_version.clone(),
            ));
        }
        warnings.push(Warning {
            code: "schema_version_mismatch".to_string(),
            message: format!(
                "bundle schema {} differs from local {}",
                bundle.schema_version, TRANSFER_SCHEMA_VERSION,
            ),
        });
    }

    // 2. Verify checksum.
    let expected = compute_bundle_checksum(bundle)?;
    if bundle.checksum != expected {
        return Err(TransferError::ChecksumMismatch {
            expected,
            actual: bundle.checksum.clone(),
        });
    }

    // 3. Check prior_prob sum.
    if let Some(ref priors) = bundle.priors {
        let sum = priors.classes.useful.prior_prob
            + priors.classes.useful_bad.prior_prob
            + priors.classes.abandoned.prior_prob
            + priors.classes.zombie.prior_prob;
        if (sum - 1.0).abs() > 0.01 {
            return Err(TransferError::PriorProbSum(sum));
        }
        if (sum - 1.0).abs() > 1e-6 {
            warnings.push(Warning {
                code: "prior_prob_drift".to_string(),
                message: format!(
                    "class prior probabilities sum to {:.6}, not exactly 1.0",
                    sum
                ),
            });
        }
        pt_config::validate::validate_priors(priors)
            .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
    }

    if let Some(signatures) = &bundle.signatures {
        signatures
            .validate()
            .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
        for pattern in &signatures.patterns {
            // Inactive patterns can later be activated; validate them as well.
            pattern
                .signature
                .validate_for_activation()
                .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
        }
    }

    if let Some(stats) = &bundle.baseline_stats {
        if !stats.observation_window_hours.is_finite() || stats.observation_window_hours < 0.0 {
            return Err(TransferError::InvalidConfiguration(
                "baseline observation window must be finite and nonnegative".to_string(),
            ));
        }
        if !stats.mean_cpu_utilization.is_finite() || stats.mean_cpu_utilization < 0.0 {
            return Err(TransferError::InvalidConfiguration(
                "baseline CPU mean must be finite and nonnegative".to_string(),
            ));
        }
        if stats
            .class_distribution
            .values()
            .any(|fraction| !fraction.is_finite() || !(0.0..=1.0).contains(fraction))
            || (!stats.class_distribution.is_empty()
                && (stats.class_distribution.values().sum::<f64>() - 1.0).abs() > 1e-6)
        {
            return Err(TransferError::InvalidConfiguration(
                "baseline class fractions must be finite probabilities summing to one".to_string(),
            ));
        }
        if stats.total_processes_seen == 0
            && (stats.mean_cpu_utilization != 0.0 || !stats.class_distribution.is_empty())
        {
            return Err(TransferError::InvalidConfiguration(
                "empty baseline cannot contain a CPU mean or class observations".to_string(),
            ));
        }
    }

    // 4. Check for empty bundle.
    if bundle.priors.is_none() && bundle.signatures.is_none() {
        warnings.push(Warning {
            code: "empty_bundle".to_string(),
            message: "bundle contains neither priors nor signatures".to_string(),
        });
    }

    Ok(warnings)
}

fn contains_detected_secret(
    value: &serde_json::Value,
    detector: &pt_redact::SecretDetector,
) -> bool {
    match value {
        serde_json::Value::String(value) => contains_detected_secret_text(value, detector),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_detected_secret(value, detector)),
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            contains_detected_secret_text(key, detector)
                || contains_detected_secret(value, detector)
        }),
        _ => false,
    }
}

fn contains_detected_secret_text(value: &str, detector: &pt_redact::SecretDetector) -> bool {
    // Explicit credential and argument patterns span the complete text. Entropy
    // describes individual tokens, not an entire prose comment: the shipped
    // command-category explanation exceeds the detector's entropy threshold.
    !pt_redact::detect::find_all_secrets(value).is_empty()
        || value
            .split_whitespace()
            .any(|token| detector.detect(token).is_some())
}

/// Weighted merge of two Beta-distribution parameter sets.
///
/// α_merged = w_l·α_l + w_i·α_i
/// β_merged = w_l·β_l + w_i·β_i
pub fn merge_beta_params(
    local: &BetaParams,
    incoming: &BetaParams,
    local_weight: f64,
    incoming_weight: f64,
) -> Result<BetaParams, TransferError> {
    if local_weight < 0.0 || incoming_weight < 0.0 {
        return Err(TransferError::InvalidWeight(
            "weights must be non-negative".to_string(),
        ));
    }
    let total = local_weight + incoming_weight;
    if total == 0.0 {
        return Err(TransferError::InvalidWeight(
            "total weight must be positive".to_string(),
        ));
    }
    let wl = local_weight / total;
    let wi = incoming_weight / total;
    Ok(BetaParams::new(
        wl * local.alpha + wi * incoming.alpha,
        wl * local.beta + wi * incoming.beta,
    ))
}

/// Merge class parameters with weighted averaging of all Beta-distributed fields.
fn merge_class_params(
    local: &ClassParams,
    incoming: &ClassParams,
    local_weight: f64,
    incoming_weight: f64,
    strategy: MergeStrategy,
) -> Result<ClassParams, TransferError> {
    match strategy {
        MergeStrategy::Replace => Ok(incoming.clone()),
        MergeStrategy::KeepLocal => Ok(local.clone()),
        MergeStrategy::Weighted => {
            let total = local_weight + incoming_weight;
            let wl = if total > 0.0 {
                local_weight / total
            } else {
                0.5
            };
            let wi = 1.0 - wl;

            Ok(ClassParams {
                prior_prob: wl * local.prior_prob + wi * incoming.prior_prob,
                cpu_beta: merge_beta_params(&local.cpu_beta, &incoming.cpu_beta, wl, wi)?,
                runtime_gamma: local.runtime_gamma.clone(),
                orphan_beta: merge_beta_params(&local.orphan_beta, &incoming.orphan_beta, wl, wi)?,
                tty_beta: merge_beta_params(&local.tty_beta, &incoming.tty_beta, wl, wi)?,
                net_beta: merge_beta_params(&local.net_beta, &incoming.net_beta, wl, wi)?,
                io_active_beta: match (&local.io_active_beta, &incoming.io_active_beta) {
                    (Some(l), Some(i)) => Some(merge_beta_params(l, i, wl, wi)?),
                    (Some(l), None) => Some(l.clone()),
                    (None, Some(i)) => Some(i.clone()),
                    (None, None) => None,
                },
                queue_saturation_beta: match (
                    &local.queue_saturation_beta,
                    &incoming.queue_saturation_beta,
                ) {
                    (Some(l), Some(i)) => Some(merge_beta_params(l, i, wl, wi)?),
                    (Some(l), None) => Some(l.clone()),
                    (None, Some(i)) => Some(i.clone()),
                    (None, None) => None,
                },
                hazard_gamma: local.hazard_gamma.clone(),
                competing_hazards: local.competing_hazards.clone(),
            })
        }
    }
}

/// Merge priors from two sources using the given strategy.
///
/// For `Weighted`, uses equal weights (0.5/0.5) unless caller adjusts via
/// baseline normalization beforehand.
pub fn merge_priors(
    local: &Priors,
    incoming: &Priors,
    strategy: MergeStrategy,
) -> Result<Priors, TransferError> {
    merge_priors_weighted(local, incoming, strategy, 0.5, 0.5)
}

/// Merge priors with explicit weights.
pub fn merge_priors_weighted(
    local: &Priors,
    incoming: &Priors,
    strategy: MergeStrategy,
    local_weight: f64,
    incoming_weight: f64,
) -> Result<Priors, TransferError> {
    match strategy {
        MergeStrategy::Replace => Ok(incoming.clone()),
        MergeStrategy::KeepLocal => Ok(local.clone()),
        MergeStrategy::Weighted => {
            let mut merged = local.clone();

            merged.classes.useful = merge_class_params(
                &local.classes.useful,
                &incoming.classes.useful,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.useful_bad = merge_class_params(
                &local.classes.useful_bad,
                &incoming.classes.useful_bad,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.abandoned = merge_class_params(
                &local.classes.abandoned,
                &incoming.classes.abandoned,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.zombie = merge_class_params(
                &local.classes.zombie,
                &incoming.classes.zombie,
                local_weight,
                incoming_weight,
                strategy,
            )?;

            // Renormalize prior_probs to sum to 1.0
            let sum = merged.classes.useful.prior_prob
                + merged.classes.useful_bad.prior_prob
                + merged.classes.abandoned.prior_prob
                + merged.classes.zombie.prior_prob;
            if sum > 0.0 {
                merged.classes.useful.prior_prob /= sum;
                merged.classes.useful_bad.prior_prob /= sum;
                merged.classes.abandoned.prior_prob /= sum;
                merged.classes.zombie.prior_prob /= sum;
            }

            merged.updated_at = Some(chrono::Utc::now().to_rfc3339());

            Ok(merged)
        }
    }
}

/// Adjust priors based on baseline differences between source and target hosts.
///
/// Scales Beta pseudo-observation counts by the ratio of total processes seen,
/// so priors from a high-traffic server are down-weighted when applied to a
/// workstation (and vice versa).
pub fn normalize_baseline(
    priors: &mut Priors,
    source_stats: &BaselineStats,
    target_stats: &BaselineStats,
) {
    if source_stats.total_processes_seen == 0 || target_stats.total_processes_seen == 0 {
        return;
    }

    // Scale factor: ratio of observation counts (clamped to [0.1, 10.0]).
    let raw_ratio =
        target_stats.total_processes_seen as f64 / source_stats.total_processes_seen as f64;
    let scale = raw_ratio.clamp(0.1, 10.0);

    fn scale_beta(bp: &mut BetaParams, factor: f64) {
        bp.alpha = (bp.alpha * factor).max(0.01);
        bp.beta = (bp.beta * factor).max(0.01);
    }

    for class in [
        &mut priors.classes.useful,
        &mut priors.classes.useful_bad,
        &mut priors.classes.abandoned,
        &mut priors.classes.zombie,
    ] {
        scale_beta(&mut class.cpu_beta, scale);
        scale_beta(&mut class.orphan_beta, scale);
        scale_beta(&mut class.tty_beta, scale);
        scale_beta(&mut class.net_beta, scale);
        if let Some(ref mut io) = class.io_active_beta {
            scale_beta(io, scale);
        }
    }
}

/// Compare local and incoming fields, optionally including the actual merged priors.
/// Comparison-only callers leave merged values unknown instead of predicting a strategy.
pub fn compute_diff(
    local_priors: Option<&Priors>,
    local_signatures: Option<&PersistedSchema>,
    incoming: &TransferBundle,
    merged_priors: Option<&Priors>,
    merged_signatures: Option<&PersistedSchema>,
) -> Result<TransferDiff, TransferError> {
    let mut priors_changes = Vec::new();
    let mut signature_changes = Vec::new();
    let baseline_adjustments = Vec::new();

    // Compare the full typed configuration, not a hand-maintained shortlist
    // of Beta fields. This also exposes optional removals, Gamma hazards,
    // category/state arrays, booleans and future serialized parameters.
    if let Some(incoming_priors) = &incoming.priors {
        let local = serde_json::to_value(local_priors)?;
        let incoming = serde_json::to_value(incoming_priors)?;
        let merged = merged_priors.map(serde_json::to_value).transpose()?;
        diff_prior_values(
            &mut Vec::new(),
            &local,
            &incoming,
            merged.as_ref(),
            &mut priors_changes,
        );
    }

    if let Some(incoming_sigs) = &incoming.signatures {
        let local_names: BTreeMap<&str, &PersistedPattern> = local_signatures
            .map(|sigs| {
                sigs.patterns
                    .iter()
                    .map(|pattern| (pattern.signature.name.as_str(), pattern))
                    .collect()
            })
            .unwrap_or_default();
        let incoming_names: BTreeMap<&str, &PersistedPattern> = incoming_sigs
            .patterns
            .iter()
            .map(|pattern| (pattern.signature.name.as_str(), pattern))
            .collect();
        let merged_names: Option<BTreeMap<&str, &PersistedPattern>> =
            merged_signatures.map(|sigs| {
                sigs.patterns
                    .iter()
                    .map(|pattern| (pattern.signature.name.as_str(), pattern))
                    .collect()
            });
        let effective_names = merged_names.as_ref().unwrap_or(&incoming_names);
        let names: BTreeSet<_> = local_names
            .keys()
            .chain(incoming_names.keys())
            .chain(effective_names.keys())
            .copied()
            .collect();

        for name in names {
            let local = local_names
                .get(name)
                .map(|pattern| SignatureConfiguration::from(*pattern));
            let incoming = incoming_names
                .get(name)
                .map(|pattern| SignatureConfiguration::from(*pattern));
            let effective = effective_names
                .get(name)
                .map(|pattern| SignatureConfiguration::from(*pattern));
            let change_type = match (&local, &effective) {
                (None, Some(_)) => SignatureChangeType::Added,
                (Some(_), None) => SignatureChangeType::Removed,
                (Some(local), Some(effective)) if local != effective => {
                    SignatureChangeType::Updated
                }
                _ => SignatureChangeType::Unchanged,
            };
            let merged = merged_signatures.and(effective);
            signature_changes.push(SignatureChange {
                name: name.to_string(),
                change_type,
                local_confidence: local
                    .as_ref()
                    .map(|value| value.signature.confidence_weight),
                incoming_confidence: incoming
                    .as_ref()
                    .map(|value| value.signature.confidence_weight),
                merged_confidence: merged
                    .as_ref()
                    .map(|value| value.signature.confidence_weight),
                local,
                incoming,
                merged,
            });
        }
    }

    Ok(TransferDiff {
        priors_changes,
        signature_changes,
        baseline_adjustments,
    })
}

/// Walk all serialized prior fields in deterministic order. A type/presence
/// change is shown at its complete subtree so removed options remain visible.
fn diff_prior_values(
    path: &mut Vec<String>,
    local: &Value,
    incoming: &Value,
    merged: Option<&Value>,
    changes: &mut Vec<PriorChange>,
) {
    if local == incoming && merged.is_none_or(|value| value == local) {
        return;
    }

    if let (Value::Object(local), Value::Object(incoming)) = (local, incoming) {
        if merged.is_none_or(Value::is_object) {
            let keys: BTreeSet<_> = local
                .keys()
                .chain(incoming.keys())
                .chain(
                    merged
                        .and_then(Value::as_object)
                        .into_iter()
                        .flat_map(|map| map.keys()),
                )
                .collect();
            for key in keys {
                path.push(key.clone());
                diff_prior_values(
                    path,
                    local.get(key).unwrap_or(&Value::Null),
                    incoming.get(key).unwrap_or(&Value::Null),
                    merged.map(|value| value.get(key).unwrap_or(&Value::Null)),
                    changes,
                );
                path.pop();
            }
            return;
        }
    }

    if let (Value::Array(local), Value::Array(incoming)) = (local, incoming) {
        if merged.is_none_or(Value::is_array) {
            let len = local
                .len()
                .max(incoming.len())
                .max(merged.and_then(Value::as_array).map_or(0, Vec::len));
            for index in 0..len {
                path.push(index.to_string());
                diff_prior_values(
                    path,
                    local.get(index).unwrap_or(&Value::Null),
                    incoming.get(index).unwrap_or(&Value::Null),
                    merged.map(|value| value.get(index).unwrap_or(&Value::Null)),
                    changes,
                );
                path.pop();
            }
            return;
        }
    }

    let (class, field) = if path.len() >= 3 && path[0] == "classes" {
        (path[1].clone(), path[2..].join("."))
    } else {
        ("configuration".to_string(), path.join("."))
    };
    changes.push(PriorChange {
        class,
        field,
        path: path
            .iter()
            .map(|part| format!("/{}", part.replace('~', "~0").replace('/', "~1")))
            .collect(),
        local_value: local.clone(),
        incoming_value: incoming.clone(),
        merged_value: merged.cloned(),
        applied: merged.map(|value| value != local),
    });
}

/// Resolve signature conflicts during import, returning summary of changes.
pub fn resolve_signature_conflicts(
    local: &PersistedSchema,
    incoming: &PersistedSchema,
    resolution: ConflictResolution,
) -> (PersistedSchema, Vec<ImportConflict>) {
    let mut result_patterns = local.patterns.clone();
    let mut conflicts = Vec::new();

    let local_names: HashMap<&str, usize> = local
        .patterns
        .iter()
        .enumerate()
        .map(|(i, p)| (p.signature.name.as_str(), i))
        .collect();

    for incoming_pattern in &incoming.patterns {
        let name = &incoming_pattern.signature.name;
        if let Some(&idx) = local_names.get(name.as_str()) {
            let existing = &local.patterns[idx];
            let existing_conf = existing.signature.confidence_weight;
            let imported_conf = incoming_pattern.signature.confidence_weight;

            let conflict = ImportConflict {
                name: name.clone(),
                resolution,
                existing_confidence: Some(existing_conf),
                imported_confidence: Some(imported_conf),
            };

            match resolution {
                ConflictResolution::KeepExisting => {}
                ConflictResolution::ReplaceWithImported => {
                    result_patterns[idx] = incoming_pattern.clone();
                }
                ConflictResolution::KeepHigherConfidence => {
                    if imported_conf > existing_conf {
                        result_patterns[idx] = incoming_pattern.clone();
                    }
                }
                ConflictResolution::Merge => {
                    if imported_conf > existing_conf {
                        result_patterns[idx] = incoming_pattern.clone();
                    }
                }
            }
            conflicts.push(conflict);
        } else {
            // New pattern, always add.
            result_patterns.push(incoming_pattern.clone());
        }
    }

    let schema = PersistedSchema {
        schema_version: local.schema_version,
        patterns: result_patterns,
        metadata: local.metadata.clone(),
    };

    (schema, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_priors() -> Priors {
        Priors::default()
    }

    fn minimal_baseline() -> BaselineStats {
        BaselineStats {
            total_processes_seen: 5000,
            observation_window_hours: 72.0,
            class_distribution: {
                let mut m = BTreeMap::new();
                m.insert("useful".to_string(), 0.7);
                m.insert("useful_bad".to_string(), 0.1);
                m.insert("abandoned".to_string(), 0.15);
                m.insert("zombie".to_string(), 0.05);
                m
            },
            mean_cpu_utilization: 45.0,
            host_type: Some("server".to_string()),
        }
    }

    #[test]
    fn export_bundle_roundtrip_json() {
        let priors = minimal_priors();
        let baseline = minimal_baseline();
        let bundle = export_bundle(
            Some(&priors),
            None,
            Some(&baseline),
            "host-abc",
            Some("server"),
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let reloaded: TransferBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.schema_version, TRANSFER_SCHEMA_VERSION);
        assert_eq!(reloaded.source_host_id, "host-abc");
        assert_eq!(reloaded.source_host_profile.as_deref(), Some("server"));
        assert!(reloaded.priors.is_some());
        assert!(reloaded.signatures.is_none());
        assert!(reloaded.baseline_stats.is_some());
        assert!(!reloaded.checksum.is_empty());
    }

    #[test]
    fn validate_bundle_ok() {
        let priors = minimal_priors();
        let bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        let warnings = validate_bundle(&bundle).unwrap();
        // No warnings for a clean bundle
        assert!(
            warnings
                .iter()
                .all(|w| w.code != "empty_bundle" || bundle.priors.is_some()),
            "unexpected warnings: {:?}",
            warnings,
        );
    }

    #[test]
    fn baseline_statistics_refuse_nonfinite_negative_and_inconsistent_values() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut baseline = minimal_baseline();
            baseline.observation_window_hours = invalid;
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
            baseline = minimal_baseline();
            baseline.mean_cpu_utilization = invalid;
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
            baseline = minimal_baseline();
            baseline
                .class_distribution
                .insert("useful".to_string(), invalid);
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
        }
        let mut baseline = minimal_baseline();
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 1.1)]);
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 0.5)]);
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 1.0)]);
        export_bundle(None, None, Some(&baseline), "host-owned", None).unwrap();
        baseline.total_processes_seen = 0;
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution.clear();
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.mean_cpu_utilization = 0.0;
        baseline.observation_window_hours = 0.0;
        export_bundle(None, None, Some(&baseline), "host-owned", None).unwrap();
    }

    #[test]
    fn validate_bundle_checksum_mismatch() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.checksum = "bad".to_string();
        let err = validate_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn validate_bundle_bad_schema_version() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.schema_version = "99.0.0".to_string();
        // Recompute checksum to avoid checksum error.
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        let err = validate_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("unsupported schema version"));
    }

    #[test]
    fn validate_bundle_prior_prob_sum_error() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.priors.as_mut().unwrap().classes.useful.prior_prob = 0.9;
        // Deliberately build a checksummed but invalid incoming configuration.
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        assert!(matches!(
            validate_bundle(&bundle),
            Err(TransferError::PriorProbSum(_))
        ));
    }

    #[test]
    fn checksum_survives_independent_matcher_map_order_and_rejects_tampering() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;

        let mut signature = SupervisorSignature::new("transfer-owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["^transfer-owned$"]);
        let entries = [
            ("MODE", "^test$"),
            ("RUNNER", "^owned$"),
            ("WORKSPACE", "^fixture$"),
        ];
        signature.patterns.environment_vars = entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        let schema = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(signature, PatternSource::Custom)],
            metadata: None,
        };
        let bundle = export_bundle(None, Some(&schema), None, "host-owned", None).unwrap();
        let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
        for _ in 0..4 {
            let mut independent: TransferBundle = serde_json::from_slice(&bytes).unwrap();
            validate_bundle(&independent).expect("unchanged incoming checksum must validate");
            assert_eq!(independent.checksum, bundle.checksum);
            let matcher = &mut independent.signatures.as_mut().unwrap().patterns[0]
                .signature
                .patterns
                .environment_vars;
            *matcher = entries
                .iter()
                .rev()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            assert_eq!(
                compute_bundle_checksum(&independent).unwrap(),
                bundle.checksum
            );
            validate_bundle(&independent).unwrap();
            independent.signatures.as_mut().unwrap().patterns[0]
                .signature
                .patterns
                .environment_vars
                .insert("MODE".to_string(), "^changed$".to_string());
            assert!(matches!(
                validate_bundle(&independent),
                Err(TransferError::ChecksumMismatch { .. })
            ));
        }
    }

    #[test]
    fn checksummed_invalid_priors_and_inactive_redacted_matchers_are_refused() {
        use crate::supervision::pattern_persistence::{
            PatternLifecycle, PatternSource, PersistedPattern,
        };
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;

        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        bundle
            .priors
            .as_mut()
            .unwrap()
            .classes
            .useful
            .cpu_beta
            .alpha = -1.0;
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        assert!(matches!(
            validate_bundle(&bundle),
            Err(TransferError::InvalidConfiguration(_))
        ));

        let signature = SupervisorSignature::new("redacted-owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["[HASH:k1:abcd]"]);
        let mut pattern = PersistedPattern::new(signature, PatternSource::Custom);
        pattern.lifecycle = PatternLifecycle::Removed;
        bundle.priors = None;
        bundle.signatures = Some(PersistedSchema {
            schema_version: 2,
            patterns: vec![pattern],
            metadata: None,
        });
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        let error = validate_bundle(&bundle).unwrap_err();
        assert!(matches!(error, TransferError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("redacted matcher"));
    }

    #[test]
    fn intact_transfer_refuses_detected_credentials_in_values_and_keys() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;
        let canary = "AKIAIOSFODNN7EXAMPLE";
        let mut priors = minimal_priors();
        let clean = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        for field in ["schema_version", "checksum"] {
            let mut poisoned = clean.clone();
            if field == "schema_version" {
                poisoned.schema_version = canary.to_string();
            } else {
                poisoned.checksum = canary.to_string();
            }
            let error = validate_bundle(&poisoned).unwrap_err();
            assert!(matches!(error, TransferError::SensitiveContent));
            assert!(!error.to_string().contains(canary));
        }
        priors.classes.useful.cpu_beta.comment = Some(canary.to_string());
        let error = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap_err();
        assert!(matches!(error, TransferError::SensitiveContent));
        assert!(!error.to_string().contains(canary));
        let mut signature = SupervisorSignature::new("owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["^owned$"]);
        signature
            .patterns
            .environment_vars
            .insert(canary.to_string(), ".*".to_string());
        let schema = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(signature, PatternSource::Custom)],
            metadata: None,
        };
        let error = export_bundle(None, Some(&schema), None, "host-owned", None).unwrap_err();
        assert!(matches!(error, TransferError::SensitiveContent));
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn intact_transfer_preserves_shipped_prose_but_refuses_embedded_secret_tokens() {
        let mut priors: Priors = serde_json::from_str(include_str!(
            "../../../pt-config/src/schemas/priors.default.json"
        ))
        .unwrap();
        let comment = priors.command_categories.as_ref().unwrap().comment.clone();
        let bundle = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        assert_eq!(
            bundle.priors.unwrap().command_categories.unwrap().comment,
            comment
        );
        for text in [
            "ordinary note AKIAIOSFODNN7EXAMPLE more text",
            "ordinary note aB3$cD4@eF5#gH6!iJ7%kL8 more text",
            "ordinary note --password short-value more text",
        ] {
            priors.classes.useful.cpu_beta.comment = Some(text.to_string());
            let error = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap_err();
            assert!(matches!(error, TransferError::SensitiveContent));
            assert!(!error.to_string().contains(text));
        }
    }

    #[test]
    fn merge_beta_equal_weights() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let m = merge_beta_params(&a, &b, 0.5, 0.5).unwrap();
        assert!((m.alpha - 5.0).abs() < 1e-9);
        assert!((m.beta - 5.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_zero_local_weight() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(10.0, 10.0);
        let m = merge_beta_params(&a, &b, 0.0, 1.0).unwrap();
        assert!((m.alpha - 10.0).abs() < 1e-9);
        assert!((m.beta - 10.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_zero_incoming_weight() {
        let a = BetaParams::new(3.0, 7.0);
        let b = BetaParams::new(10.0, 10.0);
        let m = merge_beta_params(&a, &b, 1.0, 0.0).unwrap();
        assert!((m.alpha - 3.0).abs() < 1e-9);
        assert!((m.beta - 7.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_both_zero_weight_errors() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let err = merge_beta_params(&a, &b, 0.0, 0.0).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn merge_beta_negative_weight_errors() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let err = merge_beta_params(&a, &b, -1.0, 1.0).unwrap_err();
        assert!(err.to_string().contains("non-negative"));
    }

    #[test]
    fn merge_beta_asymmetric_weights() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(10.0, 2.0);
        // w_l=0.75, w_i=0.25 (after normalization)
        let m = merge_beta_params(&a, &b, 3.0, 1.0).unwrap();
        let expected_alpha = 0.75 * 2.0 + 0.25 * 10.0; // 4.0
        let expected_beta = 0.75 * 8.0 + 0.25 * 2.0; // 6.5
        assert!((m.alpha - expected_alpha).abs() < 1e-9);
        assert!((m.beta - expected_beta).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_replace() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let result = merge_priors(&local, &incoming, MergeStrategy::Replace).unwrap();
        assert!((result.classes.useful.prior_prob - 0.99).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_keep_local() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let result = merge_priors(&local, &incoming, MergeStrategy::KeepLocal).unwrap();
        assert!((result.classes.useful.prior_prob - local.classes.useful.prior_prob).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_weighted_sums_to_one() {
        let local = minimal_priors();
        let incoming = minimal_priors();
        let result = merge_priors(&local, &incoming, MergeStrategy::Weighted).unwrap();
        let sum = result.classes.useful.prior_prob
            + result.classes.useful_bad.prior_prob
            + result.classes.abandoned.prior_prob
            + result.classes.zombie.prior_prob;
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn normalize_baseline_scales_beta_params() {
        let mut priors = minimal_priors();
        let original_alpha = priors.classes.useful.cpu_beta.alpha;

        let source = BaselineStats {
            total_processes_seen: 1000,
            observation_window_hours: 24.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 80.0,
            host_type: Some("server".to_string()),
        };
        let target = BaselineStats {
            total_processes_seen: 2000,
            observation_window_hours: 24.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 30.0,
            host_type: Some("workstation".to_string()),
        };

        normalize_baseline(&mut priors, &source, &target);
        // Scale = 2000/1000 = 2.0, so alpha should double.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original_alpha * 2.0).abs() < 1e-9,
            "expected alpha={}, got alpha={}",
            original_alpha * 2.0,
            priors.classes.useful.cpu_beta.alpha,
        );
    }

    #[test]
    fn normalize_baseline_identity_transform() {
        let original = minimal_priors();
        let mut priors = original.clone();
        let stats = minimal_baseline();
        normalize_baseline(&mut priors, &stats, &stats);
        // Same source and target: scale = 1.0, no change.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
                < 1e-9
        );
    }

    #[test]
    fn normalize_baseline_zero_source_noop() {
        let original = minimal_priors();
        let mut priors = original.clone();
        let source = BaselineStats {
            total_processes_seen: 0,
            observation_window_hours: 0.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 0.0,
            host_type: None,
        };
        let target = minimal_baseline();
        normalize_baseline(&mut priors, &source, &target);
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
                < 1e-9
        );
    }

    #[test]
    fn normalize_baseline_clamps_extreme_ratio() {
        let mut priors = minimal_priors();
        let source = BaselineStats {
            total_processes_seen: 1,
            observation_window_hours: 1.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 1.0,
            host_type: None,
        };
        let target = BaselineStats {
            total_processes_seen: 1_000_000,
            observation_window_hours: 1000.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 90.0,
            host_type: None,
        };
        let original_alpha = priors.classes.useful.cpu_beta.alpha;
        normalize_baseline(&mut priors, &source, &target);
        // Clamped to 10.0x.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original_alpha * 10.0).abs() < 1e-9,
            "expected alpha={}, got alpha={}",
            original_alpha * 10.0,
            priors.classes.useful.cpu_beta.alpha,
        );
    }

    #[test]
    fn compute_diff_no_changes() {
        let priors = minimal_priors();
        let bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        let diff = compute_diff(Some(&priors), None, &bundle, None, None).unwrap();
        assert!(diff.priors_changes.is_empty());
    }

    #[test]
    fn compute_diff_detects_prior_change() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let bundle = export_bundle(Some(&incoming), None, None, "h2", None).unwrap();
        let diff = compute_diff(Some(&local), None, &bundle, None, None).unwrap();
        assert!(
            !diff.priors_changes.is_empty(),
            "expected prior changes, got none"
        );
        let useful_change = diff
            .priors_changes
            .iter()
            .find(|c| c.class == "useful" && c.field == "prior_prob");
        assert!(useful_change.is_some());
    }

    #[test]
    fn compute_diff_reports_raw_and_actual_merged_values_for_each_strategy() {
        let mut local = minimal_priors();
        local.classes.useful.cpu_beta.alpha = 2.0;
        let mut incoming = minimal_priors();
        incoming.classes.useful.cpu_beta.alpha = 6.0;
        let bundle = export_bundle(Some(&incoming), None, None, "host-owned", None).unwrap();
        for (strategy, expected) in [
            (MergeStrategy::Weighted, 4.0),
            (MergeStrategy::Replace, 6.0),
            (MergeStrategy::KeepLocal, 2.0),
        ] {
            let merged = merge_priors(&local, &incoming, strategy).unwrap();
            let diff = compute_diff(Some(&local), None, &bundle, Some(&merged), None).unwrap();
            let change = diff
                .priors_changes
                .iter()
                .find(|change| change.class == "useful" && change.field == "cpu_beta.alpha")
                .expect("actual changed field reported");
            assert_eq!(change.local_value, 2.0);
            assert_eq!(change.incoming_value, 6.0);
            assert_eq!(change.merged_value, Some(serde_json::json!(expected)));
            assert_eq!(change.applied, Some(strategy != MergeStrategy::KeepLocal));
        }
        let comparison = compute_diff(Some(&local), None, &bundle, None, None).unwrap();
        assert!(comparison
            .priors_changes
            .iter()
            .all(|change| change.merged_value.is_none()));
    }

    #[test]
    fn prior_preview_covers_gamma_optional_hazard_and_global_parameters() {
        let mut local_value = serde_json::to_value(minimal_priors()).unwrap();
        local_value["classes"]["useful"]["hazard_gamma"] =
            serde_json::json!({"shape": 2.0, "rate": 0.02});
        local_value["classes"]["useful"]["competing_hazards"] =
            serde_json::json!({"finish": {"shape": 2.0, "rate": 0.04}});
        local_value["classes"]["useful"]["queue_saturation_beta"] =
            serde_json::json!({"alpha": 2.0, "beta": 4.0});
        let local: Priors = serde_json::from_value(local_value).unwrap();
        let local_value = serde_json::to_value(&local).unwrap();

        // The existing merger keeps Gamma and global parameters local while
        // averaging Beta fields. Preview must expose that actual disposition.
        let cases = [
            (
                "/classes/useful/runtime_gamma/shape",
                serde_json::json!(6.0),
                serde_json::json!(2.0),
            ),
            (
                "/classes/useful/hazard_gamma/rate",
                serde_json::json!(0.08),
                serde_json::json!(0.02),
            ),
            (
                "/classes/useful/competing_hazards/finish/rate",
                serde_json::json!(0.12),
                serde_json::json!(0.04),
            ),
            (
                "/classes/useful/io_active_beta/alpha",
                serde_json::json!(10.0),
                serde_json::json!(8.0),
            ),
            (
                "/classes/useful/queue_saturation_beta/beta",
                serde_json::json!(8.0),
                serde_json::json!(6.0),
            ),
            (
                "/command_categories/useful/alpha/0",
                serde_json::json!(9.0),
                serde_json::json!(3.0),
            ),
            (
                "/state_flags/useful/alpha/0",
                serde_json::json!(9.0),
                serde_json::json!(5.0),
            ),
            (
                "/hierarchical/shrinkage_enabled",
                serde_json::json!(false),
                serde_json::json!(true),
            ),
            (
                "/classes/useful/runtime_gamma/rate",
                serde_json::json!(0.00010000001),
                serde_json::json!(0.0001),
            ),
            (
                "/classes/useful/io_active_beta",
                Value::Null,
                local_value["classes"]["useful"]["io_active_beta"].clone(),
            ),
        ];
        for (path, changed_value, weighted_value) in cases {
            let mut incoming_value = local_value.clone();
            *incoming_value
                .pointer_mut(path)
                .expect("existing fixture field") = changed_value;
            let incoming: Priors = serde_json::from_value(incoming_value).unwrap();
            let incoming_value = serde_json::to_value(&incoming).unwrap();
            let bundle = export_bundle(Some(&incoming), None, None, "host-owned", None).unwrap();
            for strategy in [
                MergeStrategy::Replace,
                MergeStrategy::KeepLocal,
                MergeStrategy::Weighted,
            ] {
                let merged = merge_priors(&local, &incoming, strategy).unwrap();
                let diff = compute_diff(Some(&local), None, &bundle, Some(&merged), None).unwrap();
                let change = diff
                    .priors_changes
                    .iter()
                    .find(|change| change.path == path)
                    .unwrap_or_else(|| panic!("missing {path} for {strategy:?}: {diff:?}"));
                let local_field = local_value.pointer(path).unwrap();
                let incoming_field = incoming_value.pointer(path).unwrap();
                let expected = match strategy {
                    MergeStrategy::Replace => incoming_field,
                    MergeStrategy::KeepLocal => local_field,
                    MergeStrategy::Weighted => &weighted_value,
                };
                assert_eq!(&change.local_value, local_field, "{path}");
                assert_eq!(&change.incoming_value, incoming_field, "{path}");
                assert_eq!(
                    change.merged_value.as_ref(),
                    Some(expected),
                    "{path}: {strategy:?}"
                );
                assert_eq!(change.applied, Some(expected != local_field), "{path}");
            }
        }
    }

    #[test]
    fn prior_diff_exposes_optional_additions_and_string_array_edits() {
        let local = minimal_priors();
        let mut incoming = serde_json::to_value(&local).unwrap();
        incoming["semi_markov"] = serde_json::json!({
            "useful_duration": {"shape": 3.0, "rate": 0.01}
        });
        incoming["command_categories"]["category_names"][0] = serde_json::json!("benchmark");
        let incoming: Priors = serde_json::from_value(incoming).unwrap();
        let bundle = export_bundle(Some(&incoming), None, None, "host-owned", None).unwrap();
        let diff = compute_diff(Some(&local), None, &bundle, None, None).unwrap();
        let addition = diff
            .priors_changes
            .iter()
            .find(|change| change.path == "/semi_markov")
            .unwrap();
        assert!(addition.local_value.is_null());
        assert_eq!(addition.incoming_value["useful_duration"]["shape"], 3.0);
        assert!(addition.merged_value.is_none());
        assert!(addition.applied.is_none());
        let category = diff
            .priors_changes
            .iter()
            .find(|change| change.path == "/command_categories/category_names/0")
            .unwrap();
        assert_eq!(category.local_value, "test");
        assert_eq!(category.incoming_value, "benchmark");
        let paths: Vec<_> = diff
            .priors_changes
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn compute_diff_detects_signature_added() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::{SignaturePatterns, SupervisorSignature};
        use crate::supervision::SupervisorCategory;

        let sig = SupervisorSignature {
            name: "new_sig".to_string(),
            category: SupervisorCategory::Other,
            patterns: SignaturePatterns {
                process_names: vec!["^test$".to_string()],
                ..Default::default()
            },
            confidence_weight: 0.8,
            notes: None,
            builtin: false,
            priors: Default::default(),
            expectations: Default::default(),
            priority: 100,
        };
        let incoming_sigs = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(sig, PatternSource::Custom)],
            metadata: None,
        };
        let bundle = export_bundle(None, Some(&incoming_sigs), None, "h3", None).unwrap();
        let local_sigs = PersistedSchema::new();
        let diff = compute_diff(None, Some(&local_sigs), &bundle, None, None).unwrap();
        assert_eq!(diff.signature_changes.len(), 1);
        assert!(matches!(
            diff.signature_changes[0].change_type,
            SignatureChangeType::Added
        ));
    }

    #[test]
    fn merge_strategy_from_str() {
        assert_eq!(
            "weighted".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Weighted
        );
        assert_eq!(
            "replace".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Replace
        );
        assert_eq!(
            "keep-local".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::KeepLocal
        );
        assert!("invalid".parse::<MergeStrategy>().is_err());
    }

    #[test]
    fn signature_diff_detects_equal_confidence_matcher_changes_in_name_order() {
        use crate::supervision::pattern_persistence::PatternSource;
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;

        let zulu = PersistedPattern::new(
            SupervisorSignature::new("zulu", SupervisorCategory::Other)
                .with_process_patterns(vec!["^old-worker$"]),
            PatternSource::Custom,
        );
        let alpha = PersistedPattern::new(
            SupervisorSignature::new("alpha", SupervisorCategory::Other)
                .with_process_patterns(vec!["^alpha$"]),
            PatternSource::Custom,
        );
        let local = PersistedSchema {
            schema_version: 2,
            patterns: vec![zulu.clone(), alpha],
            metadata: None,
        };
        let unchanged = export_bundle(None, Some(&local), None, "host", None).unwrap();
        let diff = compute_diff(None, Some(&local), &unchanged, None, None).unwrap();
        assert!(diff
            .signature_changes
            .iter()
            .all(|change| matches!(change.change_type, SignatureChangeType::Unchanged)));

        let mut incoming = local.clone();
        incoming.patterns[0].signature.patterns.process_names = vec!["^new-worker$".to_string()];
        let bundle = export_bundle(None, Some(&incoming), None, "host", None).unwrap();
        let diff = compute_diff(None, Some(&local), &bundle, None, None).unwrap();
        assert_eq!(
            diff.signature_changes
                .iter()
                .map(|change| change.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zulu"]
        );
        let changed = &diff.signature_changes[1];
        assert!(matches!(changed.change_type, SignatureChangeType::Updated));
        assert_eq!(changed.local_confidence, changed.incoming_confidence);
    }

    #[test]
    fn deterministic_checksum() {
        // Same input should produce same checksum every time.
        // We need stable exported_at to test this, so construct directly.
        let priors = minimal_priors();
        let mut b1 = TransferBundle {
            schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            source_host_id: "host1".to_string(),
            source_host_profile: None,
            priors: Some(priors.clone()),
            signatures: None,
            baseline_stats: None,
            checksum: String::new(),
        };
        b1.checksum = compute_bundle_checksum(&b1).unwrap();

        let mut b2 = TransferBundle {
            schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            source_host_id: "host1".to_string(),
            source_host_profile: None,
            priors: Some(priors),
            signatures: None,
            baseline_stats: None,
            checksum: String::new(),
        };
        b2.checksum = compute_bundle_checksum(&b2).unwrap();

        assert_eq!(b1.checksum, b2.checksum);
    }

    #[test]
    fn empty_bundle_warning() {
        let bundle = export_bundle(None, None, None, "h1", None).unwrap();
        let warnings = validate_bundle(&bundle).unwrap();
        assert!(warnings.iter().any(|w| w.code == "empty_bundle"));
    }

    #[test]
    fn baseline_stats_serde_roundtrip() {
        let stats = minimal_baseline();
        let json = serde_json::to_string(&stats).unwrap();
        let back: BaselineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_processes_seen, 5000);
        assert_eq!(back.host_type.as_deref(), Some("server"));
    }

    #[test]
    fn transfer_diff_empty_when_no_data() {
        let bundle = export_bundle(None, None, None, "h1", None).unwrap();
        let diff = compute_diff(None, None, &bundle, None, None).unwrap();
        assert!(diff.priors_changes.is_empty());
        assert!(diff.signature_changes.is_empty());
        assert!(diff.baseline_adjustments.is_empty());
    }
}
