//! Pattern/signature library persistence and versioning.
//!
//! This module manages the persistent storage of process patterns (signatures)
//! with versioning, lifecycle management, and import/export functionality.
//!
//! # Storage Structure
//!
//! ```text
//! ~/.config/process_triage/
//! ├── patterns/
//! │   ├── built_in.json      # Shipped with pt, read-only
//! │   ├── learned.json       # User-learned patterns from decisions
//! │   ├── custom.json        # User-defined custom patterns
//! │   └── disabled.json      # IDs of disabled patterns
//! └── pattern_stats.json     # Match statistics per pattern
//! ```
//!
//! # Pattern Sources
//!
//! 1. **Built-in**: Shipped with pt-core, read-only, auto-updated on upgrade
//! 2. **Learned**: Generated from user decisions (kill/keep patterns)
//! 3. **Custom**: User-defined via config or CLI
//! 4. **Community**: Fetched from central registry (future)
//!
//! # Pattern Lifecycle
//!
//! ```text
//! [New] → [Learning] → [Stable] → [Deprecated] → [Removed]
//!
//! New: First observation, confidence < 0.5
//! Learning: Building confidence, 0.5 ≤ confidence < 0.8
//! Stable: High confidence, confidence ≥ 0.8, count ≥ 10
//! Deprecated: Marked for removal, still matches but warns
//! Removed: No longer in active library
//! ```

use super::signature::{SignatureError, SignatureSchema, SupervisorSignature, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Default configuration directory name.
const CONFIG_DIR_NAME: &str = "process_triage";

/// Patterns subdirectory name.
const PATTERNS_DIR_NAME: &str = "patterns";

/// Built-in patterns filename.
const BUILT_IN_FILE: &str = "built_in.json";

/// Learned patterns filename.
const LEARNED_FILE: &str = "learned.json";

/// Custom patterns filename.
const CUSTOM_FILE: &str = "custom.json";

/// Disabled patterns filename.
const DISABLED_FILE: &str = "disabled.json";

/// Pattern statistics filename.
const STATS_FILE: &str = "pattern_stats.json";

/// Errors from pattern persistence operations.
#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),

    #[error("Pattern not found: {0}")]
    PatternNotFound(String),

    #[error("Pattern already exists: {0}")]
    PatternAlreadyExists(String),

    #[error("Cannot modify built-in pattern: {0}")]
    BuiltInReadOnly(String),

    #[error("Migration failed from version {from} to {to}: {reason}")]
    MigrationFailed { from: u32, to: u32, reason: String },

    #[error("Invalid pattern lifecycle transition: {from:?} -> {to:?}")]
    InvalidLifecycleTransition {
        from: PatternLifecycle,
        to: PatternLifecycle,
    },

    #[error("Config directory not found and could not be created")]
    ConfigDirNotFound,
}

/// Pattern lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternLifecycle {
    /// First observation, confidence < 0.5
    New,
    /// Building confidence, 0.5 ≤ confidence < 0.8
    Learning,
    /// High confidence, confidence ≥ 0.8, count ≥ 10
    Stable,
    /// Marked for removal, still matches but warns
    Deprecated,
    /// No longer in active library (tombstone for sync)
    Removed,
}

impl Default for PatternLifecycle {
    fn default() -> Self {
        Self::New
    }
}

impl PatternLifecycle {
    /// Check if this lifecycle allows matching processes.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::New | Self::Learning | Self::Stable)
    }

    /// Check if this pattern should warn on match.
    pub fn should_warn(&self) -> bool {
        matches!(self, Self::Deprecated)
    }

    /// Compute suggested lifecycle based on confidence and match count.
    pub fn from_stats(confidence: f64, match_count: u32) -> Self {
        if confidence >= 0.8 && match_count >= 10 {
            Self::Stable
        } else if confidence >= 0.5 {
            Self::Learning
        } else {
            Self::New
        }
    }

    /// Check if transition to target state is valid.
    pub fn can_transition_to(&self, target: Self) -> bool {
        use PatternLifecycle::*;
        match (self, target) {
            // Forward progression
            (New, Learning) => true,
            (Learning, Stable) => true,
            // Deprecation from any active state
            (New | Learning | Stable, Deprecated) => true,
            // Removal from deprecated
            (Deprecated, Removed) => true,
            // Can reactivate deprecated patterns
            (Deprecated, New | Learning | Stable) => true,
            // Same state is fine
            (a, b) if *a == b => true,
            // Everything else is invalid
            _ => false,
        }
    }
}

/// Source of a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternSource {
    /// Shipped with pt-core.
    BuiltIn,
    /// Learned from user decisions.
    Learned,
    /// User-defined custom pattern.
    Custom,
    /// Fetched from community registry.
    Community,
    /// Imported from another system.
    Imported,
}

impl Default for PatternSource {
    fn default() -> Self {
        Self::Custom
    }
}

impl PatternSource {
    /// Check if patterns from this source can be modified.
    pub fn is_mutable(&self) -> bool {
        !matches!(self, Self::BuiltIn)
    }

    /// Get the filename for this source.
    pub fn filename(&self) -> Option<&'static str> {
        match self {
            Self::BuiltIn => Some(BUILT_IN_FILE),
            Self::Learned => Some(LEARNED_FILE),
            Self::Custom | Self::Imported => Some(CUSTOM_FILE),
            Self::Community => None, // Community patterns have their own storage
        }
    }
}

/// Statistics for a single pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternStats {
    /// Total number of matches.
    pub match_count: u32,
    /// Number of times user accepted the match classification.
    pub accept_count: u32,
    /// Number of times user rejected/overrode the match.
    pub reject_count: u32,
    /// First seen timestamp (unix epoch seconds).
    pub first_seen: Option<u64>,
    /// Last match timestamp (unix epoch seconds).
    pub last_match: Option<u64>,
    /// Computed confidence based on accept/reject ratio.
    pub computed_confidence: Option<f64>,
    /// Historical confidence values (for trend analysis).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_history: Vec<ConfidenceSnapshot>,
}

impl PatternStats {
    /// Record a pattern match.
    pub fn record_match(&mut self, accepted: bool) {
        self.match_count += 1;
        if accepted {
            self.accept_count += 1;
        } else {
            self.reject_count += 1;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if self.first_seen.is_none() {
            self.first_seen = Some(now);
        }
        self.last_match = Some(now);

        // Recompute confidence
        self.update_confidence();
    }

    /// Update computed confidence based on accept/reject ratio.
    pub fn update_confidence(&mut self) {
        if self.match_count > 0 {
            // Use Laplace smoothing: (accept + 1) / (total + 2)
            let confidence =
                (self.accept_count as f64 + 1.0) / (self.match_count as f64 + 2.0);
            self.computed_confidence = Some(confidence);
        }
    }

    /// Get the acceptance rate (0.0 to 1.0).
    pub fn acceptance_rate(&self) -> Option<f64> {
        if self.match_count > 0 {
            Some(self.accept_count as f64 / self.match_count as f64)
        } else {
            None
        }
    }

    /// Get suggested lifecycle based on stats.
    pub fn suggested_lifecycle(&self) -> PatternLifecycle {
        PatternLifecycle::from_stats(
            self.computed_confidence.unwrap_or(0.0),
            self.match_count,
        )
    }
}

/// A snapshot of confidence at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSnapshot {
    /// Timestamp (unix epoch seconds).
    pub timestamp: u64,
    /// Confidence value at this time.
    pub confidence: f64,
    /// Match count at this time.
    pub match_count: u32,
}

/// Extended pattern with metadata for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPattern {
    /// The core signature.
    #[serde(flatten)]
    pub signature: SupervisorSignature,

    /// Source of this pattern.
    #[serde(default)]
    pub source: PatternSource,

    /// Lifecycle state.
    #[serde(default)]
    pub lifecycle: PatternLifecycle,

    /// Version of this pattern (for updates).
    #[serde(default = "default_version")]
    pub version: String,

    /// When this pattern was created (unix epoch seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,

    /// When this pattern was last updated (unix epoch seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

impl PersistedPattern {
    /// Create from a signature with specified source.
    pub fn new(signature: SupervisorSignature, source: PatternSource) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        Self {
            signature,
            source,
            lifecycle: PatternLifecycle::New,
            version: default_version(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a built-in pattern (stable by default).
    pub fn builtin(signature: SupervisorSignature) -> Self {
        let mut pattern = Self::new(signature, PatternSource::BuiltIn);
        pattern.lifecycle = PatternLifecycle::Stable;
        pattern
    }

    /// Mark as updated.
    pub fn touch(&mut self) {
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
    }

    /// Transition to a new lifecycle state.
    pub fn transition_lifecycle(
        &mut self,
        target: PatternLifecycle,
    ) -> Result<(), PersistenceError> {
        if !self.lifecycle.can_transition_to(target) {
            return Err(PersistenceError::InvalidLifecycleTransition {
                from: self.lifecycle,
                to: target,
            });
        }
        self.lifecycle = target;
        self.touch();
        Ok(())
    }
}

/// Persisted schema with extended pattern metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSchema {
    /// Schema version number.
    pub schema_version: u32,

    /// Patterns with extended metadata.
    #[serde(default)]
    pub patterns: Vec<PersistedPattern>,

    /// Optional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SchemaMetadata>,
}

/// Extended metadata for persisted schemas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaMetadata {
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Author or maintainer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Export timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<u64>,

    /// Source system identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_system: Option<String>,

    /// Checksum for integrity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl PersistedSchema {
    /// Create a new empty schema.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            patterns: vec![],
            metadata: None,
        }
    }

    /// Validate the schema.
    pub fn validate(&self) -> Result<(), PersistenceError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(SignatureError::UnsupportedVersion {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            }
            .into());
        }

        for pattern in &self.patterns {
            pattern.signature.validate()?;
        }

        Ok(())
    }

    /// Load from JSON string.
    pub fn from_json(json: &str) -> Result<Self, PersistenceError> {
        let schema: Self = serde_json::from_str(json)?;
        schema.validate()?;
        Ok(schema)
    }

    /// Load from file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, PersistenceError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Save to file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), PersistenceError> {
        let json = self.to_json()?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Convert to basic SignatureSchema (for matcher).
    pub fn to_signature_schema(&self) -> SignatureSchema {
        SignatureSchema {
            schema_version: self.schema_version,
            signatures: self
                .patterns
                .iter()
                .filter(|p| p.lifecycle.is_active())
                .map(|p| p.signature.clone())
                .collect(),
            metadata: None,
        }
    }
}

impl Default for PersistedSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Disabled patterns tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisabledPatterns {
    /// Set of disabled pattern names.
    #[serde(default)]
    pub disabled: HashSet<String>,

    /// Reason for each disabled pattern.
    #[serde(default)]
    pub reasons: HashMap<String, String>,

    /// When each pattern was disabled.
    #[serde(default)]
    pub disabled_at: HashMap<String, u64>,
}

impl DisabledPatterns {
    /// Check if a pattern is disabled.
    pub fn is_disabled(&self, name: &str) -> bool {
        self.disabled.contains(name)
    }

    /// Disable a pattern with optional reason.
    pub fn disable(&mut self, name: &str, reason: Option<&str>) {
        self.disabled.insert(name.to_string());
        if let Some(r) = reason {
            self.reasons.insert(name.to_string(), r.to_string());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.disabled_at.insert(name.to_string(), now);
    }

    /// Re-enable a pattern.
    pub fn enable(&mut self, name: &str) {
        self.disabled.remove(name);
        self.reasons.remove(name);
        self.disabled_at.remove(name);
    }

    /// Load from file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Save to file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), PersistenceError> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

/// All pattern statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllPatternStats {
    /// Version of stats format.
    #[serde(default = "default_stats_version")]
    pub version: u32,

    /// Stats by pattern name.
    #[serde(default)]
    pub patterns: HashMap<String, PatternStats>,

    /// Last update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<u64>,
}

fn default_stats_version() -> u32 {
    1
}

impl AllPatternStats {
    /// Get stats for a pattern.
    pub fn get(&self, name: &str) -> Option<&PatternStats> {
        self.patterns.get(name)
    }

    /// Get or create stats for a pattern.
    pub fn get_or_create(&mut self, name: &str) -> &mut PatternStats {
        self.patterns.entry(name.to_string()).or_default()
    }

    /// Record a match for a pattern.
    pub fn record_match(&mut self, name: &str, accepted: bool) {
        self.get_or_create(name).record_match(accepted);
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
    }

    /// Load from file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Save to file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), PersistenceError> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

/// Conflict resolution strategy for imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep the existing pattern.
    KeepExisting,
    /// Replace with imported pattern.
    ReplaceWithImported,
    /// Keep the higher-confidence pattern.
    KeepHigherConfidence,
    /// Merge: keep higher confidence, combine counts.
    Merge,
}

impl Default for ConflictResolution {
    fn default() -> Self {
        Self::KeepHigherConfidence
    }
}

/// Result of an import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportResult {
    /// Number of patterns imported.
    pub imported: usize,
    /// Number of patterns updated (conflicts resolved).
    pub updated: usize,
    /// Number of patterns skipped.
    pub skipped: usize,
    /// Details of conflicts resolved.
    pub conflicts: Vec<ImportConflict>,
}

/// Details of a conflict during import.
#[derive(Debug, Clone)]
pub struct ImportConflict {
    /// Pattern name.
    pub name: String,
    /// Resolution applied.
    pub resolution: ConflictResolution,
    /// Existing confidence before resolution.
    pub existing_confidence: Option<f64>,
    /// Imported confidence.
    pub imported_confidence: Option<f64>,
}

/// Pattern library manager.
///
/// This struct manages the persistent storage of patterns including:
/// - Loading patterns from multiple sources
/// - Saving changes back to appropriate files
/// - Managing pattern lifecycle
/// - Tracking statistics
/// - Import/export with conflict resolution
pub struct PatternLibrary {
    /// Base configuration directory.
    config_dir: PathBuf,

    /// Built-in patterns (read-only).
    built_in: PersistedSchema,

    /// Learned patterns from user decisions.
    learned: PersistedSchema,

    /// Custom user-defined patterns.
    custom: PersistedSchema,

    /// Disabled pattern tracking.
    disabled: DisabledPatterns,

    /// Pattern statistics.
    stats: AllPatternStats,

    /// Whether any changes need saving.
    dirty: bool,
}

impl PatternLibrary {
    /// Create a new library manager with the given config directory.
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            built_in: PersistedSchema::new(),
            learned: PersistedSchema::new(),
            custom: PersistedSchema::new(),
            disabled: DisabledPatterns::default(),
            stats: AllPatternStats::default(),
            dirty: false,
        }
    }

    /// Create with default config directory (~/.config/process_triage).
    pub fn with_default_config() -> Result<Self, PersistenceError> {
        let config_dir = dirs::config_dir()
            .ok_or(PersistenceError::ConfigDirNotFound)?
            .join(CONFIG_DIR_NAME);

        Ok(Self::new(config_dir))
    }

    /// Get the patterns directory path.
    pub fn patterns_dir(&self) -> PathBuf {
        self.config_dir.join(PATTERNS_DIR_NAME)
    }

    /// Ensure the storage directories exist.
    pub fn ensure_directories(&self) -> Result<(), PersistenceError> {
        let patterns_dir = self.patterns_dir();
        if !patterns_dir.exists() {
            fs::create_dir_all(&patterns_dir)?;
        }
        Ok(())
    }

    /// Load all patterns from storage.
    pub fn load(&mut self) -> Result<(), PersistenceError> {
        self.ensure_directories()?;

        let patterns_dir = self.patterns_dir();

        // Load built-in patterns
        let built_in_path = patterns_dir.join(BUILT_IN_FILE);
        if built_in_path.exists() {
            self.built_in = PersistedSchema::from_file(&built_in_path)?;
        }

        // Load learned patterns
        let learned_path = patterns_dir.join(LEARNED_FILE);
        if learned_path.exists() {
            self.learned = PersistedSchema::from_file(&learned_path)?;
        }

        // Load custom patterns
        let custom_path = patterns_dir.join(CUSTOM_FILE);
        if custom_path.exists() {
            self.custom = PersistedSchema::from_file(&custom_path)?;
        }

        // Load disabled patterns
        let disabled_path = patterns_dir.join(DISABLED_FILE);
        if disabled_path.exists() {
            self.disabled = DisabledPatterns::from_file(&disabled_path)?;
        }

        // Load statistics
        let stats_path = self.config_dir.join(STATS_FILE);
        if stats_path.exists() {
            self.stats = AllPatternStats::from_file(&stats_path)?;
        }

        self.dirty = false;
        Ok(())
    }

    /// Save all modified patterns to storage.
    pub fn save(&mut self) -> Result<(), PersistenceError> {
        if !self.dirty {
            return Ok(());
        }

        self.ensure_directories()?;
        let patterns_dir = self.patterns_dir();

        // Save learned patterns
        self.learned.save_to_file(patterns_dir.join(LEARNED_FILE))?;

        // Save custom patterns
        self.custom.save_to_file(patterns_dir.join(CUSTOM_FILE))?;

        // Save disabled patterns
        self.disabled.save_to_file(patterns_dir.join(DISABLED_FILE))?;

        // Save statistics
        self.stats.save_to_file(self.config_dir.join(STATS_FILE))?;

        self.dirty = false;
        Ok(())
    }

    /// Initialize built-in patterns from defaults.
    ///
    /// This is called during installation or upgrade to write the default
    /// built-in patterns to the storage location.
    pub fn initialize_built_in(
        &mut self,
        signatures: Vec<SupervisorSignature>,
    ) -> Result<(), PersistenceError> {
        self.ensure_directories()?;

        let patterns: Vec<PersistedPattern> = signatures
            .into_iter()
            .map(PersistedPattern::builtin)
            .collect();

        self.built_in = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns,
            metadata: Some(SchemaMetadata {
                description: Some("Built-in process patterns shipped with pt".to_string()),
                ..Default::default()
            }),
        };

        let path = self.patterns_dir().join(BUILT_IN_FILE);
        self.built_in.save_to_file(path)?;

        Ok(())
    }

    /// Get all active patterns (excluding disabled and removed).
    pub fn all_active_patterns(&self) -> Vec<&PersistedPattern> {
        let mut patterns: Vec<&PersistedPattern> = self
            .built_in
            .patterns
            .iter()
            .chain(self.learned.patterns.iter())
            .chain(self.custom.patterns.iter())
            .filter(|p| {
                p.lifecycle.is_active() && !self.disabled.is_disabled(&p.signature.name)
            })
            .collect();

        // Sort by priority (lower number = higher priority)
        patterns.sort_by_key(|p| p.signature.priority);
        patterns
    }

    /// Get a pattern by name.
    pub fn get_pattern(&self, name: &str) -> Option<&PersistedPattern> {
        self.custom
            .patterns
            .iter()
            .chain(self.learned.patterns.iter())
            .chain(self.built_in.patterns.iter())
            .find(|p| p.signature.name == name)
    }

    /// Get a mutable pattern by name (excludes built-in).
    pub fn get_pattern_mut(&mut self, name: &str) -> Option<&mut PersistedPattern> {
        // Check custom first
        if let Some(idx) = self
            .custom
            .patterns
            .iter()
            .position(|p| p.signature.name == name)
        {
            return Some(&mut self.custom.patterns[idx]);
        }

        // Check learned
        if let Some(idx) = self
            .learned
            .patterns
            .iter()
            .position(|p| p.signature.name == name)
        {
            return Some(&mut self.learned.patterns[idx]);
        }

        None
    }

    /// Add a custom pattern.
    pub fn add_custom(&mut self, signature: SupervisorSignature) -> Result<(), PersistenceError> {
        if self.get_pattern(&signature.name).is_some() {
            return Err(PersistenceError::PatternAlreadyExists(signature.name));
        }

        signature.validate()?;
        self.custom
            .patterns
            .push(PersistedPattern::new(signature, PatternSource::Custom));
        self.dirty = true;
        Ok(())
    }

    /// Add a learned pattern (from user decisions).
    pub fn add_learned(&mut self, signature: SupervisorSignature) -> Result<(), PersistenceError> {
        signature.validate()?;

        // If already exists as learned, update it
        if let Some(idx) = self
            .learned
            .patterns
            .iter()
            .position(|p| p.signature.name == signature.name)
        {
            self.learned.patterns[idx].signature = signature;
            self.learned.patterns[idx].touch();
        } else {
            self.learned
                .patterns
                .push(PersistedPattern::new(signature, PatternSource::Learned));
        }

        self.dirty = true;
        Ok(())
    }

    /// Remove a custom or learned pattern (cannot remove built-in).
    pub fn remove_pattern(&mut self, name: &str) -> Result<(), PersistenceError> {
        // Check if it's built-in
        if self
            .built_in
            .patterns
            .iter()
            .any(|p| p.signature.name == name)
        {
            return Err(PersistenceError::BuiltInReadOnly(name.to_string()));
        }

        // Try to remove from custom
        let custom_len_before = self.custom.patterns.len();
        self.custom
            .patterns
            .retain(|p| p.signature.name != name);
        if self.custom.patterns.len() < custom_len_before {
            self.dirty = true;
            return Ok(());
        }

        // Try to remove from learned
        let learned_len_before = self.learned.patterns.len();
        self.learned
            .patterns
            .retain(|p| p.signature.name != name);
        if self.learned.patterns.len() < learned_len_before {
            self.dirty = true;
            return Ok(());
        }

        Err(PersistenceError::PatternNotFound(name.to_string()))
    }

    /// Disable a pattern.
    pub fn disable_pattern(&mut self, name: &str, reason: Option<&str>) -> Result<(), PersistenceError> {
        if self.get_pattern(name).is_none() {
            return Err(PersistenceError::PatternNotFound(name.to_string()));
        }
        self.disabled.disable(name, reason);
        self.dirty = true;
        Ok(())
    }

    /// Enable a previously disabled pattern.
    pub fn enable_pattern(&mut self, name: &str) -> Result<(), PersistenceError> {
        if !self.disabled.is_disabled(name) {
            return Err(PersistenceError::PatternNotFound(name.to_string()));
        }
        self.disabled.enable(name);
        self.dirty = true;
        Ok(())
    }

    /// Record a pattern match (for statistics).
    pub fn record_match(&mut self, name: &str, accepted: bool) {
        self.stats.record_match(name, accepted);
        self.dirty = true;
    }

    /// Get statistics for a pattern.
    pub fn get_stats(&self, name: &str) -> Option<&PatternStats> {
        self.stats.get(name)
    }

    /// Export patterns to a schema for sharing.
    pub fn export(&self, include_sources: &[PatternSource]) -> PersistedSchema {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        let patterns: Vec<PersistedPattern> = self
            .all_active_patterns()
            .into_iter()
            .filter(|p| include_sources.contains(&p.source))
            .cloned()
            .collect();

        PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns,
            metadata: Some(SchemaMetadata {
                exported_at: now,
                description: Some("Exported pattern library".to_string()),
                ..Default::default()
            }),
        }
    }

    /// Import patterns with conflict resolution.
    pub fn import(
        &mut self,
        schema: PersistedSchema,
        resolution: ConflictResolution,
    ) -> Result<ImportResult, PersistenceError> {
        schema.validate()?;

        let mut result = ImportResult::default();

        for mut imported_pattern in schema.patterns {
            imported_pattern.source = PatternSource::Imported;

            let existing = self.get_pattern(&imported_pattern.signature.name);

            if let Some(existing) = existing {
                // Conflict exists
                let existing_conf = existing.signature.confidence_weight;
                let imported_conf = imported_pattern.signature.confidence_weight;

                let conflict = ImportConflict {
                    name: imported_pattern.signature.name.clone(),
                    resolution,
                    existing_confidence: Some(existing_conf),
                    imported_confidence: Some(imported_conf),
                };

                match resolution {
                    ConflictResolution::KeepExisting => {
                        result.skipped += 1;
                    }
                    ConflictResolution::ReplaceWithImported => {
                        // Remove existing and add imported
                        let _ = self.remove_pattern(&imported_pattern.signature.name);
                        self.custom.patterns.push(imported_pattern);
                        result.updated += 1;
                    }
                    ConflictResolution::KeepHigherConfidence => {
                        if imported_conf > existing_conf {
                            let _ = self.remove_pattern(&imported_pattern.signature.name);
                            self.custom.patterns.push(imported_pattern);
                            result.updated += 1;
                        } else {
                            result.skipped += 1;
                        }
                    }
                    ConflictResolution::Merge => {
                        // Merge stats and keep higher confidence pattern
                        let name = imported_pattern.signature.name.clone();
                        if imported_conf > existing_conf {
                            let _ = self.remove_pattern(&name);
                            self.custom.patterns.push(imported_pattern);
                        }
                        // Stats will accumulate naturally
                        result.updated += 1;
                    }
                }

                result.conflicts.push(conflict);
            } else {
                // No conflict, just add
                self.custom.patterns.push(imported_pattern);
                result.imported += 1;
            }
        }

        if result.imported > 0 || result.updated > 0 {
            self.dirty = true;
        }

        Ok(result)
    }

    /// Convert to SignatureSchema for use with the matcher.
    pub fn to_signature_schema(&self) -> SignatureSchema {
        SignatureSchema {
            schema_version: SCHEMA_VERSION,
            signatures: self
                .all_active_patterns()
                .into_iter()
                .map(|p| p.signature.clone())
                .collect(),
            metadata: None,
        }
    }

    /// Update lifecycle based on statistics.
    pub fn update_lifecycles(&mut self) -> Vec<(String, PatternLifecycle, PatternLifecycle)> {
        let mut transitions = Vec::new();

        for pattern in self
            .learned
            .patterns
            .iter_mut()
            .chain(self.custom.patterns.iter_mut())
        {
            if let Some(stats) = self.stats.get(&pattern.signature.name) {
                let suggested = stats.suggested_lifecycle();
                if pattern.lifecycle != suggested && pattern.lifecycle.can_transition_to(suggested) {
                    let old = pattern.lifecycle;
                    pattern.lifecycle = suggested;
                    pattern.touch();
                    transitions.push((pattern.signature.name.clone(), old, suggested));
                    self.dirty = true;
                }
            }
        }

        transitions
    }
}

/// Migrate schema from an older version to current.
pub fn migrate_schema(
    schema: &mut PersistedSchema,
    from_version: u32,
) -> Result<(), PersistenceError> {
    if from_version == SCHEMA_VERSION {
        return Ok(());
    }

    if from_version > SCHEMA_VERSION {
        return Err(PersistenceError::MigrationFailed {
            from: from_version,
            to: SCHEMA_VERSION,
            reason: "Cannot downgrade schema version".to_string(),
        });
    }

    // Version 1 -> 2 migration: Add priors and expectations fields
    if from_version == 1 && SCHEMA_VERSION >= 2 {
        // The default fields are already set by serde
        // Just update the version number
        schema.schema_version = 2;
    }

    // Future migrations would go here

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_test_signature(name: &str) -> SupervisorSignature {
        SupervisorSignature {
            name: name.to_string(),
            category: super::super::types::SupervisorCategory::Other,
            patterns: super::super::signature::SignaturePatterns {
                process_names: vec![format!("^{}$", name)],
                ..Default::default()
            },
            confidence_weight: 0.8,
            notes: None,
            builtin: false,
            priors: Default::default(),
            expectations: Default::default(),
            priority: 100,
        }
    }

    #[test]
    fn test_pattern_lifecycle_transitions() {
        use PatternLifecycle::*;

        assert!(New.can_transition_to(Learning));
        assert!(Learning.can_transition_to(Stable));
        assert!(Stable.can_transition_to(Deprecated));
        assert!(Deprecated.can_transition_to(Removed));

        // Reactivation
        assert!(Deprecated.can_transition_to(Stable));

        // Invalid transitions
        assert!(!New.can_transition_to(Stable));
        assert!(!Removed.can_transition_to(Stable));
    }

    #[test]
    fn test_pattern_stats_recording() {
        let mut stats = PatternStats::default();

        stats.record_match(true);
        stats.record_match(true);
        stats.record_match(false);

        assert_eq!(stats.match_count, 3);
        assert_eq!(stats.accept_count, 2);
        assert_eq!(stats.reject_count, 1);

        // Laplace smoothing: (2+1)/(3+2) = 0.6
        assert!((stats.computed_confidence.unwrap() - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_library_add_and_get() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = make_test_signature("test_pattern");
        lib.add_custom(sig.clone()).expect("add");

        let pattern = lib.get_pattern("test_pattern");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().signature.name, "test_pattern");
    }

    #[test]
    fn test_library_disable_enable() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = make_test_signature("test_pattern");
        lib.add_custom(sig).expect("add");

        lib.disable_pattern("test_pattern", Some("testing"))
            .expect("disable");
        assert!(lib.disabled.is_disabled("test_pattern"));

        // Pattern should not appear in active patterns
        let active: Vec<_> = lib
            .all_active_patterns()
            .iter()
            .map(|p| p.signature.name.clone())
            .collect();
        assert!(!active.contains(&"test_pattern".to_string()));

        lib.enable_pattern("test_pattern").expect("enable");
        assert!(!lib.disabled.is_disabled("test_pattern"));
    }

    #[test]
    fn test_library_persistence() {
        let dir = tempdir().expect("tempdir");

        // Create and save
        {
            let mut lib = PatternLibrary::new(dir.path());
            let sig = make_test_signature("persisted_pattern");
            lib.add_custom(sig).expect("add");
            lib.save().expect("save");
        }

        // Load and verify
        {
            let mut lib = PatternLibrary::new(dir.path());
            lib.load().expect("load");
            let pattern = lib.get_pattern("persisted_pattern");
            assert!(pattern.is_some());
        }
    }

    #[test]
    fn test_import_conflict_resolution() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        // Add existing pattern with low confidence
        let mut sig1 = make_test_signature("conflict_test");
        sig1.confidence_weight = 0.5;
        lib.add_custom(sig1).expect("add");

        // Import pattern with higher confidence
        let mut sig2 = make_test_signature("conflict_test");
        sig2.confidence_weight = 0.9;

        let import_schema = PersistedSchema {
            schema_version: SCHEMA_VERSION,
            patterns: vec![PersistedPattern::new(sig2, PatternSource::Imported)],
            metadata: None,
        };

        let result = lib
            .import(import_schema, ConflictResolution::KeepHigherConfidence)
            .expect("import");

        assert_eq!(result.updated, 1);
        assert_eq!(result.conflicts.len(), 1);

        // Should have the higher confidence version now
        let pattern = lib.get_pattern("conflict_test").unwrap();
        assert!((pattern.signature.confidence_weight - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_export() {
        let dir = tempdir().expect("tempdir");
        let mut lib = PatternLibrary::new(dir.path());

        let sig = make_test_signature("export_test");
        lib.add_custom(sig).expect("add");

        let exported = lib.export(&[PatternSource::Custom]);
        assert_eq!(exported.patterns.len(), 1);
        assert_eq!(exported.patterns[0].signature.name, "export_test");
    }
}
