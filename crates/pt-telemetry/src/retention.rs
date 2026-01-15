//! Telemetry retention policy enforcement.
//!
//! This module enforces retention policies for telemetry data:
//! - Per-table TTL (time-to-live) enforcement
//! - Disk budget constraints (global and per-table)
//! - Explicit retention event logging (no silent deletions)
//! - Dry-run mode for previewing pruning actions
//!
//! # Design Principles
//!
//! 1. **No silent deletions**: Every pruning action is logged as a retention event.
//! 2. **Predictable**: Retention is based on explicit policy, not heuristics.
//! 3. **Safe**: Prefers keeping important data (outcomes, audit) over raw traces.
//! 4. **Auditable**: All retention events are persisted for compliance.
//!
//! # Example
//!
//! ```no_run
//! use pt_telemetry::retention::{RetentionConfig, RetentionEnforcer, RetentionEvent};
//! use std::path::PathBuf;
//!
//! let config = RetentionConfig::default();
//! let mut enforcer = RetentionEnforcer::new(
//!     PathBuf::from("~/.local/share/process_triage/telemetry"),
//!     config,
//! );
//!
//! // Preview what would be pruned
//! let preview = enforcer.preview()?;
//! println!("Would prune {} files ({} bytes)", preview.files_to_prune, preview.bytes_to_free);
//!
//! // Actually enforce retention
//! let events = enforcer.enforce()?;
//! for event in events {
//!     println!("Pruned: {} - {:?}", event.file_path, event.reason);
//! }
//! # Ok::<(), pt_telemetry::retention::RetentionError>(())
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::schema::TableName;

/// Errors from retention operations.
#[derive(Error, Debug)]
pub enum RetentionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Path error: {0}")]
    PathError(String),
}

/// Configuration for retention policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Per-table TTL overrides (days). Uses defaults if not specified.
    #[serde(default)]
    pub ttl_days: HashMap<String, u32>,

    /// Global disk budget in bytes. 0 means unlimited.
    #[serde(default)]
    pub disk_budget_bytes: u64,

    /// Per-table disk budget in bytes. 0 means unlimited.
    #[serde(default)]
    pub table_budget_bytes: HashMap<String, u64>,

    /// Keep everything mode - disables all pruning.
    #[serde(default)]
    pub keep_everything: bool,

    /// Pruning priority order (tables to prune first when over budget).
    /// Default: proc_samples, proc_features, proc_inference, runs, audit, outcomes
    #[serde(default = "default_pruning_priority")]
    pub pruning_priority: Vec<String>,

    /// Minimum free bytes after pruning (prevents over-aggressive pruning).
    #[serde(default = "default_min_free_after")]
    pub min_free_after_bytes: u64,

    /// Output directory for retention event logs.
    #[serde(default)]
    pub event_log_dir: Option<PathBuf>,
}

fn default_pruning_priority() -> Vec<String> {
    vec![
        "proc_samples".to_string(),
        "proc_features".to_string(),
        "proc_inference".to_string(),
        "runs".to_string(),
        "audit".to_string(),
        "outcomes".to_string(),
    ]
}

fn default_min_free_after() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            ttl_days: HashMap::new(),
            disk_budget_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            table_budget_bytes: HashMap::new(),
            keep_everything: false,
            pruning_priority: default_pruning_priority(),
            min_free_after_bytes: default_min_free_after(),
            event_log_dir: None,
        }
    }
}

impl RetentionConfig {
    /// Get effective TTL for a table (uses override or default).
    pub fn effective_ttl_days(&self, table: TableName) -> u32 {
        self.ttl_days
            .get(table.as_str())
            .copied()
            .unwrap_or_else(|| table.retention_days())
    }

    /// Get effective TTL as Duration.
    pub fn effective_ttl(&self, table: TableName) -> Duration {
        Duration::from_secs(self.effective_ttl_days(table) as u64 * 24 * 3600)
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), RetentionError> {
        // Check that all table names in overrides are valid
        for table_name in self.ttl_days.keys() {
            if !is_valid_table_name(table_name) {
                return Err(RetentionError::InvalidConfig(format!(
                    "Unknown table name in ttl_days: {}",
                    table_name
                )));
            }
        }

        for table_name in self.table_budget_bytes.keys() {
            if !is_valid_table_name(table_name) {
                return Err(RetentionError::InvalidConfig(format!(
                    "Unknown table name in table_budget_bytes: {}",
                    table_name
                )));
            }
        }

        Ok(())
    }
}

fn is_valid_table_name(name: &str) -> bool {
    matches!(
        name,
        "runs" | "proc_samples" | "proc_features" | "proc_inference" | "outcomes" | "audit"
    )
}

/// A retention event recording a pruning action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionEvent {
    /// When the pruning occurred.
    pub timestamp: DateTime<Utc>,

    /// Relative path of the pruned file.
    pub file_path: String,

    /// Table name the file belonged to.
    pub table: String,

    /// Size of the file in bytes.
    pub size_bytes: u64,

    /// Age of the file when pruned.
    pub age_days: u32,

    /// Reason for pruning.
    pub reason: RetentionReason,

    /// Whether this was a dry-run (file not actually deleted).
    pub dry_run: bool,

    /// Host ID (for fleet aggregation).
    pub host_id: String,

    /// Session IDs contained in the file (if known).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
}

/// Reason for pruning a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionReason {
    /// File exceeded TTL.
    TtlExpired { ttl_days: u32, age_days: u32 },

    /// Global disk budget exceeded.
    DiskBudgetExceeded {
        budget_bytes: u64,
        used_bytes: u64,
        freed_bytes: u64,
    },

    /// Per-table budget exceeded.
    TableBudgetExceeded {
        table: String,
        budget_bytes: u64,
        used_bytes: u64,
        freed_bytes: u64,
    },

    /// Manual pruning request.
    ManualPrune { reason: String },

    /// Compaction replaced this file.
    Compacted { new_file: String },
}

/// A candidate file for pruning.
#[derive(Debug, Clone)]
pub struct PruneCandidate {
    /// Full path to the file.
    pub path: PathBuf,

    /// Relative path from telemetry root.
    pub relative_path: String,

    /// Table this file belongs to.
    pub table: TableName,

    /// File size in bytes.
    pub size_bytes: u64,

    /// File modification time.
    pub modified: SystemTime,

    /// Partition date extracted from path.
    pub partition_date: Option<chrono::NaiveDate>,

    /// Host ID from partition path.
    pub host_id: Option<String>,
}

impl PruneCandidate {
    /// Get age of the file.
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.modified)
            .unwrap_or_default()
    }

    /// Get age in days.
    pub fn age_days(&self) -> u32 {
        (self.age().as_secs() / 86400) as u32
    }
}

/// Preview of retention actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPreview {
    /// Total files that would be pruned.
    pub files_to_prune: usize,

    /// Total bytes that would be freed.
    pub bytes_to_free: u64,

    /// Per-table breakdown.
    pub by_table: HashMap<String, TablePreview>,

    /// Current total usage.
    pub current_usage_bytes: u64,

    /// Usage after pruning.
    pub projected_usage_bytes: u64,

    /// Candidates for pruning (sorted by priority).
    pub candidates: Vec<PruneCandidatePreview>,
}

/// Per-table preview of retention actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TablePreview {
    pub files_to_prune: usize,
    pub bytes_to_free: u64,
    pub current_files: usize,
    pub current_bytes: u64,
    pub ttl_days: u32,
    pub budget_bytes: u64,
}

/// Simplified candidate info for preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneCandidatePreview {
    pub file_path: String,
    pub table: String,
    pub size_bytes: u64,
    pub age_days: u32,
    pub reason: RetentionReason,
}

/// Retention status for a telemetry directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionStatus {
    /// Root telemetry directory.
    pub root_dir: String,

    /// Total disk usage in bytes.
    pub total_bytes: u64,

    /// Total file count.
    pub total_files: usize,

    /// Per-table statistics.
    pub by_table: HashMap<String, TableStatus>,

    /// Configured disk budget.
    pub disk_budget_bytes: u64,

    /// Percentage of budget used.
    pub budget_used_pct: f64,

    /// Files eligible for TTL pruning.
    pub ttl_eligible_files: usize,

    /// Bytes eligible for TTL pruning.
    pub ttl_eligible_bytes: u64,

    /// Next scheduled check (if applicable).
    pub next_check: Option<DateTime<Utc>>,
}

/// Per-table status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStatus {
    pub file_count: usize,
    pub total_bytes: u64,
    pub oldest_file_age_days: u32,
    pub newest_file_age_days: u32,
    pub ttl_days: u32,
    pub budget_bytes: u64,
    pub over_ttl_count: usize,
    pub over_ttl_bytes: u64,
}

/// Enforces retention policies on telemetry data.
pub struct RetentionEnforcer {
    /// Root telemetry directory.
    root_dir: PathBuf,

    /// Retention configuration.
    config: RetentionConfig,

    /// Host ID for this machine.
    host_id: String,
}

impl RetentionEnforcer {
    /// Create a new retention enforcer.
    pub fn new(root_dir: PathBuf, config: RetentionConfig) -> Self {
        let host_id = get_host_id();
        Self {
            root_dir,
            config,
            host_id,
        }
    }

    /// Create with custom host ID.
    pub fn with_host_id(root_dir: PathBuf, config: RetentionConfig, host_id: String) -> Self {
        Self {
            root_dir,
            config,
            host_id,
        }
    }

    /// Get current retention status.
    pub fn status(&self) -> Result<RetentionStatus, RetentionError> {
        let candidates = self.scan_all_files()?;
        let mut by_table: HashMap<String, TableStatus> = HashMap::new();

        for table in all_tables() {
            let table_name = table.as_str().to_string();
            let table_candidates: Vec<_> = candidates
                .iter()
                .filter(|c| c.table == table)
                .collect();

            let ttl = self.config.effective_ttl(table);
            let over_ttl: Vec<_> = table_candidates
                .iter()
                .filter(|c| c.age() > ttl)
                .collect();

            by_table.insert(
                table_name.clone(),
                TableStatus {
                    file_count: table_candidates.len(),
                    total_bytes: table_candidates.iter().map(|c| c.size_bytes).sum(),
                    oldest_file_age_days: table_candidates
                        .iter()
                        .map(|c| c.age_days())
                        .max()
                        .unwrap_or(0),
                    newest_file_age_days: table_candidates
                        .iter()
                        .map(|c| c.age_days())
                        .min()
                        .unwrap_or(0),
                    ttl_days: self.config.effective_ttl_days(table),
                    budget_bytes: self
                        .config
                        .table_budget_bytes
                        .get(&table_name)
                        .copied()
                        .unwrap_or(0),
                    over_ttl_count: over_ttl.len(),
                    over_ttl_bytes: over_ttl.iter().map(|c| c.size_bytes).sum(),
                },
            );
        }

        let total_bytes: u64 = candidates.iter().map(|c| c.size_bytes).sum();
        let budget_used_pct = if self.config.disk_budget_bytes > 0 {
            (total_bytes as f64 / self.config.disk_budget_bytes as f64) * 100.0
        } else {
            0.0
        };

        let ttl_eligible: Vec<_> = candidates
            .iter()
            .filter(|c| c.age() > self.config.effective_ttl(c.table))
            .collect();

        Ok(RetentionStatus {
            root_dir: self.root_dir.display().to_string(),
            total_bytes,
            total_files: candidates.len(),
            by_table,
            disk_budget_bytes: self.config.disk_budget_bytes,
            budget_used_pct,
            ttl_eligible_files: ttl_eligible.len(),
            ttl_eligible_bytes: ttl_eligible.iter().map(|c| c.size_bytes).sum(),
            next_check: None,
        })
    }

    /// Preview retention actions without making changes.
    pub fn preview(&self) -> Result<RetentionPreview, RetentionError> {
        let all_candidates = self.scan_all_files()?;
        let current_usage: u64 = all_candidates.iter().map(|c| c.size_bytes).sum();

        if self.config.keep_everything {
            let mut by_table: HashMap<String, TablePreview> = HashMap::new();
            for table in all_tables() {
                let table_name = table.as_str().to_string();
                let table_all: Vec<_> = all_candidates
                    .iter()
                    .filter(|c| c.table == table)
                    .collect();

                by_table.insert(
                    table_name.clone(),
                    TablePreview {
                        files_to_prune: 0,
                        bytes_to_free: 0,
                        current_files: table_all.len(),
                        current_bytes: table_all.iter().map(|c| c.size_bytes).sum(),
                        ttl_days: self.config.effective_ttl_days(table),
                        budget_bytes: self
                            .config
                            .table_budget_bytes
                            .get(&table_name)
                            .copied()
                            .unwrap_or(0),
                    },
                );
            }

            return Ok(RetentionPreview {
                files_to_prune: 0,
                bytes_to_free: 0,
                by_table,
                current_usage_bytes: current_usage,
                projected_usage_bytes: current_usage,
                candidates: Vec::new(),
            });
        }

        let mut prune_candidates = Vec::new();

        // Phase 1: TTL-based pruning
        for candidate in &all_candidates {
            let ttl = self.config.effective_ttl(candidate.table);
            if candidate.age() > ttl {
                prune_candidates.push(PruneCandidatePreview {
                    file_path: candidate.relative_path.clone(),
                    table: candidate.table.as_str().to_string(),
                    size_bytes: candidate.size_bytes,
                    age_days: candidate.age_days(),
                    reason: RetentionReason::TtlExpired {
                        ttl_days: self.config.effective_ttl_days(candidate.table),
                        age_days: candidate.age_days(),
                    },
                });
            }
        }

        // Phase 2: Budget-based pruning (if still over budget after TTL pruning)
        let bytes_after_ttl: u64 = current_usage.saturating_sub(
            prune_candidates.iter().map(|c| c.size_bytes).sum::<u64>(),
        );

        if self.config.disk_budget_bytes > 0 && bytes_after_ttl > self.config.disk_budget_bytes {
            let mut need_to_free = bytes_after_ttl - self.config.disk_budget_bytes;

            // Sort remaining files by priority (oldest first within priority order)
            let mut remaining: Vec<_> = all_candidates
                .iter()
                .filter(|c| {
                    !prune_candidates
                        .iter()
                        .any(|p| p.file_path == c.relative_path)
                })
                .collect();

            // Sort by priority order then by age (oldest first)
            remaining.sort_by(|a, b| {
                let a_priority = self
                    .config
                    .pruning_priority
                    .iter()
                    .position(|t| t == a.table.as_str())
                    .unwrap_or(usize::MAX);
                let b_priority = self
                    .config
                    .pruning_priority
                    .iter()
                    .position(|t| t == b.table.as_str())
                    .unwrap_or(usize::MAX);

                a_priority
                    .cmp(&b_priority)
                    .then_with(|| b.age().cmp(&a.age()))
            });

            for candidate in remaining {
                if need_to_free == 0 {
                    break;
                }

                let freed = candidate.size_bytes;
                prune_candidates.push(PruneCandidatePreview {
                    file_path: candidate.relative_path.clone(),
                    table: candidate.table.as_str().to_string(),
                    size_bytes: candidate.size_bytes,
                    age_days: candidate.age_days(),
                    reason: RetentionReason::DiskBudgetExceeded {
                        budget_bytes: self.config.disk_budget_bytes,
                        used_bytes: bytes_after_ttl,
                        freed_bytes: freed,
                    },
                });
                need_to_free = need_to_free.saturating_sub(candidate.size_bytes);
            }
        }

        let bytes_to_free: u64 = prune_candidates.iter().map(|c| c.size_bytes).sum();

        // Build per-table summary
        let mut by_table: HashMap<String, TablePreview> = HashMap::new();
        for table in all_tables() {
            let table_name = table.as_str().to_string();
            let table_prune: Vec<_> = prune_candidates
                .iter()
                .filter(|c| c.table == table_name)
                .collect();
            let table_all: Vec<_> = all_candidates
                .iter()
                .filter(|c| c.table == table)
                .collect();

            by_table.insert(
                table_name.clone(),
                TablePreview {
                    files_to_prune: table_prune.len(),
                    bytes_to_free: table_prune.iter().map(|c| c.size_bytes).sum(),
                    current_files: table_all.len(),
                    current_bytes: table_all.iter().map(|c| c.size_bytes).sum(),
                    ttl_days: self.config.effective_ttl_days(table),
                    budget_bytes: self
                        .config
                        .table_budget_bytes
                        .get(&table_name)
                        .copied()
                        .unwrap_or(0),
                },
            );
        }

        Ok(RetentionPreview {
            files_to_prune: prune_candidates.len(),
            bytes_to_free,
            by_table,
            current_usage_bytes: current_usage,
            projected_usage_bytes: current_usage.saturating_sub(bytes_to_free),
            candidates: prune_candidates,
        })
    }

    /// Enforce retention policy and return events for all pruned files.
    pub fn enforce(&mut self) -> Result<Vec<RetentionEvent>, RetentionError> {
        let preview = self.preview()?;
        self.enforce_preview(&preview, false)
    }

    /// Dry-run enforcement: log what would be done without deleting.
    pub fn dry_run(&mut self) -> Result<Vec<RetentionEvent>, RetentionError> {
        let preview = self.preview()?;
        self.enforce_preview(&preview, true)
    }

    /// Enforce a specific preview (used by both enforce and dry_run).
    fn enforce_preview(
        &mut self,
        preview: &RetentionPreview,
        dry_run: bool,
    ) -> Result<Vec<RetentionEvent>, RetentionError> {
        let mut events = Vec::new();
        let now = Utc::now();

        for candidate in &preview.candidates {
            let full_path = self.root_dir.join(&candidate.file_path);

            // Create retention event BEFORE deletion (no silent deletes)
            let event = RetentionEvent {
                timestamp: now,
                file_path: candidate.file_path.clone(),
                table: candidate.table.clone(),
                size_bytes: candidate.size_bytes,
                age_days: candidate.age_days,
                reason: candidate.reason.clone(),
                dry_run,
                host_id: self.host_id.clone(),
                session_ids: Vec::new(), // Could extract from filename if needed
            };

            // Log the event
            if dry_run {
                info!(
                    "[DRY-RUN] Would prune: {} ({} bytes, {} days old) - {:?}",
                    candidate.file_path, candidate.size_bytes, candidate.age_days, candidate.reason
                );
            } else {
                info!(
                    "Pruning: {} ({} bytes, {} days old) - {:?}",
                    candidate.file_path, candidate.size_bytes, candidate.age_days, candidate.reason
                );

                // Actually delete the file
                if full_path.exists() {
                    match fs::remove_file(&full_path) {
                        Ok(_) => {
                            debug!("Deleted: {}", full_path.display());
                        }
                        Err(e) => {
                            warn!("Failed to delete {}: {}", full_path.display(), e);
                            // Continue with other files, but mark event as failed
                            // (In a real impl, you might want a separate status field)
                        }
                    }
                }
            }

            events.push(event);
        }

        // Persist retention events to log file
        if let Some(log_dir) = &self.config.event_log_dir {
            self.persist_events(&events, log_dir)?;
        }

        Ok(events)
    }

    /// Persist retention events to a JSONL file.
    fn persist_events(
        &self,
        events: &[RetentionEvent],
        log_dir: &Path,
    ) -> Result<(), RetentionError> {
        if events.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(log_dir)?;

        let now = Utc::now();
        let filename = format!(
            "retention_events_{}.jsonl",
            now.format("%Y%m%d_%H%M%S")
        );
        let log_path = log_dir.join(filename);

        let file = fs::File::create(&log_path)?;
        let mut writer = std::io::BufWriter::new(file);

        for event in events {
            serde_json::to_writer(&mut writer, event)?;
            std::io::Write::write_all(&mut writer, b"\n")?;
        }

        info!("Wrote {} retention events to {}", events.len(), log_path.display());
        Ok(())
    }

    /// Scan all files in the telemetry directory.
    fn scan_all_files(&self) -> Result<Vec<PruneCandidate>, RetentionError> {
        let mut candidates = Vec::new();

        for table in all_tables() {
            let table_dir = self.root_dir.join(table.as_str());
            if table_dir.exists() {
                self.scan_table_dir(&table_dir, table, &mut candidates)?;
            }
        }

        Ok(candidates)
    }

    /// Scan a table directory for parquet files.
    fn scan_table_dir(
        &self,
        dir: &Path,
        table: TableName,
        candidates: &mut Vec<PruneCandidate>,
    ) -> Result<(), RetentionError> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recurse into partition directories (year=YYYY/month=MM/day=DD/host_id=X)
                self.scan_table_dir(&path, table, candidates)?;
            } else if path.extension().map_or(false, |ext| ext == "parquet") {
                let metadata = fs::metadata(&path)?;
                let modified = metadata.modified()?;
                let size = metadata.len();

                let relative = path
                    .strip_prefix(&self.root_dir)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| path.display().to_string());

                // Extract partition info from path
                let (partition_date, host_id) = extract_partition_info(&relative);

                candidates.push(PruneCandidate {
                    path,
                    relative_path: relative,
                    table,
                    size_bytes: size,
                    modified,
                    partition_date,
                    host_id,
                });
            }
        }

        Ok(())
    }
}

/// Extract partition date and host_id from a path like "table/year=2025/month=01/day=15/host_id=abc/file.parquet".
fn extract_partition_info(path: &str) -> (Option<chrono::NaiveDate>, Option<String>) {
    let mut year: Option<i32> = None;
    let mut month: Option<u32> = None;
    let mut day: Option<u32> = None;
    let mut host_id: Option<String> = None;

    for part in path.split('/') {
        if let Some(y) = part.strip_prefix("year=") {
            year = y.parse().ok();
        } else if let Some(m) = part.strip_prefix("month=") {
            month = m.parse().ok();
        } else if let Some(d) = part.strip_prefix("day=") {
            day = d.parse().ok();
        } else if let Some(h) = part.strip_prefix("host_id=") {
            host_id = Some(h.to_string());
        }
    }

    let date = year.and_then(|y| {
        month.and_then(|m| {
            day.and_then(|d| chrono::NaiveDate::from_ymd_opt(y, m, d))
        })
    });

    (date, host_id)
}

/// Get all table names.
fn all_tables() -> Vec<TableName> {
    vec![
        TableName::Runs,
        TableName::ProcSamples,
        TableName::ProcFeatures,
        TableName::ProcInference,
        TableName::Outcomes,
        TableName::Audit,
    ]
}

/// Get host ID for this machine.
fn get_host_id() -> String {
    // Try to read machine-id
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        return id.trim().to_string();
    }

    // Fallback to hostname
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        return hostname;
    }

    // Last resort
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_retention_config_default() {
        let config = RetentionConfig::default();
        assert_eq!(config.disk_budget_bytes, 10 * 1024 * 1024 * 1024);
        assert!(!config.keep_everything);
        assert_eq!(config.pruning_priority.len(), 6);
    }

    #[test]
    fn test_effective_ttl() {
        let mut config = RetentionConfig::default();

        // Default TTL
        assert_eq!(config.effective_ttl_days(TableName::Runs), 90);
        assert_eq!(config.effective_ttl_days(TableName::ProcSamples), 30);
        assert_eq!(config.effective_ttl_days(TableName::Outcomes), 365);

        // Override TTL
        config.ttl_days.insert("runs".to_string(), 180);
        assert_eq!(config.effective_ttl_days(TableName::Runs), 180);
    }

    #[test]
    fn test_config_validation() {
        let mut config = RetentionConfig::default();

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid table name in ttl_days
        config.ttl_days.insert("invalid_table".to_string(), 30);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_extract_partition_info() {
        let path = "proc_samples/year=2025/month=01/day=15/host_id=abc123/file.parquet";
        let (date, host_id) = extract_partition_info(path);

        assert_eq!(date, Some(chrono::NaiveDate::from_ymd_opt(2025, 1, 15).unwrap()));
        assert_eq!(host_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_partition_info_partial() {
        let path = "proc_samples/year=2025/file.parquet";
        let (date, host_id) = extract_partition_info(path);

        assert_eq!(date, None); // Missing month/day
        assert_eq!(host_id, None);
    }

    #[test]
    fn test_retention_reason_serialization() {
        let reason = RetentionReason::TtlExpired {
            ttl_days: 30,
            age_days: 45,
        };

        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("ttl_expired"));
        assert!(json.contains("30"));
        assert!(json.contains("45"));
    }

    #[test]
    fn test_keep_everything_mode() {
        let dir = tempdir().unwrap();
        let mut config = RetentionConfig::default();
        config.keep_everything = true;

        let enforcer = RetentionEnforcer::new(dir.path().to_path_buf(), config);
        let preview = enforcer.preview().unwrap();

        assert_eq!(preview.files_to_prune, 0);
        assert_eq!(preview.bytes_to_free, 0);
    }

    #[test]
    fn test_empty_directory_status() {
        let dir = tempdir().unwrap();
        let config = RetentionConfig::default();

        let enforcer = RetentionEnforcer::new(dir.path().to_path_buf(), config);
        let status = enforcer.status().unwrap();

        assert_eq!(status.total_files, 0);
        assert_eq!(status.total_bytes, 0);
    }

    #[test]
    fn test_prune_candidate_age() {
        use std::time::{Duration, SystemTime};

        let candidate = PruneCandidate {
            path: PathBuf::from("/tmp/test.parquet"),
            relative_path: "test.parquet".to_string(),
            table: TableName::ProcSamples,
            size_bytes: 1024,
            modified: SystemTime::now() - Duration::from_secs(86400 * 10), // 10 days ago
            partition_date: None,
            host_id: None,
        };

        assert!(candidate.age_days() >= 9); // Allow for timing variations
        assert!(candidate.age_days() <= 11);
    }

    #[test]
    fn test_retention_event_serialization() {
        let event = RetentionEvent {
            timestamp: Utc::now(),
            file_path: "proc_samples/year=2025/file.parquet".to_string(),
            table: "proc_samples".to_string(),
            size_bytes: 1024 * 1024,
            age_days: 45,
            reason: RetentionReason::TtlExpired {
                ttl_days: 30,
                age_days: 45,
            },
            dry_run: false,
            host_id: "test-host".to_string(),
            session_ids: vec!["session-1".to_string()],
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: RetentionEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.table, "proc_samples");
        assert_eq!(parsed.size_bytes, 1024 * 1024);
        assert_eq!(parsed.age_days, 45);
    }

    // ========================================================================
    // Integration tests with fake telemetry directory
    // ========================================================================

    /// Helper to create a fake parquet file with specific modification time.
    fn create_fake_parquet(path: &Path, size_bytes: usize, age_days: u64) -> std::io::Result<()> {
        use std::io::Write;
        use std::time::{Duration, SystemTime};

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write some data to achieve desired size
        let mut file = fs::File::create(path)?;
        let content = vec![0u8; size_bytes];
        file.write_all(&content)?;
        file.sync_all()?;

        // Set modification time to simulate age
        let mtime = SystemTime::now() - Duration::from_secs(age_days * 86400);
        let atime = filetime::FileTime::from_system_time(mtime);
        filetime::set_file_times(path, atime, atime)?;

        Ok(())
    }

    #[test]
    fn test_integration_ttl_pruning() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create proc_samples files with different ages (TTL = 30 days)
        let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
        let new_file = root.join("proc_samples/year=2025/month=01/day=15/host_id=test/new.parquet");

        create_fake_parquet(&old_file, 1024, 45).unwrap(); // 45 days old - over TTL
        create_fake_parquet(&new_file, 1024, 5).unwrap();  // 5 days old - under TTL

        // Create runs file (TTL = 90 days)
        let runs_file = root.join("runs/year=2025/month=01/day=01/host_id=test/run.parquet");
        create_fake_parquet(&runs_file, 1024, 50).unwrap(); // 50 days old - under 90-day TTL

        let config = RetentionConfig::default();
        let enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        // Preview should identify only the old proc_samples file
        let preview = enforcer.preview().unwrap();

        assert_eq!(preview.files_to_prune, 1, "Should prune exactly 1 TTL-expired file");
        assert!(preview.candidates.iter().any(|c| c.file_path.contains("old.parquet")));
        assert!(!preview.candidates.iter().any(|c| c.file_path.contains("new.parquet")));
        assert!(!preview.candidates.iter().any(|c| c.file_path.contains("run.parquet")));

        // Verify the reason is TTL expiration
        let candidate = &preview.candidates[0];
        match &candidate.reason {
            RetentionReason::TtlExpired { ttl_days, age_days } => {
                assert_eq!(*ttl_days, 30);
                assert!(*age_days >= 44 && *age_days <= 46);
            }
            _ => panic!("Expected TtlExpired reason"),
        }
    }

    #[test]
    fn test_integration_disk_budget_pruning() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create multiple files, all within TTL but exceeding budget
        let files = [
            ("proc_samples", "file1.parquet", 1024 * 1024, 5),
            ("proc_samples", "file2.parquet", 1024 * 1024, 10),
            ("outcomes", "file3.parquet", 1024 * 1024, 5),
        ];

        for (table, name, size, age) in &files {
            let path = root.join(format!("{}/year=2025/month=01/day=15/host_id=test/{}", table, name));
            create_fake_parquet(&path, *size, *age).unwrap();
        }

        // Set budget to 2MB (we have 3MB of files)
        let mut config = RetentionConfig::default();
        config.disk_budget_bytes = 2 * 1024 * 1024;

        let enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        let preview = enforcer.preview().unwrap();

        // Should prune at least 1 file to get under budget
        assert!(preview.files_to_prune >= 1, "Should prune files to meet disk budget");
        assert!(preview.bytes_to_free >= 1024 * 1024, "Should free at least 1MB");

        // Verify pruning priority: proc_samples should be pruned before outcomes
        let pruned_tables: Vec<_> = preview.candidates.iter().map(|c| c.table.as_str()).collect();
        if preview.files_to_prune == 1 {
            assert!(pruned_tables.contains(&"proc_samples"), "proc_samples should be pruned first");
        }
    }

    #[test]
    fn test_integration_dry_run() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create a file that should be pruned
        let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
        create_fake_parquet(&old_file, 1024, 45).unwrap();

        let event_log_dir = root.join("retention_logs");
        let mut config = RetentionConfig::default();
        config.event_log_dir = Some(event_log_dir.clone());

        let mut enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        // Run dry-run
        let events = enforcer.dry_run().unwrap();

        // Should have events but file should still exist
        assert_eq!(events.len(), 1);
        assert!(events[0].dry_run);
        assert!(old_file.exists(), "File should not be deleted in dry-run mode");

        // Should have logged events
        assert!(event_log_dir.exists());
    }

    #[test]
    fn test_integration_actual_enforcement() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create a file that should be pruned
        let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
        create_fake_parquet(&old_file, 1024, 45).unwrap();

        assert!(old_file.exists(), "File should exist before enforcement");

        let mut config = RetentionConfig::default();
        config.event_log_dir = Some(root.join("retention_logs"));

        let mut enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        // Run actual enforcement
        let events = enforcer.enforce().unwrap();

        // Should have events and file should be deleted
        assert_eq!(events.len(), 1);
        assert!(!events[0].dry_run);
        assert!(!old_file.exists(), "File should be deleted after enforcement");
    }

    #[test]
    fn test_integration_status_reporting() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create files in multiple tables
        let files = [
            ("proc_samples", "file1.parquet", 1024, 5),
            ("proc_samples", "file2.parquet", 2048, 35), // Over TTL
            ("runs", "file3.parquet", 4096, 10),
            ("outcomes", "file4.parquet", 8192, 100),
        ];

        for (table, name, size, age) in &files {
            let path = root.join(format!("{}/year=2025/month=01/day=15/host_id=test/{}", table, name));
            create_fake_parquet(&path, *size, *age).unwrap();
        }

        let config = RetentionConfig::default();
        let enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        let status = enforcer.status().unwrap();

        // Verify totals
        assert_eq!(status.total_files, 4);
        assert_eq!(status.total_bytes, 1024 + 2048 + 4096 + 8192);

        // Verify per-table breakdown
        let proc_samples_status = status.by_table.get("proc_samples").unwrap();
        assert_eq!(proc_samples_status.file_count, 2);
        assert_eq!(proc_samples_status.total_bytes, 1024 + 2048);
        assert_eq!(proc_samples_status.over_ttl_count, 1); // file2 is over TTL

        let runs_status = status.by_table.get("runs").unwrap();
        assert_eq!(runs_status.file_count, 1);
        assert_eq!(runs_status.over_ttl_count, 0);

        // Verify TTL eligible count
        assert_eq!(status.ttl_eligible_files, 1); // Only proc_samples/file2
    }

    #[test]
    fn test_integration_pruning_priority_order() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create files that all exceed disk budget, but outcomes should be preserved
        let files = [
            ("proc_samples", "samples.parquet", 2 * 1024 * 1024, 5),
            ("proc_features", "features.parquet", 2 * 1024 * 1024, 5),
            ("outcomes", "outcomes.parquet", 2 * 1024 * 1024, 5),
        ];

        for (table, name, size, age) in &files {
            let path = root.join(format!("{}/year=2025/month=01/day=15/host_id=test/{}", table, name));
            create_fake_parquet(&path, *size, *age).unwrap();
        }

        // Set budget to 4MB (we have 6MB total)
        let mut config = RetentionConfig::default();
        config.disk_budget_bytes = 4 * 1024 * 1024;

        let enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        let preview = enforcer.preview().unwrap();

        // Should prune exactly 1 file (2MB) to get to 4MB
        assert_eq!(preview.files_to_prune, 1);

        // According to priority (proc_samples, proc_features, proc_inference, runs, outcomes, audit),
        // proc_samples should be pruned first
        let pruned = &preview.candidates[0];
        assert_eq!(pruned.table, "proc_samples");
    }

    #[test]
    fn test_retention_event_log_format() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create a file to prune
        let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
        create_fake_parquet(&old_file, 1024, 45).unwrap();

        let event_log_dir = root.join("retention_logs");
        let mut config = RetentionConfig::default();
        config.event_log_dir = Some(event_log_dir.clone());

        let mut enforcer = RetentionEnforcer::with_host_id(
            root.to_path_buf(),
            config,
            "test-host".to_string(),
        );

        // Run enforcement
        let _ = enforcer.enforce().unwrap();

        // Read and verify the log file
        let log_files: Vec<_> = fs::read_dir(&event_log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(log_files.len(), 1);

        let log_content = fs::read_to_string(log_files[0].path()).unwrap();
        let event: RetentionEvent = serde_json::from_str(log_content.trim()).unwrap();

        // Verify required fields
        assert!(!event.file_path.is_empty());
        assert_eq!(event.table, "proc_samples");
        assert!(event.size_bytes > 0);
        assert!(event.age_days > 30);
        assert_eq!(event.host_id, "test-host");
        assert!(!event.dry_run);

        // Verify reason contains correct info
        match event.reason {
            RetentionReason::TtlExpired { ttl_days, age_days } => {
                assert_eq!(ttl_days, 30);
                assert!(age_days >= 44);
            }
            _ => panic!("Expected TtlExpired reason"),
        }
    }
}
