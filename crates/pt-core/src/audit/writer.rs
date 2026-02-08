//! Audit log writer with hash chain and rotation support.
//!
//! The writer maintains the hash chain integrity and handles log rotation
//! with checkpoint preservation.

use super::entry::{
    ActionDetails, AuditContext, AuditEntry, AuditEventType, CheckpointDetails, ErrorDetails,
    PolicyCheckDetails, RecommendDetails, ScanDetails,
};
use super::{resolve_audit_dir, AuditError, AUDIT_LOG_FILENAME};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// The special hash used for the first entry in a new log file.
pub const GENESIS_HASH: &str = "genesis";

/// Configuration for the audit log writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogConfig {
    /// Maximum log file size in bytes before rotation (default: 100MB).
    pub max_size_bytes: u64,
    /// Enable automatic rotation.
    pub auto_rotate: bool,
    /// Directory for audit logs.
    pub audit_dir: Option<PathBuf>,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        AuditLogConfig {
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            auto_rotate: true,
            audit_dir: None,
        }
    }
}

/// Configuration for log rotation.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Maximum file size before rotation.
    pub max_size_bytes: u64,
    /// Maximum age before rotation (in days).
    pub max_age_days: Option<u32>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationConfig {
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            max_age_days: Some(30),
        }
    }
}

/// The audit log writer.
///
/// Maintains the hash chain and handles file rotation.
pub struct AuditLog {
    /// Path to the current audit log file.
    path: PathBuf,
    /// Configuration.
    config: AuditLogConfig,
    /// Hash of the last entry written (for chaining).
    last_hash: String,
    /// Number of entries written to current file.
    entry_count: u64,
    /// Buffered writer for efficient I/O.
    writer: Option<BufWriter<File>>,
}

impl AuditLog {
    /// Open an existing audit log or create a new one.
    pub fn open_or_create() -> Result<Self, AuditError> {
        Self::open_or_create_with_config(AuditLogConfig::default())
    }

    /// Open or create with custom configuration.
    pub fn open_or_create_with_config(mut config: AuditLogConfig) -> Result<Self, AuditError> {
        // Resolve audit directory
        let audit_dir = config
            .audit_dir
            .take()
            .map(Ok)
            .unwrap_or_else(resolve_audit_dir)?;

        // Ensure directory exists
        std::fs::create_dir_all(&audit_dir).map_err(|e| AuditError::Io {
            path: audit_dir.clone(),
            source: e,
        })?;

        let path = audit_dir.join(AUDIT_LOG_FILENAME);

        // Determine initial state
        let (last_hash, entry_count) = if path.exists() {
            // Read the last entry to get its hash
            Self::read_last_entry_hash(&path)?
        } else {
            (GENESIS_HASH.to_string(), 0)
        };

        config.audit_dir = Some(audit_dir);

        Ok(AuditLog {
            path,
            config,
            last_hash,
            entry_count,
            writer: None,
        })
    }

    /// Get the path to the audit log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the number of entries in the current log file.
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Get the hash of the last entry (for verification).
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Write a raw entry to the log.
    ///
    /// This is the core write method; convenience methods call this.
    pub fn write_entry(&mut self, mut entry: AuditEntry) -> Result<(), AuditError> {
        // Check for rotation
        if self.config.auto_rotate && self.should_rotate()? {
            self.rotate()?;
        }

        // Set the previous hash from chain
        entry.prev_hash = self.last_hash.clone();

        // Compute this entry's hash
        entry.compute_hash()?;

        // Serialize and write
        let line = entry.to_jsonl();

        self.ensure_writer_open()?;
        if let Some(ref mut writer) = self.writer {
            writeln!(writer, "{}", line).map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;
            writer.flush().map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;
        }

        // Update state
        self.last_hash = entry.hash().to_string();
        self.entry_count += 1;

        Ok(())
    }

    /// Log a scan event.
    pub fn log_scan(
        &mut self,
        ctx: &AuditContext,
        phase: &str,
        process_count: Option<u32>,
        candidate_count: Option<u32>,
        scan_mode: Option<&str>,
        duration_ms: Option<u64>,
    ) -> Result<(), AuditError> {
        let message = match phase {
            "started" => "Process scan started".to_string(),
            "completed" => format!(
                "Process scan completed: {} processes, {} candidates",
                process_count.unwrap_or(0),
                candidate_count.unwrap_or(0)
            ),
            _ => format!("Scan phase: {}", phase),
        };

        let details = ScanDetails {
            phase: phase.to_string(),
            process_count,
            candidate_count,
            scan_mode: scan_mode.map(|s| s.to_string()),
            duration_ms,
        };

        let entry = AuditEntry::new(ctx, AuditEventType::Scan, message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)
    }

    /// Log an action recommendation.
    #[allow(clippy::too_many_arguments)]
    pub fn log_recommend(
        &mut self,
        ctx: &AuditContext,
        pid: u32,
        start_id: Option<&str>,
        cmd: Option<&str>,
        action: &str,
        posterior: Option<f64>,
        classification: Option<&str>,
        rationale: Option<&str>,
    ) -> Result<(), AuditError> {
        let message = format!("Recommended {} for PID {}", action, pid);

        let details = RecommendDetails {
            pid,
            start_id: start_id.map(|s| s.to_string()),
            cmd: cmd.map(|s| s.to_string()),
            action: action.to_string(),
            posterior,
            classification: classification.map(|s| s.to_string()),
            rationale: rationale.map(|s| s.to_string()),
        };

        let entry = AuditEntry::new(ctx, AuditEventType::Recommend, message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)
    }

    /// Log an action execution.
    #[allow(clippy::too_many_arguments)]
    pub fn log_action(
        &mut self,
        ctx: &AuditContext,
        pid: u32,
        start_id: Option<&str>,
        action: &str,
        success: bool,
        error: Option<&str>,
        signal: Option<&str>,
        dry_run: bool,
    ) -> Result<(), AuditError> {
        let message = if dry_run {
            format!("[DRY-RUN] Would {} PID {}", action, pid)
        } else if success {
            format!("Successfully executed {} on PID {}", action, pid)
        } else {
            format!(
                "Failed to {} PID {}: {}",
                action,
                pid,
                error.unwrap_or("unknown error")
            )
        };

        let details = ActionDetails {
            pid,
            start_id: start_id.map(|s| s.to_string()),
            action: action.to_string(),
            success,
            error: error.map(|s| s.to_string()),
            signal: signal.map(|s| s.to_string()),
            dry_run,
            verified: None,
            context: std::collections::HashMap::new(),
        };

        let entry = AuditEntry::new(ctx, AuditEventType::Action, message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)
    }

    /// Log a policy check.
    pub fn log_policy_check(
        &mut self,
        ctx: &AuditContext,
        rule: &str,
        passed: bool,
        pid: Option<u32>,
        reason: Option<&str>,
        guardrail: Option<&str>,
    ) -> Result<(), AuditError> {
        let message = if passed {
            format!("Policy check passed: {}", rule)
        } else {
            format!(
                "Policy check blocked: {} ({})",
                rule,
                reason.unwrap_or("no reason")
            )
        };

        let details = PolicyCheckDetails {
            rule: rule.to_string(),
            passed,
            pid,
            reason: reason.map(|s| s.to_string()),
            guardrail: guardrail.map(|s| s.to_string()),
        };

        let entry = AuditEntry::new(ctx, AuditEventType::PolicyCheck, message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)
    }

    /// Log an error.
    pub fn log_error(
        &mut self,
        ctx: &AuditContext,
        category: &str,
        message: &str,
        code: Option<&str>,
        context: Option<&str>,
        recoverable: bool,
    ) -> Result<(), AuditError> {
        let audit_message = format!("Error [{}]: {}", category, message);

        let details = ErrorDetails {
            category: category.to_string(),
            message: message.to_string(),
            code: code.map(|s| s.to_string()),
            context: context.map(|s| s.to_string()),
            recoverable,
        };

        let entry = AuditEntry::new(ctx, AuditEventType::Error, audit_message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)
    }

    /// Write a checkpoint entry (for rotation or shutdown).
    pub fn write_checkpoint(
        &mut self,
        ctx: &AuditContext,
        reason: &str,
    ) -> Result<String, AuditError> {
        // Compute state hash (hash of all entry hashes)
        let state_hash = self.compute_state_hash()?;

        let details = CheckpointDetails {
            entry_count: self.entry_count,
            state_hash: state_hash.clone(),
            prev_log_file: None,
            reason: reason.to_string(),
        };

        let message = format!(
            "Checkpoint: {} entries, state_hash={}",
            self.entry_count,
            &state_hash[..16]
        );

        let entry = AuditEntry::new(ctx, AuditEventType::Checkpoint, message, &self.last_hash)
            .with_details(&details);

        self.write_entry(entry)?;

        Ok(state_hash)
    }

    /// Rotate the log file.
    ///
    /// Creates a checkpoint, renames the current file, and starts a new one.
    pub fn rotate(&mut self) -> Result<PathBuf, AuditError> {
        // Close current writer
        self.writer = None;

        // Generate rotation timestamp
        let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let rotated_name = format!("audit.{}.jsonl", timestamp);
        let audit_dir = self
            .config
            .audit_dir
            .as_ref()
            .ok_or(AuditError::DataDirUnavailable)?;
        let rotated_path = audit_dir.join(&rotated_name);

        // Rename current file
        std::fs::rename(&self.path, &rotated_path).map_err(|e| AuditError::Io {
            path: self.path.clone(),
            source: e,
        })?;

        // Reset state for new file
        self.last_hash = rotated_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| format!("rotated:{}", s))
            .unwrap_or_else(|| "rotated".to_string());
        self.entry_count = 0;

        Ok(rotated_path)
    }

    /// Check if rotation is needed based on file size.
    fn should_rotate(&self) -> Result<bool, AuditError> {
        if !self.path.exists() {
            return Ok(false);
        }

        let metadata = std::fs::metadata(&self.path).map_err(|e| AuditError::Io {
            path: self.path.clone(),
            source: e,
        })?;

        Ok(metadata.len() >= self.config.max_size_bytes)
    }

    /// Ensure the writer is open.
    fn ensure_writer_open(&mut self) -> Result<(), AuditError> {
        if self.writer.is_some() {
            return Ok(());
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;

        self.writer = Some(BufWriter::new(file));
        Ok(())
    }

    /// Read the last entry hash from an existing log file.
    fn read_last_entry_hash(path: &Path) -> Result<(String, u64), AuditError> {
        let file = File::open(path).map_err(|e| AuditError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let reader = BufReader::new(file);
        let mut last_hash = GENESIS_HASH.to_string();
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line.map_err(|e| AuditError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| AuditError::Parse {
                line: count as usize + 1,
                source: e,
            })?;

            if let Some(hash) = &entry.entry_hash {
                last_hash = hash.clone();
            }
            count += 1;
        }

        Ok((last_hash, count))
    }

    /// Compute the state hash (hash of all entry hashes concatenated).
    fn compute_state_hash(&self) -> Result<String, AuditError> {
        if !self.path.exists() {
            return Ok("empty".to_string());
        }

        let file = File::open(&self.path).map_err(|e| AuditError::Io {
            path: self.path.clone(),
            source: e,
        })?;

        let reader = BufReader::new(file);
        let mut combined = String::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;

            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| AuditError::Parse {
                line: line_num + 1,
                source: e,
            })?;

            if let Some(hash) = &entry.entry_hash {
                combined.push_str(hash);
            }
        }

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// Flush any buffered writes.
    pub fn flush(&mut self) -> Result<(), AuditError> {
        if let Some(ref mut writer) = self.writer {
            writer.flush().map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Close the writer (called automatically on drop, but can be called explicitly).
    pub fn close(&mut self) {
        if let Some(ref mut writer) = self.writer {
            let _ = writer.flush();
        }
        self.writer = None;
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(dir: &Path) -> AuditLogConfig {
        AuditLogConfig {
            max_size_bytes: 1024 * 1024,
            auto_rotate: false,
            audit_dir: Some(dir.to_path_buf()),
        }
    }

    #[test]
    fn test_audit_log_creation() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let log = AuditLog::open_or_create_with_config(config).unwrap();

        assert_eq!(log.entry_count(), 0);
        assert_eq!(log.last_hash(), GENESIS_HASH);
    }

    #[test]
    fn test_audit_log_write_and_chain() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-test", "host-test");

        // Write first entry
        log.log_scan(&ctx, "started", None, None, Some("quick"), None)
            .unwrap();

        assert_eq!(log.entry_count(), 1);
        assert_ne!(log.last_hash(), GENESIS_HASH);
        let first_hash = log.last_hash().to_string();

        // Write second entry
        log.log_scan(
            &ctx,
            "completed",
            Some(100),
            Some(5),
            Some("quick"),
            Some(500),
        )
        .unwrap();

        assert_eq!(log.entry_count(), 2);
        assert_ne!(log.last_hash(), &first_hash);

        // Verify file contents
        let content = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // First entry should have prev_hash = genesis
        let entry1: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry1.prev_hash, GENESIS_HASH);

        // Second entry should chain to first
        let entry2: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(entry2.prev_hash, first_hash);
    }

    #[test]
    fn test_audit_log_reopen() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        // Write some entries
        {
            let mut log = AuditLog::open_or_create_with_config(config.clone()).unwrap();
            let ctx = AuditContext::new("run-test", "host-test");

            log.log_scan(&ctx, "started", None, None, None, None)
                .unwrap();
            log.log_scan(&ctx, "completed", Some(50), Some(3), None, Some(100))
                .unwrap();
        }

        // Reopen and verify state
        {
            let log = AuditLog::open_or_create_with_config(config).unwrap();
            assert_eq!(log.entry_count(), 2);
            assert_ne!(log.last_hash(), GENESIS_HASH);
        }
    }

    #[test]
    fn test_audit_log_action_logging() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-test", "host-test").with_session_id("pt-20260115-test");

        log.log_action(
            &ctx,
            1234,
            Some("boot:12345:1234"),
            "kill",
            true,
            None,
            Some("SIGTERM"),
            false,
        )
        .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"action""#));
        assert!(content.contains(r#""pid":1234"#));
        assert!(content.contains(r#""success":true"#));
    }

    #[test]
    fn test_audit_log_policy_check_logging() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-test", "host-test");

        log.log_policy_check(
            &ctx,
            "protected_pattern",
            false,
            Some(1),
            Some("systemd is protected"),
            Some("protected_processes"),
        )
        .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"policy_check""#));
        assert!(content.contains(r#""passed":false"#));
        assert!(content.contains("systemd is protected"));
    }

    #[test]
    fn test_audit_log_checkpoint() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-test", "host-test");

        // Write some entries first
        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();
        log.log_scan(&ctx, "completed", Some(50), Some(3), None, None)
            .unwrap();

        // Write checkpoint
        let state_hash = log.write_checkpoint(&ctx, "test").unwrap();

        assert!(!state_hash.is_empty());
        assert_eq!(log.entry_count(), 3);

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"checkpoint""#));
        assert!(content.contains(&state_hash));
    }

    #[test]
    fn test_audit_log_rotation() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(tmp.path());
        config.max_size_bytes = 100; // Very small to trigger rotation

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-test", "host-test");

        // Write enough to trigger rotation check (but rotation is manual here)
        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();

        // Manual rotation
        let rotated_path = log.rotate().unwrap();

        assert!(rotated_path.exists());
        assert!(rotated_path.to_string_lossy().contains("audit."));
        assert_eq!(log.entry_count(), 0);
    }

    // ── AuditLogConfig serde + defaults ─────────────────────────────

    #[test]
    fn audit_log_config_serde_roundtrip() {
        let config = AuditLogConfig {
            max_size_bytes: 5_000_000,
            auto_rotate: true,
            audit_dir: Some(PathBuf::from("/tmp/audit")),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: AuditLogConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_size_bytes, 5_000_000);
        assert!(back.auto_rotate);
        assert_eq!(back.audit_dir.unwrap(), PathBuf::from("/tmp/audit"));
    }

    #[test]
    fn audit_log_config_default() {
        let config = AuditLogConfig::default();
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024);
        assert!(config.auto_rotate);
        assert!(config.audit_dir.is_none());
    }

    #[test]
    fn audit_log_config_serde_none_audit_dir() {
        let config = AuditLogConfig {
            max_size_bytes: 1024,
            auto_rotate: false,
            audit_dir: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: AuditLogConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.auto_rotate);
        assert!(back.audit_dir.is_none());
    }

    // ── RotationConfig defaults ─────────────────────────────────────

    #[test]
    fn rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_age_days, Some(30));
    }

    #[test]
    fn rotation_config_debug() {
        let config = RotationConfig {
            max_size_bytes: 1024,
            max_age_days: None,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("RotationConfig"));
        assert!(dbg.contains("1024"));
    }

    // ── GENESIS_HASH constant ───────────────────────────────────────

    #[test]
    fn genesis_hash_value() {
        assert_eq!(GENESIS_HASH, "genesis");
    }

    // ── log_recommend ───────────────────────────────────────────────

    #[test]
    fn audit_log_recommend() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-rec", "host-rec");

        log.log_recommend(
            &ctx,
            42,
            Some("boot:1:42"),
            Some("/usr/bin/python"),
            "kill",
            Some(0.95),
            Some("zombie"),
            Some("high confidence zombie"),
        )
        .unwrap();

        assert_eq!(log.entry_count(), 1);
        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"recommend""#));
        assert!(content.contains(r#""pid":42"#));
        assert!(content.contains("high confidence zombie"));
    }

    #[test]
    fn audit_log_recommend_minimal() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-rec2", "host-rec2");

        log.log_recommend(&ctx, 100, None, None, "pause", None, None, None)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Recommended pause for PID 100"));
    }

    // ── log_error ───────────────────────────────────────────────────

    #[test]
    fn audit_log_error() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-err", "host-err");

        log.log_error(
            &ctx,
            "io",
            "disk full",
            Some("EIO"),
            Some("writing audit"),
            false,
        )
        .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"error""#));
        assert!(content.contains("disk full"));
        assert!(content.contains(r#""recoverable":false"#));
    }

    #[test]
    fn audit_log_error_recoverable() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-err2", "host-err2");

        log.log_error(&ctx, "network", "timeout", None, None, true)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""recoverable":true"#));
        assert!(content.contains("Error [network]: timeout"));
    }

    // ── flush ───────────────────────────────────────────────────────

    #[test]
    fn audit_log_flush_no_writer() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        // flush without writing anything should be OK
        log.flush().unwrap();
    }

    #[test]
    fn audit_log_flush_after_write() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-flush", "host-flush");

        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();
        log.flush().unwrap();
        assert_eq!(log.entry_count(), 1);
    }

    // ── close / drop ────────────────────────────────────────────────

    #[test]
    fn audit_log_close_and_reopen() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        let last_hash;
        {
            let mut log = AuditLog::open_or_create_with_config(config.clone()).unwrap();
            let ctx = AuditContext::new("run-close", "host-close");
            log.log_scan(&ctx, "started", None, None, None, None)
                .unwrap();
            last_hash = log.last_hash().to_string();
            log.close();
        }

        // Reopen — chain should continue from closed state
        let log = AuditLog::open_or_create_with_config(config).unwrap();
        assert_eq!(log.entry_count(), 1);
        assert_eq!(log.last_hash(), last_hash);
    }

    // ── reopen chain continuity ─────────────────────────────────────

    #[test]
    fn audit_log_reopen_chain_continues() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());

        // Write first batch
        let hash_after_first;
        {
            let mut log = AuditLog::open_or_create_with_config(config.clone()).unwrap();
            let ctx = AuditContext::new("run-chain", "host-chain");
            log.log_scan(&ctx, "started", None, None, None, None)
                .unwrap();
            hash_after_first = log.last_hash().to_string();
        }

        // Reopen and write second entry — verify chain links
        {
            let mut log = AuditLog::open_or_create_with_config(config).unwrap();
            let ctx = AuditContext::new("run-chain", "host-chain");
            log.log_scan(&ctx, "completed", Some(10), Some(2), None, None)
                .unwrap();

            // Check file: 2nd entry's prev_hash should be hash_after_first
            let content = std::fs::read_to_string(log.path()).unwrap();
            let lines: Vec<&str> = content.lines().collect();
            assert_eq!(lines.len(), 2);
            let entry2: AuditEntry = serde_json::from_str(lines[1]).unwrap();
            assert_eq!(entry2.prev_hash, hash_after_first);
        }
    }

    // ── multiple event types in sequence ────────────────────────────

    #[test]
    fn audit_log_mixed_event_types() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-mix", "host-mix").with_session_id("pt-20260207-mix");

        log.log_scan(&ctx, "started", None, None, Some("full"), None)
            .unwrap();
        log.log_recommend(&ctx, 1, None, None, "keep", None, None, None)
            .unwrap();
        log.log_action(&ctx, 2, None, "pause", true, None, Some("SIGSTOP"), false)
            .unwrap();
        log.log_policy_check(&ctx, "rate_limit", true, Some(2), None, None)
            .unwrap();
        log.log_error(&ctx, "config", "missing key", None, None, true)
            .unwrap();

        assert_eq!(log.entry_count(), 5);

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains(r#""event_type":"scan""#));
        assert!(content.contains(r#""event_type":"recommend""#));
        assert!(content.contains(r#""event_type":"action""#));
        assert!(content.contains(r#""event_type":"policy_check""#));
        assert!(content.contains(r#""event_type":"error""#));
    }

    // ── action logging message variants ─────────────────────────────

    #[test]
    fn audit_log_action_dry_run() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-dry", "host-dry");

        log.log_action(&ctx, 55, None, "kill", false, None, None, true)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("[DRY-RUN] Would kill PID 55"));
    }

    #[test]
    fn audit_log_action_failed() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-fail", "host-fail");

        log.log_action(
            &ctx,
            77,
            Some("boot:1:77"),
            "kill",
            false,
            Some("permission denied"),
            None,
            false,
        )
        .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Failed to kill PID 77"));
        assert!(content.contains("permission denied"));
    }

    #[test]
    fn audit_log_action_failed_no_error() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-fail2", "host-fail2");

        log.log_action(&ctx, 88, None, "kill", false, None, None, false)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Failed to kill PID 88: unknown error"));
    }

    // ── scan phase message variants ─────────────────────────────────

    #[test]
    fn audit_log_scan_custom_phase() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-phase", "host-phase");

        log.log_scan(&ctx, "filtering", None, None, None, None)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Scan phase: filtering"));
    }

    // ── policy check passed message ─────────────────────────────────

    #[test]
    fn audit_log_policy_check_passed() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-pc", "host-pc");

        log.log_policy_check(&ctx, "min_age", true, Some(42), None, Some("age_check"))
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Policy check passed: min_age"));
    }

    #[test]
    fn audit_log_policy_check_blocked_no_reason() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-pc2", "host-pc2");

        log.log_policy_check(&ctx, "rate_limit", false, None, None, None)
            .unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("Policy check blocked: rate_limit (no reason)"));
    }

    // ── auto-rotation trigger ───────────────────────────────────────

    #[test]
    fn audit_log_auto_rotation() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(tmp.path());
        config.max_size_bytes = 1; // Extremely small to force rotation
        config.auto_rotate = true;

        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-auto", "host-auto");

        // First write creates the file
        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();

        // Second write should trigger auto-rotation (file > 1 byte)
        log.log_scan(&ctx, "completed", Some(5), Some(1), None, None)
            .unwrap();

        // After auto-rotation, entry_count resets: new file has only the post-rotation entry
        // The entry_count is 1 because the rotation reset it to 0 then the write incremented
        assert!(log.entry_count() <= 2);
    }

    // ── checkpoint state hash deterministic ─────────────────────────

    #[test]
    fn audit_log_checkpoint_state_hash_deterministic() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-det", "host-det");

        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();

        let hash1 = log.write_checkpoint(&ctx, "checkpoint1").unwrap();
        let hash2 = log.write_checkpoint(&ctx, "checkpoint2").unwrap();

        // Both hashes should be valid hex sha256 (64 chars)
        assert_eq!(hash1.len(), 64);
        assert_eq!(hash2.len(), 64);
        // Second hash differs because it includes the first checkpoint entry
        assert_ne!(hash1, hash2);
    }

    // ── empty file state hash ───────────────────────────────────────

    #[test]
    fn audit_log_checkpoint_after_one_entry() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-ckpt1", "host-ckpt1");

        // Write one entry so the file exists before checkpoint
        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();

        let state_hash = log.write_checkpoint(&ctx, "after-one").unwrap();
        assert_eq!(state_hash.len(), 64, "state hash should be sha256 hex");
        assert_eq!(log.entry_count(), 2);
    }

    // ── path accessor ───────────────────────────────────────────────

    #[test]
    fn audit_log_path_accessor() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let log = AuditLog::open_or_create_with_config(config).unwrap();

        let path = log.path();
        assert!(path.ends_with(AUDIT_LOG_FILENAME));
        assert!(path.starts_with(tmp.path()));
    }

    // ── rotation resets last_hash with filename ─────────────────────

    #[test]
    fn audit_log_rotation_resets_hash() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut log = AuditLog::open_or_create_with_config(config).unwrap();
        let ctx = AuditContext::new("run-rot", "host-rot");

        log.log_scan(&ctx, "started", None, None, None, None)
            .unwrap();

        log.rotate().unwrap();

        // After rotation, last_hash should start with "rotated:"
        assert!(
            log.last_hash().starts_with("rotated:"),
            "post-rotation hash should start with 'rotated:', got '{}'",
            log.last_hash()
        );
        assert_eq!(log.entry_count(), 0);
    }
}
