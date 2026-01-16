//! Agent inbox for dormant mode escalations and notifications.
//!
//! This module implements the inbox system from Plan §3.5 and §3.7:
//! - Stores pending plans from dormant mode escalations
//! - Tracks lock contention events
//! - Records respawn detection notifications
//! - Provides acknowledgement mechanism

use chrono::Utc;
use pt_common::schema::SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const INBOX_DIR: &str = "inbox";
const INBOX_FILE: &str = "items.jsonl";

/// Errors from inbox operations.
#[derive(Debug, Error)]
pub enum InboxError {
    #[error("failed to resolve data directory")]
    DataDirUnavailable,

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse JSON: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },

    #[error("item not found: {0}")]
    ItemNotFound(String),
}

/// Type of inbox item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxItemType {
    /// Daemon detected issue and generated plan.
    DormantEscalation,
    /// Daemon wanted to escalate but lock was held.
    LockContention,
    /// Kill action resulted in respawn.
    RespawnDetected,
    /// Shadow mode detected model drift.
    CalibrationDrift,
    /// Periodic cleanup suggested.
    MaintenanceReminder,
    /// Manual notification.
    Manual,
}

impl std::fmt::Display for InboxItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DormantEscalation => write!(f, "dormant_escalation"),
            Self::LockContention => write!(f, "lock_contention"),
            Self::RespawnDetected => write!(f, "respawn_detected"),
            Self::CalibrationDrift => write!(f, "calibration_drift"),
            Self::MaintenanceReminder => write!(f, "maintenance_reminder"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

/// A single inbox item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    /// Unique identifier for this item.
    pub id: String,
    /// Type of notification.
    #[serde(rename = "type")]
    pub item_type: InboxItemType,
    /// When the item was created.
    pub created_at: String,
    /// Associated session ID (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Trigger reason (for escalations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    /// Human-readable summary.
    pub summary: String,
    /// Number of candidates (for escalations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<u32>,
    /// Whether the item has been acknowledged.
    pub acknowledged: bool,
    /// When the item was acknowledged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<String>,
    /// Command to review this item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_command: Option<String>,
    /// Additional message (for lock contention, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Deferred session ID (for lock contention).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_session_id: Option<String>,
}

impl InboxItem {
    /// Create a new inbox item with a generated ID.
    pub fn new(item_type: InboxItemType, summary: String) -> Self {
        let now = Utc::now();
        let id = format!(
            "inbox-{}-{}",
            now.format("%Y%m%d%H%M%S"),
            &uuid::Uuid::new_v4().to_string()[..4]
        );
        Self {
            id,
            item_type,
            created_at: now.to_rfc3339(),
            session_id: None,
            trigger: None,
            summary,
            candidates: None,
            acknowledged: false,
            acknowledged_at: None,
            review_command: None,
            message: None,
            deferred_session_id: None,
        }
    }

    /// Create a dormant escalation item.
    pub fn dormant_escalation(
        session_id: String,
        trigger: String,
        summary: String,
        candidates: u32,
    ) -> Self {
        let mut item = Self::new(InboxItemType::DormantEscalation, summary);
        item.session_id = Some(session_id.clone());
        item.trigger = Some(trigger);
        item.candidates = Some(candidates);
        item.review_command = Some(format!("pt agent plan --session {}", session_id));
        item
    }

    /// Create a lock contention item.
    pub fn lock_contention(message: String, deferred_session_id: Option<String>) -> Self {
        let mut item = Self::new(InboxItemType::LockContention, message.clone());
        item.message = Some(message);
        item.deferred_session_id = deferred_session_id;
        item
    }

    /// Create a respawn detection item.
    pub fn respawn_detected(
        session_id: String,
        summary: String,
        review_command: Option<String>,
    ) -> Self {
        let mut item = Self::new(InboxItemType::RespawnDetected, summary);
        item.session_id = Some(session_id);
        item.review_command = review_command;
        item
    }

    /// Mark this item as acknowledged.
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
        self.acknowledged_at = Some(Utc::now().to_rfc3339());
    }
}

/// Response for inbox listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxResponse {
    /// Schema version.
    pub schema_version: String,
    /// When the response was generated.
    pub generated_at: String,
    /// All inbox items.
    pub items: Vec<InboxItem>,
    /// Count of unread/unacknowledged items.
    pub unread_count: u32,
}

impl InboxResponse {
    /// Create a new response from items.
    pub fn new(items: Vec<InboxItem>) -> Self {
        let unread_count = items.iter().filter(|i| !i.acknowledged).count() as u32;
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            items,
            unread_count,
        }
    }
}

/// Store for inbox items.
#[derive(Debug, Clone)]
pub struct InboxStore {
    inbox_path: PathBuf,
}

impl InboxStore {
    /// Create a store from environment.
    pub fn from_env() -> Result<Self, InboxError> {
        let data_dir = resolve_data_dir()?;
        let inbox_path = data_dir.join(INBOX_DIR).join(INBOX_FILE);
        Ok(Self { inbox_path })
    }

    /// Create a store from a specific data directory.
    pub fn from_data_dir(data_dir: &Path) -> Self {
        Self {
            inbox_path: data_dir.join(INBOX_DIR).join(INBOX_FILE),
        }
    }

    /// Get all inbox items.
    pub fn list(&self) -> Result<Vec<InboxItem>, InboxError> {
        if !self.inbox_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.inbox_path).map_err(|e| InboxError::Io {
            path: self.inbox_path.clone(),
            source: e,
        })?;

        let mut items = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let item: InboxItem =
                serde_json::from_str(line).map_err(|e| InboxError::Json { source: e })?;
            items.push(item);
        }

        // Sort by created_at (newest first)
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
    }

    /// Get unacknowledged items only.
    pub fn list_unread(&self) -> Result<Vec<InboxItem>, InboxError> {
        let items = self.list()?;
        Ok(items.into_iter().filter(|i| !i.acknowledged).collect())
    }

    /// Add an item to the inbox.
    pub fn add(&self, item: &InboxItem) -> Result<(), InboxError> {
        // Ensure parent directory exists
        if let Some(parent) = self.inbox_path.parent() {
            fs::create_dir_all(parent).map_err(|e| InboxError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let line = serde_json::to_string(item).map_err(|e| InboxError::Json { source: e })?;

        // Append to file
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.inbox_path)
            .map_err(|e| InboxError::Io {
                path: self.inbox_path.clone(),
                source: e,
            })?;

        writeln!(file, "{}", line).map_err(|e| InboxError::Io {
            path: self.inbox_path.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Acknowledge an item by ID.
    pub fn acknowledge(&self, item_id: &str) -> Result<InboxItem, InboxError> {
        let mut items = self.list()?;
        let mut found = None;

        for item in &mut items {
            if item.id == item_id {
                item.acknowledge();
                found = Some(item.clone());
                break;
            }
        }

        match found {
            Some(item) => {
                self.write_all(&items)?;
                Ok(item)
            }
            None => Err(InboxError::ItemNotFound(item_id.to_string())),
        }
    }

    /// Clear all acknowledged items.
    pub fn clear_acknowledged(&self) -> Result<u32, InboxError> {
        let items = self.list()?;
        let unacknowledged: Vec<_> = items.into_iter().filter(|i| !i.acknowledged).collect();
        let cleared_count = self.list()?.len() - unacknowledged.len();
        self.write_all(&unacknowledged)?;
        Ok(cleared_count as u32)
    }

    /// Clear all items.
    pub fn clear_all(&self) -> Result<u32, InboxError> {
        let count = self.list()?.len();
        if self.inbox_path.exists() {
            fs::remove_file(&self.inbox_path).map_err(|e| InboxError::Io {
                path: self.inbox_path.clone(),
                source: e,
            })?;
        }
        Ok(count as u32)
    }

    /// Write all items to the file (replaces existing content).
    fn write_all(&self, items: &[InboxItem]) -> Result<(), InboxError> {
        // Ensure parent directory exists
        if let Some(parent) = self.inbox_path.parent() {
            fs::create_dir_all(parent).map_err(|e| InboxError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let mut content = String::new();
        for item in items {
            let line = serde_json::to_string(item).map_err(|e| InboxError::Json { source: e })?;
            content.push_str(&line);
            content.push('\n');
        }

        fs::write(&self.inbox_path, content).map_err(|e| InboxError::Io {
            path: self.inbox_path.clone(),
            source: e,
        })?;

        Ok(())
    }
}

/// Resolve the data directory.
fn resolve_data_dir() -> Result<PathBuf, InboxError> {
    const ENV_DATA_DIR: &str = "PROCESS_TRIAGE_DATA";
    const DIR_NAME: &str = "process_triage";

    // 1) Explicit override
    if let Ok(dir) = std::env::var(ENV_DATA_DIR) {
        return Ok(PathBuf::from(dir));
    }

    // 2) XDG_DATA_HOME
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join(DIR_NAME));
    }

    // 3) Platform default
    if let Some(base) = dirs::data_dir() {
        return Ok(base.join(DIR_NAME));
    }

    Err(InboxError::DataDirUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (InboxStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = InboxStore::from_data_dir(tmp.path());
        (store, tmp)
    }

    #[test]
    fn test_empty_inbox() {
        let (store, _tmp) = test_store();
        let items = store.list().unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_add_and_list() {
        let (store, _tmp) = test_store();

        let item = InboxItem::new(
            InboxItemType::DormantEscalation,
            "High load detected".to_string(),
        );
        store.add(&item).unwrap();

        let items = store.list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, item.id);
        assert!(!items[0].acknowledged);
    }

    #[test]
    fn test_acknowledge() {
        let (store, _tmp) = test_store();

        let item = InboxItem::new(InboxItemType::LockContention, "Lock held".to_string());
        let item_id = item.id.clone();
        store.add(&item).unwrap();

        let acked = store.acknowledge(&item_id).unwrap();
        assert!(acked.acknowledged);
        assert!(acked.acknowledged_at.is_some());

        let items = store.list().unwrap();
        assert!(items[0].acknowledged);
    }

    #[test]
    fn test_clear_acknowledged() {
        let (store, _tmp) = test_store();

        let item1 = InboxItem::new(InboxItemType::Manual, "Test 1".to_string());
        let item2 = InboxItem::new(InboxItemType::Manual, "Test 2".to_string());
        let id1 = item1.id.clone();
        store.add(&item1).unwrap();
        store.add(&item2).unwrap();

        store.acknowledge(&id1).unwrap();
        let cleared = store.clear_acknowledged().unwrap();
        assert_eq!(cleared, 1);

        let items = store.list().unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].acknowledged);
    }

    #[test]
    fn test_dormant_escalation() {
        let item = InboxItem::dormant_escalation(
            "session-123".to_string(),
            "sustained_load".to_string(),
            "3 KILL candidates identified".to_string(),
            3,
        );
        assert_eq!(item.item_type, InboxItemType::DormantEscalation);
        assert_eq!(item.session_id, Some("session-123".to_string()));
        assert_eq!(item.candidates, Some(3));
        assert!(item.review_command.is_some());
    }

    #[test]
    fn test_inbox_response() {
        let item1 = InboxItem::new(InboxItemType::Manual, "Test 1".to_string());
        let mut item2 = InboxItem::new(InboxItemType::Manual, "Test 2".to_string());
        item2.acknowledge();

        let response = InboxResponse::new(vec![item1, item2]);
        assert_eq!(response.items.len(), 2);
        assert_eq!(response.unread_count, 1);
    }
}
