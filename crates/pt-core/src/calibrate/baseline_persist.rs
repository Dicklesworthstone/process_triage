//! Baseline persistence, export/import, and management.
//!
//! Provides serialization, versioned storage, reset, and round-trip
//! export/import for per-host baselines. Supports fleet transfer learning.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::baseline::{BaselineConfig, BaselineStore, BaselineSummary};

/// On-disk format for persisted baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBaselines {
    /// Schema version for backward compatibility.
    pub schema_version: u32,
    /// Host fingerprint (machine-id or boot_id).
    pub host_fingerprint: String,
    /// Timestamp of last update (epoch seconds).
    pub updated_at: f64,
    /// Redaction policy version active when baselines were computed.
    pub redaction_policy_version: Option<String>,
    /// Per-metric baselines.
    pub baselines: HashMap<String, BaselineSummary>,
    /// Global fallback baseline.
    pub global: Option<BaselineSummary>,
    /// Metadata for provenance tracking.
    pub metadata: BaselineMetadata,
}

/// Provenance metadata for baselines.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineMetadata {
    /// Number of reset operations performed.
    pub reset_count: u32,
    /// Timestamp of last reset (epoch seconds).
    pub last_reset_at: Option<f64>,
    /// Source of import (if imported from another host).
    pub imported_from: Option<String>,
    /// Timestamp of import.
    pub imported_at: Option<f64>,
    /// Total observations used across all baselines.
    pub total_observations: usize,
}

/// Error from baseline persistence operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BaselinePersistError {
    /// Schema version mismatch.
    SchemaMismatch { expected: u32, found: u32 },
    /// Serialization error.
    SerializeError(String),
    /// Deserialization error.
    DeserializeError(String),
    /// IO error.
    IoError(String),
    /// No baseline data to export.
    NoData,
}

impl std::fmt::Display for BaselinePersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch { expected, found } => {
                write!(
                    f,
                    "Schema version mismatch: expected {}, found {}",
                    expected, found
                )
            }
            Self::SerializeError(msg) => write!(f, "Serialize error: {}", msg),
            Self::DeserializeError(msg) => write!(f, "Deserialize error: {}", msg),
            Self::IoError(msg) => write!(f, "IO error: {}", msg),
            Self::NoData => write!(f, "No baseline data to export"),
        }
    }
}

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Manages baseline lifecycle: load, save, reset, export, import.
#[derive(Debug, Clone)]
pub struct BaselineManager {
    /// Current persisted state.
    pub state: PersistedBaselines,
    /// Configuration.
    pub config: BaselineConfig,
}

impl BaselineManager {
    /// Create a new manager for a host.
    pub fn new(host_fingerprint: String, config: BaselineConfig) -> Self {
        Self {
            state: PersistedBaselines {
                schema_version: CURRENT_SCHEMA_VERSION,
                host_fingerprint,
                updated_at: 0.0,
                redaction_policy_version: None,
                baselines: HashMap::new(),
                global: None,
                metadata: BaselineMetadata::default(),
            },
            config,
        }
    }

    /// Load from a BaselineStore (in-memory representation).
    pub fn from_store(store: &BaselineStore, host_fingerprint: String, now: f64) -> Self {
        let total_obs: usize = store.baselines.values().map(|b| b.n).sum();
        Self {
            state: PersistedBaselines {
                schema_version: CURRENT_SCHEMA_VERSION,
                host_fingerprint,
                updated_at: now,
                redaction_policy_version: None,
                baselines: store.baselines.clone(),
                global: store.global.clone(),
                metadata: BaselineMetadata {
                    total_observations: total_obs,
                    ..Default::default()
                },
            },
            config: BaselineConfig::default(),
        }
    }

    /// Export to JSON string.
    pub fn export_json(&self) -> Result<String, BaselinePersistError> {
        if self.state.baselines.is_empty() && self.state.global.is_none() {
            return Err(BaselinePersistError::NoData);
        }
        serde_json::to_string_pretty(&self.state)
            .map_err(|e| BaselinePersistError::SerializeError(e.to_string()))
    }

    /// Import from JSON string.
    pub fn import_json(
        json: &str,
        target_host: &str,
        now: f64,
    ) -> Result<Self, BaselinePersistError> {
        let mut state: PersistedBaselines = serde_json::from_str(json)
            .map_err(|e| BaselinePersistError::DeserializeError(e.to_string()))?;

        // Version check: only accept current or older.
        if state.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(BaselinePersistError::SchemaMismatch {
                expected: CURRENT_SCHEMA_VERSION,
                found: state.schema_version,
            });
        }

        // Record import provenance.
        let source_host = state.host_fingerprint.clone();
        state.metadata.imported_from = Some(source_host);
        state.metadata.imported_at = Some(now);
        state.host_fingerprint = target_host.to_string();
        state.updated_at = now;

        Ok(Self {
            state,
            config: BaselineConfig::default(),
        })
    }

    /// Reset all baselines for this host.
    pub fn reset(&mut self, now: f64) {
        self.state.baselines.clear();
        self.state.global = None;
        self.state.metadata.reset_count += 1;
        self.state.metadata.last_reset_at = Some(now);
        self.state.metadata.total_observations = 0;
        self.state.updated_at = now;
    }

    /// Update a specific baseline key.
    pub fn update_baseline(&mut self, key: String, summary: BaselineSummary, now: f64) {
        self.state.baselines.insert(key, summary);
        self.state.updated_at = now;
        self.state.metadata.total_observations = self.state.baselines.values().map(|b| b.n).sum();
    }

    /// Set the global fallback baseline.
    pub fn set_global(&mut self, summary: BaselineSummary, now: f64) {
        self.state.global = Some(summary);
        self.state.updated_at = now;
    }

    /// Convert to a BaselineStore for use in scoring.
    pub fn to_store(&self) -> BaselineStore {
        BaselineStore {
            baselines: self.state.baselines.clone(),
            global: self.state.global.clone(),
        }
    }

    /// Check if the host is in cold-start mode (no baselines or all cold-start).
    pub fn is_cold_start(&self) -> bool {
        self.state.baselines.is_empty() || self.state.baselines.values().all(|b| b.cold_start)
    }

    /// Summary string for display.
    pub fn summary(&self) -> String {
        let n_baselines = self.state.baselines.len();
        let cold = self
            .state
            .baselines
            .values()
            .filter(|b| b.cold_start)
            .count();
        let warm = n_baselines - cold;
        format!(
            "host={} baselines={} (warm={}, cold={}) obs={} resets={} schema=v{}",
            self.state.host_fingerprint,
            n_baselines,
            warm,
            cold,
            self.state.metadata.total_observations,
            self.state.metadata.reset_count,
            self.state.schema_version,
        )
    }

    /// Number of baseline keys.
    pub fn baseline_count(&self) -> usize {
        self.state.baselines.len()
    }
}

/// Generate a baseline update telemetry event (append-only log entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineUpdateEvent {
    /// Event type.
    pub event_type: BaselineEventType,
    /// Timestamp.
    pub timestamp: f64,
    /// Host fingerprint.
    pub host_fingerprint: String,
    /// Affected baseline keys.
    pub affected_keys: Vec<String>,
    /// Additional context.
    pub context: Option<String>,
}

/// Types of baseline events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineEventType {
    Updated,
    Reset,
    Imported,
    Exported,
}

impl std::fmt::Display for BaselineEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Updated => write!(f, "updated"),
            Self::Reset => write!(f, "reset"),
            Self::Imported => write!(f, "imported"),
            Self::Exported => write!(f, "exported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_summary(n: usize, mean: f64) -> BaselineSummary {
        BaselineSummary {
            n,
            mean,
            std_dev: 10.0,
            median: mean,
            mad: 7.5,
            percentiles: [mean - 20.0, mean - 5.0, mean, mean + 5.0, mean + 20.0],
            cold_start: n < 30,
            schema_version: 1,
        }
    }

    #[test]
    fn test_new_manager_is_empty() {
        let mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        assert_eq!(mgr.baseline_count(), 0);
        assert!(mgr.is_cold_start());
    }

    #[test]
    fn test_update_baseline() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 1000.0);
        assert_eq!(mgr.baseline_count(), 1);
        assert_eq!(mgr.state.metadata.total_observations, 100);
    }

    #[test]
    fn test_reset() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 1000.0);
        mgr.reset(2000.0);
        assert_eq!(mgr.baseline_count(), 0);
        assert_eq!(mgr.state.metadata.reset_count, 1);
        assert_eq!(mgr.state.metadata.last_reset_at, Some(2000.0));
    }

    #[test]
    fn test_export_import_roundtrip() {
        let mut mgr = BaselineManager::new("host-source".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 1000.0);
        mgr.set_global(make_summary(1000, 400.0), 1000.0);

        let json = mgr.export_json().unwrap();
        let imported = BaselineManager::import_json(&json, "host-target", 2000.0).unwrap();

        assert_eq!(imported.state.host_fingerprint, "host-target");
        assert_eq!(
            imported.state.metadata.imported_from,
            Some("host-source".to_string())
        );
        assert_eq!(imported.baseline_count(), 1);
        assert!(imported.state.global.is_some());
    }

    #[test]
    fn test_export_empty_fails() {
        let mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        let err = mgr.export_json().unwrap_err();
        match err {
            BaselinePersistError::NoData => {}
            _ => panic!("Expected NoData, got {:?}", err),
        }
    }

    #[test]
    fn test_schema_version_check() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(50, 300.0), 1000.0);
        mgr.state.schema_version = 999;

        let json = serde_json::to_string(&mgr.state).unwrap();
        let err = BaselineManager::import_json(&json, "host-target", 2000.0).unwrap_err();
        match err {
            BaselinePersistError::SchemaMismatch {
                expected: 1,
                found: 999,
            } => {}
            _ => panic!("Expected SchemaMismatch, got {:?}", err),
        }
    }

    #[test]
    fn test_cold_start_detection() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        assert!(mgr.is_cold_start());

        mgr.update_baseline("rss".to_string(), make_summary(10, 500.0), 1000.0);
        assert!(mgr.is_cold_start()); // n=10 < 30 → cold

        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 2000.0);
        assert!(!mgr.is_cold_start()); // n=100 >= 30 → warm
    }

    #[test]
    fn test_to_store() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 1000.0);
        mgr.set_global(make_summary(1000, 400.0), 1000.0);

        let store = mgr.to_store();
        assert_eq!(store.baselines.len(), 1);
        assert!(store.global.is_some());
    }

    #[test]
    fn test_summary_string() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.update_baseline("rss".to_string(), make_summary(100, 500.0), 1000.0);
        let s = mgr.summary();
        assert!(s.contains("host=host-abc"));
        assert!(s.contains("baselines=1"));
        assert!(s.contains("warm=1"));
    }

    #[test]
    fn test_from_store() {
        let mut store = BaselineStore::default();
        store
            .baselines
            .insert("cpu".to_string(), make_summary(50, 0.3));
        store.global = Some(make_summary(500, 0.25));

        let mgr = BaselineManager::from_store(&store, "host-xyz".to_string(), 5000.0);
        assert_eq!(mgr.baseline_count(), 1);
        assert_eq!(mgr.state.host_fingerprint, "host-xyz");
        assert_eq!(mgr.state.metadata.total_observations, 50);
    }

    #[test]
    fn test_multiple_resets_increment_count() {
        let mut mgr = BaselineManager::new("host-abc".to_string(), BaselineConfig::default());
        mgr.reset(1000.0);
        mgr.reset(2000.0);
        mgr.reset(3000.0);
        assert_eq!(mgr.state.metadata.reset_count, 3);
    }
}
