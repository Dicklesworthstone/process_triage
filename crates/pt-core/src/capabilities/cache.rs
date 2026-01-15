//! Capability cache management.
//!
//! Provides persistent caching of detected capabilities with configurable TTL.

use super::detect::{detect_capabilities, Capabilities};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Default cache TTL: 24 hours.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Cache file name.
const CACHE_FILE_NAME: &str = "capabilities.json";

/// Errors from cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("cache directory does not exist: {0}")]
    DirectoryNotFound(PathBuf),

    #[error("cache file corrupted")]
    Corrupted,
}

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Directory for cache files.
    pub cache_dir: PathBuf,

    /// Time-to-live for cached data.
    pub ttl: Duration,

    /// Whether to force refresh (ignore cache).
    pub force_refresh: bool,
}

impl CacheConfig {
    /// Create cache config with default TTL.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            force_refresh: false,
        }
    }

    /// Set custom TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Force refresh on next get.
    pub fn force_refresh(mut self) -> Self {
        self.force_refresh = true;
        self
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self::new(default_cache_dir())
    }
}

/// Cached capabilities with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCapabilities {
    /// The cached capabilities.
    capabilities: Capabilities,

    /// When the cache was written.
    cached_at: String,

    /// Cache file format version.
    version: u32,

    /// Host ID for cache validation.
    host_id: String,
}

impl CachedCapabilities {
    const CURRENT_VERSION: u32 = 1;

    fn new(capabilities: Capabilities, host_id: String) -> Self {
        Self {
            capabilities,
            cached_at: chrono::Utc::now().to_rfc3339(),
            version: Self::CURRENT_VERSION,
            host_id,
        }
    }

    /// Check if cache is valid for the given TTL.
    fn is_valid(&self, ttl: Duration, current_host_id: &str) -> bool {
        // Check version
        if self.version != Self::CURRENT_VERSION {
            debug!("cache version mismatch");
            return false;
        }

        // Check host ID
        if self.host_id != current_host_id {
            debug!("cache host ID mismatch");
            return false;
        }

        // Check TTL - use milliseconds for sub-second precision
        if let Ok(cached_time) = chrono::DateTime::parse_from_rfc3339(&self.cached_at) {
            let now = chrono::Utc::now();
            let age = now.signed_duration_since(cached_time);
            let age_ms = age.num_milliseconds().max(0) as u64;
            let ttl_ms = ttl.as_millis() as u64;
            if age_ms >= ttl_ms {
                debug!(age_ms, ttl_ms, "cache expired");
                return false;
            }
            return true;
        }

        false
    }
}

/// Capability cache manager.
#[derive(Debug, Clone)]
pub struct CapabilityCache {
    config: CacheConfig,
    host_id: String,
}

impl CapabilityCache {
    /// Create a new capability cache.
    pub fn new(config: CacheConfig) -> Self {
        let host_id = crate::logging::get_host_id();
        Self { config, host_id }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get cached capabilities or detect fresh.
    ///
    /// Returns cached capabilities if:
    /// - Cache exists and is not expired
    /// - Cache was created on the same host
    /// - Force refresh is not set
    ///
    /// Otherwise, detects fresh capabilities and caches them.
    pub fn get(&self) -> Result<Capabilities, CacheError> {
        // Check if we should use cache
        if !self.config.force_refresh {
            if let Some(cached) = self.load_cache()? {
                if cached.is_valid(self.config.ttl, &self.host_id) {
                    info!("using cached capabilities");
                    return Ok(cached.capabilities);
                }
            }
        }

        // Detect fresh capabilities
        info!("detecting fresh capabilities");
        let capabilities = detect_capabilities();

        // Cache the result
        if let Err(e) = self.save_cache(&capabilities) {
            warn!(error = %e, "failed to cache capabilities");
        }

        Ok(capabilities)
    }

    /// Force refresh capabilities (ignore cache).
    pub fn refresh(&self) -> Result<Capabilities, CacheError> {
        let capabilities = detect_capabilities();

        if let Err(e) = self.save_cache(&capabilities) {
            warn!(error = %e, "failed to cache capabilities");
        }

        Ok(capabilities)
    }

    /// Clear the cache.
    pub fn clear(&self) -> Result<(), CacheError> {
        let cache_path = self.cache_path();
        if cache_path.exists() {
            fs::remove_file(&cache_path)?;
            info!(path = %cache_path.display(), "cache cleared");
        }
        Ok(())
    }

    /// Check if cache exists and is valid.
    pub fn is_cached(&self) -> bool {
        if let Ok(Some(cached)) = self.load_cache() {
            return cached.is_valid(self.config.ttl, &self.host_id);
        }
        false
    }

    /// Get cache age in seconds (None if not cached).
    pub fn cache_age_secs(&self) -> Option<u64> {
        if let Ok(Some(cached)) = self.load_cache() {
            if let Ok(cached_time) = chrono::DateTime::parse_from_rfc3339(&cached.cached_at) {
                let now = chrono::Utc::now();
                let age = now.signed_duration_since(cached_time);
                return Some(age.num_seconds().max(0) as u64);
            }
        }
        None
    }

    /// Get the cache file path.
    fn cache_path(&self) -> PathBuf {
        self.config.cache_dir.join(CACHE_FILE_NAME)
    }

    /// Load cached capabilities from disk.
    fn load_cache(&self) -> Result<Option<CachedCapabilities>, CacheError> {
        let cache_path = self.cache_path();

        if !cache_path.exists() {
            return Ok(None);
        }

        let contents = fs::read_to_string(&cache_path)?;
        let cached: CachedCapabilities = serde_json::from_str(&contents)?;

        Ok(Some(cached))
    }

    /// Save capabilities to cache.
    fn save_cache(&self, capabilities: &Capabilities) -> Result<(), CacheError> {
        // Ensure cache directory exists
        if !self.config.cache_dir.exists() {
            fs::create_dir_all(&self.config.cache_dir)?;
        }

        let cached = CachedCapabilities::new(capabilities.clone(), self.host_id.clone());
        let json = serde_json::to_vec_pretty(&cached)?;

        // Write atomically
        let cache_path = self.cache_path();
        let tmp_path = cache_path.with_extension("json.tmp");

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(&json)?;
            file.flush()?;
        }

        fs::rename(tmp_path, &cache_path)?;

        debug!(path = %cache_path.display(), "capabilities cached");
        Ok(())
    }
}

/// Get the default cache directory.
pub fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("process_triage")
}

/// Get capabilities with caching (convenience function).
///
/// Uses default cache configuration.
pub fn get_capabilities() -> Capabilities {
    let cache = CapabilityCache::with_defaults();
    cache.get().unwrap_or_else(|e| {
        warn!(error = %e, "cache error, detecting fresh");
        detect_capabilities()
    })
}

/// Get capabilities with custom TTL (convenience function).
pub fn get_capabilities_with_ttl(ttl: Duration) -> Capabilities {
    let config = CacheConfig::default().with_ttl(ttl);
    let cache = CapabilityCache::new(config);
    cache.get().unwrap_or_else(|e| {
        warn!(error = %e, "cache error, detecting fresh");
        detect_capabilities()
    })
}

/// Force refresh capabilities (convenience function).
pub fn refresh_capabilities() -> Capabilities {
    let cache = CapabilityCache::with_defaults();
    cache.refresh().unwrap_or_else(|e| {
        warn!(error = %e, "cache error, detecting fresh");
        detect_capabilities()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cache() -> (CapabilityCache, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let config = CacheConfig::new(dir.path());
        (CapabilityCache::new(config), dir)
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(DEFAULT_CACHE_TTL_SECS));
        assert!(!config.force_refresh);
    }

    #[test]
    fn test_cache_config_builder() {
        let config = CacheConfig::new("/tmp/test")
            .with_ttl(Duration::from_secs(3600))
            .force_refresh();

        assert_eq!(config.ttl, Duration::from_secs(3600));
        assert!(config.force_refresh);
    }

    #[test]
    fn test_cache_get_creates_cache() {
        let (cache, dir) = test_cache();

        // First get should detect fresh
        let caps = cache.get().expect("get");
        assert!(!caps.platform.os.is_empty());

        // Cache file should exist
        let cache_path = dir.path().join(CACHE_FILE_NAME);
        assert!(cache_path.exists());
    }

    #[test]
    fn test_cache_uses_cached() {
        let (cache, _dir) = test_cache();

        // First get - detects fresh
        let caps1 = cache.get().expect("get1");

        // Second get - should use cache
        let caps2 = cache.get().expect("get2");

        // Should be the same (detected_at should match)
        assert_eq!(caps1.detected_at, caps2.detected_at);
    }

    #[test]
    fn test_cache_refresh_ignores_cache() {
        let (cache, _dir) = test_cache();

        // First get
        let caps1 = cache.get().expect("get");

        // Small delay to ensure different timestamp
        std::thread::sleep(Duration::from_millis(10));

        // Refresh should detect fresh
        let caps2 = cache.refresh().expect("refresh");

        // detected_at should be different
        assert_ne!(caps1.detected_at, caps2.detected_at);
    }

    #[test]
    fn test_cache_clear() {
        let (cache, dir) = test_cache();

        // Create cache
        let _ = cache.get().expect("get");

        let cache_path = dir.path().join(CACHE_FILE_NAME);
        assert!(cache_path.exists());

        // Clear cache
        cache.clear().expect("clear");
        assert!(!cache_path.exists());
    }

    #[test]
    fn test_cache_is_cached() {
        let (cache, _dir) = test_cache();

        // Initially not cached
        assert!(!cache.is_cached());

        // After get, should be cached
        let _ = cache.get().expect("get");
        assert!(cache.is_cached());

        // After clear, not cached
        cache.clear().expect("clear");
        assert!(!cache.is_cached());
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let dir = TempDir::new().expect("tempdir");
        let config = CacheConfig::new(dir.path()).with_ttl(Duration::from_secs(0));
        let cache = CapabilityCache::new(config);

        // Get capabilities
        let caps1 = cache.get().expect("get1");

        // Small delay
        std::thread::sleep(Duration::from_millis(10));

        // Should detect fresh due to 0 TTL
        let caps2 = cache.get().expect("get2");

        // detected_at should be different
        assert_ne!(caps1.detected_at, caps2.detected_at);
    }

    #[test]
    fn test_cache_age() {
        let (cache, _dir) = test_cache();

        // Initially no cache age
        assert!(cache.cache_age_secs().is_none());

        // After get, should have age
        let _ = cache.get().expect("get");
        let age = cache.cache_age_secs();
        assert!(age.is_some());
        assert!(age.unwrap() < 60); // Should be very recent
    }

    #[test]
    fn test_convenience_functions() {
        // Test get_capabilities
        let caps = get_capabilities();
        assert!(!caps.platform.os.is_empty());

        // Test refresh_capabilities
        let caps2 = refresh_capabilities();
        assert!(!caps2.platform.os.is_empty());
    }

    #[test]
    fn test_default_cache_dir() {
        let dir = default_cache_dir();
        assert!(dir.to_string_lossy().contains("process_triage"));
    }

    #[test]
    fn test_cached_capabilities_validity() {
        let caps = detect_capabilities();
        let host_id = "test-host".to_string();
        let cached = CachedCapabilities::new(caps, host_id.clone());

        // Should be valid with same host and reasonable TTL
        assert!(cached.is_valid(Duration::from_secs(3600), &host_id));

        // Should be invalid with different host
        assert!(!cached.is_valid(Duration::from_secs(3600), "other-host"));

        // Should be invalid with 0 TTL (after any time passes)
        std::thread::sleep(Duration::from_millis(10));
        assert!(!cached.is_valid(Duration::from_secs(0), &host_id));
    }
}
