//! System capability detection and caching.
//!
//! This module provides detection of system capabilities for process triage:
//! - Platform information (OS, kernel, container detection)
//! - Available data sources (procfs, sysfs, perf_events, eBPF)
//! - Tool availability and versions
//! - User permissions and Linux capabilities
//! - Supervisor systems (systemd, launchd, docker)
//! - Available actions (kill, pause, renice, cgroup ops)
//!
//! Results are cached with configurable TTL (default 24h) for performance.

mod cache;
mod detect;

pub use cache::{
    default_cache_dir, get_capabilities, get_capabilities_with_ttl, refresh_capabilities,
    CacheConfig, CacheError, CapabilityCache, DEFAULT_CACHE_TTL_SECS,
};
pub use detect::{
    detect_capabilities, ActionCapabilities, Capabilities, DataSourceCapabilities,
    DetectionError, PermissionCapabilities, PlatformInfo, SupervisorCapabilities,
    ToolCapabilities, ToolCapability,
};
