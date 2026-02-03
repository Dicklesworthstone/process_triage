//! Fleet discovery and host registration protocol.
//!
//! Manages host lifecycle (join, heartbeat, leave, timeout), tracks fleet
//! membership, and provides host capability queries. The actual transport
//! (mDNS, TCP, etc.) is handled by the CLI layer; this module provides
//! the state machine and protocol types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Host capabilities advertised during registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCapabilities {
    /// Number of CPU cores.
    pub cores: u32,
    /// Total memory in GB.
    pub memory_gb: f64,
    /// Process triage version.
    pub pt_version: String,
    /// Additional capability flags.
    #[serde(default)]
    pub features: Vec<String>,
}

/// Host status in the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    /// Active and healthy.
    Active,
    /// Missed heartbeats, may be down.
    Degraded,
    /// Confirmed offline (missed too many heartbeats).
    Offline,
    /// Voluntarily left the fleet.
    Left,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Degraded => write!(f, "degraded"),
            Self::Offline => write!(f, "offline"),
            Self::Left => write!(f, "left"),
        }
    }
}

/// Role of a host in the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostRole {
    /// Coordinator: manages fleet state, accepts joins.
    Coordinator,
    /// Member: participates in fleet operations.
    Member,
}

/// A registered host in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHost {
    /// Unique host identifier.
    pub host_id: String,
    /// Human-readable hostname.
    pub hostname: String,
    /// IP addresses.
    pub ip_addresses: Vec<String>,
    /// Host capabilities.
    pub capabilities: HostCapabilities,
    /// Role in the fleet.
    pub role: HostRole,
    /// Current status.
    pub status: HostStatus,
    /// Registration timestamp (epoch seconds).
    pub registered_at: f64,
    /// Last heartbeat timestamp (epoch seconds).
    pub last_heartbeat: f64,
    /// Number of heartbeats received.
    pub heartbeat_count: u64,
    /// Authentication token hash (not the token itself).
    pub auth_token_hash: Option<String>,
}

/// Configuration for fleet registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetRegistryConfig {
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: f64,
    /// Number of missed heartbeats before degraded.
    pub degraded_after_missed: u32,
    /// Number of missed heartbeats before offline.
    pub offline_after_missed: u32,
    /// Maximum number of hosts in the fleet.
    pub max_hosts: usize,
    /// Whether to require authentication.
    pub require_auth: bool,
}

impl Default for FleetRegistryConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 30.0,
            degraded_after_missed: 2,
            offline_after_missed: 3,
            max_hosts: 100,
            require_auth: false,
        }
    }
}

/// Error from fleet registry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetRegistryError {
    /// Host already registered.
    AlreadyRegistered(String),
    /// Host not found.
    NotFound(String),
    /// Fleet is full.
    FleetFull { max: usize },
    /// Authentication required but not provided.
    AuthRequired,
    /// Authentication failed.
    AuthFailed,
}

impl std::fmt::Display for FleetRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRegistered(id) => write!(f, "Host already registered: {}", id),
            Self::NotFound(id) => write!(f, "Host not found: {}", id),
            Self::FleetFull { max } => write!(f, "Fleet full (max {})", max),
            Self::AuthRequired => write!(f, "Authentication required"),
            Self::AuthFailed => write!(f, "Authentication failed"),
        }
    }
}

/// Heartbeat message from a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub host_id: String,
    pub timestamp: f64,
    /// Summary statistics from the host.
    pub process_count: Option<usize>,
    pub active_kills: Option<usize>,
}

/// Response to a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    pub accepted: bool,
    pub fleet_size: usize,
    pub active_hosts: usize,
}

/// The fleet registry managing all host state.
#[derive(Debug, Clone)]
pub struct FleetRegistry {
    hosts: HashMap<String, FleetHost>,
    config: FleetRegistryConfig,
    /// Shared secret for authentication (if configured).
    shared_secret_hash: Option<String>,
}

impl FleetRegistry {
    /// Create a new empty registry.
    pub fn new(config: FleetRegistryConfig) -> Self {
        Self {
            hosts: HashMap::new(),
            config,
            shared_secret_hash: None,
        }
    }

    /// Set the shared secret (stored as-is; in production, hash before storing).
    pub fn set_shared_secret(&mut self, secret_hash: String) {
        self.shared_secret_hash = Some(secret_hash);
        self.config.require_auth = true;
    }

    /// Register a new host.
    pub fn register(
        &mut self,
        host_id: String,
        hostname: String,
        ip_addresses: Vec<String>,
        capabilities: HostCapabilities,
        role: HostRole,
        now: f64,
        auth_token_hash: Option<String>,
    ) -> Result<(), FleetRegistryError> {
        if self.config.require_auth {
            match (&self.shared_secret_hash, &auth_token_hash) {
                (Some(expected), Some(provided)) if expected == provided => {}
                (Some(_), Some(_)) => return Err(FleetRegistryError::AuthFailed),
                (Some(_), None) => return Err(FleetRegistryError::AuthRequired),
                _ => {}
            }
        }

        if self.hosts.contains_key(&host_id) {
            return Err(FleetRegistryError::AlreadyRegistered(host_id));
        }

        let active_count = self.active_host_count();
        if active_count >= self.config.max_hosts {
            return Err(FleetRegistryError::FleetFull {
                max: self.config.max_hosts,
            });
        }

        self.hosts.insert(
            host_id.clone(),
            FleetHost {
                host_id,
                hostname,
                ip_addresses,
                capabilities,
                role,
                status: HostStatus::Active,
                registered_at: now,
                last_heartbeat: now,
                heartbeat_count: 0,
                auth_token_hash,
            },
        );

        Ok(())
    }

    /// Process a heartbeat from a host.
    pub fn heartbeat(&mut self, hb: &Heartbeat) -> Result<HeartbeatAck, FleetRegistryError> {
        let host = self
            .hosts
            .get_mut(&hb.host_id)
            .ok_or_else(|| FleetRegistryError::NotFound(hb.host_id.clone()))?;

        host.last_heartbeat = hb.timestamp;
        host.heartbeat_count += 1;
        if host.status == HostStatus::Degraded {
            host.status = HostStatus::Active;
        }

        Ok(HeartbeatAck {
            accepted: true,
            fleet_size: self.hosts.len(),
            active_hosts: self.active_host_count(),
        })
    }

    /// Mark a host as voluntarily leaving.
    pub fn leave(&mut self, host_id: &str) -> Result<(), FleetRegistryError> {
        let host = self
            .hosts
            .get_mut(host_id)
            .ok_or_else(|| FleetRegistryError::NotFound(host_id.to_string()))?;
        host.status = HostStatus::Left;
        Ok(())
    }

    /// Update host statuses based on heartbeat timeouts.
    pub fn check_heartbeats(&mut self, now: f64) {
        let interval = self.config.heartbeat_interval_secs;
        let degraded_threshold = interval * self.config.degraded_after_missed as f64;
        let offline_threshold = interval * self.config.offline_after_missed as f64;

        for host in self.hosts.values_mut() {
            if host.status == HostStatus::Left {
                continue;
            }
            let elapsed = now - host.last_heartbeat;
            if elapsed > offline_threshold {
                host.status = HostStatus::Offline;
            } else if elapsed > degraded_threshold {
                host.status = HostStatus::Degraded;
            }
        }
    }

    /// Get a host by ID.
    pub fn get_host(&self, host_id: &str) -> Option<&FleetHost> {
        self.hosts.get(host_id)
    }

    /// List all hosts.
    pub fn all_hosts(&self) -> Vec<&FleetHost> {
        self.hosts.values().collect()
    }

    /// List active hosts.
    pub fn active_hosts(&self) -> Vec<&FleetHost> {
        self.hosts
            .values()
            .filter(|h| h.status == HostStatus::Active)
            .collect()
    }

    /// Count of active hosts.
    pub fn active_host_count(&self) -> usize {
        self.hosts
            .values()
            .filter(|h| h.status == HostStatus::Active || h.status == HostStatus::Degraded)
            .count()
    }

    /// Total fleet size (including offline/left).
    pub fn fleet_size(&self) -> usize {
        self.hosts.len()
    }

    /// Remove hosts that have been offline for a long time.
    pub fn prune_offline(&mut self, max_offline_secs: f64, now: f64) -> usize {
        let before = self.hosts.len();
        self.hosts.retain(|_, h| {
            if h.status == HostStatus::Offline || h.status == HostStatus::Left {
                (now - h.last_heartbeat) <= max_offline_secs
            } else {
                true
            }
        });
        before - self.hosts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_caps() -> HostCapabilities {
        HostCapabilities {
            cores: 8,
            memory_gb: 32.0,
            pt_version: "2.1.0".to_string(),
            features: vec![],
        }
    }

    fn register_host(reg: &mut FleetRegistry, id: &str, now: f64) {
        reg.register(
            id.to_string(),
            format!("{}.local", id),
            vec!["192.168.1.1".to_string()],
            make_caps(),
            HostRole::Member,
            now,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_register_and_list() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "host-1", 1000.0);
        register_host(&mut reg, "host-2", 1000.0);
        assert_eq!(reg.fleet_size(), 2);
        assert_eq!(reg.active_host_count(), 2);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "host-1", 1000.0);
        let err = reg
            .register(
                "host-1".to_string(),
                "h1".to_string(),
                vec![],
                make_caps(),
                HostRole::Member,
                1000.0,
                None,
            )
            .unwrap_err();
        assert_eq!(
            err,
            FleetRegistryError::AlreadyRegistered("host-1".to_string())
        );
    }

    #[test]
    fn test_fleet_full() {
        let config = FleetRegistryConfig {
            max_hosts: 2,
            ..Default::default()
        };
        let mut reg = FleetRegistry::new(config);
        register_host(&mut reg, "h1", 1000.0);
        register_host(&mut reg, "h2", 1000.0);
        let err = reg
            .register(
                "h3".to_string(),
                "h3".to_string(),
                vec![],
                make_caps(),
                HostRole::Member,
                1000.0,
                None,
            )
            .unwrap_err();
        assert_eq!(err, FleetRegistryError::FleetFull { max: 2 });
    }

    #[test]
    fn test_heartbeat() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "h1", 1000.0);

        let ack = reg
            .heartbeat(&Heartbeat {
                host_id: "h1".to_string(),
                timestamp: 1030.0,
                process_count: Some(42),
                active_kills: None,
            })
            .unwrap();
        assert!(ack.accepted);
        assert_eq!(reg.get_host("h1").unwrap().heartbeat_count, 1);
    }

    #[test]
    fn test_heartbeat_unknown_host() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        let err = reg
            .heartbeat(&Heartbeat {
                host_id: "unknown".to_string(),
                timestamp: 1000.0,
                process_count: None,
                active_kills: None,
            })
            .unwrap_err();
        assert_eq!(err, FleetRegistryError::NotFound("unknown".to_string()));
    }

    #[test]
    fn test_timeout_degraded_then_offline() {
        let config = FleetRegistryConfig {
            heartbeat_interval_secs: 30.0,
            degraded_after_missed: 2,
            offline_after_missed: 3,
            ..Default::default()
        };
        let mut reg = FleetRegistry::new(config);
        register_host(&mut reg, "h1", 1000.0);

        // After 70s (>2*30), should be degraded.
        reg.check_heartbeats(1070.0);
        assert_eq!(reg.get_host("h1").unwrap().status, HostStatus::Degraded);

        // After 100s (>3*30), should be offline.
        reg.check_heartbeats(1100.0);
        assert_eq!(reg.get_host("h1").unwrap().status, HostStatus::Offline);
    }

    #[test]
    fn test_heartbeat_recovers_from_degraded() {
        let config = FleetRegistryConfig {
            heartbeat_interval_secs: 30.0,
            degraded_after_missed: 2,
            offline_after_missed: 3,
            ..Default::default()
        };
        let mut reg = FleetRegistry::new(config);
        register_host(&mut reg, "h1", 1000.0);

        reg.check_heartbeats(1070.0);
        assert_eq!(reg.get_host("h1").unwrap().status, HostStatus::Degraded);

        reg.heartbeat(&Heartbeat {
            host_id: "h1".to_string(),
            timestamp: 1075.0,
            process_count: None,
            active_kills: None,
        })
        .unwrap();
        assert_eq!(reg.get_host("h1").unwrap().status, HostStatus::Active);
    }

    #[test]
    fn test_leave() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "h1", 1000.0);
        reg.leave("h1").unwrap();
        assert_eq!(reg.get_host("h1").unwrap().status, HostStatus::Left);
        assert_eq!(reg.active_host_count(), 0);
    }

    #[test]
    fn test_auth_required() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        reg.set_shared_secret("secret123".to_string());

        let err = reg
            .register(
                "h1".to_string(),
                "h1".to_string(),
                vec![],
                make_caps(),
                HostRole::Member,
                1000.0,
                None,
            )
            .unwrap_err();
        assert_eq!(err, FleetRegistryError::AuthRequired);

        let err = reg
            .register(
                "h1".to_string(),
                "h1".to_string(),
                vec![],
                make_caps(),
                HostRole::Member,
                1000.0,
                Some("wrong".to_string()),
            )
            .unwrap_err();
        assert_eq!(err, FleetRegistryError::AuthFailed);

        reg.register(
            "h1".to_string(),
            "h1".to_string(),
            vec![],
            make_caps(),
            HostRole::Member,
            1000.0,
            Some("secret123".to_string()),
        )
        .unwrap();
        assert_eq!(reg.fleet_size(), 1);
    }

    #[test]
    fn test_prune_offline() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "h1", 1000.0);
        register_host(&mut reg, "h2", 1000.0);

        reg.check_heartbeats(1100.0); // Both offline.
        assert_eq!(reg.fleet_size(), 2);

        let pruned = reg.prune_offline(3600.0, 5000.0);
        assert_eq!(pruned, 2);
        assert_eq!(reg.fleet_size(), 0);
    }

    #[test]
    fn test_active_hosts_filter() {
        let mut reg = FleetRegistry::new(FleetRegistryConfig::default());
        register_host(&mut reg, "h1", 1000.0);
        register_host(&mut reg, "h2", 1000.0);
        register_host(&mut reg, "h3", 1000.0);

        reg.leave("h2").unwrap();
        let active = reg.active_hosts();
        assert_eq!(active.len(), 2);
    }
}
