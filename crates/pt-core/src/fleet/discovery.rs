//! Fleet discovery providers and configuration.
//!
//! Provides:
//! - Provider trait + registry
//! - Static inventory provider
//! - DNS provider scaffold (feature-gated)
//! - Config schema for future AWS/GCP/K8s providers

use crate::fleet::inventory::{load_inventory_from_path, FleetInventory, InventoryError};
use crate::fleet::inventory::{HostRecord, INVENTORY_SCHEMA_VERSION};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DISCOVERY_SCHEMA_VERSION: &str = "1.0.0";

/// Errors returned by discovery providers.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("inventory error: {0}")]
    Inventory(#[from] InventoryError),
    #[error("discovery error: {0}")]
    Other(String),
}

/// Fleet discovery provider interface.
pub trait InventoryProvider {
    /// Provider name used for logs/telemetry.
    fn name(&self) -> &str;
    /// Discover hosts and return a normalized fleet inventory.
    fn discover(&self) -> Result<FleetInventory, DiscoveryError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetDiscoveryConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
    #[serde(default)]
    pub refresh_interval_secs: Option<u64>,
    #[serde(default)]
    pub stale_while_revalidate_secs: Option<u64>,
}

fn default_schema_version() -> String {
    DISCOVERY_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    Static {
        path: String,
    },
    Dns {
        service: String,
        #[serde(default)]
        domain: Option<String>,
        #[serde(default = "default_use_srv")]
        use_srv: bool,
        #[serde(default)]
        port: Option<u16>,
    },
    Aws {
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        tag_filters: HashMap<String, String>,
    },
    Gcp {
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        labels: HashMap<String, String>,
    },
    K8s {
        #[serde(default)]
        namespace: Option<String>,
        #[serde(default)]
        label_selector: Option<String>,
    },
}

fn default_use_srv() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryConfigFormat {
    Toml,
    Yaml,
    Json,
}

impl DiscoveryConfigFormat {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }
}

impl FleetDiscoveryConfig {
    pub fn load_from_path(path: &Path) -> Result<Self, DiscoveryError> {
        let content = fs::read_to_string(path).map_err(|e| {
            DiscoveryError::Other(format!("failed to read discovery config: {}", e))
        })?;
        let format = detect_format(path)?;
        Self::parse_str(&content, format)
    }

    pub(crate) fn parse_str(
        content: &str,
        format: DiscoveryConfigFormat,
    ) -> Result<Self, DiscoveryError> {
        let config = match format {
            DiscoveryConfigFormat::Toml => toml::from_str(content).map_err(|e| {
                DiscoveryError::Other(format!("failed to parse toml discovery config: {}", e))
            })?,
            DiscoveryConfigFormat::Yaml => serde_yaml::from_str(content).map_err(|e| {
                DiscoveryError::Other(format!("failed to parse yaml discovery config: {}", e))
            })?,
            DiscoveryConfigFormat::Json => serde_json::from_str(content).map_err(|e| {
                DiscoveryError::Other(format!("failed to parse json discovery config: {}", e))
            })?,
        };
        Ok(config)
    }
}

fn detect_format(path: &Path) -> Result<DiscoveryConfigFormat, DiscoveryError> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "toml" => Ok(DiscoveryConfigFormat::Toml),
        "yaml" | "yml" => Ok(DiscoveryConfigFormat::Yaml),
        "json" => Ok(DiscoveryConfigFormat::Json),
        _ => Err(DiscoveryError::Other(format!(
            "unsupported discovery config format: {}",
            ext
        ))),
    }
}

/// Provider registry that aggregates results from configured providers.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Vec<Box<dyn InventoryProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn from_config(config: &FleetDiscoveryConfig) -> Result<Self, DiscoveryError> {
        if config.providers.is_empty() {
            return Err(DiscoveryError::Other(
                "discovery config has no providers".to_string(),
            ));
        }

        let mut registry = Self::new();
        for provider in &config.providers {
            match provider {
                ProviderConfig::Static { path } => {
                    registry
                        .providers
                        .push(Box::new(StaticInventoryProvider::new(PathBuf::from(path))));
                }
                ProviderConfig::Dns {
                    service,
                    domain,
                    use_srv,
                    port,
                } => {
                    registry.providers.push(Box::new(DnsDiscoveryProvider::new(
                        service,
                        domain.as_deref(),
                        *use_srv,
                        *port,
                    )));
                }
                ProviderConfig::Aws { .. } => {
                    return Err(DiscoveryError::Other(
                        "aws provider not implemented".to_string(),
                    ));
                }
                ProviderConfig::Gcp { .. } => {
                    return Err(DiscoveryError::Other(
                        "gcp provider not implemented".to_string(),
                    ));
                }
                ProviderConfig::K8s { .. } => {
                    return Err(DiscoveryError::Other(
                        "k8s provider not implemented".to_string(),
                    ));
                }
            }
        }

        Ok(registry)
    }

    pub fn discover_all(&self) -> Result<FleetInventory, DiscoveryError> {
        let mut inventories = Vec::new();
        for provider in &self.providers {
            inventories.push(provider.discover()?);
        }
        Ok(merge_inventories(&inventories))
    }
}

/// Static inventory provider reading from a config file.
#[derive(Debug, Clone)]
pub struct StaticInventoryProvider {
    path: PathBuf,
}

impl StaticInventoryProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn from_path(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl InventoryProvider for StaticInventoryProvider {
    fn name(&self) -> &str {
        "static"
    }

    fn discover(&self) -> Result<FleetInventory, DiscoveryError> {
        Ok(load_inventory_from_path(&self.path)?)
    }
}

/// DNS-based discovery provider scaffold.
#[derive(Debug, Clone)]
pub struct DnsDiscoveryProvider {
    service: String,
    domain: Option<String>,
    use_srv: bool,
    port: Option<u16>,
}

impl DnsDiscoveryProvider {
    pub fn new(service: &str, domain: Option<&str>, use_srv: bool, port: Option<u16>) -> Self {
        Self {
            service: service.to_string(),
            domain: domain.map(|s| s.to_string()),
            use_srv,
            port,
        }
    }
}

impl InventoryProvider for DnsDiscoveryProvider {
    fn name(&self) -> &str {
        "dns"
    }

    fn discover(&self) -> Result<FleetInventory, DiscoveryError> {
        if !cfg!(feature = "fleet-dns") {
            return Err(DiscoveryError::Other(
                "dns provider requires feature \"fleet-dns\"".to_string(),
            ));
        }

        if self.use_srv {
            return Err(DiscoveryError::Other(
                "dns SRV lookup not implemented yet".to_string(),
            ));
        }

        let hostname = if let Some(domain) = &self.domain {
            format!("{}.{}", self.service, domain)
        } else {
            self.service.clone()
        };

        let host = HostRecord {
            hostname,
            tags: HashMap::new(),
            access_method: None,
            credentials_ref: None,
            last_seen: None,
            status: None,
        };

        Ok(FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            hosts: vec![host],
        })
    }
}

fn merge_inventories(inventories: &[FleetInventory]) -> FleetInventory {
    let mut by_host: HashMap<String, HostRecord> = HashMap::new();
    for inventory in inventories {
        for host in &inventory.hosts {
            if let Some(existing) = by_host.get_mut(&host.hostname) {
                for (k, v) in &host.tags {
                    existing.tags.entry(k.clone()).or_insert_with(|| v.clone());
                }
                if existing.access_method.is_none() {
                    existing.access_method = host.access_method;
                }
                if existing.credentials_ref.is_none() {
                    existing.credentials_ref = host.credentials_ref.clone();
                }
                if existing.last_seen.is_none() {
                    existing.last_seen = host.last_seen.clone();
                }
                if existing.status.is_none() {
                    existing.status = host.status;
                }
            } else {
                by_host.insert(host.hostname.clone(), host.clone());
            }
        }
    }

    let mut hosts: Vec<HostRecord> = by_host.into_values().collect();
    hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    FleetInventory {
        schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        hosts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_discovery_config_toml_static() {
        let input = r#"
schema_version = "1.0.0"

[[providers]]
type = "static"
path = "fleet.toml"
"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Toml).unwrap();
        assert_eq!(config.providers.len(), 1);
        match &config.providers[0] {
            ProviderConfig::Static { path } => assert_eq!(path, "fleet.toml"),
            _ => panic!("unexpected provider type"),
        }
    }

    #[test]
    fn registry_requires_providers() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: Vec::new(),
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let err = ProviderRegistry::from_config(&config)
            .err()
            .expect("expected error");
        assert!(err.to_string().contains("no providers"));
    }
}
