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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    // ── DiscoveryConfigFormat ───────────────────────────────────────

    #[test]
    fn config_format_as_str() {
        assert_eq!(DiscoveryConfigFormat::Toml.as_str(), "toml");
        assert_eq!(DiscoveryConfigFormat::Yaml.as_str(), "yaml");
        assert_eq!(DiscoveryConfigFormat::Json.as_str(), "json");
    }

    #[test]
    fn config_format_eq() {
        assert_eq!(DiscoveryConfigFormat::Toml, DiscoveryConfigFormat::Toml);
        assert_ne!(DiscoveryConfigFormat::Toml, DiscoveryConfigFormat::Json);
    }

    // ── detect_format ───────────────────────────────────────────────

    #[test]
    fn detect_format_toml() {
        let fmt = detect_format(Path::new("fleet.toml")).unwrap();
        assert_eq!(fmt, DiscoveryConfigFormat::Toml);
    }

    #[test]
    fn detect_format_yaml() {
        let fmt = detect_format(Path::new("fleet.yaml")).unwrap();
        assert_eq!(fmt, DiscoveryConfigFormat::Yaml);
    }

    #[test]
    fn detect_format_yml() {
        let fmt = detect_format(Path::new("fleet.yml")).unwrap();
        assert_eq!(fmt, DiscoveryConfigFormat::Yaml);
    }

    #[test]
    fn detect_format_json() {
        let fmt = detect_format(Path::new("fleet.json")).unwrap();
        assert_eq!(fmt, DiscoveryConfigFormat::Json);
    }

    #[test]
    fn detect_format_uppercase() {
        let fmt = detect_format(Path::new("fleet.TOML")).unwrap();
        assert_eq!(fmt, DiscoveryConfigFormat::Toml);
    }

    #[test]
    fn detect_format_unknown() {
        let err = detect_format(Path::new("fleet.xml")).unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn detect_format_no_extension() {
        let err = detect_format(Path::new("fleet")).unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    // ── parse_str TOML ──────────────────────────────────────────────

    #[test]
    fn parse_toml_dns_provider() {
        let input = r#"
[[providers]]
type = "dns"
service = "myservice"
domain = "example.com"
use_srv = false
port = 8080
"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Toml).unwrap();
        match &config.providers[0] {
            ProviderConfig::Dns {
                service,
                domain,
                use_srv,
                port,
            } => {
                assert_eq!(service, "myservice");
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert!(!use_srv);
                assert_eq!(*port, Some(8080));
            }
            _ => panic!("expected Dns"),
        }
    }

    #[test]
    fn parse_toml_defaults() {
        let input = r#"
[[providers]]
type = "static"
path = "hosts.toml"
"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Toml).unwrap();
        assert_eq!(config.schema_version, DISCOVERY_SCHEMA_VERSION);
        assert!(config.generated_at.is_none());
        assert!(config.cache_ttl_secs.is_none());
    }

    #[test]
    fn parse_toml_with_cache_ttl() {
        let input = r#"
cache_ttl_secs = 300
refresh_interval_secs = 60
stale_while_revalidate_secs = 120

[[providers]]
type = "static"
path = "fleet.toml"
"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Toml).unwrap();
        assert_eq!(config.cache_ttl_secs, Some(300));
        assert_eq!(config.refresh_interval_secs, Some(60));
        assert_eq!(config.stale_while_revalidate_secs, Some(120));
    }

    // ── parse_str JSON ──────────────────────────────────────────────

    #[test]
    fn parse_json_static() {
        let input = r#"{"providers":[{"type":"static","path":"hosts.json"}]}"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        assert_eq!(config.providers.len(), 1);
    }

    #[test]
    fn parse_json_multiple_providers() {
        let input = r#"{
            "providers": [
                {"type": "static", "path": "hosts.json"},
                {"type": "dns", "service": "svc"}
            ]
        }"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        assert_eq!(config.providers.len(), 2);
    }

    #[test]
    fn parse_json_invalid() {
        let result = FleetDiscoveryConfig::parse_str("{bad}", DiscoveryConfigFormat::Json);
        assert!(result.is_err());
    }

    // ── parse_str YAML ──────────────────────────────────────────────

    #[test]
    fn parse_yaml_static() {
        let input = "providers:\n  - type: static\n    path: hosts.yaml\n";
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Yaml).unwrap();
        assert_eq!(config.providers.len(), 1);
    }

    // ── ProviderConfig serde ────────────────────────────────────────

    #[test]
    fn provider_config_aws_serde() {
        let input =
            r#"{"providers":[{"type":"aws","region":"us-east-1","tag_filters":{"env":"prod"}}]}"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        match &config.providers[0] {
            ProviderConfig::Aws {
                region,
                tag_filters,
            } => {
                assert_eq!(region.as_deref(), Some("us-east-1"));
                assert_eq!(tag_filters.get("env").map(|s| s.as_str()), Some("prod"));
            }
            _ => panic!("expected Aws"),
        }
    }

    #[test]
    fn provider_config_gcp_serde() {
        let input =
            r#"{"providers":[{"type":"gcp","project":"my-proj","labels":{"team":"infra"}}]}"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        match &config.providers[0] {
            ProviderConfig::Gcp { project, labels } => {
                assert_eq!(project.as_deref(), Some("my-proj"));
                assert_eq!(labels.get("team").map(|s| s.as_str()), Some("infra"));
            }
            _ => panic!("expected Gcp"),
        }
    }

    #[test]
    fn provider_config_k8s_serde() {
        let input =
            r#"{"providers":[{"type":"k8s","namespace":"prod","label_selector":"app=web"}]}"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        match &config.providers[0] {
            ProviderConfig::K8s {
                namespace,
                label_selector,
            } => {
                assert_eq!(namespace.as_deref(), Some("prod"));
                assert_eq!(label_selector.as_deref(), Some("app=web"));
            }
            _ => panic!("expected K8s"),
        }
    }

    #[test]
    fn provider_config_dns_defaults() {
        let input = r#"{"providers":[{"type":"dns","service":"svc"}]}"#;
        let config = FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Json).unwrap();
        match &config.providers[0] {
            ProviderConfig::Dns {
                use_srv,
                domain,
                port,
                ..
            } => {
                assert!(*use_srv); // default_use_srv is true
                assert!(domain.is_none());
                assert!(port.is_none());
            }
            _ => panic!("expected Dns"),
        }
    }

    // ── FleetDiscoveryConfig serde roundtrip ─────────────────────────

    #[test]
    fn discovery_config_serde_roundtrip() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: Some("2026-01-15T00:00:00Z".to_string()),
            providers: vec![ProviderConfig::Static {
                path: "fleet.toml".to_string(),
            }],
            cache_ttl_secs: Some(600),
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: FleetDiscoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, DISCOVERY_SCHEMA_VERSION);
        assert_eq!(back.providers.len(), 1);
        assert_eq!(back.cache_ttl_secs, Some(600));
    }

    // ── ProviderRegistry from_config ─────────────────────────────────

    #[test]
    fn registry_from_config_static() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: vec![ProviderConfig::Static {
                path: "fleet.toml".to_string(),
            }],
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let registry = ProviderRegistry::from_config(&config).unwrap();
        assert_eq!(registry.providers.len(), 1);
    }

    #[test]
    fn registry_from_config_dns() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: vec![ProviderConfig::Dns {
                service: "svc".to_string(),
                domain: None,
                use_srv: false,
                port: None,
            }],
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let registry = ProviderRegistry::from_config(&config).unwrap();
        assert_eq!(registry.providers.len(), 1);
    }

    #[test]
    fn registry_from_config_aws_not_implemented() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: vec![ProviderConfig::Aws {
                region: None,
                tag_filters: HashMap::new(),
            }],
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let err = ProviderRegistry::from_config(&config).err().unwrap();
        assert!(err.to_string().contains("aws"));
    }

    #[test]
    fn registry_from_config_gcp_not_implemented() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: vec![ProviderConfig::Gcp {
                project: None,
                labels: HashMap::new(),
            }],
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let err = ProviderRegistry::from_config(&config).err().unwrap();
        assert!(err.to_string().contains("gcp"));
    }

    #[test]
    fn registry_from_config_k8s_not_implemented() {
        let config = FleetDiscoveryConfig {
            schema_version: DISCOVERY_SCHEMA_VERSION.to_string(),
            generated_at: None,
            providers: vec![ProviderConfig::K8s {
                namespace: None,
                label_selector: None,
            }],
            cache_ttl_secs: None,
            refresh_interval_secs: None,
            stale_while_revalidate_secs: None,
        };
        let err = ProviderRegistry::from_config(&config).err().unwrap();
        assert!(err.to_string().contains("k8s"));
    }

    // ── StaticInventoryProvider ──────────────────────────────────────

    #[test]
    fn static_provider_name() {
        let p = StaticInventoryProvider::new(PathBuf::from("fleet.toml"));
        assert_eq!(p.name(), "static");
    }

    #[test]
    fn static_provider_from_path() {
        let p = StaticInventoryProvider::from_path(Path::new("/tmp/fleet.toml"));
        assert_eq!(p.path, PathBuf::from("/tmp/fleet.toml"));
    }

    // ── DnsDiscoveryProvider ────────────────────────────────────────

    #[test]
    fn dns_provider_name() {
        let p = DnsDiscoveryProvider::new("svc", None, true, None);
        assert_eq!(p.name(), "dns");
    }

    #[test]
    fn dns_provider_construction() {
        let p = DnsDiscoveryProvider::new("myservice", Some("example.com"), false, Some(8080));
        assert_eq!(p.service, "myservice");
        assert_eq!(p.domain.as_deref(), Some("example.com"));
        assert!(!p.use_srv);
    }

    // ── merge_inventories ───────────────────────────────────────────

    #[test]
    fn merge_inventories_empty() {
        let result = merge_inventories(&[]);
        assert!(result.hosts.is_empty());
    }

    #[test]
    fn merge_inventories_single() {
        let inv = FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            hosts: vec![HostRecord {
                hostname: "host1".to_string(),
                tags: HashMap::new(),
                access_method: None,
                credentials_ref: None,
                last_seen: None,
                status: None,
            }],
        };
        let result = merge_inventories(&[inv]);
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].hostname, "host1");
    }

    #[test]
    fn merge_inventories_deduplicates_by_hostname() {
        let inv1 = FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            hosts: vec![HostRecord {
                hostname: "host1".to_string(),
                tags: HashMap::from([("env".to_string(), "prod".to_string())]),
                access_method: None,
                credentials_ref: None,
                last_seen: None,
                status: None,
            }],
        };
        let inv2 = FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            hosts: vec![HostRecord {
                hostname: "host1".to_string(),
                tags: HashMap::from([("role".to_string(), "web".to_string())]),
                access_method: None,
                credentials_ref: None,
                last_seen: Some("2026-01-01".to_string()),
                status: None,
            }],
        };
        let result = merge_inventories(&[inv1, inv2]);
        assert_eq!(result.hosts.len(), 1);
        // Tags merged
        assert_eq!(
            result.hosts[0].tags.get("env").map(|s| s.as_str()),
            Some("prod")
        );
        assert_eq!(
            result.hosts[0].tags.get("role").map(|s| s.as_str()),
            Some("web")
        );
        // last_seen filled from second
        assert!(result.hosts[0].last_seen.is_some());
    }

    #[test]
    fn merge_inventories_sorted_by_hostname() {
        let inv = FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            hosts: vec![
                HostRecord {
                    hostname: "charlie".to_string(),
                    tags: HashMap::new(),
                    access_method: None,
                    credentials_ref: None,
                    last_seen: None,
                    status: None,
                },
                HostRecord {
                    hostname: "alpha".to_string(),
                    tags: HashMap::new(),
                    access_method: None,
                    credentials_ref: None,
                    last_seen: None,
                    status: None,
                },
                HostRecord {
                    hostname: "bravo".to_string(),
                    tags: HashMap::new(),
                    access_method: None,
                    credentials_ref: None,
                    last_seen: None,
                    status: None,
                },
            ],
        };
        let result = merge_inventories(&[inv]);
        assert_eq!(result.hosts[0].hostname, "alpha");
        assert_eq!(result.hosts[1].hostname, "bravo");
        assert_eq!(result.hosts[2].hostname, "charlie");
    }

    // ── DiscoveryError ──────────────────────────────────────────────

    #[test]
    fn discovery_error_display() {
        let e = DiscoveryError::Other("test error".to_string());
        assert!(e.to_string().contains("test error"));
    }

    // ── load_from_path with tempfile ─────────────────────────────────

    #[test]
    fn load_from_path_json() {
        let tmp = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        std::fs::write(
            tmp.path(),
            r#"{"providers":[{"type":"static","path":"hosts.json"}]}"#,
        )
        .unwrap();
        let config = FleetDiscoveryConfig::load_from_path(tmp.path()).unwrap();
        assert_eq!(config.providers.len(), 1);
    }

    #[test]
    fn load_from_path_nonexistent() {
        let result = FleetDiscoveryConfig::load_from_path(Path::new(
            "/tmp/nonexistent-pt-discovery-test.json",
        ));
        assert!(result.is_err());
    }
}
