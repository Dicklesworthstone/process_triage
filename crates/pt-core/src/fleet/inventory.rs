//! Fleet inventory parsing and static discovery provider.
//!
//! Supports static configuration via TOML/YAML/JSON inventory files.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const INVENTORY_SCHEMA_VERSION: &str = "1.0.0";

/// Access method for a fleet host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMethod {
    Ssh,
    Agent,
    Api,
}

/// Inventory status for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Active,
    Unreachable,
    Excluded,
}

/// Fleet inventory entry for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    /// Hostname or IP.
    pub hostname: String,
    /// Host tags for filtering/grouping.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tags: HashMap<String, String>,
    /// Access method (ssh/agent/api).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_method: Option<AccessMethod>,
    /// Reference to credentials store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_ref: Option<String>,
    /// Timestamp of last successful contact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Inventory status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InventoryStatus>,
}

/// Fleet inventory loaded from a static config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetInventory {
    pub schema_version: String,
    pub generated_at: String,
    pub hosts: Vec<HostRecord>,
}

/// Supported inventory formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryFormat {
    Toml,
    Yaml,
    Json,
}

impl InventoryFormat {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("failed to read inventory file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported inventory format: {extension}")]
    UnsupportedFormat { extension: String },
    #[error("failed to parse {format} inventory: {message}")]
    Parse { format: String, message: String },
    #[error("inventory contains no hosts")]
    EmptyHosts,
}

#[derive(Debug, Deserialize)]
struct StaticInventoryConfig {
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    hosts: Vec<HostSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HostSpec {
    Simple(String),
    Detailed(HostRecordConfig),
}

#[derive(Debug, Deserialize)]
struct HostRecordConfig {
    #[serde(alias = "host")]
    hostname: String,
    #[serde(default)]
    tags: HashMap<String, String>,
    #[serde(default)]
    access_method: Option<AccessMethod>,
    #[serde(default)]
    credentials_ref: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    status: Option<InventoryStatus>,
}

impl From<HostRecordConfig> for HostRecord {
    fn from(value: HostRecordConfig) -> Self {
        Self {
            hostname: value.hostname,
            tags: value.tags,
            access_method: value.access_method,
            credentials_ref: value.credentials_ref,
            last_seen: value.last_seen,
            status: value.status,
        }
    }
}

/// Load a static inventory from a file path.
pub fn load_inventory_from_path(path: &Path) -> Result<FleetInventory, InventoryError> {
    let content = fs::read_to_string(path).map_err(|source| InventoryError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let format = detect_format(path)?;
    parse_inventory_str(&content, format)
}

fn detect_format(path: &Path) -> Result<InventoryFormat, InventoryError> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "toml" => Ok(InventoryFormat::Toml),
        "yaml" | "yml" => Ok(InventoryFormat::Yaml),
        "json" => Ok(InventoryFormat::Json),
        _ => Err(InventoryError::UnsupportedFormat { extension: ext }),
    }
}

/// Parse inventory config from a string.
pub fn parse_inventory_str(
    content: &str,
    format: InventoryFormat,
) -> Result<FleetInventory, InventoryError> {
    let config: StaticInventoryConfig = match format {
        InventoryFormat::Toml => toml::from_str(content).map_err(|e| InventoryError::Parse {
            format: format.as_str().to_string(),
            message: e.to_string(),
        })?,
        InventoryFormat::Yaml => {
            serde_yaml::from_str(content).map_err(|e| InventoryError::Parse {
                format: format.as_str().to_string(),
                message: e.to_string(),
            })?
        }
        InventoryFormat::Json => {
            serde_json::from_str(content).map_err(|e| InventoryError::Parse {
                format: format.as_str().to_string(),
                message: e.to_string(),
            })?
        }
    };

    if config.hosts.is_empty() {
        return Err(InventoryError::EmptyHosts);
    }

    let hosts: Vec<HostRecord> = config
        .hosts
        .into_iter()
        .map(|spec| match spec {
            HostSpec::Simple(hostname) => HostRecord {
                hostname,
                tags: HashMap::new(),
                access_method: None,
                credentials_ref: None,
                last_seen: None,
                status: None,
            },
            HostSpec::Detailed(record) => record.into(),
        })
        .collect();

    Ok(FleetInventory {
        schema_version: config
            .schema_version
            .unwrap_or_else(|| INVENTORY_SCHEMA_VERSION.to_string()),
        generated_at: config
            .generated_at
            .unwrap_or_else(|| Utc::now().to_rfc3339()),
        hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_toml_simple_hosts() {
        let input = r#"
schema_version = "1.0.0"
hosts = ["host-a", "host-b"]
"#;
        let inventory = parse_inventory_str(input, InventoryFormat::Toml).unwrap();
        assert_eq!(inventory.hosts.len(), 2);
        assert_eq!(inventory.hosts[0].hostname, "host-a");
    }

    #[test]
    fn parse_toml_detailed_hosts() {
        let input = r#"
hosts = [
  { host = "db-1", access_method = "ssh", tags = { role = "db" } },
  { hostname = "web-1", status = "active" }
]
"#;
        let inventory = parse_inventory_str(input, InventoryFormat::Toml).unwrap();
        assert_eq!(inventory.hosts.len(), 2);
        assert_eq!(inventory.hosts[0].hostname, "db-1");
        assert_eq!(
            inventory.hosts[0].tags.get("role").map(String::as_str),
            Some("db")
        );
    }

    #[test]
    fn parse_yaml_simple_hosts() {
        let input = r#"
hosts:
  - host-a
  - host-b
"#;
        let inventory = parse_inventory_str(input, InventoryFormat::Yaml).unwrap();
        assert_eq!(inventory.hosts.len(), 2);
        assert_eq!(inventory.hosts[1].hostname, "host-b");
    }

    #[test]
    fn parse_json_simple_hosts() {
        let input = r#"
{
  "hosts": ["host-a", "host-b"]
}
"#;
        let inventory = parse_inventory_str(input, InventoryFormat::Json).unwrap();
        assert_eq!(inventory.hosts.len(), 2);
        assert_eq!(inventory.hosts[1].hostname, "host-b");
    }
}
