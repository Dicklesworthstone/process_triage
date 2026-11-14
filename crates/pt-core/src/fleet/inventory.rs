//! Fleet inventory parsing and static discovery provider.
//!
//! Supports static configuration via TOML/YAML/JSON inventory files.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    #[error("invalid fleet host filter: {pattern:?}")]
    InvalidFilter { pattern: String },
    #[error("invalid SSH inventory target: {hostname:?}")]
    InvalidHost { hostname: String },
    #[error("fleet host {hostname:?} uses unsupported access method {access_method:?}; this command requires SSH")]
    UnsupportedAccess {
        hostname: String,
        access_method: AccessMethod,
    },
}

/// Select concrete SSH destinations without resolving aliases or inventing
/// hosts from wildcard patterns. Positive filters are ORed and any matching
/// `!pattern` excludes a host. With only negative filters, the positive set is
/// the whole inventory. An explicit excluded record wins over every duplicate.
///
/// The order and spelling of the first selected occurrence are retained. SSH
/// resolves HostName, User, ProxyJump and credentials using the original alias.
pub fn select_ssh_hosts(
    inventory: &FleetInventory,
    patterns: &[String],
) -> Result<Vec<String>, InventoryError> {
    for pattern in patterns {
        let value = pattern.strip_prefix('!').unwrap_or(pattern);
        if value.is_empty()
            || value.len() > 1024
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._@:%[]*?".contains(&byte))
        {
            return Err(InventoryError::InvalidFilter {
                pattern: pattern.clone(),
            });
        }
    }
    let excluded: HashSet<_> = inventory
        .hosts
        .iter()
        .filter(|host| host.status == Some(InventoryStatus::Excluded))
        .map(|host| host.hostname.as_str())
        .collect();
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    for host in &inventory.hosts {
        if excluded.contains(host.hostname.as_str())
            || !host_patterns_match(&host.hostname, patterns, true)
        {
            continue;
        }
        if !valid_ssh_inventory_target(&host.hostname) {
            return Err(InventoryError::InvalidHost {
                hostname: host.hostname.clone(),
            });
        }
        if let Some(access_method @ (AccessMethod::Agent | AccessMethod::Api)) = host.access_method
        {
            return Err(InventoryError::UnsupportedAccess {
                hostname: host.hostname.clone(),
                access_method,
            });
        }
        if seen.insert(host.hostname.as_str()) {
            selected.push(host.hostname.clone());
        }
    }
    if selected.is_empty() {
        return Err(InventoryError::EmptyHosts);
    }
    Ok(selected)
}

fn valid_ssh_inventory_target(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 1024
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._@:%[]".contains(&byte))
        && host.matches('@').count() <= 1
        && host
            .split('@')
            .all(|part| !part.is_empty() && !part.starts_with('-'))
}

/// OpenSSH Host patterns use `*` and `?`, not regular expressions or bracket
/// ranges. Arguments, including aliases, are case-sensitive as in ssh_config.
pub(super) fn host_pattern_matches(host: &str, pattern: &str) -> bool {
    let host = host.as_bytes();
    let pattern = pattern.as_bytes();
    let (mut h, mut p) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while h < host.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == host[h]) {
            h += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = h;
        } else if let Some(position) = star {
            retry += 1;
            h = retry;
            p = position + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

pub(super) fn host_patterns_match(host: &str, patterns: &[String], implicit_all: bool) -> bool {
    let mut positive = implicit_all && !patterns.iter().any(|pattern| !pattern.starts_with('!'));
    for pattern in patterns {
        if let Some(exclusion) = pattern.strip_prefix('!') {
            if host_pattern_matches(host, exclusion) {
                return false;
            }
        } else if host_pattern_matches(host, pattern) {
            positive = true;
        }
    }
    positive
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
            yaml_serde::from_str(content).map_err(|e| InventoryError::Parse {
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
    fn select_ssh_hosts_filters_concrete_aliases_and_deduplicates() {
        let inventory = parse_inventory_str(
            r#"{"hosts":["worker-1","dev-a","worker-2","worker-1","DEV-A","mac-mini"]}"#,
            InventoryFormat::Json,
        )
        .unwrap();
        let selected = select_ssh_hosts(
            &inventory,
            &["worker-?".into(), "dev-*".into(), "!worker-2".into()],
        )
        .unwrap();
        assert_eq!(selected, ["worker-1", "dev-a"]);
        assert_eq!(
            select_ssh_hosts(&inventory, &["!worker-*".into()]).unwrap(),
            ["dev-a", "DEV-A", "mac-mini"]
        );
        assert_eq!(
            select_ssh_hosts(&inventory, &[]).unwrap(),
            ["worker-1", "dev-a", "worker-2", "DEV-A", "mac-mini"]
        );
    }

    #[test]
    fn select_ssh_hosts_exclusion_wins_in_either_duplicate_order() {
        for hosts in [
            r#"[{"host":"node","status":"active"},{"host":"node","status":"excluded"},"other"]"#,
            r#"[{"host":"node","status":"excluded"},{"host":"node","status":"active"},"other"]"#,
        ] {
            let inventory =
                parse_inventory_str(&format!("{{\"hosts\":{hosts}}}"), InventoryFormat::Json)
                    .unwrap();
            assert_eq!(select_ssh_hosts(&inventory, &[]).unwrap(), ["other"]);
        }
    }

    #[test]
    fn select_ssh_hosts_refuses_unsupported_only_when_selected() {
        let inventory = parse_inventory_str(
            r#"{"hosts":["ssh-node",{"host":"api-node","access_method":"api"},{"host":"agent-node","access_method":"agent"},"-bad"]}"#,
            InventoryFormat::Json,
        ).unwrap();
        assert_eq!(
            select_ssh_hosts(&inventory, &["ssh-*".into()]).unwrap(),
            ["ssh-node"]
        );
        for name in ["api-node", "agent-node"] {
            assert!(matches!(
                select_ssh_hosts(&inventory, &[name.into()]),
                Err(InventoryError::UnsupportedAccess { .. })
            ));
        }
        assert!(matches!(
            select_ssh_hosts(&inventory, &["-bad".into()]),
            Err(InventoryError::InvalidHost { .. })
        ));
    }

    #[test]
    fn select_ssh_hosts_does_not_let_duplicate_ssh_mask_an_api_record() {
        let inventory = parse_inventory_str(
            r#"{"hosts":["node",{"host":"node","access_method":"api"}]}"#,
            InventoryFormat::Json,
        )
        .unwrap();
        assert!(matches!(
            select_ssh_hosts(&inventory, &[]),
            Err(InventoryError::UnsupportedAccess { .. })
        ));
    }

    #[test]
    fn select_ssh_hosts_rejects_unsafe_targets_and_invalid_filters() {
        for host in [
            "",
            "-oProxyCommand=x",
            "user@-node",
            "@node",
            "user@",
            "a@@b",
            "node name",
            "node;command",
            "node\nsecond",
        ] {
            let inventory = parse_inventory_str(
                &serde_json::json!({"hosts": [host]}).to_string(),
                InventoryFormat::Json,
            )
            .unwrap();
            assert!(
                matches!(
                    select_ssh_hosts(&inventory, &[]),
                    Err(InventoryError::InvalidHost { .. })
                ),
                "{host:?}"
            );
        }
        let inventory =
            parse_inventory_str(r#"{"hosts":["node"]}"#, InventoryFormat::Json).unwrap();
        for pattern in ["", "!", "!!node", "two hosts", "node,other", "node;command"] {
            assert!(
                matches!(
                    select_ssh_hosts(&inventory, &[pattern.into()]),
                    Err(InventoryError::InvalidFilter { .. })
                ),
                "{pattern}"
            );
        }
        assert!(matches!(
            select_ssh_hosts(&inventory, &["missing-*".into()]),
            Err(InventoryError::EmptyHosts)
        ));
    }

    #[test]
    fn ssh_pattern_matching_preserves_openssh_negation_semantics() {
        assert!(host_pattern_matches("worker-12", "w*r?er-??"));
        assert!(!host_pattern_matches("worker-12", "WORKER-*"));
        assert!(!host_pattern_matches("worker-12", "worker-?"));
        assert!(!host_pattern_matches("worker-1", "worker-[12]"));
        assert!(!host_patterns_match("node", &["!other".into()], false));
        assert!(host_patterns_match(
            "node",
            &["!other".into(), "*".into()],
            false
        ));
        assert!(!host_patterns_match(
            "node",
            &["node".into(), "!node".into()],
            false
        ));
        assert!(host_pattern_matches("", "*"));
        assert!(!host_pattern_matches("", "?"));
    }

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
    fn parse_yaml_detailed_hosts() {
        let input = r#"
schema_version: "1.0.0"
generated_at: "2026-10-04T12:00:00Z"
hosts:
  - host: db-1
    access_method: ssh
    credentials_ref: fleet-key
    status: active
    tags:
      role: database
"#;
        let inventory = parse_inventory_str(input, InventoryFormat::Yaml).unwrap();
        assert_eq!(inventory.generated_at, "2026-10-04T12:00:00Z");
        assert_eq!(inventory.hosts.len(), 1);
        let host = &inventory.hosts[0];
        assert_eq!(host.hostname, "db-1");
        assert_eq!(host.access_method, Some(AccessMethod::Ssh));
        assert_eq!(host.credentials_ref.as_deref(), Some("fleet-key"));
        assert_eq!(host.status, Some(InventoryStatus::Active));
        assert_eq!(host.tags.get("role").map(String::as_str), Some("database"));
    }

    #[test]
    fn parse_yaml_malformed_is_parse_error() {
        let error = parse_inventory_str("hosts: [host-a", InventoryFormat::Yaml).unwrap_err();
        match error {
            InventoryError::Parse { format, message } => {
                assert_eq!(format, "yaml");
                assert!(!message.is_empty());
            }
            other => panic!("expected YAML parse error, got {other}"),
        }
    }

    #[test]
    fn parse_yaml_invalid_access_method_is_parse_error() {
        let input = "hosts:\n  - hostname: db-1\n    access_method: unknown\n";
        let error = parse_inventory_str(input, InventoryFormat::Yaml).unwrap_err();
        assert!(matches!(error, InventoryError::Parse { format, .. } if format == "yaml"));
    }

    #[test]
    fn parse_yaml_empty_hosts_is_error() {
        let error = parse_inventory_str("hosts: []", InventoryFormat::Yaml).unwrap_err();
        assert!(matches!(error, InventoryError::EmptyHosts));
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
