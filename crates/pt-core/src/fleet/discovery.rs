//! Fleet discovery providers and configuration.
//!
//! Provides:
//! - Provider trait + registry
//! - Static inventory provider
//! - DNS provider scaffold (feature-gated)
//! - Config schema for future AWS/GCP/K8s providers

use crate::fleet::inventory::{
    host_patterns_match, AccessMethod, HostRecord, InventoryStatus, INVENTORY_SCHEMA_VERSION,
};
use crate::fleet::inventory::{load_inventory_from_path, FleetInventory, InventoryError};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
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
            DiscoveryConfigFormat::Yaml => yaml_serde::from_str(content).map_err(|e| {
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

/// Read concrete aliases from a user OpenSSH configuration without launching
/// `ssh -G` (which can execute `Match exec`). The alias remains the destination;
/// the transport must use this same file with `ssh -F` so OpenSSH still owns
/// connection details such as ProxyJump and IdentityFile.
///
/// Unconditional Include files support lexical glob order, `~/` and the OpenSSH
/// user-config rule that relative paths start at `~/.ssh`, even with a custom
/// root file. Conditional Includes and token/environment-expanded Include paths
/// are refused rather than returning a misleading partial inventory. Match and
/// canonicalization rules are left to SSH; their presence suppresses the
/// informational HostName/User/Port tags, never executes their conditions.
#[derive(Debug, Clone)]
pub struct SshConfigInventoryProvider {
    path: PathBuf,
}

impl SshConfigInventoryProvider {
    pub fn from_path(path: &Path) -> Self {
        Self { path: path.into() }
    }
}

impl InventoryProvider for SshConfigInventoryProvider {
    fn name(&self) -> &str {
        "ssh_config"
    }

    fn discover(&self) -> Result<FleetInventory, DiscoveryError> {
        let mut parser = SshConfigParser::new(dirs::home_dir());
        parser.read_file(&self.path, false)?;
        parser.inventory()
    }
}

const SSH_CONFIG_MAX_BYTES: usize = 4 * 1024 * 1024;
const SSH_CONFIG_MAX_FILES: usize = 256;
const SSH_CONFIG_MAX_DEPTH: usize = 16;
const SSH_CONFIG_MAX_ALIASES: usize = 4096;
const SSH_CONFIG_MAX_GLOB_ENTRIES: usize = 16_384;

enum SshDirective {
    Host(Vec<String>),
    Value(&'static str, String),
}

struct SshConfigParser {
    home: Option<PathBuf>,
    active_files: Vec<PathBuf>,
    files: usize,
    bytes: usize,
    glob_entries: usize,
    directives: Vec<SshDirective>,
    aliases: Vec<String>,
    seen_aliases: HashSet<String>,
    defer_metadata: bool,
}

fn ssh_config_error(message: impl Into<String>) -> DiscoveryError {
    DiscoveryError::Other(format!("SSH config discovery: {}", message.into()))
}

impl SshConfigParser {
    fn new(home: Option<PathBuf>) -> Self {
        Self {
            home,
            active_files: Vec::new(),
            files: 0,
            bytes: 0,
            glob_entries: 0,
            directives: Vec::new(),
            aliases: Vec::new(),
            seen_aliases: HashSet::new(),
            defer_metadata: false,
        }
    }

    fn read_file(&mut self, path: &Path, included: bool) -> Result<(), DiscoveryError> {
        if self.active_files.len() >= SSH_CONFIG_MAX_DEPTH || self.files >= SSH_CONFIG_MAX_FILES {
            return Err(ssh_config_error(
                "Include depth or file-count limit exceeded",
            ));
        }
        let canonical = match fs::canonicalize(path) {
            Ok(path) => path,
            Err(error) if included && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(ssh_config_error(format!(
                    "cannot read {}: {error}",
                    path.display()
                )))
            }
        };
        if self.active_files.contains(&canonical) {
            return Err(ssh_config_error(format!(
                "Include cycle at {}",
                path.display()
            )));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(&canonical).map_err(|error| {
            ssh_config_error(format!("cannot open {}: {error}", path.display()))
        })?;
        if !file
            .metadata()
            .map_err(|error| ssh_config_error(error.to_string()))?
            .is_file()
        {
            return Err(ssh_config_error(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let remaining = SSH_CONFIG_MAX_BYTES.saturating_sub(self.bytes);
        let mut contents = String::new();
        file.take(remaining as u64 + 1)
            .read_to_string(&mut contents)
            .map_err(|error| {
                ssh_config_error(format!("cannot read {}: {error}", path.display()))
            })?;
        if contents.len() > remaining {
            return Err(ssh_config_error("total Include byte limit exceeded"));
        }
        self.bytes += contents.len();
        self.files += 1;
        self.active_files.push(canonical);
        let result = self.read_contents(&contents, path);
        self.active_files.pop();
        result
    }

    fn read_contents(&mut self, contents: &str, path: &Path) -> Result<(), DiscoveryError> {
        let mut unconditional = true;
        for (index, line) in contents.lines().enumerate() {
            let fail = |message: &str| {
                ssh_config_error(format!("{}:{}: {message}", path.display(), index + 1))
            };
            if line.len() > 16_384 || line.contains('\0') {
                return Err(fail("invalid or oversized line"));
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let split = line
                .find(|character: char| character.is_ascii_whitespace() || character == '=')
                .unwrap_or(line.len());
            let keyword = line[..split].to_ascii_lowercase();
            let mut values = line[split..].trim_start();
            if let Some(after) = values.strip_prefix('=') {
                values = after.trim_start();
            }
            if !matches!(
                keyword.as_str(),
                "host"
                    | "match"
                    | "include"
                    | "hostname"
                    | "user"
                    | "port"
                    | "canonicalizehostname"
            ) {
                continue;
            }
            if self.directives.len() >= 32_768 {
                return Err(fail("directive limit exceeded"));
            }
            let values = ssh_config_arguments(values).map_err(|message| fail(message))?;
            if values.is_empty() {
                return Err(fail("missing directive arguments"));
            }
            match keyword.as_str() {
                "host" => {
                    if values
                        .iter()
                        .any(|value| value.is_empty() || value.len() > 1024)
                    {
                        return Err(fail("invalid Host pattern"));
                    }
                    unconditional = values.iter().any(|value| value == "*")
                        && !values.iter().any(|value| value.starts_with('!'));
                    for alias in &values {
                        if alias.starts_with('!')
                            || alias.contains(['*', '?'])
                            || !host_patterns_match(alias, &values, false)
                        {
                            continue;
                        }
                        if self.seen_aliases.insert(alias.clone()) {
                            if self.aliases.len() >= SSH_CONFIG_MAX_ALIASES {
                                return Err(fail("concrete alias limit exceeded"));
                            }
                            self.aliases.push(alias.clone());
                        }
                    }
                    self.directives.push(SshDirective::Host(values));
                }
                "match" => {
                    unconditional = values.len() == 1 && values[0].eq_ignore_ascii_case("all");
                    if !unconditional {
                        self.defer_metadata = true;
                    }
                    self.directives.push(SshDirective::Host(if unconditional {
                        vec!["*".into()]
                    } else {
                        vec![]
                    }));
                }
                "include" => {
                    if !unconditional {
                        return Err(fail("conditional Include cannot be enumerated safely; use an unconditional Include or explicit inventory"));
                    }
                    for value in values {
                        let include = self.include_path(&value)?;
                        for matched in self.expand_include(&include)? {
                            self.read_file(&matched, true)?;
                            // OpenSSH restores the containing file's active
                            // Host/Match state after each included file.
                            self.directives.push(SshDirective::Host(vec!["*".into()]));
                        }
                    }
                }
                "canonicalizehostname" => {
                    if values.len() != 1 || !matches!(values[0].as_str(), "no" | "none") {
                        self.defer_metadata = true;
                    }
                }
                _ => {
                    if values.len() != 1 || values[0].is_empty() {
                        return Err(fail("expected one nonempty directive value"));
                    }
                    let tag = match keyword.as_str() {
                        "hostname" => "ssh_hostname",
                        "user" => "ssh_user",
                        "port" => {
                            if !values[0].bytes().all(|byte| byte.is_ascii_digit())
                                || values[0]
                                    .parse::<u16>()
                                    .ok()
                                    .filter(|port| *port > 0)
                                    .is_none()
                            {
                                return Err(fail("Port must be between 1 and 65535"));
                            }
                            "ssh_port"
                        }
                        _ => unreachable!(),
                    };
                    self.directives
                        .push(SshDirective::Value(tag, values[0].clone()));
                }
            }
        }
        Ok(())
    }

    fn include_path(&self, value: &str) -> Result<PathBuf, DiscoveryError> {
        if value.is_empty() || value.len() > 4096 || value.contains(['%', '$']) {
            return Err(ssh_config_error(
                "Include tokens and environment expansion require explicit inventory",
            ));
        }
        if let Some(suffix) = value.strip_prefix("~/") {
            return self
                .home
                .as_ref()
                .map(|home| home.join(suffix))
                .ok_or_else(|| ssh_config_error("home directory unavailable for Include"));
        }
        if value.starts_with('~') {
            return Err(ssh_config_error(
                "Include supports ~/ but not another user's home directory",
            ));
        }
        let path = PathBuf::from(value);
        if path.is_absolute() {
            Ok(path)
        } else {
            self.home
                .as_ref()
                .map(|home| home.join(".ssh").join(path))
                .ok_or_else(|| ssh_config_error("home directory unavailable for relative Include"))
        }
    }

    fn expand_include(&mut self, pattern: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
        let mut paths = vec![PathBuf::new()];
        for component in pattern.components() {
            let part = component.as_os_str();
            let has_glob = part.to_string_lossy().contains(['*', '?', '[', '\\']);
            if !has_glob {
                for path in &mut paths {
                    path.push(part);
                }
                continue;
            }
            let mut next = Vec::new();
            for directory in paths {
                let entries = match fs::read_dir(&directory) {
                    Ok(entries) => entries,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        continue
                    }
                    Err(error) => {
                        return Err(ssh_config_error(format!(
                            "cannot expand Include in {}: {error}",
                            directory.display()
                        )))
                    }
                };
                for entry in entries {
                    self.glob_entries += 1;
                    if self.glob_entries > SSH_CONFIG_MAX_GLOB_ENTRIES {
                        return Err(ssh_config_error("Include directory-entry limit exceeded"));
                    }
                    let entry = entry.map_err(|error| ssh_config_error(error.to_string()))?;
                    if include_component_matches(part, &entry.file_name())? {
                        next.push(entry.path());
                        if next.len() > SSH_CONFIG_MAX_FILES {
                            return Err(ssh_config_error("Include glob match limit exceeded"));
                        }
                    }
                }
            }
            paths = next;
        }
        paths.sort();
        Ok(paths)
    }

    fn inventory(self) -> Result<FleetInventory, DiscoveryError> {
        if self.aliases.is_empty() {
            return Err(ssh_config_error(
                "no concrete Host aliases found; wildcard-only stanzas do not create hosts",
            ));
        }
        let hosts = self
            .aliases
            .into_iter()
            .map(|hostname| {
                let mut tags = HashMap::new();
                tags.insert("inventory_source".into(), "ssh_config".into());
                tags.insert(
                    "ssh_metadata".into(),
                    if self.defer_metadata {
                        "deferred_to_ssh_match_or_canonicalization"
                    } else {
                        "static_config_only"
                    }
                    .into(),
                );
                if !self.defer_metadata {
                    let mut active = true;
                    for directive in &self.directives {
                        match directive {
                            SshDirective::Host(patterns) => {
                                active = host_patterns_match(&hostname, patterns, false)
                            }
                            SshDirective::Value(tag, value) if active => {
                                tags.entry((*tag).into()).or_insert_with(|| value.clone());
                            }
                            _ => {}
                        }
                    }
                }
                HostRecord {
                    hostname,
                    tags,
                    access_method: Some(AccessMethod::Ssh),
                    credentials_ref: None,
                    last_seen: None,
                    status: None,
                }
            })
            .collect();
        Ok(FleetInventory {
            schema_version: INVENTORY_SCHEMA_VERSION.into(),
            generated_at: Utc::now().to_rfc3339(),
            hosts,
        })
    }
}

/// Tokenize only inventory-relevant directives. Commands in other options are
/// opaque; no expansion, process launch or shell evaluation occurs here.
fn ssh_config_arguments(value: &str) -> Result<Vec<String>, &'static str> {
    let mut values = Vec::new();
    let mut chars = value.chars().peekable();
    while chars.peek().is_some() {
        while chars
            .peek()
            .is_some_and(|character| matches!(character, ' ' | '\t'))
        {
            chars.next();
        }
        if chars.peek().is_none_or(|character| *character == '#') {
            break;
        }
        let mut token = String::new();
        let mut quote = None;
        while let Some(character) = chars.next() {
            match character {
                '\\' if chars.peek().is_some_and(|next| {
                    matches!(next, '\'' | '"' | '\\') || (quote.is_none() && *next == ' ')
                }) =>
                {
                    token.push(chars.next().expect("peeked escape"));
                }
                '\'' | '"' if quote.is_none() => quote = Some(character),
                character if quote == Some(character) => quote = None,
                ' ' | '\t' if quote.is_none() => break,
                character => token.push(character),
            }
        }
        if quote.is_some() {
            return Err("unterminated quoted argument");
        }
        values.push(token);
    }
    Ok(values)
}

#[cfg(unix)]
fn include_component_matches(
    pattern: &std::ffi::OsStr,
    name: &std::ffi::OsStr,
) -> Result<bool, DiscoveryError> {
    use std::os::unix::ffi::OsStrExt;
    let pattern = std::ffi::CString::new(pattern.as_bytes())
        .map_err(|_| ssh_config_error("invalid Include pattern"))?;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| ssh_config_error("invalid Include entry"))?;
    // SAFETY: both inputs are owned, NUL-terminated strings. fnmatch only reads
    // them; FNM_PERIOD matches glob's rule for hidden path components.
    let result = unsafe { libc::fnmatch(pattern.as_ptr(), name.as_ptr(), libc::FNM_PERIOD) };
    match result {
        0 => Ok(true),
        libc::FNM_NOMATCH => Ok(false),
        _ => Err(ssh_config_error("invalid Include glob")),
    }
}

#[cfg(not(unix))]
fn include_component_matches(
    _pattern: &std::ffi::OsStr,
    _name: &std::ffi::OsStr,
) -> Result<bool, DiscoveryError> {
    Err(ssh_config_error(
        "Include glob discovery requires a Unix platform",
    ))
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
                // A second provider must not turn an explicitly unsupported
                // transport into an apparently runnable SSH host.
                if existing.access_method.is_none()
                    || matches!(
                        host.access_method,
                        Some(AccessMethod::Agent | AccessMethod::Api)
                    )
                {
                    existing.access_method = host.access_method;
                }
                if existing.credentials_ref.is_none() {
                    existing.credentials_ref = host.credentials_ref.clone();
                }
                if existing.last_seen.is_none() {
                    existing.last_seen = host.last_seen.clone();
                }
                if existing.status.is_none() || host.status == Some(InventoryStatus::Excluded) {
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

    fn ssh_fixture(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config");
        fs::write(&path, contents).unwrap();
        (directory, path)
    }

    #[test]
    fn ssh_aliases_keep_connection_names_and_first_applicable_values() {
        let (_directory, path) = ssh_fixture(
            r#"
Host dev-a dev-b
    User build
    Port=2222
Host dev-a
    HostName 192.0.2.10
    User ignored-later-value
Host dev-* !dev-b
    HostName shared.example
Host *
    HostName fallback.example
    User fallback
    Port 22
"#,
        );
        let inventory = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap();
        assert_eq!(
            inventory
                .hosts
                .iter()
                .map(|host| host.hostname.as_str())
                .collect::<Vec<_>>(),
            vec!["dev-a", "dev-b"]
        );
        let a = &inventory.hosts[0];
        assert_eq!(a.tags["ssh_hostname"], "192.0.2.10");
        assert_eq!(a.tags["ssh_user"], "build");
        assert_eq!(a.tags["ssh_port"], "2222");
        let b = &inventory.hosts[1];
        assert_eq!(b.tags["ssh_hostname"], "fallback.example");
        assert_eq!(b.tags["ssh_port"], "2222");
        assert_eq!(a.access_method, Some(AccessMethod::Ssh));
    }

    #[test]
    fn ssh_global_values_win_and_negated_aliases_do_not_materialize() {
        let (_directory, path) = ssh_fixture("User first\nHost no !no yes\n User later\nHost yes\n Port 2200\nHost *.example ? !never\n");
        let inventory = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap();
        assert_eq!(inventory.hosts.len(), 1);
        assert_eq!(inventory.hosts[0].hostname, "yes");
        assert_eq!(inventory.hosts[0].tags["ssh_user"], "first");
        assert_eq!(inventory.hosts[0].tags["ssh_port"], "2200");
    }

    #[test]
    fn ssh_include_globs_use_lexical_order_and_restore_outer_scope() {
        let (directory, path) =
            ssh_fixture("Include \"~/configs/[12]-*.conf\"\nHost final\n User final-user\n");
        let fragments = directory.path().join("configs");
        fs::create_dir(&fragments).unwrap();
        fs::write(
            fragments.join("2-default.conf"),
            "Host *\n User fallback\nHost second\n HostName two.example\n",
        )
        .unwrap();
        fs::write(
            fragments.join("1-first.conf"),
            "Host first\n User preferred\n",
        )
        .unwrap();
        fs::write(fragments.join(".hidden.conf"), "Host hidden\n").unwrap();
        let mut parser = SshConfigParser::new(Some(directory.path().into()));
        parser.read_file(&path, false).unwrap();
        let inventory = parser.inventory().unwrap();
        assert_eq!(
            inventory
                .hosts
                .iter()
                .map(|host| host.hostname.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second", "final"]
        );
        assert_eq!(inventory.hosts[0].tags["ssh_user"], "preferred");
        assert_eq!(inventory.hosts[1].tags["ssh_user"], "fallback");
        // The wildcard in the second include applies before the later explicit
        // stanza, and the first-value rule therefore preserves its value.
        assert_eq!(inventory.hosts[2].tags["ssh_user"], "fallback");
    }

    #[test]
    fn ssh_include_does_not_leak_its_host_state_back_to_parent() {
        let (directory, path) = ssh_fixture("Include ~/fragment\nUser global\nHost other\n");
        fs::write(directory.path().join("fragment"), "Host first\n").unwrap();
        let mut parser = SshConfigParser::new(Some(directory.path().into()));
        parser.read_file(&path, false).unwrap();
        let inventory = parser.inventory().unwrap();
        assert_eq!(inventory.hosts[1].tags["ssh_user"], "global");
    }

    #[test]
    fn ssh_relative_includes_start_at_user_ssh_directory() {
        let (directory, path) = ssh_fixture("Include config.d/*.conf missing.conf\n");
        let fragments = directory.path().join(".ssh/config.d");
        fs::create_dir_all(&fragments).unwrap();
        fs::write(
            fragments.join("worker.conf"),
            "Host worker-1\n HostName worker.example\n",
        )
        .unwrap();
        let mut parser = SshConfigParser::new(Some(directory.path().into()));
        parser.read_file(&path, false).unwrap();
        let inventory = parser.inventory().unwrap();
        assert_eq!(inventory.hosts[0].hostname, "worker-1");
    }

    #[test]
    fn ssh_match_commands_are_never_run_and_metadata_is_not_guessed() {
        let (directory, path) = ssh_fixture("");
        let marker = directory.path().join("must-not-exist");
        fs::write(&path, format!("Host node\n HostName original.example\nMatch exec \"touch {}\"\n User conditional\nMatch all\n User fallback\n", marker.display())).unwrap();
        let inventory = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap();
        assert_eq!(inventory.hosts[0].hostname, "node");
        assert!(!marker.exists());
        assert!(!inventory.hosts[0].tags.contains_key("ssh_user"));
        assert!(!inventory.hosts[0].tags.contains_key("ssh_hostname"));
        assert_eq!(
            inventory.hosts[0].tags["ssh_metadata"],
            "deferred_to_ssh_match_or_canonicalization"
        );
    }

    #[test]
    fn ssh_conditional_include_and_dynamic_paths_refuse_partial_inventory() {
        for contents in [
            "Host foo\n Include missing\n",
            "Host foo\nMatch exec false\n Include missing\n",
            "Include ${HOME}/config\nHost foo\n",
            "Include ~/.ssh/%h.conf\nHost foo\n",
        ] {
            let (_directory, path) = ssh_fixture(contents);
            assert!(
                SshConfigInventoryProvider::from_path(&path)
                    .discover()
                    .is_err(),
                "{contents}"
            );
        }
    }

    #[test]
    fn ssh_include_cycle_and_depth_are_bounded() {
        let (directory, path) = ssh_fixture("");
        fs::write(&path, format!("Include {}\nHost node\n", path.display())).unwrap();
        let error = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap_err();
        assert!(error.to_string().contains("cycle"));
        for index in 0..=SSH_CONFIG_MAX_DEPTH {
            let next = directory.path().join(format!("depth-{}", index + 1));
            fs::write(
                directory.path().join(format!("depth-{index}")),
                format!("Include {}\n", next.display()),
            )
            .unwrap();
        }
        let error = SshConfigInventoryProvider::from_path(&directory.path().join("depth-0"))
            .discover()
            .unwrap_err();
        assert!(error.to_string().contains("depth"));
    }

    #[test]
    fn ssh_missing_root_invalid_port_quotes_and_wildcard_only_fail() {
        let (directory, path) = ssh_fixture("Host *\nUser worker\n");
        assert!(SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap_err()
            .to_string()
            .contains("concrete"));
        assert!(
            SshConfigInventoryProvider::from_path(&directory.path().join("missing"))
                .discover()
                .is_err()
        );
        for contents in [
            "Host x\nPort 65536\n",
            "Host x\nPort 0\n",
            "Host \"unfinished\n",
            "Host x\nUser x y\n",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(
                SshConfigInventoryProvider::from_path(&path)
                    .discover()
                    .is_err(),
                "{contents}"
            );
        }
    }

    #[test]
    fn ssh_quoted_values_comments_and_opaque_commands() {
        let (_directory, path) = ssh_fixture("# comment\n hOsT=\"node\" # comment\n User='build-user'\n HostName \"node.example\"\n ProxyCommand sh -c 'an opaque command\n LocalCommand touch /must-not-run\n");
        let inventory = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap();
        assert_eq!(inventory.hosts[0].tags["ssh_user"], "build-user");
        assert_eq!(inventory.hosts[0].tags["ssh_hostname"], "node.example");
        assert_eq!(
            ssh_config_arguments(r#""a b" plain\ value # ignored"#).unwrap(),
            ["a b", "plain value"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_includes_refuse_fifo_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let (directory, path) = ssh_fixture("");
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: owned NUL-terminated pathname in a private test directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        fs::write(&path, format!("Include {}\nHost node\n", fifo.display())).unwrap();
        let error = SshConfigInventoryProvider::from_path(&path)
            .discover()
            .unwrap_err();
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn discovery_merge_cannot_hide_exclusion_or_unsupported_transport() {
        let mut first = crate::fleet::inventory::parse_inventory_str(
            r#"{"hosts":[{"host":"node","access_method":"ssh","status":"active"}]}"#,
            crate::fleet::inventory::InventoryFormat::Json,
        )
        .unwrap();
        let mut second = first.clone();
        second.hosts[0].status = Some(InventoryStatus::Excluded);
        assert_eq!(
            merge_inventories(&[first.clone(), second]).hosts[0].status,
            Some(InventoryStatus::Excluded)
        );
        let mut second = first.clone();
        second.hosts[0].access_method = Some(AccessMethod::Api);
        assert!(crate::fleet::inventory::select_ssh_hosts(
            &merge_inventories(&[first.clone(), second]),
            &[]
        )
        .is_err());
        first.hosts[0].status = Some(InventoryStatus::Excluded);
        assert!(
            crate::fleet::inventory::select_ssh_hosts(&merge_inventories(&[first]), &[]).is_err()
        );
    }

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
        match &config.providers[0] {
            ProviderConfig::Static { path } => assert_eq!(path, "hosts.yaml"),
            other => panic!("expected Static provider, got {other:?}"),
        }
    }

    #[test]
    fn parse_yaml_malformed_is_error() {
        let input = "providers: [{type: static, path: hosts.yaml}";
        let error =
            FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Yaml).unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to parse yaml discovery config"));
    }

    #[test]
    fn parse_yaml_unknown_provider_is_error() {
        let input = "providers:\n  - type: unknown\n    path: hosts.yaml\n";
        let error =
            FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Yaml).unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to parse yaml discovery config"));
    }

    #[test]
    fn parse_yaml_missing_static_path_is_error() {
        let input = "providers:\n  - type: static\n";
        let error =
            FleetDiscoveryConfig::parse_str(input, DiscoveryConfigFormat::Yaml).unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to parse yaml discovery config"));
        assert!(error.to_string().contains("path"));
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
