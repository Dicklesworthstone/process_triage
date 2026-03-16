//! Resource node model and normalization for listeners, sockets, lockfiles,
//! and pidfiles in process provenance.
//!
//! Defines how shared-resource ownership markers are represented and normalized
//! so they can be attached to processes without schema drift or double-counting.
//! Resources are the substrate for blast-radius reasoning: if two processes
//! share a port or lockfile, killing one may affect the other.
//!
//! Key design decisions:
//! - Each resource has a canonical stable ID based on its kind + key
//! - Deduplication uses the stable ID; two observations of the same port
//!   produce the same resource node
//! - Sensitivity/redaction is inherited from the resource kind
//! - Absent or partially observed resources get explicit uncertainty states

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ProvenanceConfidence, ProvenanceNodeId, ProvenanceNodeKind, ProvenanceObservationStatus,
    ProvenanceRedactionState, ProvenanceSensitivity,
};

/// Schema version for resource evidence normalization.
pub const RESOURCE_EVIDENCE_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Resource kinds and raw evidence
// ---------------------------------------------------------------------------

/// The kind of shared resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// TCP/UDP listener on a port.
    Listener,
    /// Unix domain socket.
    UnixSocket,
    /// File-based lock (e.g., `.lock`, `lockfile`).
    Lockfile,
    /// PID file recording a process's identity.
    Pidfile,
    /// Shared memory segment.
    SharedMemory,
    /// Named pipe (FIFO).
    NamedPipe,
    /// D-Bus name ownership.
    DbusName,
    /// GPU device slot.
    GpuDevice,
}

impl ResourceKind {
    /// Slug for stable ID generation.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Listener => "listener",
            Self::UnixSocket => "unix_socket",
            Self::Lockfile => "lockfile",
            Self::Pidfile => "pidfile",
            Self::SharedMemory => "shm",
            Self::NamedPipe => "fifo",
            Self::DbusName => "dbus",
            Self::GpuDevice => "gpu",
        }
    }

    /// Default sensitivity for this resource kind.
    pub fn default_sensitivity(self) -> ProvenanceSensitivity {
        match self {
            Self::Listener | Self::UnixSocket => ProvenanceSensitivity::OperatorContext,
            Self::Lockfile | Self::Pidfile => ProvenanceSensitivity::LocalPath,
            Self::SharedMemory | Self::NamedPipe => ProvenanceSensitivity::OperatorContext,
            Self::DbusName => ProvenanceSensitivity::PublicOperational,
            Self::GpuDevice => ProvenanceSensitivity::PublicOperational,
        }
    }
}

/// Raw evidence about a shared resource owned or used by a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawResourceEvidence {
    /// The kind of resource.
    pub kind: ResourceKind,
    /// The canonical key for this resource (e.g., "tcp:8080", "/tmp/my.lock").
    pub key: String,
    /// The PID that owns or uses this resource.
    pub owner_pid: u32,
    /// How this resource was discovered.
    pub collection_method: ResourceCollectionMethod,
    /// Whether the resource is actively held vs. stale.
    pub state: ResourceState,
    /// Additional context about the resource.
    pub details: ResourceDetails,
    /// ISO-8601 timestamp of observation.
    pub observed_at: String,
}

/// How a resource was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCollectionMethod {
    /// Read from /proc/net, ss, or netstat.
    ProcNet,
    /// Read from /proc/[pid]/fd.
    ProcFd,
    /// Read from lsof output.
    Lsof,
    /// Read from filesystem scan.
    FilesystemScan,
    /// Inferred from command line or config.
    Inferred,
    /// Synthetic/test.
    Synthetic,
}

/// Whether the resource is actively held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// Actively held by the process.
    Active,
    /// Stale — file exists but process may have died without cleanup.
    Stale,
    /// Partially observed — some evidence but incomplete.
    Partial,
    /// Conflicted — multiple processes claim the same resource.
    Conflicted,
    /// The resource was not found (negative evidence).
    Missing,
}

/// Kind-specific details about the resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ResourceDetails {
    /// TCP or UDP listener.
    Listener {
        protocol: String,
        port: u16,
        bind_address: String,
    },
    /// Unix domain socket.
    UnixSocket { path: String, socket_type: String },
    /// File-based lock.
    Lockfile {
        path: String,
        /// Whether the lock uses flock/fcntl or just file existence.
        mechanism: LockMechanism,
    },
    /// PID file.
    Pidfile {
        path: String,
        /// The PID recorded in the file (may differ from owner_pid if stale).
        recorded_pid: Option<u32>,
    },
    /// Generic resource (shm, fifo, dbus, gpu).
    Generic { description: String },
}

/// How a lockfile implements its lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMechanism {
    /// Uses flock() or fcntl() advisory locking.
    Advisory,
    /// Uses file existence (create-exclusive).
    Existence,
    /// Unknown mechanism.
    Unknown,
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// A normalized resource identity with a stable, deduplicated ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedResource {
    /// Stable identifier for this resource, based on kind + canonical key.
    pub resource_id: String,
    /// The kind of resource.
    pub kind: ResourceKind,
    /// The canonical key.
    pub canonical_key: String,
    /// Display label for user-facing output.
    pub label: String,
    /// Observation status.
    pub observation_status: ProvenanceObservationStatus,
    /// Confidence in this resource evidence.
    pub confidence: ProvenanceConfidence,
    /// Sensitivity classification for redaction.
    pub sensitivity: ProvenanceSensitivity,
    /// Redaction state based on sensitivity.
    pub redaction: ProvenanceRedactionState,
    /// Reasons for confidence downgrade.
    pub downgrade_reasons: Vec<String>,
}

impl NormalizedResource {
    /// Generate a provenance node ID for this resource.
    pub fn node_id(&self) -> ProvenanceNodeId {
        ProvenanceNodeId::new(
            ProvenanceNodeKind::Resource,
            &format!("resource:{}", self.resource_id),
        )
    }
}

/// Compute a stable resource ID from kind and canonical key.
///
/// Two observations of the same resource (same kind + key) will always
/// produce the same ID, enabling deduplication.
pub fn stable_resource_id(kind: ResourceKind, canonical_key: &str) -> String {
    let input = format!("{}:{}", kind.slug(), canonical_key);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Normalize a raw resource evidence into a stable resource identity.
pub fn normalize_resource(evidence: &RawResourceEvidence) -> NormalizedResource {
    let canonical_key = canonicalize_resource_key(evidence.kind, &evidence.key);
    let resource_id = stable_resource_id(evidence.kind, &canonical_key);
    let label = make_resource_label(evidence);

    let mut confidence = match evidence.state {
        ResourceState::Active => ProvenanceConfidence::High,
        ResourceState::Stale => ProvenanceConfidence::Medium,
        ResourceState::Partial => ProvenanceConfidence::Low,
        ResourceState::Conflicted => ProvenanceConfidence::Low,
        ResourceState::Missing => ProvenanceConfidence::Unknown,
    };

    let observation_status = match evidence.state {
        ResourceState::Active => ProvenanceObservationStatus::Observed,
        ResourceState::Stale => ProvenanceObservationStatus::Partial,
        ResourceState::Partial => ProvenanceObservationStatus::Partial,
        ResourceState::Conflicted => ProvenanceObservationStatus::Conflicted,
        ResourceState::Missing => ProvenanceObservationStatus::Missing,
    };

    let mut downgrade_reasons = Vec::new();
    let sensitivity = evidence.kind.default_sensitivity();

    // Downgrade if collection method is inference-based
    if evidence.collection_method == ResourceCollectionMethod::Inferred {
        confidence = downgrade(confidence);
        downgrade_reasons
            .push("resource detected via inference, not direct observation".to_string());
    }

    // Determine redaction based on sensitivity
    let redaction = match sensitivity {
        ProvenanceSensitivity::LocalPath | ProvenanceSensitivity::SecretAdjacent => {
            ProvenanceRedactionState::Partial
        }
        ProvenanceSensitivity::InfrastructureIdentity => ProvenanceRedactionState::Partial,
        _ => ProvenanceRedactionState::None,
    };

    NormalizedResource {
        resource_id,
        kind: evidence.kind,
        canonical_key,
        label,
        observation_status,
        confidence,
        sensitivity,
        redaction,
        downgrade_reasons,
    }
}

/// Canonicalize a resource key for consistent hashing.
fn canonicalize_resource_key(kind: ResourceKind, key: &str) -> String {
    match kind {
        ResourceKind::Listener => {
            // Normalize "0.0.0.0:8080" and ":::8080" and "*:8080" to a canonical form
            key.replace("0.0.0.0:", "any:")
                .replace(":::", "any6:")
                .replace("*:", "any:")
        }
        ResourceKind::UnixSocket | ResourceKind::Lockfile | ResourceKind::Pidfile => {
            // Normalize path separators and strip trailing slashes
            let normalized = key.replace('\\', "/");
            if normalized.len() > 1 {
                normalized.trim_end_matches('/').to_string()
            } else {
                normalized
            }
        }
        _ => key.to_string(),
    }
}

/// Create a human-readable label for a resource.
fn make_resource_label(evidence: &RawResourceEvidence) -> String {
    match &evidence.details {
        ResourceDetails::Listener {
            protocol,
            port,
            bind_address,
        } => format!("{protocol}:{bind_address}:{port}"),
        ResourceDetails::UnixSocket { path, .. } => {
            // Shorten long socket paths
            if path.len() > 40 {
                format!("unix:...{}", &path[path.len() - 30..])
            } else {
                format!("unix:{path}")
            }
        }
        ResourceDetails::Lockfile { path, .. } => {
            if let Some(name) = path.rsplit('/').next() {
                format!("lock:{name}")
            } else {
                format!("lock:{path}")
            }
        }
        ResourceDetails::Pidfile { path, .. } => {
            if let Some(name) = path.rsplit('/').next() {
                format!("pid:{name}")
            } else {
                format!("pid:{path}")
            }
        }
        ResourceDetails::Generic { description } => description.clone(),
    }
}

fn downgrade(c: ProvenanceConfidence) -> ProvenanceConfidence {
    match c {
        ProvenanceConfidence::High => ProvenanceConfidence::Medium,
        ProvenanceConfidence::Medium => ProvenanceConfidence::Low,
        ProvenanceConfidence::Low | ProvenanceConfidence::Unknown => ProvenanceConfidence::Unknown,
    }
}

/// Canonical debug event names.
pub const RESOURCE_EVIDENCE_NORMALIZED: &str = "provenance_resource_evidence_normalized";
pub const RESOURCE_EVIDENCE_CONFLICT: &str = "provenance_resource_evidence_conflict";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_resource_id_deterministic() {
        let id1 = stable_resource_id(ResourceKind::Listener, "tcp:8080");
        let id2 = stable_resource_id(ResourceKind::Listener, "tcp:8080");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn stable_resource_id_differs_by_kind() {
        let id1 = stable_resource_id(ResourceKind::Listener, "8080");
        let id2 = stable_resource_id(ResourceKind::Lockfile, "8080");
        assert_ne!(id1, id2);
    }

    #[test]
    fn listener_normalization() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: "0.0.0.0:8080".to_string(),
            owner_pid: 123,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port: 8080,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.kind, ResourceKind::Listener);
        assert_eq!(normalized.canonical_key, "any:8080");
        assert_eq!(normalized.confidence, ProvenanceConfidence::High);
        assert_eq!(
            normalized.observation_status,
            ProvenanceObservationStatus::Observed
        );
        assert!(normalized.label.contains("tcp"));
    }

    #[test]
    fn listener_wildcard_dedup() {
        let id1 = stable_resource_id(ResourceKind::Listener, "any:8080");
        let ev = RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: "0.0.0.0:8080".to_string(),
            owner_pid: 1,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port: 8080,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };
        let normalized = normalize_resource(&ev);
        assert_eq!(normalized.resource_id, id1);
    }

    #[test]
    fn lockfile_normalization() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: "/var/run/myapp.lock".to_string(),
            owner_pid: 456,
            collection_method: ResourceCollectionMethod::FilesystemScan,
            state: ResourceState::Active,
            details: ResourceDetails::Lockfile {
                path: "/var/run/myapp.lock".to_string(),
                mechanism: LockMechanism::Advisory,
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.kind, ResourceKind::Lockfile);
        assert_eq!(normalized.confidence, ProvenanceConfidence::High);
        assert_eq!(normalized.sensitivity, ProvenanceSensitivity::LocalPath);
        assert_eq!(normalized.redaction, ProvenanceRedactionState::Partial);
        assert!(normalized.label.contains("myapp.lock"));
    }

    #[test]
    fn stale_resource_downgrades_confidence() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Pidfile,
            key: "/var/run/old.pid".to_string(),
            owner_pid: 789,
            collection_method: ResourceCollectionMethod::FilesystemScan,
            state: ResourceState::Stale,
            details: ResourceDetails::Pidfile {
                path: "/var/run/old.pid".to_string(),
                recorded_pid: Some(100),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.confidence, ProvenanceConfidence::Medium);
        assert_eq!(
            normalized.observation_status,
            ProvenanceObservationStatus::Partial
        );
    }

    #[test]
    fn conflicted_resource() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: "tcp:3000".to_string(),
            owner_pid: 111,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Conflicted,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port: 3000,
                bind_address: "127.0.0.1".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.confidence, ProvenanceConfidence::Low);
        assert_eq!(
            normalized.observation_status,
            ProvenanceObservationStatus::Conflicted
        );
    }

    #[test]
    fn inferred_resource_downgrades() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: "tcp:9090".to_string(),
            owner_pid: 222,
            collection_method: ResourceCollectionMethod::Inferred,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port: 9090,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.confidence, ProvenanceConfidence::Medium);
        assert!(!normalized.downgrade_reasons.is_empty());
    }

    #[test]
    fn missing_resource() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: "/tmp/missing.lock".to_string(),
            owner_pid: 333,
            collection_method: ResourceCollectionMethod::FilesystemScan,
            state: ResourceState::Missing,
            details: ResourceDetails::Lockfile {
                path: "/tmp/missing.lock".to_string(),
                mechanism: LockMechanism::Existence,
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(normalized.confidence, ProvenanceConfidence::Unknown);
        assert_eq!(
            normalized.observation_status,
            ProvenanceObservationStatus::Missing
        );
    }

    #[test]
    fn node_id_deterministic() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::UnixSocket,
            key: "/tmp/app.sock".to_string(),
            owner_pid: 444,
            collection_method: ResourceCollectionMethod::ProcFd,
            state: ResourceState::Active,
            details: ResourceDetails::UnixSocket {
                path: "/tmp/app.sock".to_string(),
                socket_type: "stream".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let n1 = normalize_resource(&evidence);
        let n2 = normalize_resource(&evidence);
        assert_eq!(n1.node_id(), n2.node_id());
        assert!(n1.node_id().0.starts_with("pn_resource_"));
    }

    #[test]
    fn dbus_is_public_operational() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::DbusName,
            key: "org.freedesktop.Notifications".to_string(),
            owner_pid: 555,
            collection_method: ResourceCollectionMethod::Inferred,
            state: ResourceState::Active,
            details: ResourceDetails::Generic {
                description: "dbus:org.freedesktop.Notifications".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert_eq!(
            normalized.sensitivity,
            ProvenanceSensitivity::PublicOperational
        );
        assert_eq!(normalized.redaction, ProvenanceRedactionState::None);
    }

    #[test]
    fn json_round_trip() {
        let evidence = RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: "tcp:443".to_string(),
            owner_pid: 1,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port: 443,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        let json = serde_json::to_string(&normalized).expect("serialize");
        let parsed: NormalizedResource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.resource_id, normalized.resource_id);
        assert_eq!(parsed.kind, normalized.kind);
    }

    #[test]
    fn resource_kind_slugs() {
        assert_eq!(ResourceKind::Listener.slug(), "listener");
        assert_eq!(ResourceKind::UnixSocket.slug(), "unix_socket");
        assert_eq!(ResourceKind::Lockfile.slug(), "lockfile");
        assert_eq!(ResourceKind::Pidfile.slug(), "pidfile");
        assert_eq!(ResourceKind::SharedMemory.slug(), "shm");
        assert_eq!(ResourceKind::NamedPipe.slug(), "fifo");
        assert_eq!(ResourceKind::DbusName.slug(), "dbus");
        assert_eq!(ResourceKind::GpuDevice.slug(), "gpu");
    }

    #[test]
    fn unix_socket_label_truncation() {
        let long_path =
            "/very/long/path/to/a/deeply/nested/application/socket/that/exceeds/the/threshold.sock";
        let evidence = RawResourceEvidence {
            kind: ResourceKind::UnixSocket,
            key: long_path.to_string(),
            owner_pid: 666,
            collection_method: ResourceCollectionMethod::ProcFd,
            state: ResourceState::Active,
            details: ResourceDetails::UnixSocket {
                path: long_path.to_string(),
                socket_type: "stream".to_string(),
            },
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let normalized = normalize_resource(&evidence);
        assert!(normalized.label.starts_with("unix:..."));
        assert!(normalized.label.len() < long_path.len());
    }
}
