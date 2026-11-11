//! Network resource provenance collector for listeners and sockets.
//!
//! Bridges the existing `collect_network_info()` into `RawResourceEvidence`
//! for the provenance graph. Handles conflict detection when multiple processes
//! bind the same port, and partial-evidence cases when socket attribution is
//! incomplete.

use pt_common::{
    RawResourceEvidence, ResourceCollectionMethod, ResourceDetails, ResourceKind, ResourceState,
};

/// Collect listener and socket resource evidence for a process.
///
/// Uses the existing network collection infrastructure to gather TCP/UDP listeners
/// and Unix sockets, then converts them to `RawResourceEvidence` for provenance.
#[cfg(target_os = "linux")]
pub fn collect_listener_resources(pid: u32) -> Vec<RawResourceEvidence> {
    collect_listener_resources_from(pid, &super::network::NetworkSnapshot::collect())
}

/// Like [`collect_listener_resources`], but against a shared socket snapshot.
///
/// Scans that evaluate many candidates must take ONE `NetworkSnapshot` and pass it
/// here: re-parsing all of `/proc/net/{tcp,tcp6,udp,udp6,unix}` per candidate made
/// `agent plan` take 366 s on a loaded 64-core host (2026-09-24 fleet run).
#[cfg(target_os = "linux")]
pub fn collect_listener_resources_from(
    pid: u32,
    snapshot: &super::network::NetworkSnapshot,
) -> Vec<RawResourceEvidence> {
    collect_listener_resources_from_checked(pid, snapshot).unwrap_or_default()
}

/// Collect namespace-bound resource evidence without converting missing
/// observation coverage into a complete empty resource inventory.
#[cfg(target_os = "linux")]
pub fn collect_listener_resources_from_checked(
    pid: u32,
    snapshot: &super::network::NetworkSnapshot,
) -> std::io::Result<Vec<RawResourceEvidence>> {
    snapshot
        .get_process_info_checked(pid)
        .and_then(|info| listener_resources_from_info(pid, &info))
}

#[cfg(target_os = "linux")]
fn listener_resources_from_info(
    pid: u32,
    net_info: &super::network::NetworkInfo,
) -> std::io::Result<Vec<RawResourceEvidence>> {
    // Addresses and abstract Unix names are namespace-local. Without observed
    // namespace identity, identical text cannot establish resource sharing.
    let Some(namespace) = net_info.namespace else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "network resources have no observed namespace identity",
        ));
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut resources = Vec::new();

    // Convert listening ports to resource evidence
    for port in &net_info.listen_ports {
        resources.push(RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: namespace
                .resource_key(&format!("{}:{}:{}", port.protocol, port.address, port.port)),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: port.protocol.clone(),
                port: port.port,
                bind_address: port.address.clone(),
            },
            observed_at: now.clone(),
        });
    }

    // Convert Unix sockets to resource evidence
    for sock in &net_info.unix_sockets {
        if let Some(path) = &sock.path {
            if !path.is_empty() {
                resources.push(RawResourceEvidence {
                    kind: ResourceKind::UnixSocket,
                    // Abstract names belong to a network namespace.
                    // Filesystem path text does not: distinct mounts can
                    // contain the same path, while an inherited socket can
                    // remain shared after its holders switch namespaces.
                    key: if path.starts_with('@') {
                        namespace.resource_key(&format!("unix:{path}"))
                    } else {
                        format!("unix:inode:{}", sock.inode)
                    },
                    owner_pid: pid,
                    collection_method: ResourceCollectionMethod::ProcNet,
                    state: ResourceState::Active,
                    details: ResourceDetails::UnixSocket {
                        path: path.clone(),
                        socket_type: format!("{:?}", sock.socket_type),
                    },
                    observed_at: now.clone(),
                });
            }
        }
    }
    Ok(resources)
}

/// Detect listener conflicts: multiple processes listening on the same port.
///
/// Returns a list of resource evidence entries marked as `Conflicted` for
/// ports where more than one process appears to be listening.
pub fn detect_listener_conflicts(
    all_resources: &[RawResourceEvidence],
) -> Vec<RawResourceEvidence> {
    use std::collections::HashMap;

    let mut port_owners: HashMap<String, Vec<u32>> = HashMap::new();

    for resource in all_resources {
        if resource.kind == ResourceKind::Listener {
            port_owners
                .entry(resource.key.clone())
                .or_default()
                .push(resource.owner_pid);
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut conflicts = Vec::new();

    for (key, pids) in &port_owners {
        if pids.len() > 1 {
            for &pid in pids {
                if let Some(original) = all_resources
                    .iter()
                    .find(|r| r.key == *key && r.owner_pid == pid)
                {
                    conflicts.push(RawResourceEvidence {
                        kind: original.kind,
                        key: original.key.clone(),
                        owner_pid: pid,
                        collection_method: original.collection_method,
                        state: ResourceState::Conflicted,
                        details: original.details.clone(),
                        observed_at: now.clone(),
                    });
                }
            }
        }
    }

    conflicts
}

/// Collect shared memory and named FIFO evidence from /proc/[pid]/fd.
///
/// Supplements listener collection with non-network IPC resources visible
/// in the process's file descriptor table.
#[cfg(target_os = "linux")]
pub fn collect_fd_ipc_resources(pid: u32) -> Vec<RawResourceEvidence> {
    use std::fs;
    use std::path::PathBuf;

    let now = chrono::Utc::now().to_rfc3339();
    let mut resources = Vec::new();
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));

    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return resources,
    };

    const MAX_FDS: usize = 10_000;

    for (count, entry) in entries.flatten().enumerate() {
        if count >= MAX_FDS {
            break;
        }

        let link = match fs::read_link(entry.path()) {
            Ok(l) => l,
            Err(_) => continue,
        };

        let target = link.to_string_lossy();

        // Detect shared memory segments
        if let Some(shm_name) = target.strip_prefix("/dev/shm/") {
            if !shm_name.is_empty() {
                resources.push(RawResourceEvidence {
                    kind: ResourceKind::SharedMemory,
                    key: format!("shm:{shm_name}"),
                    owner_pid: pid,
                    collection_method: ResourceCollectionMethod::ProcFd,
                    state: ResourceState::Active,
                    details: ResourceDetails::Generic {
                        description: format!("shm:/dev/shm/{shm_name}"),
                    },
                    observed_at: now.clone(),
                });
            }
            continue;
        }

        // Detect named FIFOs (not anonymous pipes)
        if let Ok(metadata) = fs::metadata(link.as_path()) {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_fifo() {
                let path = target.to_string();
                resources.push(RawResourceEvidence {
                    kind: ResourceKind::NamedPipe,
                    key: path.clone(),
                    owner_pid: pid,
                    collection_method: ResourceCollectionMethod::ProcFd,
                    state: ResourceState::Active,
                    details: ResourceDetails::Generic {
                        description: format!("fifo:{path}"),
                    },
                    observed_at: now.clone(),
                });
            }
        }
    }

    resources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_and_abstract_socket_keys_are_scoped_by_observed_namespace() {
        use super::super::network::{
            ListenPort, NetworkInfo, NetworkNamespace, UnixSocket, UnixSocketState, UnixSocketType,
        };
        let mut info = NetworkInfo {
            namespace: Some(NetworkNamespace {
                device: 4,
                inode: 100,
            }),
            listen_ports: vec![ListenPort {
                protocol: "tcp".to_string(),
                port: 8080,
                address: "0.0.0.0".to_string(),
                inode: 42,
            }],
            unix_sockets: vec![UnixSocket {
                path: Some("@agent".to_string()),
                socket_type: UnixSocketType::Stream,
                state: UnixSocketState::Unconnected,
                inode: 43,
                ref_count: 1,
            }],
            ..NetworkInfo::default()
        };
        let first = listener_resources_from_info(1, &info).unwrap();
        let same_namespace = listener_resources_from_info(2, &info).unwrap();
        assert_eq!(first[0].key, same_namespace[0].key);
        info.namespace = Some(NetworkNamespace {
            device: 4,
            inode: 200,
        });
        let second = listener_resources_from_info(3, &info).unwrap();
        assert_ne!(first[0].key, second[0].key);
        assert_ne!(first[1].key, second[1].key);
        assert!(detect_listener_conflicts(&[first[0].clone(), second[0].clone()]).is_empty());
        assert_eq!(
            detect_listener_conflicts(&[first[0].clone(), same_namespace[0].clone()]).len(),
            2
        );
        info.namespace = None;
        assert!(listener_resources_from_info(3, &info).is_err());
    }

    #[test]
    fn filesystem_unix_resources_use_socket_identity_instead_of_path_text() {
        use super::super::network::{
            NetworkInfo, NetworkNamespace, UnixSocket, UnixSocketState, UnixSocketType,
        };
        let mut info = NetworkInfo {
            namespace: Some(NetworkNamespace {
                device: 4,
                inode: 100,
            }),
            unix_sockets: vec![UnixSocket {
                path: Some("/run/agent.sock".to_string()),
                socket_type: UnixSocketType::Stream,
                state: UnixSocketState::Unconnected,
                inode: 43,
                ref_count: 1,
            }],
            ..NetworkInfo::default()
        };
        let first = listener_resources_from_info(1, &info).unwrap();
        info.namespace = Some(NetworkNamespace {
            device: 4,
            inode: 200,
        });
        let inherited = listener_resources_from_info(2, &info).unwrap();
        assert_eq!(first[0].key, inherited[0].key);
        info.unix_sockets[0].inode = 44;
        let same_path_other_socket = listener_resources_from_info(3, &info).unwrap();
        assert_ne!(first[0].key, same_path_other_socket[0].key);
        assert!(
            matches!(&first[0].details, ResourceDetails::UnixSocket { path, .. } if path == "/run/agent.sock")
        );
    }

    #[test]
    fn detect_conflicts_empty() {
        assert!(detect_listener_conflicts(&[]).is_empty());
    }

    #[test]
    fn detect_conflicts_no_overlap() {
        let resources = vec![
            RawResourceEvidence {
                kind: ResourceKind::Listener,
                key: "tcp:0.0.0.0:8080".to_string(),
                owner_pid: 100,
                collection_method: ResourceCollectionMethod::ProcNet,
                state: ResourceState::Active,
                details: ResourceDetails::Listener {
                    protocol: "tcp".to_string(),
                    port: 8080,
                    bind_address: "0.0.0.0".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
            RawResourceEvidence {
                kind: ResourceKind::Listener,
                key: "tcp:0.0.0.0:3000".to_string(),
                owner_pid: 200,
                collection_method: ResourceCollectionMethod::ProcNet,
                state: ResourceState::Active,
                details: ResourceDetails::Listener {
                    protocol: "tcp".to_string(),
                    port: 3000,
                    bind_address: "0.0.0.0".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
        ];
        assert!(detect_listener_conflicts(&resources).is_empty());
    }

    #[test]
    fn detect_conflicts_shared_port() {
        let resources = vec![
            RawResourceEvidence {
                kind: ResourceKind::Listener,
                key: "tcp:0.0.0.0:8080".to_string(),
                owner_pid: 100,
                collection_method: ResourceCollectionMethod::ProcNet,
                state: ResourceState::Active,
                details: ResourceDetails::Listener {
                    protocol: "tcp".to_string(),
                    port: 8080,
                    bind_address: "0.0.0.0".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
            RawResourceEvidence {
                kind: ResourceKind::Listener,
                key: "tcp:0.0.0.0:8080".to_string(),
                owner_pid: 200,
                collection_method: ResourceCollectionMethod::ProcNet,
                state: ResourceState::Active,
                details: ResourceDetails::Listener {
                    protocol: "tcp".to_string(),
                    port: 8080,
                    bind_address: "0.0.0.0".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
        ];

        let conflicts = detect_listener_conflicts(&resources);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts
            .iter()
            .all(|c| c.state == ResourceState::Conflicted));
    }

    #[test]
    fn detect_conflicts_ignores_non_listeners() {
        let resources = vec![
            RawResourceEvidence {
                kind: ResourceKind::UnixSocket,
                key: "/tmp/app.sock".to_string(),
                owner_pid: 100,
                collection_method: ResourceCollectionMethod::ProcFd,
                state: ResourceState::Active,
                details: ResourceDetails::UnixSocket {
                    path: "/tmp/app.sock".to_string(),
                    socket_type: "stream".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
            RawResourceEvidence {
                kind: ResourceKind::UnixSocket,
                key: "/tmp/app.sock".to_string(),
                owner_pid: 200,
                collection_method: ResourceCollectionMethod::ProcFd,
                state: ResourceState::Active,
                details: ResourceDetails::UnixSocket {
                    path: "/tmp/app.sock".to_string(),
                    socket_type: "stream".to_string(),
                },
                observed_at: "2026-03-16T00:00:00Z".to_string(),
            },
        ];
        assert!(detect_listener_conflicts(&resources).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_listeners_for_self_does_not_panic() {
        let pid = std::process::id();
        let resources = collect_listener_resources(pid);
        assert!(resources.iter().all(|r| r.owner_pid == pid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_fd_ipc_for_self_does_not_panic() {
        let pid = std::process::id();
        let resources = collect_fd_ipc_resources(pid);
        assert!(resources.iter().all(|r| r.owner_pid == pid));
    }
}
