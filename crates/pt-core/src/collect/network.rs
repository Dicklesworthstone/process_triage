//! Network connection collection for process analysis.
//!
//! This module provides network connection information per process:
//! - TCP/UDP/Unix socket enumeration
//! - Connection states (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
//! - Local and remote addresses
//! - Per-process socket counts
//!
//! # Data Sources
//! - `/proc/[pid]/net/*` - Socket tables in the target's network namespace
//! - `/proc/[pid]/fd/` - Per-process socket mappings

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Identity of a network namespace, held open for the lifetime of its snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkNamespace {
    pub device: u64,
    pub inode: u64,
}

impl NetworkNamespace {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    pub fn resource_key(&self, resource: &str) -> String {
        format!("netns:{}:{}:{resource}", self.device, self.inode)
    }
}

/// Network connection information for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Namespace in which socket addresses were observed. Legacy serialized
    /// observations without this field cannot establish cross-process sharing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<NetworkNamespace>,
    /// Total socket count by protocol.
    pub socket_counts: SocketCounts,
    /// Active TCP connections.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tcp_connections: Vec<TcpConnection>,
    /// Active UDP sockets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub udp_sockets: Vec<UdpSocket>,
    /// Listening ports (TCP and UDP).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listen_ports: Vec<ListenPort>,
    /// Unix domain sockets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unix_sockets: Vec<UnixSocket>,
}

impl NetworkInfo {
    /// Total receive queue depth across all TCP connections (bytes).
    ///
    /// A large aggregate rx_queue signals that the process is not draining
    /// incoming data — a hallmark of stalled / useful-bad behaviour.
    pub fn total_rx_queue(&self) -> u64 {
        self.tcp_connections
            .iter()
            .map(|c| u64::from(c.rx_queue))
            .sum()
    }

    /// Total transmit queue depth across all TCP connections (bytes).
    pub fn total_tx_queue(&self) -> u64 {
        self.tcp_connections
            .iter()
            .map(|c| u64::from(c.tx_queue))
            .sum()
    }

    /// Whether any socket has a saturated queue (rx_queue > threshold bytes).
    pub fn has_saturated_queue(&self, threshold: u32) -> bool {
        self.tcp_connections
            .iter()
            .any(|c| c.rx_queue > threshold || c.tx_queue > threshold)
    }
}

#[derive(Debug, Default)]
struct NetworkTables {
    tcp_by_inode: HashMap<u64, TcpConnection>,
    udp_by_inode: HashMap<u64, UdpSocket>,
    unix_by_inode: HashMap<u64, UnixSocket>,
    other_inodes: HashSet<u64>,
}

type ObservedNetworkTables = Result<Arc<NetworkTables>, (std::io::ErrorKind, String)>;

#[derive(Debug)]
struct NamespaceTables {
    _namespace: fs::File,
    tables: OnceLock<ObservedNetworkTables>,
}

/// Scan-scoped socket tables, indexed by network namespace and socket inode.
///
/// Tables are read lazily from `/proc/PID/net` once per observed namespace.
/// Holding namespace handles prevents inode reuse while the snapshot is alive.
/// Construct a fresh snapshot for each scan and before action-time validation.
#[derive(Debug)]
pub struct NetworkSnapshot {
    proc_root: PathBuf,
    namespaces: Mutex<HashMap<NetworkNamespace, Arc<NamespaceTables>>>,
}

impl Default for NetworkSnapshot {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            namespaces: Mutex::new(HashMap::new()),
        }
    }
}

impl NetworkSnapshot {
    /// Start a scan-scoped snapshot. Each namespace is collected on first use.
    pub fn collect() -> Self {
        Self::default()
    }

    /// Get complete network evidence, retaining diagnostics for inaccessible,
    /// truncated, unclassified or changing observations.
    pub fn get_process_info_checked(&self, pid: u32) -> std::io::Result<NetworkInfo> {
        let process_dir = self.proc_root.join(pid.to_string());
        let before = read_network_process_identity(&process_dir, pid)?;
        let namespace_handle = fs::File::open(process_dir.join("ns/net"))?;
        let namespace = NetworkNamespace::from_metadata(&namespace_handle.metadata()?);
        let socket_inodes = get_process_socket_inodes_from(&process_dir.join("fd"), 50_000)?;
        let mut info = NetworkInfo {
            namespace: Some(namespace),
            ..NetworkInfo::default()
        };

        if !socket_inodes.is_empty() {
            let tables = self.tables_for(&process_dir, namespace, namespace_handle)?;
            info = tables.process_info(&socket_inodes, namespace)?;
        }

        revalidate_network_observation(&process_dir, pid, namespace, before, &socket_inodes)?;
        Ok(info)
    }

    /// Get complete evidence, or `None` when its coverage cannot be established.
    pub fn get_process_info(&self, pid: u32) -> Option<NetworkInfo> {
        self.get_process_info_checked(pid).ok()
    }

    fn tables_for(
        &self,
        process_dir: &Path,
        namespace: NetworkNamespace,
        handle: fs::File,
    ) -> std::io::Result<Arc<NetworkTables>> {
        check_network_namespace(process_dir, namespace)?;
        let entry = {
            let mut namespaces = self
                .namespaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(namespaces.entry(namespace).or_insert_with(|| {
                Arc::new(NamespaceTables {
                    _namespace: handle,
                    tables: OnceLock::new(),
                })
            }))
        };
        // Serialize only readers of the same namespace. Different containers
        // can collect in parallel; a shared namespace is still parsed once.
        let observed = entry.tables.get_or_init(|| {
            let result = NetworkTables::read_from(&process_dir.join("net")).and_then(|tables| {
                check_network_namespace(process_dir, namespace)?;
                Ok(Arc::new(tables))
            });
            result.map_err(|error| (error.kind(), error.to_string()))
        });
        match observed {
            Ok(tables) => Ok(Arc::clone(tables)),
            Err((kind, reason)) => Err(std::io::Error::new(*kind, reason.clone())),
        }
    }
}

fn invalid_network(reason: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, reason)
}

fn read_network_process_identity(
    process_dir: &Path,
    pid: u32,
) -> std::io::Result<(u64, u64, u64, u32)> {
    let directory = fs::metadata(process_dir)?;
    let content = fs::read_to_string(process_dir.join("stat"))?;
    let stat = super::proc_parsers::parse_required_proc_stat_content(pid, &content)
        .map_err(|error| invalid_network(&error.to_string()))?;
    Ok((
        directory.dev(),
        directory.ino(),
        stat.starttime,
        directory.uid(),
    ))
}

fn check_network_namespace(process_dir: &Path, expected: NetworkNamespace) -> std::io::Result<()> {
    let observed = NetworkNamespace::from_metadata(&fs::metadata(process_dir.join("ns/net"))?);
    if observed != expected {
        return Err(invalid_network(
            "network namespace changed during collection",
        ));
    }
    Ok(())
}

fn revalidate_network_observation(
    process_dir: &Path,
    pid: u32,
    namespace: NetworkNamespace,
    identity: (u64, u64, u64, u32),
    sockets: &HashSet<u64>,
) -> std::io::Result<()> {
    // Neither a namespace switch nor PID reuse may join evidence from two
    // processes. FD churn also makes a negative socket observation unsafe.
    let observed_sockets = get_process_socket_inodes_from(&process_dir.join("fd"), 50_000)?;
    check_network_namespace(process_dir, namespace)?;
    if read_network_process_identity(process_dir, pid)? != identity || &observed_sockets != sockets
    {
        return Err(invalid_network(
            "process or socket descriptors changed during collection",
        ));
    }
    Ok(())
}

fn read_optional_socket_table(path: &Path) -> std::io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        // Protocol modules (notably IPv6) may be absent. This never proves
        // absence: every descriptor must still resolve through another table.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        )),
    }
}

impl NetworkTables {
    fn read_from(net_dir: &Path) -> std::io::Result<Self> {
        let mut tables = Self::default();
        for (name, ipv6, tcp) in [
            ("tcp", false, true),
            ("tcp6", true, true),
            ("udp", false, false),
            ("udp6", true, false),
        ] {
            let Some(content) = read_optional_socket_table(&net_dir.join(name))? else {
                continue;
            };
            validate_inet_table(&content, ipv6)?;
            if tcp {
                for connection in parse_proc_net_tcp_reader(content.as_bytes(), ipv6) {
                    tables.tcp_by_inode.insert(connection.inode, connection);
                }
            } else {
                for socket in parse_proc_net_udp_reader(content.as_bytes(), ipv6) {
                    tables.udp_by_inode.insert(socket.inode, socket);
                }
            }
        }
        if let Some(content) = read_optional_socket_table(&net_dir.join("unix"))? {
            for socket in parse_proc_net_unix_reader(content.as_bytes())? {
                tables.unix_by_inode.insert(socket.inode, socket);
            }
        }
        for (name, ipv6) in [
            ("raw", false),
            ("raw6", true),
            ("udplite", false),
            ("udplite6", true),
        ] {
            if let Some(content) = read_optional_socket_table(&net_dir.join(name))? {
                validate_inet_table(&content, ipv6)?;
                tables
                    .other_inodes
                    .extend(inet_table_inodes(content.as_bytes())?);
            }
        }
        for name in ["netlink", "packet"] {
            if let Some(content) = read_optional_socket_table(&net_dir.join(name))? {
                tables.other_inodes.extend(named_inode_table(&content)?);
            }
        }
        let mut observed = HashSet::new();
        for &inode in tables
            .tcp_by_inode
            .keys()
            .chain(tables.udp_by_inode.keys())
            .chain(tables.unix_by_inode.keys())
            .chain(tables.other_inodes.iter())
        {
            if inode != 0 && !observed.insert(inode) {
                return Err(invalid_network(
                    "socket inode appears in multiple protocol tables",
                ));
            }
        }
        Ok(tables)
    }

    fn process_info(
        &self,
        socket_inodes: &HashSet<u64>,
        namespace: NetworkNamespace,
    ) -> std::io::Result<NetworkInfo> {
        let mut info = NetworkInfo {
            namespace: Some(namespace),
            ..NetworkInfo::default()
        };

        for &inode in socket_inodes {
            // Check TCP
            if let Some(conn) = self.tcp_by_inode.get(&inode) {
                if conn.is_ipv6 {
                    info.socket_counts.tcp6 += 1;
                    if conn.state.is_listen() {
                        info.listen_ports.push(ListenPort {
                            protocol: "tcp6".to_string(),
                            port: conn.local_port,
                            address: conn.local_addr.clone(),
                            inode,
                        });
                    }
                } else {
                    info.socket_counts.tcp += 1;
                    if conn.state.is_listen() {
                        info.listen_ports.push(ListenPort {
                            protocol: "tcp".to_string(),
                            port: conn.local_port,
                            address: conn.local_addr.clone(),
                            inode,
                        });
                    }
                }
                info.tcp_connections.push(conn.clone());
                continue;
            }

            // Check UDP
            if let Some(sock) = self.udp_by_inode.get(&inode) {
                if sock.is_ipv6 {
                    info.socket_counts.udp6 += 1;
                    if sock.local_port != 0 && sock.remote_port == 0 {
                        info.listen_ports.push(ListenPort {
                            protocol: "udp6".to_string(),
                            port: sock.local_port,
                            address: sock.local_addr.clone(),
                            inode,
                        });
                    }
                } else {
                    info.socket_counts.udp += 1;
                    if sock.local_port != 0 && sock.remote_port == 0 {
                        info.listen_ports.push(ListenPort {
                            protocol: "udp".to_string(),
                            port: sock.local_port,
                            address: sock.local_addr.clone(),
                            inode,
                        });
                    }
                }
                info.udp_sockets.push(sock.clone());
                continue;
            }

            // Check Unix
            if let Some(sock) = self.unix_by_inode.get(&inode) {
                info.socket_counts.unix += 1;
                info.unix_sockets.push(sock.clone());
                continue;
            }
            if self.other_inodes.contains(&inode) {
                info.socket_counts.raw += 1;
                continue;
            }
            return Err(invalid_network(&format!(
                "socket inode {inode} is absent from the namespace snapshot; its protocol, namespace or creation time is unknown"
            )));
        }

        info.tcp_connections.sort_by_key(|socket| socket.inode);
        info.udp_sockets.sort_by_key(|socket| socket.inode);
        info.unix_sockets.sort_by_key(|socket| socket.inode);
        info.listen_ports.sort_by_key(|socket| socket.inode);
        Ok(info)
    }
}

/// Socket counts by protocol type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SocketCounts {
    /// TCP socket count.
    pub tcp: usize,
    /// TCP6 socket count.
    pub tcp6: usize,
    /// UDP socket count.
    pub udp: usize,
    /// UDP6 socket count.
    pub udp6: usize,
    /// Unix domain socket count.
    pub unix: usize,
    /// Other observed kernel sockets (raw IP, UDP-Lite, netlink and packet).
    pub raw: usize,
}

/// TCP connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnection {
    /// Local address.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address.
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// Connection state.
    pub state: TcpState,
    /// Socket inode number.
    pub inode: u64,
    /// IPv6 connection.
    pub is_ipv6: bool,
    /// Transmit queue size (bytes pending in kernel send buffer).
    #[serde(default)]
    pub tx_queue: u32,
    /// Receive queue size (bytes pending in kernel receive buffer).
    #[serde(default)]
    pub rx_queue: u32,
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl TcpState {
    /// Parse TCP state from /proc/net/tcp hex value.
    pub fn from_hex(hex: u8) -> Self {
        match hex {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x03 => TcpState::SynRecv,
            0x04 => TcpState::FinWait1,
            0x05 => TcpState::FinWait2,
            0x06 => TcpState::TimeWait,
            0x07 => TcpState::Close,
            0x08 => TcpState::CloseWait,
            0x09 => TcpState::LastAck,
            0x0A => TcpState::Listen,
            0x0B => TcpState::Closing,
            _ => TcpState::Unknown,
        }
    }

    /// Whether this state represents an active connection.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::SynSent | TcpState::SynRecv
        )
    }

    /// Whether this state is a listening socket.
    pub fn is_listen(&self) -> bool {
        matches!(self, TcpState::Listen)
    }
}

/// UDP socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSocket {
    /// Local address.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address (often 0.0.0.0:0 for unconnected).
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// Socket inode number.
    pub inode: u64,
    /// IPv6 socket.
    pub is_ipv6: bool,
}

/// Listening port information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenPort {
    /// Protocol (tcp, tcp6, udp, udp6).
    pub protocol: String,
    /// Port number.
    pub port: u16,
    /// Bind address.
    pub address: String,
    /// Socket inode.
    pub inode: u64,
}

/// Unix domain socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocket {
    /// Socket path (if bound).
    pub path: Option<String>,
    /// Socket type (stream, dgram, seqpacket).
    pub socket_type: UnixSocketType,
    /// Socket state.
    pub state: UnixSocketState,
    /// Socket inode number.
    pub inode: u64,
    /// Kernel reference count reported by `/proc/net/unix`.
    #[serde(default)]
    pub ref_count: u32,
}

/// Unix socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketType {
    Stream,
    Dgram,
    SeqPacket,
    Unknown,
}

impl UnixSocketType {
    /// Parse from /proc/net/unix type field.
    pub fn from_type(t: u16) -> Self {
        match t {
            1 => UnixSocketType::Stream,
            2 => UnixSocketType::Dgram,
            5 => UnixSocketType::SeqPacket,
            _ => UnixSocketType::Unknown,
        }
    }
}

/// Unix socket state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketState {
    Free,
    Unconnected,
    Connecting,
    Connected,
    Disconnecting,
    Unknown,
}

impl UnixSocketState {
    /// Parse from /proc/net/unix state field.
    pub fn from_state(s: u8) -> Self {
        match s {
            0 => UnixSocketState::Free,
            1 => UnixSocketState::Unconnected,
            2 => UnixSocketState::Connecting,
            3 => UnixSocketState::Connected,
            4 => UnixSocketState::Disconnecting,
            _ => UnixSocketState::Unknown,
        }
    }
}

/// Collect network information for a specific process.
///
/// This function reads /proc/\[pid\]/fd to find socket inodes, then
/// looks them up in the target's /proc/[pid]/net tables.
///
/// Note: For bulk collection, use `NetworkSnapshot::collect()` and `get_process_info`
/// to avoid reading /proc/net/* files repeatedly.
pub fn collect_network_info(pid: u32) -> Option<NetworkInfo> {
    let snapshot = NetworkSnapshot::collect();
    snapshot.get_process_info(pid)
}

/// Read the complete descriptor directory. An inspection budget or failed
/// read is unavailable evidence, never a complete empty socket inventory.
fn get_process_socket_inodes_from(
    fd_path: &Path,
    max_inspect: usize,
) -> std::io::Result<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for (inspected_count, entry) in fs::read_dir(fd_path)?.enumerate() {
        if inspected_count >= max_inspect {
            return Err(invalid_network("descriptor inspection limit exceeded"));
        }
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            return Err(invalid_network("invalid descriptor directory entry"));
        }
        let target = fs::read_link(entry.path())?;
        let target = target.to_string_lossy();
        if let Some(inode) = target.strip_prefix("socket:") {
            let inode = inode
                .strip_prefix('[')
                .and_then(|inode| inode.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u64>().ok())
                .filter(|inode| *inode != 0)
                .ok_or_else(|| invalid_network("invalid socket descriptor link"))?;
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

/// Parse /proc/net/tcp or /proc/net/tcp6 file.
pub fn parse_proc_net_tcp(path: &str, is_ipv6: bool) -> Option<Vec<TcpConnection>> {
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    Some(parse_proc_net_tcp_reader(reader, is_ipv6))
}

/// Parse TCP content from a reader.
pub fn parse_proc_net_tcp_reader<R: BufRead>(reader: R, is_ipv6: bool) -> Vec<TcpConnection> {
    let mut connections = Vec::new();

    // Skip header line using skip(1), flatten() to ignore I/O errors on individual lines
    for line in reader.lines().skip(1).flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
        let local = parts[1];
        let remote = parts[2];
        let state_hex = parts[3];
        let queue_str = parts[4]; // tx_queue:rx_queue
        let inode_str = parts[9];

        let (local_addr, local_port) = parse_addr_port(local, is_ipv6);
        let (remote_addr, remote_port) = parse_addr_port(remote, is_ipv6);
        let state = u8::from_str_radix(state_hex, 16)
            .map(TcpState::from_hex)
            .unwrap_or(TcpState::Unknown);
        let inode = inode_str.parse().unwrap_or(0);

        let (tx_queue, rx_queue) = parse_queue_sizes(queue_str);

        connections.push(TcpConnection {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            inode,
            is_ipv6,
            tx_queue,
            rx_queue,
        });
    }

    connections
}

/// Parse TCP content (for testing).
#[cfg(test)]
pub fn parse_proc_net_tcp_content(content: &str, is_ipv6: bool) -> Vec<TcpConnection> {
    parse_proc_net_tcp_reader(content.as_bytes(), is_ipv6)
}

/// Parse /proc/net/udp or /proc/net/udp6 file.
pub fn parse_proc_net_udp(path: &str, is_ipv6: bool) -> Option<Vec<UdpSocket>> {
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    Some(parse_proc_net_udp_reader(reader, is_ipv6))
}

/// Parse UDP content from a reader.
pub fn parse_proc_net_udp_reader<R: BufRead>(reader: R, is_ipv6: bool) -> Vec<UdpSocket> {
    let mut sockets = Vec::new();

    for line in reader.lines().skip(1).flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode_str = parts[9];

        let (local_addr, local_port) = parse_addr_port(local, is_ipv6);
        let (remote_addr, remote_port) = parse_addr_port(remote, is_ipv6);
        let inode = inode_str.parse().unwrap_or(0);

        sockets.push(UdpSocket {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            inode,
            is_ipv6,
        });
    }

    sockets
}

/// Parse UDP content (for testing).
#[cfg(test)]
pub fn parse_proc_net_udp_content(content: &str, is_ipv6: bool) -> Vec<UdpSocket> {
    parse_proc_net_udp_reader(content.as_bytes(), is_ipv6)
}

/// Parse /proc/net/unix file.
pub fn parse_proc_net_unix(path: &str) -> std::io::Result<Vec<UnixSocket>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    parse_proc_net_unix_reader(reader)
}

/// Parse Unix socket content from a reader.
pub fn parse_proc_net_unix_reader<R: BufRead>(reader: R) -> std::io::Result<Vec<UnixSocket>> {
    let mut sockets = Vec::new();
    let invalid = |reason: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, reason);
    let mut lines = reader.lines();
    let header = lines
        .next()
        .ok_or_else(|| invalid("missing UNIX socket table header"))??;
    if !header.split_whitespace().eq([
        "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
    ]) {
        return Err(invalid("invalid UNIX socket table header"));
    }
    let mut inodes = HashSet::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut remaining = line.as_str();
        let mut parts = Vec::with_capacity(7);
        for _ in 0..7 {
            remaining = remaining.trim_start();
            if remaining.is_empty() {
                return Err(invalid("truncated UNIX socket table row"));
            }
            let end = remaining
                .find(char::is_whitespace)
                .unwrap_or(remaining.len());
            parts.push(&remaining[..end]);
            remaining = &remaining[end..];
        }

        // Format: Num RefCount Protocol Flags Type St Inode Path
        let slot = parts[0]
            .strip_suffix(':')
            .ok_or_else(|| invalid("invalid UNIX socket slot"))?;
        u64::from_str_radix(slot, 16).map_err(|_| invalid("invalid UNIX socket slot"))?;
        let ref_count =
            u32::from_str_radix(parts[1], 16).map_err(|_| invalid("invalid UNIX refcount"))?;
        for field in &parts[2..4] {
            u32::from_str_radix(field, 16)
                .map_err(|_| invalid("invalid UNIX protocol or flags"))?;
        }
        let socket_type = UnixSocketType::from_type(
            u16::from_str_radix(parts[4], 16).map_err(|_| invalid("invalid UNIX socket type"))?,
        );
        let state = UnixSocketState::from_state(
            u8::from_str_radix(parts[5], 16).map_err(|_| invalid("invalid UNIX socket state"))?,
        );
        let inode = parts[6]
            .parse()
            .map_err(|_| invalid("invalid UNIX socket inode"))?;
        if !inodes.insert(inode) {
            return Err(invalid("duplicate UNIX socket inode"));
        }
        let path = if remaining.trim_start().is_empty() {
            None
        } else {
            Some(remaining.trim_start().to_string())
        };

        sockets.push(UnixSocket {
            path,
            socket_type,
            state,
            inode,
            ref_count,
        });
    }

    Ok(sockets)
}

/// Parse Unix socket content (for testing).
#[cfg(test)]
pub fn parse_proc_net_unix_content(content: &str) -> std::io::Result<Vec<UnixSocket>> {
    parse_proc_net_unix_reader(content.as_bytes())
}

/// Prove that an otherwise unclassified descriptor inode belongs to TCP/UDP.
/// A missing or malformed table never establishes absence.
#[cfg(target_os = "linux")]
pub(crate) fn has_inet_socket_inode(pid: u32, inode: u64) -> std::io::Result<bool> {
    for protocol in ["tcp", "udp", "tcp6", "udp6"] {
        let path = format!("/proc/{pid}/net/{protocol}");
        let contextual = |source: std::io::Error| {
            std::io::Error::new(source.kind(), format!("{path}: {source}"))
        };
        let file = fs::File::open(&path).map_err(contextual)?;
        if inet_table_has_inode(BufReader::new(file), inode).map_err(contextual)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(target_os = "linux", test))]
fn inet_table_has_inode<R: BufRead>(reader: R, inode: u64) -> std::io::Result<bool> {
    Ok(inet_table_inodes_until(reader, Some(inode))?.contains(&inode))
}

fn inet_table_inodes<R: BufRead>(reader: R) -> std::io::Result<HashSet<u64>> {
    inet_table_inodes_until(reader, None)
}

fn inet_table_inodes_until<R: BufRead>(
    reader: R,
    required_inode: Option<u64>,
) -> std::io::Result<HashSet<u64>> {
    let invalid = |reason: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, reason);
    let mut inodes = HashSet::new();
    let mut lines = reader.lines();
    let header = lines
        .next()
        .ok_or_else(|| invalid("missing TCP/UDP table header"))??;
    let fields: Vec<_> = header.split_whitespace().collect();
    if fields.first() != Some(&"sl")
        || !fields.contains(&"local_address")
        || !(fields.contains(&"rem_address") || fields.contains(&"remote_address"))
        || !fields.contains(&"inode")
    {
        return Err(invalid("invalid TCP/UDP table header"));
    }
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(invalid("truncated TCP/UDP socket row"));
        }
        let address = |value: &str| {
            value.split_once(':').is_some_and(|(host, port)| {
                matches!(host.len(), 8 | 32)
                    && port.len() == 4
                    && host
                        .bytes()
                        .chain(port.bytes())
                        .all(|byte| byte.is_ascii_hexdigit())
            })
        };
        let hex_pair = |value: &str| {
            value.split_once(':').is_some_and(|(left, right)| {
                u64::from_str_radix(left, 16).is_ok() && u64::from_str_radix(right, 16).is_ok()
            })
        };
        if fields[0]
            .strip_suffix(':')
            .and_then(|slot| slot.parse::<u64>().ok())
            .is_none()
            || !address(fields[1])
            || !address(fields[2])
            || u8::from_str_radix(fields[3], 16).is_err()
            || !hex_pair(fields[4])
            || !hex_pair(fields[5])
            || u64::from_str_radix(fields[6], 16).is_err()
            || fields[7].parse::<u64>().is_err()
            || fields[8].parse::<u64>().is_err()
        {
            return Err(invalid("invalid TCP/UDP socket row"));
        }
        let observed: u64 = fields
            .get(9)
            .and_then(|inode| inode.parse().ok())
            .ok_or_else(|| invalid("invalid TCP/UDP socket inode row"))?;
        // TIME_WAIT rows can carry inode zero; they have no owning descriptor.
        if observed != 0 && !inodes.insert(observed) {
            return Err(invalid("duplicate TCP/UDP socket inode"));
        }
        // Supervision only needs positive proof of this inode's protocol.
        // Whole-snapshot validation passes None and always reads every row.
        if required_inode == Some(observed) {
            return Ok(inodes);
        }
    }
    Ok(inodes)
}

fn validate_inet_table(content: &str, ipv6: bool) -> std::io::Result<()> {
    inet_table_inodes(content.as_bytes())?;
    let address_len = if ipv6 { 32 } else { 8 };
    for line in content
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if ![fields[1], fields[2]].iter().all(|address| {
            address
                .split_once(':')
                .is_some_and(|(host, _)| host.len() == address_len)
        }) || !fields[4].split_once(':').is_some_and(|(tx, rx)| {
            u32::from_str_radix(tx, 16).is_ok() && u32::from_str_radix(rx, 16).is_ok()
        }) {
            return Err(invalid_network(
                "invalid address width or queue size in socket table",
            ));
        }
    }
    Ok(())
}

fn named_inode_table(content: &str) -> std::io::Result<HashSet<u64>> {
    let mut lines = content.lines();
    let header: Vec<_> = lines
        .next()
        .ok_or_else(|| invalid_network("missing socket table header"))?
        .split_whitespace()
        .collect();
    let inode_column = header
        .iter()
        .position(|column| column.eq_ignore_ascii_case("inode"))
        .ok_or_else(|| invalid_network("missing socket inode column"))?;
    let mut inodes = HashSet::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != header.len() {
            return Err(invalid_network("truncated kernel socket table row"));
        }
        let inode = fields[inode_column]
            .parse::<u64>()
            .map_err(|_| invalid_network("invalid kernel socket inode"))?;
        if inode != 0 && !inodes.insert(inode) {
            return Err(invalid_network("duplicate kernel socket inode"));
        }
    }
    Ok(inodes)
}

/// Parse tx_queue:rx_queue field from /proc/net/tcp format (hex encoded).
fn parse_queue_sizes(queue_field: &str) -> (u32, u32) {
    let parts: Vec<&str> = queue_field.split(':').collect();
    if parts.len() != 2 {
        return (0, 0);
    }
    let tx = u32::from_str_radix(parts[0], 16).unwrap_or(0);
    let rx = u32::from_str_radix(parts[1], 16).unwrap_or(0);
    (tx, rx)
}

/// Parse address:port from /proc/net format (hex encoded).
fn parse_addr_port(addr_port: &str, is_ipv6: bool) -> (String, u16) {
    let parts: Vec<&str> = addr_port.split(':').collect();
    if parts.len() != 2 {
        return ("".to_string(), 0);
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

    let addr = if is_ipv6 {
        parse_ipv6_addr(addr_hex)
    } else {
        parse_ipv4_addr(addr_hex)
    };

    (addr, port)
}

/// Parse IPv4 address from hex (little-endian).
fn parse_ipv4_addr(hex: &str) -> String {
    if hex.len() != 8 {
        return "0.0.0.0".to_string();
    }

    // /proc/net stores IPv4 in little-endian hex
    let bytes: Vec<u8> = (0..4)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();

    if bytes.len() != 4 {
        return "0.0.0.0".to_string();
    }

    // Reverse for little-endian
    Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]).to_string()
}

/// Parse IPv6 address from hex.
fn parse_ipv6_addr(hex: &str) -> String {
    if hex.len() != 32 {
        return "::".to_string();
    }

    // IPv6 is stored as 4 32-bit words in little-endian
    let mut segments = [0u16; 8];
    for i in 0..4 {
        let word_hex = &hex[i * 8..(i + 1) * 8];
        // Each 32-bit word is little-endian
        if let Ok(word) = u32::from_str_radix(word_hex, 16) {
            let word = word.swap_bytes(); // Convert from little-endian
            segments[i * 2] = (word >> 16) as u16;
            segments[i * 2 + 1] = (word & 0xFFFF) as u16;
        }
    }

    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INET_HEADER: &str = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    const UNIX_HEADER: &str = "Num RefCount Protocol Flags Type St Inode Path\n";

    fn fixture_process(root: &Path, pid: u32, namespace: &Path, inode: u64, port: u16) -> PathBuf {
        let dir = root.join(pid.to_string());
        for child in ["fd", "net", "ns"] {
            fs::create_dir_all(dir.join(child)).unwrap();
        }
        fs::hard_link(namespace, dir.join("ns/net")).unwrap();
        fs::write(
            dir.join("stat"),
            format!(
                "{pid} (fixture) S 1 {pid} {pid} 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 4096 1\n"
            ),
        )
        .unwrap();
        fs::write(dir.join("net/unix"), UNIX_HEADER).unwrap();
        fs::write(
            dir.join("net/tcp"),
            format!("{INET_HEADER}0: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {inode}\n"),
        ).unwrap();
        std::os::unix::fs::symlink(format!("socket:[{inode}]"), dir.join("fd/3")).unwrap();
        dir
    }

    #[test]
    fn snapshot_isolates_namespaces_and_reuses_each_observed_table() {
        let root = tempfile::tempdir().unwrap();
        let first_namespace = root.path().join("namespace-a");
        let second_namespace = root.path().join("namespace-b");
        fs::write(&first_namespace, "a").unwrap();
        fs::write(&second_namespace, "b").unwrap();
        fixture_process(root.path(), 100, &first_namespace, 42, 8080);
        fixture_process(root.path(), 200, &second_namespace, 42, 9090);
        let sibling = fixture_process(root.path(), 101, &first_namespace, 42, 8080);
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };

        let first = snapshot.get_process_info_checked(100).unwrap();
        let second = snapshot.get_process_info_checked(200).unwrap();
        assert_eq!(first.listen_ports[0].port, 8080);
        assert_eq!(second.listen_ports[0].port, 9090);
        assert_ne!(first.namespace, second.namespace);
        // A later candidate in the same namespace must not parse its table
        // again. Its live descriptor and namespace identity are still checked.
        fs::write(sibling.join("net/tcp"), "must not be read again").unwrap();
        let same_namespace = snapshot.get_process_info_checked(101).unwrap();
        assert_eq!(same_namespace.namespace, first.namespace);
        assert_eq!(same_namespace.listen_ports[0].port, 8080);
        assert_eq!(snapshot.namespaces.lock().unwrap().len(), 2);
    }

    #[test]
    fn absent_unclassified_and_changed_socket_evidence_stays_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let namespace = root.path().join("namespace");
        fs::write(&namespace, "namespace").unwrap();
        let dir = fixture_process(root.path(), 100, &namespace, 42, 8080);
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };
        assert_eq!(
            snapshot
                .get_process_info_checked(100)
                .unwrap()
                .listen_ports
                .len(),
            1
        );

        // A newly created or foreign inherited socket cannot be resolved in the
        // scan's namespace snapshot. It must not lower the impact estimate.
        std::os::unix::fs::symlink("socket:[43]", dir.join("fd/4")).unwrap();
        let error = snapshot.get_process_info_checked(100).unwrap_err();
        assert!(error.to_string().contains("socket inode 43"));
        assert!(snapshot.get_process_info(100).is_none());
        assert!(snapshot.get_process_info(999).is_none());

        let second_namespace = root.path().join("namespace-b");
        fs::write(&second_namespace, "other").unwrap();
        let observed = NetworkNamespace::from_metadata(&fs::metadata(&namespace).unwrap());
        assert!(snapshot
            .tables_for(
                &dir,
                NetworkNamespace::from_metadata(&fs::metadata(&second_namespace).unwrap()),
                fs::File::open(&second_namespace).unwrap(),
            )
            .is_err());
        assert!(check_network_namespace(&dir, observed).is_ok());
    }

    #[test]
    fn descriptor_failures_and_inspection_limits_are_not_empty_observations() {
        let root = tempfile::tempdir().unwrap();
        assert!(get_process_socket_inodes_from(root.path(), 1)
            .unwrap()
            .is_empty());
        std::os::unix::fs::symlink("/dev/null", root.path().join("0")).unwrap();
        assert!(get_process_socket_inodes_from(root.path(), 1)
            .unwrap()
            .is_empty());
        std::os::unix::fs::symlink("socket:[42]", root.path().join("3")).unwrap();
        assert!(get_process_socket_inodes_from(root.path(), 1).is_err());
        assert_eq!(
            get_process_socket_inodes_from(root.path(), 2).unwrap(),
            HashSet::from([42])
        );
        fs::write(root.path().join("4"), "not a readable descriptor link").unwrap();
        assert!(get_process_socket_inodes_from(root.path(), 10).is_err());

        let malformed = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("socket:[invalid]", malformed.path().join("0")).unwrap();
        assert!(get_process_socket_inodes_from(malformed.path(), 10).is_err());
    }

    #[test]
    fn known_other_protocols_are_counted_without_inventing_listeners() {
        let root = tempfile::tempdir().unwrap();
        let namespace = root.path().join("namespace");
        fs::write(&namespace, "namespace").unwrap();
        let dir = fixture_process(root.path(), 100, &namespace, 42, 8080);
        std::os::unix::fs::symlink("socket:[43]", dir.join("fd/4")).unwrap();
        fs::write(
            dir.join("net/netlink"),
            "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0 0 100 00000000 0 0 0 2 0 43\n",
        )
        .unwrap();
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };
        let info = snapshot.get_process_info_checked(100).unwrap();
        assert_eq!(info.socket_counts.raw, 1);
        assert_eq!(info.socket_counts.tcp, 1);
        assert_eq!(info.listen_ports.len(), 1);
    }

    #[test]
    fn malformed_tables_never_authorize_partial_network_evidence() {
        let root = tempfile::tempdir().unwrap();
        let namespace = root.path().join("namespace");
        fs::write(&namespace, "namespace").unwrap();
        let dir = fixture_process(root.path(), 100, &namespace, 42, 8080);
        let tcp = fs::read_to_string(dir.join("net/tcp")).unwrap();
        fs::write(dir.join("net/tcp"), format!("{tcp}truncated\n")).unwrap();
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };
        assert!(snapshot.get_process_info_checked(100).is_err());
        assert!(validate_inet_table(&format!("{tcp}truncated\n"), false).is_err());
        assert!(named_inode_table("Inode\n42\ninvalid\n").is_err());
    }

    #[test]
    fn empty_descriptor_inventory_is_observed_even_without_protocol_tables() {
        let root = tempfile::tempdir().unwrap();
        let process = root.path().join("100");
        fs::create_dir_all(process.join("fd")).unwrap();
        fs::create_dir_all(process.join("ns")).unwrap();
        fs::write(process.join("ns/net"), "namespace").unwrap();
        fs::write(
            process.join("stat"),
            "100 (fixture) S 1 100 100 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 4096 1\n",
        )
        .unwrap();
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };
        let info = snapshot.get_process_info_checked(100).unwrap();
        assert!(info.namespace.is_some());
        assert!(info.listen_ports.is_empty());
        assert!(snapshot.namespaces.lock().unwrap().is_empty());
    }

    #[test]
    fn final_observation_refuses_pid_reuse_and_incomplete_birth_identity() {
        let root = tempfile::tempdir().unwrap();
        let namespace_path = root.path().join("namespace");
        fs::write(&namespace_path, "namespace").unwrap();
        let dir = fixture_process(root.path(), 100, &namespace_path, 42, 8080);
        let namespace = NetworkNamespace::from_metadata(&fs::metadata(&namespace_path).unwrap());
        let identity = read_network_process_identity(&dir, 100).unwrap();
        let sockets = HashSet::from([42]);
        revalidate_network_observation(&dir, 100, namespace, identity, &sockets).unwrap();
        let stat = fs::read_to_string(dir.join("stat")).unwrap();
        fs::write(dir.join("stat"), stat.replace("12345", "23456")).unwrap();
        assert!(revalidate_network_observation(&dir, 100, namespace, identity, &sockets).is_err());
        fs::write(dir.join("stat"), "100 (fixture) S 1\n").unwrap();
        assert!(read_network_process_identity(&dir, 100).is_err());
        let snapshot = NetworkSnapshot {
            proc_root: root.path().to_path_buf(),
            ..NetworkSnapshot::default()
        };
        assert!(snapshot.get_process_info_checked(100).is_err());
    }

    #[test]
    fn test_tcp_state_from_hex() {
        assert_eq!(TcpState::from_hex(0x01), TcpState::Established);
        assert_eq!(TcpState::from_hex(0x0A), TcpState::Listen);
        assert_eq!(TcpState::from_hex(0x06), TcpState::TimeWait);
        assert_eq!(TcpState::from_hex(0xFF), TcpState::Unknown);
    }

    #[test]
    fn test_tcp_state_is_active() {
        assert!(TcpState::Established.is_active());
        assert!(!TcpState::Listen.is_active());
        assert!(!TcpState::TimeWait.is_active());
    }

    #[test]
    fn test_parse_ipv4_addr() {
        // 127.0.0.1 in little-endian hex is 0100007F
        assert_eq!(parse_ipv4_addr("0100007F"), "127.0.0.1");
        // 0.0.0.0 is 00000000
        assert_eq!(parse_ipv4_addr("00000000"), "0.0.0.0");
        // 192.168.1.1 is 0101A8C0 (little-endian)
        assert_eq!(parse_ipv4_addr("0101A8C0"), "192.168.1.1");
    }

    #[test]
    fn test_parse_ipv6_addr() {
        // ::1 (localhost)
        // Words (32-bit): 00000000 00000000 00000000 01000000 (each word LE)
        assert_eq!(parse_ipv6_addr("00000000000000000000000001000000"), "::1");

        // :: (unspecified)
        assert_eq!(parse_ipv6_addr("00000000000000000000000000000000"), "::");
    }

    #[test]
    fn test_parse_addr_port() {
        let (addr, port) = parse_addr_port("0100007F:0035", false);
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 53);

        let (addr, port) = parse_addr_port("00000000:1F90", false);
        assert_eq!(addr, "0.0.0.0");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_proc_net_tcp_content() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 0 0 10 -1
"#;

        let connections = parse_proc_net_tcp_content(content, false);
        assert_eq!(connections.len(), 2);

        // First entry: listening on 127.0.0.1:53
        assert_eq!(connections[0].local_addr, "127.0.0.1");
        assert_eq!(connections[0].local_port, 53);
        assert_eq!(connections[0].state, TcpState::Listen);
        assert_eq!(connections[0].inode, 12345);
        assert_eq!(connections[0].tx_queue, 0);
        assert_eq!(connections[0].rx_queue, 0);

        // Second entry: established connection
        assert_eq!(connections[1].local_addr, "127.0.0.1");
        assert_eq!(connections[1].local_port, 3306);
        assert_eq!(connections[1].state, TcpState::Established);
        assert_eq!(connections[1].inode, 67890);
        assert_eq!(connections[1].tx_queue, 0);
        assert_eq!(connections[1].rx_queue, 0);
    }

    #[test]
    fn test_parse_proc_net_tcp_content_preserves_queue_depth() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0200007F:1770 01 00000010:00000020 00:00000000 00000000  1000        0 99999 1 0000000000000000 20 0 0 10 -1
"#;

        let connections = parse_proc_net_tcp_content(content, false);
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].tx_queue, 16);
        assert_eq!(connections[0].rx_queue, 32);
    }

    #[test]
    fn test_parse_proc_net_udp_content() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2 0000000000000000 0
"#;

        let sockets = parse_proc_net_udp_content(content, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_addr, "0.0.0.0");
        assert_eq!(sockets[0].local_port, 53);
        assert_eq!(sockets[0].inode, 11111);
    }

    #[test]
    fn test_parse_proc_net_unix_content() {
        let content = r#"Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 22222 /var/run/dbus/system_bus_socket
0000000000000000: 00000002 00000000 00010000 0002 01 33333
"#;

        let sockets = parse_proc_net_unix_content(content).unwrap();
        assert_eq!(sockets.len(), 2);

        assert_eq!(sockets[0].socket_type, UnixSocketType::Stream);
        assert_eq!(sockets[0].inode, 22222);
        assert_eq!(sockets[0].ref_count, 2);
        assert_eq!(
            sockets[0].path,
            Some("/var/run/dbus/system_bus_socket".to_string())
        );

        assert_eq!(sockets[1].socket_type, UnixSocketType::Dgram);
        assert_eq!(sockets[1].inode, 33333);
        assert_eq!(sockets[1].ref_count, 2);
        assert_eq!(sockets[1].path, None);
    }

    #[test]
    fn test_unix_socket_type_from_type() {
        assert_eq!(UnixSocketType::from_type(1), UnixSocketType::Stream);
        assert_eq!(UnixSocketType::from_type(2), UnixSocketType::Dgram);
        assert_eq!(UnixSocketType::from_type(5), UnixSocketType::SeqPacket);
        assert_eq!(UnixSocketType::from_type(99), UnixSocketType::Unknown);
    }

    #[test]
    fn unix_table_failure_is_not_an_empty_observation() {
        const HEADER: &str = "Num RefCount Protocol Flags Type St Inode Path\n";
        assert!(parse_proc_net_unix_content(HEADER).unwrap().is_empty());
        for content in [
            "".to_string(),
            format!("{HEADER}truncated\n"),
            format!("{HEADER}0: 2 0 0 1 1 invalid /owned\n"),
            format!("{HEADER}0: invalid 0 0 1 1 42 /owned\n"),
            format!("{HEADER}0: 2 0 0 1 1 42 /owned\n1: 2 0 0 1 1 42 /other\n"),
        ] {
            assert_eq!(
                parse_proc_net_unix_content(&content).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        struct FailedRead;
        impl std::io::Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "planted reader refusal",
                ))
            }
        }
        assert_eq!(
            parse_proc_net_unix_reader(BufReader::new(FailedRead))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let sockets =
            parse_proc_net_unix_content(&format!("{HEADER}0: 2 0 0 1 1 42 /owned  path\n"))
                .unwrap();
        assert_eq!(sockets[0].path.as_deref(), Some("/owned  path"));
    }

    #[test]
    fn inet_protocol_proof_requires_a_readable_valid_inode_row() {
        const HEADER: &str = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        let row =
            "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 42\n";
        assert!(inet_table_has_inode(format!("{HEADER}{row}").as_bytes(), 42).unwrap());
        assert!(!inet_table_has_inode(format!("{HEADER}{row}").as_bytes(), 43).unwrap());
        assert!(!inet_table_has_inode(HEADER.as_bytes(), 42).unwrap());
        for content in [
            "".to_string(),
            format!("{HEADER}truncated\n"),
            format!("{HEADER}{}", row.replace("0 42", "0 invalid")),
            format!("{HEADER}{}", row.replace("0A", "invalid")),
        ] {
            assert_eq!(
                inet_table_has_inode(content.as_bytes(), 42)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn test_unix_socket_state_from_state() {
        assert_eq!(UnixSocketState::from_state(0), UnixSocketState::Free);
        assert_eq!(UnixSocketState::from_state(1), UnixSocketState::Unconnected);
        assert_eq!(UnixSocketState::from_state(3), UnixSocketState::Connected);
        assert_eq!(UnixSocketState::from_state(99), UnixSocketState::Unknown);
    }
}
