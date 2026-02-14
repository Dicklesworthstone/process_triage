//! Network connection collection for process analysis.
//!
//! This module provides network connection information per process:
//! - TCP/UDP/Unix socket enumeration
//! - Connection states (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
//! - Local and remote addresses
//! - Per-process socket counts
//!
//! # Data Sources
//! - `/proc/net/tcp`, `/proc/net/udp` - Raw socket tables
//! - `/proc/[pid]/fd/` - Per-process socket mappings
//! - `ss` command output (fallback)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Network connection information for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
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

/// A snapshot of global network state for O(1) process lookup.
///
/// This structure reads /proc/net/* files once and indexes them by inode,
/// avoiding the O(N*M) complexity of reading them for every process.
#[derive(Debug, Default)]
pub struct NetworkSnapshot {
    tcp_by_inode: HashMap<u64, TcpConnection>,
    udp_by_inode: HashMap<u64, UdpSocket>,
    unix_by_inode: HashMap<u64, UnixSocket>,
}

impl NetworkSnapshot {
    /// Collect a global snapshot of network sockets.
    pub fn collect() -> Self {
        let mut snapshot = NetworkSnapshot::default();

        // TCP
        if let Some(entries) = parse_proc_net_tcp("/proc/net/tcp", false) {
            for e in entries {
                snapshot.tcp_by_inode.insert(e.inode, e);
            }
        }
        if let Some(entries) = parse_proc_net_tcp("/proc/net/tcp6", true) {
            for e in entries {
                snapshot.tcp_by_inode.insert(e.inode, e);
            }
        }

        // UDP
        if let Some(entries) = parse_proc_net_udp("/proc/net/udp", false) {
            for e in entries {
                snapshot.udp_by_inode.insert(e.inode, e);
            }
        }
        if let Some(entries) = parse_proc_net_udp("/proc/net/udp6", true) {
            for e in entries {
                snapshot.udp_by_inode.insert(e.inode, e);
            }
        }

        // Unix
        if let Some(entries) = parse_proc_net_unix("/proc/net/unix") {
            for e in entries {
                snapshot.unix_by_inode.insert(e.inode, e);
            }
        }

        snapshot
    }

    /// Get network info for a specific process using the cached snapshot.
    pub fn get_process_info(&self, pid: u32) -> Option<NetworkInfo> {
        let socket_inodes = get_process_socket_inodes(pid)?;
        if socket_inodes.is_empty() {
            return Some(NetworkInfo::default());
        }

        let mut info = NetworkInfo::default();

        for inode in socket_inodes {
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
            }
        }

        Some(info)
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
    /// Raw socket count.
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
/// looks them up in /proc/net/tcp, /proc/net/udp, /proc/net/unix.
///
/// Note: For bulk collection, use `NetworkSnapshot::collect()` and `get_process_info`
/// to avoid reading /proc/net/* files repeatedly.
pub fn collect_network_info(pid: u32) -> Option<NetworkInfo> {
    let snapshot = NetworkSnapshot::collect();
    snapshot.get_process_info(pid)
}

/// Get all socket inode numbers for a process from /proc/[pid]/fd.
fn get_process_socket_inodes(pid: u32) -> Option<HashSet<u64>> {
    let fd_path = format!("/proc/{}/fd", pid);
    let mut inodes = HashSet::new();

    let entries = fs::read_dir(&fd_path).ok()?;
    // Limit inspection to prevent stall on processes with massive FD counts
    const MAX_INSPECT: usize = 50_000;

    for (inspected_count, entry) in entries.flatten().enumerate() {
        if inspected_count >= MAX_INSPECT {
            break;
        }

        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();
            // Socket links look like "socket:[12345]"
            if let Some(inode_str) = target_str.strip_prefix("socket:[") {
                if let Some(inode_str) = inode_str.strip_suffix(']') {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        inodes.insert(inode);
                    }
                }
            }
        }
    }

    Some(inodes)
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
        let inode_str = parts[9];

        let (local_addr, local_port) = parse_addr_port(local, is_ipv6);
        let (remote_addr, remote_port) = parse_addr_port(remote, is_ipv6);
        let state = u8::from_str_radix(state_hex, 16)
            .map(TcpState::from_hex)
            .unwrap_or(TcpState::Unknown);
        let inode = inode_str.parse().unwrap_or(0);

        connections.push(TcpConnection {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            inode,
            is_ipv6,
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
pub fn parse_proc_net_unix(path: &str) -> Option<Vec<UnixSocket>> {
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    Some(parse_proc_net_unix_reader(reader))
}

/// Parse Unix socket content from a reader.
pub fn parse_proc_net_unix_reader<R: BufRead>(reader: R) -> Vec<UnixSocket> {
    let mut sockets = Vec::new();

    for line in reader.lines().skip(1).flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }

        // Format: Num RefCount Protocol Flags Type St Inode Path
        let socket_type = parts[4]
            .parse()
            .ok()
            .map(UnixSocketType::from_type)
            .unwrap_or(UnixSocketType::Unknown);
        let state = parts[5]
            .parse()
            .ok()
            .map(UnixSocketState::from_state)
            .unwrap_or(UnixSocketState::Unknown);
        let inode = parts[6].parse().unwrap_or(0);
        let path = if parts.len() > 7 {
            Some(parts[7..].join(" "))
        } else {
            None
        };

        sockets.push(UnixSocket {
            path,
            socket_type,
            state,
            inode,
        });
    }

    sockets
}

/// Parse Unix socket content (for testing).
#[cfg(test)]
pub fn parse_proc_net_unix_content(content: &str) -> Vec<UnixSocket> {
    parse_proc_net_unix_reader(content.as_bytes())
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

        // Second entry: established connection
        assert_eq!(connections[1].local_addr, "127.0.0.1");
        assert_eq!(connections[1].local_port, 3306);
        assert_eq!(connections[1].state, TcpState::Established);
        assert_eq!(connections[1].inode, 67890);
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

        let sockets = parse_proc_net_unix_content(content);
        assert_eq!(sockets.len(), 2);

        assert_eq!(sockets[0].socket_type, UnixSocketType::Stream);
        assert_eq!(sockets[0].inode, 22222);
        assert_eq!(
            sockets[0].path,
            Some("/var/run/dbus/system_bus_socket".to_string())
        );

        assert_eq!(sockets[1].socket_type, UnixSocketType::Dgram);
        assert_eq!(sockets[1].inode, 33333);
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
    fn test_unix_socket_state_from_state() {
        assert_eq!(UnixSocketState::from_state(0), UnixSocketState::Free);
        assert_eq!(UnixSocketState::from_state(1), UnixSocketState::Unconnected);
        assert_eq!(UnixSocketState::from_state(3), UnixSocketState::Connected);
        assert_eq!(UnixSocketState::from_state(99), UnixSocketState::Unknown);
    }
}
