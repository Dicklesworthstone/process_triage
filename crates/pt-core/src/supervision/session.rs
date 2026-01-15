//! Session safety detection for protecting active user sessions.
//!
//! This module implements comprehensive session chain detection to prevent
//! killing processes that are part of the user's active session, including:
//!
//! - Current controlling TTY and related processes
//! - Parent shell chain
//! - tmux/screen server and client PIDs
//! - SSH connection chains
//! - Foreground process groups
//!
//! # Why Session Safety Matters
//!
//! Killing a process in the active session chain could:
//! - Disconnect the user from their terminal
//! - Orphan child processes unexpectedly
//! - Break SSH connections
//! - Corrupt tmux/screen sessions
//!
//! # Usage
//!
//! ```no_run
//! use pt_core::supervision::session::{SessionAnalyzer, is_in_protected_session};
//!
//! // Quick check for a single process
//! let current_pid = std::process::id();
//! let result = is_in_protected_session(1234, current_pid);
//! if result.is_protected {
//!     println!("Process is protected: {}", result.reason.unwrap_or_default());
//! }
//! ```

use super::environ::read_environ;
use super::types::SupervisionEvidence;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use thiserror::Error;
use tracing::{debug, trace};

/// Errors from session analysis.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("I/O error reading /proc/{pid}: {source}")]
    IoError {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Failed to parse /proc/{pid}/stat: {reason}")]
    StatParseError { pid: u32, reason: String },
}

/// Type of session protection detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SessionProtectionType {
    /// Process is the session leader
    SessionLeader,
    /// Process is in the same session as pt
    SameSession,
    /// Process is a parent shell of pt
    ParentShell,
    /// Process is a tmux server managing pt's session
    TmuxServer,
    /// Process is a tmux client attached to pt's session
    TmuxClient,
    /// Process is a screen server managing pt's session
    ScreenServer,
    /// Process is a screen client attached to pt's session
    ScreenClient,
    /// Process is part of an SSH chain to pt
    SshChain,
    /// Process is in pt's foreground process group
    ForegroundGroup,
    /// Process is the controlling TTY owner
    TtyController,
}

impl std::fmt::Display for SessionProtectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLeader => write!(f, "session leader"),
            Self::SameSession => write!(f, "same session"),
            Self::ParentShell => write!(f, "parent shell"),
            Self::TmuxServer => write!(f, "tmux server"),
            Self::TmuxClient => write!(f, "tmux client"),
            Self::ScreenServer => write!(f, "screen server"),
            Self::ScreenClient => write!(f, "screen client"),
            Self::SshChain => write!(f, "SSH chain"),
            Self::ForegroundGroup => write!(f, "foreground process group"),
            Self::TtyController => write!(f, "TTY controller"),
        }
    }
}

/// Result of session safety analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SessionResult {
    /// Whether the process is protected.
    pub is_protected: bool,
    /// Protection types detected.
    pub protection_types: Vec<SessionProtectionType>,
    /// Human-readable reason for protection.
    pub reason: Option<String>,
    /// Evidence items.
    pub evidence: Vec<SessionEvidence>,
    /// Session ID of the target process.
    pub session_id: Option<u32>,
    /// Process group ID of the target process.
    pub pgid: Option<u32>,
    /// TTY device number (if any).
    pub tty_nr: Option<i32>,
}

impl SessionResult {
    /// Create a result indicating no protection.
    pub fn not_protected() -> Self {
        Self {
            is_protected: false,
            protection_types: vec![],
            reason: None,
            evidence: vec![],
            session_id: None,
            pgid: None,
            tty_nr: None,
        }
    }

    /// Create a result indicating protection.
    pub fn protected(
        protection_types: Vec<SessionProtectionType>,
        reason: String,
        evidence: Vec<SessionEvidence>,
    ) -> Self {
        Self {
            is_protected: true,
            protection_types,
            reason: Some(reason),
            evidence,
            session_id: None,
            pgid: None,
            tty_nr: None,
        }
    }

    /// Add session info to the result.
    pub fn with_session_info(mut self, sid: u32, pgid: u32, tty_nr: i32) -> Self {
        self.session_id = Some(sid);
        self.pgid = Some(pgid);
        self.tty_nr = if tty_nr != 0 { Some(tty_nr) } else { None };
        self
    }
}

/// Evidence for session protection.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEvidence {
    /// Type of protection.
    pub protection_type: SessionProtectionType,
    /// Description of the evidence.
    pub description: String,
    /// Weight/confidence of this evidence.
    pub weight: f64,
}

impl From<SessionEvidence> for SupervisionEvidence {
    fn from(e: SessionEvidence) -> Self {
        SupervisionEvidence {
            evidence_type: super::types::EvidenceType::Tty,
            description: e.description,
            weight: e.weight,
        }
    }
}

/// Parsed /proc/<pid>/stat information.
#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub tty_nr: i32,
    pub tpgid: i32,
}

impl ProcStat {
    /// Parse from /proc/<pid>/stat content.
    pub fn parse(content: &str) -> Option<Self> {
        // Format: pid (comm) state ppid pgrp session tty_nr tpgid ...
        // comm can contain spaces and parentheses, so find the last ')'
        let comm_start = content.find('(')?;
        let comm_end = content.rfind(')')?;

        let pid_str = content[..comm_start].trim();
        let pid: u32 = pid_str.parse().ok()?;

        let comm = content[comm_start + 1..comm_end].to_string();

        let rest = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() < 6 {
            return None;
        }

        Some(Self {
            pid,
            comm,
            state: fields[0].chars().next()?,
            ppid: fields[1].parse().ok()?,
            pgrp: fields[2].parse().ok()?,
            session: fields[3].parse().ok()?,
            tty_nr: fields[4].parse().ok()?,
            tpgid: fields[5].parse().ok()?,
        })
    }
}

/// Read and parse /proc/<pid>/stat.
#[cfg(target_os = "linux")]
pub fn read_proc_stat(pid: u32) -> Result<ProcStat, SessionError> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SessionError::ProcessNotFound(pid)
        } else {
            SessionError::IoError { pid, source: e }
        }
    })?;

    ProcStat::parse(&content).ok_or(SessionError::StatParseError {
        pid,
        reason: "failed to parse stat fields".to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn read_proc_stat(pid: u32) -> Result<ProcStat, SessionError> {
    Err(SessionError::ProcessNotFound(pid))
}

/// SSH connection information.
#[derive(Debug, Clone, Serialize)]
pub struct SshConnectionInfo {
    /// Remote IP address.
    pub client_ip: String,
    /// Remote port.
    pub client_port: u16,
    /// Local IP address.
    pub server_ip: String,
    /// Local port.
    pub server_port: u16,
    /// SSH TTY (e.g., /dev/pts/0).
    pub ssh_tty: Option<String>,
}

impl SshConnectionInfo {
    /// Parse from SSH_CONNECTION environment variable.
    /// Format: "client_ip client_port server_ip server_port"
    pub fn from_ssh_connection(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 4 {
            Some(Self {
                client_ip: parts[0].to_string(),
                client_port: parts[1].parse().ok()?,
                server_ip: parts[2].to_string(),
                server_port: parts[3].parse().ok()?,
                ssh_tty: None,
            })
        } else {
            None
        }
    }

    /// Parse from SSH_CLIENT environment variable.
    /// Format: "client_ip client_port server_port"
    pub fn from_ssh_client(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 3 {
            Some(Self {
                client_ip: parts[0].to_string(),
                client_port: parts[1].parse().ok()?,
                server_ip: String::new(),
                server_port: parts[2].parse().ok()?,
                ssh_tty: None,
            })
        } else {
            None
        }
    }
}

/// Detect SSH connection from environment variables.
#[cfg(target_os = "linux")]
pub fn detect_ssh_connection(pid: u32) -> Option<SshConnectionInfo> {
    let env = read_environ(pid).ok()?;

    // Try SSH_CONNECTION first (most complete)
    if let Some(value) = env.get("SSH_CONNECTION") {
        if let Some(mut info) = SshConnectionInfo::from_ssh_connection(value) {
            info.ssh_tty = env.get("SSH_TTY").cloned();
            return Some(info);
        }
    }

    // Fall back to SSH_CLIENT
    if let Some(value) = env.get("SSH_CLIENT") {
        if let Some(mut info) = SshConnectionInfo::from_ssh_client(value) {
            info.ssh_tty = env.get("SSH_TTY").cloned();
            return Some(info);
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
pub fn detect_ssh_connection(_pid: u32) -> Option<SshConnectionInfo> {
    None
}

/// tmux session information.
#[derive(Debug, Clone, Serialize)]
pub struct TmuxInfo {
    /// Path to the tmux socket.
    pub socket_path: String,
    /// tmux server PID (if detectable).
    pub server_pid: Option<u32>,
    /// Session name or ID.
    pub session_id: Option<String>,
}

impl TmuxInfo {
    /// Parse from TMUX environment variable.
    /// Format: "/tmp/tmux-1000/default,12345,0" (socket,pid,pane)
    pub fn from_tmux_env(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split(',').collect();
        if parts.is_empty() {
            return None;
        }

        let socket_path = parts[0].to_string();
        let server_pid = parts.get(1).and_then(|s| s.parse().ok());

        Some(Self {
            socket_path,
            server_pid,
            session_id: None,
        })
    }
}

/// Detect tmux session from environment.
#[cfg(target_os = "linux")]
pub fn detect_tmux_session(pid: u32) -> Option<TmuxInfo> {
    let env = read_environ(pid).ok()?;
    env.get("TMUX").and_then(|v| TmuxInfo::from_tmux_env(v.as_str()))
}

#[cfg(not(target_os = "linux"))]
pub fn detect_tmux_session(_pid: u32) -> Option<TmuxInfo> {
    None
}

/// screen session information.
#[derive(Debug, Clone, Serialize)]
pub struct ScreenInfo {
    /// Session identifier (from STY).
    pub session_id: String,
    /// Parsed PID from session ID.
    pub pid: Option<u32>,
    /// Session name.
    pub name: Option<String>,
}

impl ScreenInfo {
    /// Parse from STY environment variable.
    /// Format: "12345.pts-0.hostname" or "12345.sessionname"
    pub fn from_sty_env(value: &str) -> Option<Self> {
        let session_id = value.to_string();
        let parts: Vec<&str> = value.split('.').collect();

        let pid = parts.first().and_then(|s| s.parse().ok());
        let name = if parts.len() > 1 {
            Some(parts[1..].join("."))
        } else {
            None
        };

        Some(Self {
            session_id,
            pid,
            name,
        })
    }
}

/// Detect screen session from environment.
#[cfg(target_os = "linux")]
pub fn detect_screen_session(pid: u32) -> Option<ScreenInfo> {
    let env = read_environ(pid).ok()?;
    env.get("STY").and_then(|v| ScreenInfo::from_sty_env(v.as_str()))
}

#[cfg(not(target_os = "linux"))]
pub fn detect_screen_session(_pid: u32) -> Option<ScreenInfo> {
    None
}

/// Configuration for session analysis.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum depth when walking process ancestry.
    pub max_ancestry_depth: usize,
    /// Protect processes in the same session.
    pub protect_same_session: bool,
    /// Protect parent shells.
    pub protect_parent_shells: bool,
    /// Protect tmux/screen chains.
    pub protect_multiplexers: bool,
    /// Protect SSH chains.
    pub protect_ssh_chains: bool,
    /// Protect foreground process groups.
    pub protect_foreground_groups: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_ancestry_depth: 20,
            protect_same_session: true,
            protect_parent_shells: true,
            protect_multiplexers: true,
            protect_ssh_chains: true,
            protect_foreground_groups: true,
        }
    }
}

/// Shell process names for parent shell detection.
const SHELL_NAMES: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "tcsh", "csh", "ksh", "ash",
];

/// Session analyzer for comprehensive session safety detection.
pub struct SessionAnalyzer {
    config: SessionConfig,
    /// Cache of parsed proc stats.
    stat_cache: HashMap<u32, ProcStat>,
}

impl SessionAnalyzer {
    /// Create a new analyzer with default config.
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
            stat_cache: HashMap::new(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            config,
            stat_cache: HashMap::new(),
        }
    }

    /// Clear the internal cache.
    pub fn clear_cache(&mut self) {
        self.stat_cache.clear();
    }

    /// Get or fetch ProcStat for a pid.
    fn get_stat(&mut self, pid: u32) -> Option<ProcStat> {
        if let Some(stat) = self.stat_cache.get(&pid) {
            return Some(stat.clone());
        }

        if let Ok(stat) = read_proc_stat(pid) {
            self.stat_cache.insert(pid, stat.clone());
            Some(stat)
        } else {
            None
        }
    }

    /// Walk the parent chain from a PID up to init.
    fn get_ancestry(&mut self, pid: u32) -> Vec<u32> {
        let mut chain = vec![pid];
        let mut current = pid;
        let mut visited = HashSet::new();
        visited.insert(pid);

        for _ in 0..self.config.max_ancestry_depth {
            if let Some(stat) = self.get_stat(current) {
                if stat.ppid == 0 || stat.ppid == current || visited.contains(&stat.ppid) {
                    break;
                }
                visited.insert(stat.ppid);
                chain.push(stat.ppid);
                current = stat.ppid;
            } else {
                break;
            }
        }

        chain
    }

    /// Check if a process name is a shell.
    fn is_shell(&self, comm: &str) -> bool {
        SHELL_NAMES.iter().any(|&s| comm == s)
    }

    /// Analyze whether a target PID is in the protected session chain of pt_pid.
    pub fn analyze(&mut self, target_pid: u32, pt_pid: u32) -> Result<SessionResult, SessionError> {
        trace!(target_pid, pt_pid, "analyzing session safety");

        let mut protection_types = Vec::new();
        let mut evidence = Vec::new();

        // Get stat info for both processes
        let target_stat = self
            .get_stat(target_pid)
            .ok_or(SessionError::ProcessNotFound(target_pid))?;
        let pt_stat = self
            .get_stat(pt_pid)
            .ok_or(SessionError::ProcessNotFound(pt_pid))?;

        // Check 1: Is target a session leader?
        if target_stat.pid == target_stat.session {
            protection_types.push(SessionProtectionType::SessionLeader);
            evidence.push(SessionEvidence {
                protection_type: SessionProtectionType::SessionLeader,
                description: format!("PID {} is session leader (SID={})", target_pid, target_stat.session),
                weight: 1.0,
            });
            debug!(target_pid, session = target_stat.session, "target is session leader");
        }

        // Check 2: Same session as pt?
        if self.config.protect_same_session && target_stat.session == pt_stat.session {
            protection_types.push(SessionProtectionType::SameSession);
            evidence.push(SessionEvidence {
                protection_type: SessionProtectionType::SameSession,
                description: format!(
                    "PID {} is in same session as pt (SID={})",
                    target_pid, pt_stat.session
                ),
                weight: 0.95,
            });
            debug!(target_pid, session = pt_stat.session, "target in same session as pt");
        }

        // Check 3: Parent shell of pt?
        if self.config.protect_parent_shells {
            let pt_ancestry = self.get_ancestry(pt_pid);
            if pt_ancestry.contains(&target_pid) {
                if let Some(stat) = self.get_stat(target_pid) {
                    if self.is_shell(&stat.comm) {
                        protection_types.push(SessionProtectionType::ParentShell);
                        evidence.push(SessionEvidence {
                            protection_type: SessionProtectionType::ParentShell,
                            description: format!(
                                "PID {} ({}) is parent shell of pt",
                                target_pid, stat.comm
                            ),
                            weight: 1.0,
                        });
                        debug!(target_pid, comm = %stat.comm, "target is parent shell of pt");
                    }
                }
            }
        }

        // Check 4: tmux/screen server of pt's session?
        if self.config.protect_multiplexers {
            // Check tmux
            if let Some(tmux_info) = detect_tmux_session(pt_pid) {
                if let Some(server_pid) = tmux_info.server_pid {
                    if target_pid == server_pid {
                        protection_types.push(SessionProtectionType::TmuxServer);
                        evidence.push(SessionEvidence {
                            protection_type: SessionProtectionType::TmuxServer,
                            description: format!(
                                "PID {} is tmux server for pt's session (socket: {})",
                                target_pid, tmux_info.socket_path
                            ),
                            weight: 1.0,
                        });
                        debug!(target_pid, socket = %tmux_info.socket_path, "target is pt's tmux server");
                    }
                }

                // Also check if target is in a tmux process tree
                if let Some(stat) = self.get_stat(target_pid) {
                    if stat.comm == "tmux" || stat.comm == "tmux: server" {
                        // Check if this tmux serves our session
                        let target_ancestry = self.get_ancestry(pt_pid);
                        if target_ancestry.contains(&target_pid) {
                            protection_types.push(SessionProtectionType::TmuxServer);
                            evidence.push(SessionEvidence {
                                protection_type: SessionProtectionType::TmuxServer,
                                description: format!(
                                    "PID {} (tmux) is in pt's ancestry chain",
                                    target_pid
                                ),
                                weight: 0.9,
                            });
                        }
                    }
                }
            }

            // Check screen
            if let Some(screen_info) = detect_screen_session(pt_pid) {
                if let Some(screen_pid) = screen_info.pid {
                    if target_pid == screen_pid {
                        protection_types.push(SessionProtectionType::ScreenServer);
                        evidence.push(SessionEvidence {
                            protection_type: SessionProtectionType::ScreenServer,
                            description: format!(
                                "PID {} is screen server for pt's session ({})",
                                target_pid, screen_info.session_id
                            ),
                            weight: 1.0,
                        });
                        debug!(target_pid, session_id = %screen_info.session_id, "target is pt's screen server");
                    }
                }

                // Also check if target is in a screen process tree
                if let Some(stat) = self.get_stat(target_pid) {
                    if stat.comm == "screen" || stat.comm == "SCREEN" {
                        let target_ancestry = self.get_ancestry(pt_pid);
                        if target_ancestry.contains(&target_pid) {
                            protection_types.push(SessionProtectionType::ScreenServer);
                            evidence.push(SessionEvidence {
                                protection_type: SessionProtectionType::ScreenServer,
                                description: format!(
                                    "PID {} (screen) is in pt's ancestry chain",
                                    target_pid
                                ),
                                weight: 0.9,
                            });
                        }
                    }
                }
            }
        }

        // Check 5: SSH chain protection
        if self.config.protect_ssh_chains {
            // Check if pt is in an SSH session
            if let Some(pt_ssh) = detect_ssh_connection(pt_pid) {
                // If target is sshd and in our ancestry, protect it
                if let Some(stat) = self.get_stat(target_pid) {
                    if stat.comm == "sshd" {
                        let pt_ancestry = self.get_ancestry(pt_pid);
                        if pt_ancestry.contains(&target_pid) {
                            protection_types.push(SessionProtectionType::SshChain);
                            evidence.push(SessionEvidence {
                                protection_type: SessionProtectionType::SshChain,
                                description: format!(
                                    "PID {} (sshd) is in pt's SSH chain (from {}:{})",
                                    target_pid, pt_ssh.client_ip, pt_ssh.client_port
                                ),
                                weight: 1.0,
                            });
                            debug!(
                                target_pid,
                                client_ip = %pt_ssh.client_ip,
                                "target sshd is in pt's SSH chain"
                            );
                        }
                    }
                }
            }

            // Also check if target has matching SSH session
            if let Some(target_ssh) = detect_ssh_connection(target_pid) {
                if let Some(pt_ssh) = detect_ssh_connection(pt_pid) {
                    // Same SSH connection (same client IP and port)
                    if target_ssh.client_ip == pt_ssh.client_ip
                        && target_ssh.client_port == pt_ssh.client_port
                    {
                        protection_types.push(SessionProtectionType::SshChain);
                        evidence.push(SessionEvidence {
                            protection_type: SessionProtectionType::SshChain,
                            description: format!(
                                "PID {} shares SSH connection with pt ({}:{})",
                                target_pid, pt_ssh.client_ip, pt_ssh.client_port
                            ),
                            weight: 0.85,
                        });
                    }
                }
            }
        }

        // Check 6: Foreground process group
        if self.config.protect_foreground_groups {
            // pt's foreground process group
            if pt_stat.tpgid > 0 {
                // If target is in pt's terminal's foreground group
                if target_stat.pgrp == pt_stat.tpgid as u32 {
                    protection_types.push(SessionProtectionType::ForegroundGroup);
                    evidence.push(SessionEvidence {
                        protection_type: SessionProtectionType::ForegroundGroup,
                        description: format!(
                            "PID {} is in pt's foreground process group (PGID={})",
                            target_pid, pt_stat.tpgid
                        ),
                        weight: 0.9,
                    });
                    debug!(target_pid, pgid = pt_stat.tpgid, "target in pt's foreground group");
                }
            }
        }

        // Build result
        let is_protected = !protection_types.is_empty();
        let reason = if is_protected {
            let types: Vec<String> = protection_types.iter().map(|t| t.to_string()).collect();
            Some(format!("protected: {}", types.join(", ")))
        } else {
            None
        };

        let mut result = if is_protected {
            SessionResult::protected(protection_types, reason.unwrap(), evidence)
        } else {
            SessionResult::not_protected()
        };

        result = result.with_session_info(target_stat.session, target_stat.pgrp, target_stat.tty_nr);

        Ok(result)
    }

    /// Batch analyze multiple PIDs against the same pt_pid.
    pub fn analyze_batch(
        &mut self,
        target_pids: &[u32],
        pt_pid: u32,
    ) -> Vec<(u32, Result<SessionResult, SessionError>)> {
        target_pids
            .iter()
            .map(|&pid| (pid, self.analyze(pid, pt_pid)))
            .collect()
    }

    /// Get all processes in pt's session.
    #[cfg(target_os = "linux")]
    pub fn enumerate_session_members(&mut self, pt_pid: u32) -> Result<Vec<u32>, SessionError> {
        let pt_stat = self
            .get_stat(pt_pid)
            .ok_or(SessionError::ProcessNotFound(pt_pid))?;
        let session_id = pt_stat.session;

        let mut members = Vec::new();

        // Walk /proc to find all processes in the same session
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        if let Some(stat) = self.get_stat(pid) {
                            if stat.session == session_id {
                                members.push(pid);
                            }
                        }
                    }
                }
            }
        }

        Ok(members)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enumerate_session_members(&mut self, _pt_pid: u32) -> Result<Vec<u32>, SessionError> {
        Ok(vec![])
    }
}

impl Default for SessionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for quick session safety check.
pub fn is_in_protected_session(target_pid: u32, pt_pid: u32) -> SessionResult {
    let mut analyzer = SessionAnalyzer::new();
    analyzer.analyze(target_pid, pt_pid).unwrap_or_else(|_| SessionResult::not_protected())
}

/// Check if a process is protected from being killed.
/// Returns (is_protected, reason) tuple.
pub fn check_session_protection(target_pid: u32, pt_pid: u32) -> (bool, Option<String>) {
    let result = is_in_protected_session(target_pid, pt_pid);
    (result.is_protected, result.reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_stat_parse() {
        let content = "1234 (bash) S 1000 1234 1234 34816 1234 4194304";
        let stat = ProcStat::parse(content).unwrap();

        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.comm, "bash");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 1000);
        assert_eq!(stat.pgrp, 1234);
        assert_eq!(stat.session, 1234);
    }

    #[test]
    fn test_proc_stat_parse_with_spaces_in_comm() {
        let content = "5678 (Web Content) S 1000 5678 5678 0 -1 4194304";
        let stat = ProcStat::parse(content).unwrap();

        assert_eq!(stat.pid, 5678);
        assert_eq!(stat.comm, "Web Content");
    }

    #[test]
    fn test_ssh_connection_parse() {
        let value = "192.168.1.100 54321 192.168.1.1 22";
        let info = SshConnectionInfo::from_ssh_connection(value).unwrap();

        assert_eq!(info.client_ip, "192.168.1.100");
        assert_eq!(info.client_port, 54321);
        assert_eq!(info.server_ip, "192.168.1.1");
        assert_eq!(info.server_port, 22);
    }

    #[test]
    fn test_ssh_client_parse() {
        let value = "10.0.0.5 45678 22";
        let info = SshConnectionInfo::from_ssh_client(value).unwrap();

        assert_eq!(info.client_ip, "10.0.0.5");
        assert_eq!(info.client_port, 45678);
        assert_eq!(info.server_port, 22);
    }

    #[test]
    fn test_tmux_info_parse() {
        let value = "/tmp/tmux-1000/default,12345,0";
        let info = TmuxInfo::from_tmux_env(value).unwrap();

        assert_eq!(info.socket_path, "/tmp/tmux-1000/default");
        assert_eq!(info.server_pid, Some(12345));
    }

    #[test]
    fn test_screen_info_parse() {
        let value = "12345.pts-0.hostname";
        let info = ScreenInfo::from_sty_env(value).unwrap();

        assert_eq!(info.session_id, "12345.pts-0.hostname");
        assert_eq!(info.pid, Some(12345));
        assert_eq!(info.name, Some("pts-0.hostname".to_string()));
    }

    #[test]
    fn test_session_result_not_protected() {
        let result = SessionResult::not_protected();
        assert!(!result.is_protected);
        assert!(result.protection_types.is_empty());
    }

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert!(config.protect_same_session);
        assert!(config.protect_parent_shells);
        assert!(config.protect_multiplexers);
        assert!(config.protect_ssh_chains);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_read_proc_stat_current_process() {
            let pid = std::process::id();
            let stat = read_proc_stat(pid).expect("should read current process stat");

            assert_eq!(stat.pid, pid);
            assert!(!stat.comm.is_empty());
        }

        #[test]
        fn test_session_analyzer_current_process() {
            let pid = std::process::id();
            let mut analyzer = SessionAnalyzer::new();

            // Analyzing self against self
            let result = analyzer.analyze(pid, pid).expect("should analyze");

            // Current process should be in its own session
            assert!(result.session_id.is_some());
        }

        #[test]
        fn test_session_analyzer_detects_same_session() {
            let pid = std::process::id();
            let mut analyzer = SessionAnalyzer::new();

            // Analyzing self against self - should detect same session
            let result = analyzer.analyze(pid, pid).expect("should analyze");

            // Should be protected (same session)
            assert!(result.is_protected);
            assert!(result
                .protection_types
                .contains(&SessionProtectionType::SameSession));
        }

        #[test]
        fn test_enumerate_session_members() {
            let pid = std::process::id();
            let mut analyzer = SessionAnalyzer::new();

            let members = analyzer
                .enumerate_session_members(pid)
                .expect("should enumerate");

            // At least the current process should be in its session
            assert!(members.contains(&pid));
        }
    }
}
