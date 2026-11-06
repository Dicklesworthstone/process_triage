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

use super::environ::{read_environ, EnvironError};
use super::types::SupervisionEvidence;
use serde::Serialize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
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

    #[error("Session environment evidence unavailable: {0}")]
    Environment(#[from] EnvironError),

    #[error("Session ancestry contains a cycle at PID {0}")]
    AncestryLoop(u32),

    #[error("Session ancestry for PID {pid} is incomplete at depth {depth}")]
    AncestryDepth { pid: u32, depth: usize },

    #[error("Session evidence changed for PID {0} during analysis")]
    ProcessChanged(u32),

    #[error("Session evidence is unavailable on this platform for PID {0}")]
    Unsupported(u32),
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::collect::proc_parsers::ProcessStat;

/// Read the fields used by session safety without replacing unreadable or
/// malformed fields with a zero-valued session, process group, or parent.
#[cfg(target_os = "linux")]
fn read_session_stat(pid: u32) -> Result<ProcessStat, SessionError> {
    let bytes = fs::read(format!("/proc/{pid}/stat")).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            SessionError::ProcessNotFound(pid)
        } else {
            SessionError::IoError { pid, source }
        }
    })?;
    let content = std::str::from_utf8(&bytes).map_err(|_| SessionError::StatParseError {
        pid,
        reason: "invalid UTF-8".to_string(),
    })?;
    parse_session_stat(pid, content)
}

#[cfg(target_os = "linux")]
fn parse_session_stat(pid: u32, content: &str) -> Result<ProcessStat, SessionError> {
    let invalid = |reason: &str| SessionError::StatParseError {
        pid,
        reason: reason.to_string(),
    };
    let stat = crate::collect::parse_proc_stat_content(content)
        .ok_or_else(|| invalid("invalid process stat"))?;
    if stat.pid != pid {
        return Err(invalid("PID differs from requested process"));
    }
    let close = content.rfind(')').ok_or_else(|| invalid("missing comm"))?;
    let fields: Vec<_> = content[close + 1..].split_whitespace().collect();
    if fields.first().is_none_or(|state| {
        !matches!(
            *state,
            "R" | "S" | "D" | "Z" | "T" | "t" | "X" | "x" | "K" | "W" | "P" | "I"
        )
    }) {
        return Err(invalid("missing or invalid process state"));
    }
    if fields
        .get(1)
        .and_then(|value| value.parse::<u32>().ok())
        .is_none()
        || fields
            .get(19)
            .and_then(|value| value.parse::<u64>().ok())
            .is_none()
    {
        return Err(invalid("missing or invalid parent PID or birth ticks"));
    }
    for (index, name) in [(2, "pgrp"), (3, "session"), (4, "tty_nr"), (5, "tpgid")] {
        let value = fields
            .get(index)
            .and_then(|value| value.parse::<i32>().ok())
            .ok_or_else(|| invalid(&format!("missing or invalid {name}")))?;
        if matches!(index, 2 | 3) && value < 0 {
            return Err(invalid(&format!("invalid negative {name}")));
        }
    }
    Ok(stat)
}

#[cfg(target_os = "macos")]
fn read_session_stat(pid: u32) -> Result<ProcessStat, SessionError> {
    let stat =
        crate::collect::macos::read_session_stat(pid).ok_or(SessionError::ProcessNotFound(pid))?;
    if stat.session < 0 || stat.pgrp < 0 {
        return Err(SessionError::IoError {
            pid,
            source: std::io::Error::other("cannot read native session or process group ID"),
        });
    }
    Ok(stat)
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn detect_ssh_connection(pid: u32) -> Option<SshConnectionInfo> {
    let env = read_environ(pid).ok()?;
    ssh_connection_from_env(&env)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ssh_connection_from_env(env: &HashMap<String, String>) -> Option<SshConnectionInfo> {
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
        // The socket path can itself contain commas; the final two fields are
        // the server PID and session index.
        let (socket_and_pid, _) = value.rsplit_once(',')?;
        let (socket_path, server_pid) = socket_and_pid.rsplit_once(',')?;
        let socket_path = socket_path.to_string();
        let server_pid = server_pid.parse().ok();

        Some(Self {
            socket_path,
            server_pid,
            session_id: None,
        })
    }
}

/// Detect tmux session from environment.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn detect_tmux_session(pid: u32) -> Option<TmuxInfo> {
    let env = read_environ(pid).ok()?;
    env.get("TMUX").and_then(|v| TmuxInfo::from_tmux_env(v))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn detect_screen_session(pid: u32) -> Option<ScreenInfo> {
    let env = read_environ(pid).ok()?;
    env.get("STY").and_then(|v| ScreenInfo::from_sty_env(v))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn detect_screen_session(_pid: u32) -> Option<ScreenInfo> {
    None
}

/// Optional hints remain optional to callers collecting user-intent features.
/// Safety decisions require the environment read itself to succeed, and must
/// not turn a present but unusable session identifier into evidence of absence.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invalid_session_env(pid: u32, variable: &str) -> SessionError {
    EnvironError::Parse {
        pid,
        reason: format!("invalid {variable} session identifier"),
    }
    .into()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn required_tmux_session(
    pid: u32,
    env: &HashMap<String, String>,
) -> Result<Option<TmuxInfo>, SessionError> {
    let Some(value) = env.get("TMUX").filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    TmuxInfo::from_tmux_env(value)
        .filter(|info| !info.socket_path.is_empty() && info.server_pid.is_some_and(|pid| pid > 0))
        .map(Some)
        .ok_or_else(|| invalid_session_env(pid, "TMUX"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn required_screen_session(
    pid: u32,
    env: &HashMap<String, String>,
) -> Result<Option<ScreenInfo>, SessionError> {
    let Some(value) = env.get("STY").filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    ScreenInfo::from_sty_env(value)
        .filter(|info| info.pid.is_some_and(|pid| pid > 0))
        .map(Some)
        .ok_or_else(|| invalid_session_env(pid, "STY"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn required_ssh_connection(
    pid: u32,
    env: &HashMap<String, String>,
) -> Result<Option<SshConnectionInfo>, SessionError> {
    if let Some(info) = ssh_connection_from_env(env) {
        return Ok(Some(info));
    }
    for variable in ["SSH_CONNECTION", "SSH_CLIENT"] {
        if env.get(variable).is_some_and(|value| !value.is_empty()) {
            return Err(invalid_session_env(pid, variable));
        }
    }
    Ok(None)
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SHELL_NAMES: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "tcsh", "csh", "ksh", "ash",
];

/// Session analyzer for comprehensive session safety detection.
pub struct SessionAnalyzer {
    config: SessionConfig,
    /// Facts shared within one analysis, never reused to authorize a later one.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    stat_cache: HashMap<u32, ProcessStat>,
}

impl SessionAnalyzer {
    /// Create a new analyzer with default config.
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            stat_cache: HashMap::new(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            config,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            stat_cache: HashMap::new(),
        }
    }

    /// Clear the internal cache.
    pub fn clear_cache(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.stat_cache.clear();
    }

    /// Get or fetch the session facts for a pid (/proc on Linux, proc_pidinfo +
    /// getsid on macOS).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn get_stat(&mut self, pid: u32) -> Result<ProcessStat, SessionError> {
        if let Some(stat) = self.stat_cache.get(&pid) {
            return Ok(stat.clone());
        }

        let stat = read_session_stat(pid)?;
        self.stat_cache.insert(pid, stat.clone());
        Ok(stat)
    }

    /// Walk the complete parent chain to init or a namespace boundary. Missing
    /// ancestors, cycles and a depth limit are not proof that a target is absent.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn get_ancestry(&mut self, pid: u32) -> Result<Vec<u32>, SessionError> {
        let mut chain = vec![pid];
        let mut current = pid;
        let mut visited = HashSet::new();
        visited.insert(pid);

        let mut depth = 0;
        loop {
            let stat = self.get_stat(current)?;
            if current == 1 || stat.ppid == 0 {
                return Ok(chain);
            }
            if !visited.insert(stat.ppid) {
                return Err(SessionError::AncestryLoop(stat.ppid));
            }
            if depth == self.config.max_ancestry_depth {
                return Err(SessionError::AncestryDepth { pid, depth });
            }
            chain.push(stat.ppid);
            current = stat.ppid;
            depth += 1;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn revalidate_stats(&self) -> Result<(), SessionError> {
        for (&pid, before) in &self.stat_cache {
            let after = read_session_stat(pid)?;
            if before.starttime != after.starttime
                || before.ppid != after.ppid
                || before.comm != after.comm
                || before.session != after.session
                || before.pgrp != after.pgrp
                || before.tty_nr != after.tty_nr
                || before.tpgid != after.tpgid
            {
                return Err(SessionError::ProcessChanged(pid));
            }
        }
        Ok(())
    }

    /// Check if a process name is a shell.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn is_shell(&self, comm: &str) -> bool {
        SHELL_NAMES.contains(&comm)
    }

    /// Analyze whether a target PID is in the protected session chain of pt_pid.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn analyze(&mut self, target_pid: u32, pt_pid: u32) -> Result<SessionResult, SessionError> {
        trace!(target_pid, pt_pid, "analyzing session safety");

        self.clear_cache();
        let target_stat = self.get_stat(target_pid)?;
        let pt_stat = self.get_stat(pt_pid)?;
        let pt_env = if self.config.protect_multiplexers || self.config.protect_ssh_chains {
            read_environ(pt_pid)?
        } else {
            HashMap::new()
        };
        let mut protection_types = Vec::new();
        let mut evidence = Vec::new();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Check 1: Is target a session leader?
            if target_stat.pid == target_stat.session as u32 {
                protection_types.push(SessionProtectionType::SessionLeader);
                evidence.push(SessionEvidence {
                    protection_type: SessionProtectionType::SessionLeader,
                    description: format!(
                        "PID {} is session leader (SID={})",
                        target_pid, target_stat.session
                    ),
                    weight: 1.0,
                });
                debug!(
                    target_pid,
                    session = target_stat.session,
                    "target is session leader"
                );
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
                debug!(
                    target_pid,
                    session = pt_stat.session,
                    "target in same session as pt"
                );
            }

            // Check 3: Parent shell of pt?
            if self.config.protect_parent_shells {
                let pt_ancestry = self.get_ancestry(pt_pid)?;
                if pt_ancestry.contains(&target_pid) && self.is_shell(&target_stat.comm) {
                    protection_types.push(SessionProtectionType::ParentShell);
                    evidence.push(SessionEvidence {
                        protection_type: SessionProtectionType::ParentShell,
                        description: format!(
                            "PID {} ({}) is parent shell of pt",
                            target_pid, target_stat.comm
                        ),
                        weight: 1.0,
                    });
                    debug!(target_pid, comm = %target_stat.comm, "target is parent shell of pt");
                }
            }

            // Check 6: Foreground process group
            if self.config.protect_foreground_groups {
                // pt's foreground process group
                if pt_stat.tpgid > 0 {
                    // If target is in pt's terminal's foreground group
                    if target_stat.pgrp == pt_stat.tpgid {
                        protection_types.push(SessionProtectionType::ForegroundGroup);
                        evidence.push(SessionEvidence {
                            protection_type: SessionProtectionType::ForegroundGroup,
                            description: format!(
                                "PID {} is in pt's foreground process group (PGID={})",
                                target_pid, pt_stat.tpgid
                            ),
                            weight: 0.9,
                        });
                        debug!(
                            target_pid,
                            pgid = pt_stat.tpgid,
                            "target in pt's foreground group"
                        );
                    }
                }
            }
        }

        // Check 4: tmux/screen server of pt's session?
        if self.config.protect_multiplexers {
            // Check tmux
            if let Some(tmux_info) = required_tmux_session(pt_pid, &pt_env)? {
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
                if target_stat.comm == "tmux" || target_stat.comm == "tmux: server" {
                    // Check if this tmux serves our session
                    let pt_ancestry = self.get_ancestry(pt_pid)?;
                    if pt_ancestry.contains(&target_pid) {
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

            // Check screen
            if let Some(screen_info) = required_screen_session(pt_pid, &pt_env)? {
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
                if target_stat.comm == "screen" || target_stat.comm == "SCREEN" {
                    let pt_ancestry = self.get_ancestry(pt_pid)?;
                    if pt_ancestry.contains(&target_pid) {
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

        // Check 5: SSH chain protection
        if self.config.protect_ssh_chains {
            // Check if pt is in an SSH session (needs the process ancestry)
            if let Some(pt_ssh) = required_ssh_connection(pt_pid, &pt_env)? {
                // If target is sshd and in our ancestry, protect it
                if target_stat.comm == "sshd" {
                    let pt_ancestry = self.get_ancestry(pt_pid)?;
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

                // Target environment is required only when pt has an SSH
                // connection to compare. An unrelated unreadable hint must not
                // prevent a valid independent-session decision.
                let target_env = if target_pid == pt_pid {
                    pt_env.clone()
                } else {
                    read_environ(target_pid)?
                };
                if let Some(target_ssh) = required_ssh_connection(target_pid, &target_env)? {
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

        // Build result
        let is_protected = !protection_types.is_empty();
        if !is_protected {
            self.revalidate_stats()?;
        }
        let reason = if is_protected {
            let types: Vec<String> = protection_types.iter().map(|t| t.to_string()).collect();
            Some(format!("protected: {}", types.join(", ")))
        } else {
            None
        };

        let result = if is_protected {
            SessionResult::protected(
                protection_types,
                reason.expect("is_protected is true"),
                evidence,
            )
        } else {
            SessionResult::not_protected()
        };

        Ok(result.with_session_info(
            target_stat.session as u32,
            target_stat.pgrp as u32,
            target_stat.tty_nr,
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn analyze(
        &mut self,
        target_pid: u32,
        _pt_pid: u32,
    ) -> Result<SessionResult, SessionError> {
        Err(SessionError::Unsupported(target_pid))
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
        self.clear_cache();
        let pt_stat = self.get_stat(pt_pid)?;
        let session_id = pt_stat.session;

        let mut members = Vec::new();

        // Walk /proc to find all processes in the same session
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        if let Ok(stat) = self.get_stat(pid) {
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
    analyzer
        .analyze(target_pid, pt_pid)
        .unwrap_or_else(|error| {
            SessionResult::protected(
                vec![],
                format!("session evidence unavailable: {error}"),
                vec![],
            )
        })
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
    #[cfg(target_os = "linux")]
    use crate::collect::parse_proc_stat_content;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_proc_stat_parse() {
        // Full /proc/[pid]/stat format with 22 fields after comm:
        // state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
        // utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss
        let content = "1234 (bash) S 1000 1234 1234 34816 1234 4194304 0 0 0 0 100 50 0 0 20 0 1 0 12345 1048576 256";
        let stat = parse_proc_stat_content(content).unwrap();

        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.comm, "bash");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 1000);
        assert_eq!(stat.pgrp, 1234);
        assert_eq!(stat.session, 1234);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_proc_stat_parse_with_spaces_in_comm() {
        // Full /proc/[pid]/stat format with spaces in comm field
        let content = "5678 (Web Content) S 1000 5678 5678 0 -1 4194304 0 0 0 0 200 100 0 0 20 0 4 0 12345 2097152 512";
        let stat = parse_proc_stat_content(content).unwrap();

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
    fn test_tmux_info_preserves_commas_in_socket_path() {
        let info = TmuxInfo::from_tmux_env("/tmp/work,session/default,12345,0").unwrap();
        assert_eq!(info.socket_path, "/tmp/work,session/default");
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

    /// Session safety on the live OS (Linux /proc, macOS proc_pidinfo + getsid).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod live_session_tests {
        use super::*;
        use std::io::BufRead;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        struct Reap(std::process::Child, Option<u32>);
        impl Drop for Reap {
            fn drop(&mut self) {
                if self.1.is_some() {
                    let leader = self.0.id() as libc::pid_t;
                    // SAFETY: this Child remains unreaped, pinning the leader PID.
                    // Only its verified private session can receive the group signal;
                    // a reaped/reused numeric grandchild PID is never signalled.
                    unsafe {
                        if libc::getpgid(leader) == leader
                            && libc::getsid(leader) == leader
                            && libc::getpgrp() != leader
                        {
                            libc::kill(-leader, libc::SIGKILL);
                        }
                    }
                }
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        /// `sh` leads a new session; returns it plus the pid of a non-leader member.
        fn foreign_session() -> Reap {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "sleep 60 </dev/null >/dev/null 2>&1 & echo $!; wait"])
                .stdout(Stdio::piped())
                .env_remove("SSH_CONNECTION")
                .env_remove("SSH_CLIENT");
            // SAFETY: setsid is async-signal-safe and only affects the child.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut leader = cmd.spawn().expect("spawn");
            let mut line = String::new();
            std::io::BufReader::new(leader.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let member = line.trim().parse().expect("member pid");
            let session = Reap(leader, Some(member));
            let leader_pid = session.0.id() as libc::pid_t;
            // SAFETY: these calls only inspect the owned session and caller.
            unsafe {
                assert_eq!(libc::getpgid(leader_pid), leader_pid);
                assert_eq!(libc::getsid(leader_pid), leader_pid);
                assert_ne!(libc::getpgrp(), leader_pid);
                assert_eq!(libc::getpgid(member as libc::pid_t), leader_pid);
                assert_eq!(libc::getsid(member as libc::pid_t), leader_pid);
            }
            session
        }

        fn types(target: u32) -> Vec<SessionProtectionType> {
            let mut analyzer = SessionAnalyzer::new();
            analyzer
                .analyze(target, std::process::id())
                .expect("analyze")
                .protection_types
        }

        fn unprotected_config() -> SessionConfig {
            SessionConfig {
                max_ancestry_depth: 20,
                protect_same_session: false,
                protect_parent_shells: false,
                protect_multiplexers: false,
                protect_ssh_chains: false,
                protect_foreground_groups: false,
            }
        }

        fn process_with_session_env(vars: &[(&str, String)]) -> Reap {
            let mut command = Command::new("sleep");
            command.arg("60");
            for name in ["TMUX", "STY", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"] {
                command.env_remove(name);
            }
            for (name, value) in vars {
                command.env(name, value);
            }
            Reap(
                command.spawn().expect("spawn session evidence process"),
                None,
            )
        }

        #[test]
        fn session_analysis_does_not_reuse_an_exited_process() {
            let mut target = process_with_session_env(&[]);
            let mut analyzer = SessionAnalyzer::with_config(unprotected_config());
            let pid = target.0.id();
            let result = analyzer.analyze(pid, std::process::id()).unwrap();
            assert!(!result.is_protected);

            target.0.kill().unwrap();
            target.0.wait().unwrap();
            assert!(matches!(
                analyzer.analyze(pid, std::process::id()),
                Err(SessionError::ProcessNotFound(missing)) if missing == pid
            ));
        }

        #[test]
        fn required_ancestry_depth_error_reaches_session_analysis() {
            let target = process_with_session_env(&[]);
            let caller = process_with_session_env(&[]);
            let config = SessionConfig {
                max_ancestry_depth: 0,
                protect_parent_shells: true,
                ..unprotected_config()
            };
            let mut analyzer = SessionAnalyzer::with_config(config);
            assert!(matches!(
                analyzer.analyze(target.0.id(), caller.0.id()),
                Err(SessionError::AncestryDepth { pid, depth: 0 }) if pid == caller.0.id()
            ));
        }

        #[test]
        fn malformed_required_session_hints_do_not_prove_absence() {
            let target = process_with_session_env(&[]);
            for (name, value) in [
                ("TMUX", "/tmp/socket,not-a-pid,0"),
                ("STY", "not-a-pid.session"),
                ("SSH_CONNECTION", "not-a-connection"),
                ("SSH_CLIENT", "127.0.0.1 invalid 22"),
            ] {
                let caller = process_with_session_env(&[(name, value.to_string())]);
                let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                    protect_multiplexers: true,
                    protect_ssh_chains: true,
                    ..unprotected_config()
                });
                let error = analyzer
                    .analyze(target.0.id(), caller.0.id())
                    .expect_err("malformed required evidence must refuse analysis");
                assert!(matches!(error, SessionError::Environment(_)));
                assert!(error.to_string().contains(name), "{error}");
            }
        }

        #[test]
        fn absent_and_disabled_session_hints_allow_independent_processes() {
            let target = process_with_session_env(&[(
                "SSH_CONNECTION",
                "malformed unrelated hint".to_string(),
            )]);
            let caller = process_with_session_env(&[]);
            let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                protect_multiplexers: true,
                protect_ssh_chains: true,
                ..unprotected_config()
            });
            assert!(
                !analyzer
                    .analyze(target.0.id(), caller.0.id())
                    .unwrap()
                    .is_protected
            );

            // Disabled gates need no environment evidence, even for the caller.
            let mut analyzer = SessionAnalyzer::with_config(unprotected_config());
            assert!(
                !analyzer
                    .analyze(caller.0.id(), target.0.id())
                    .unwrap()
                    .is_protected
            );
        }

        #[test]
        fn named_tmux_and_screen_servers_remain_protected() {
            let server = process_with_session_env(&[]);
            for (name, value, expected) in [
                (
                    "TMUX",
                    format!("/tmp/work,session/default,{},0", server.0.id()),
                    SessionProtectionType::TmuxServer,
                ),
                (
                    "STY",
                    format!("{}.pts-0.hostname", server.0.id()),
                    SessionProtectionType::ScreenServer,
                ),
            ] {
                let caller = process_with_session_env(&[(name, value)]);
                let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                    protect_multiplexers: true,
                    ..unprotected_config()
                });
                let result = analyzer.analyze(server.0.id(), caller.0.id()).unwrap();
                assert!(result.is_protected);
                assert!(result.protection_types.contains(&expected), "{result:?}");
            }
        }

        #[test]
        fn matching_ssh_connection_is_protected_but_distinct_peer_is_not() {
            let caller = process_with_session_env(&[(
                "SSH_CONNECTION",
                "127.0.0.1 12345 127.0.0.1 22".to_string(),
            )]);
            let matching =
                process_with_session_env(&[("SSH_CLIENT", "127.0.0.1 12345 22".to_string())]);
            let independent =
                process_with_session_env(&[("SSH_CLIENT", "127.0.0.1 23456 22".to_string())]);
            let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                protect_ssh_chains: true,
                ..unprotected_config()
            });
            let result = analyzer.analyze(matching.0.id(), caller.0.id()).unwrap();
            assert!(result.is_protected);
            assert!(result
                .protection_types
                .contains(&SessionProtectionType::SshChain));
            assert!(
                !analyzer
                    .analyze(independent.0.id(), caller.0.id())
                    .unwrap()
                    .is_protected
            );
        }

        #[test]
        fn own_session_child_is_protected() {
            let child = Reap(Command::new("sleep").arg("60").spawn().unwrap(), None);
            let t = types(child.0.id());
            assert!(t.contains(&SessionProtectionType::SameSession), "{t:?}");
        }

        #[test]
        fn foreign_session_leader_is_protected_member_is_not() {
            let session = foreign_session();
            std::thread::sleep(std::time::Duration::from_millis(200));
            let leader = types(session.0.id());
            assert!(
                leader.contains(&SessionProtectionType::SessionLeader),
                "{leader:?}"
            );
            let member = types(session.1.unwrap());
            assert!(
                !member.contains(&SessionProtectionType::SameSession)
                    && !member.contains(&SessionProtectionType::SessionLeader),
                "{member:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::collect::parse_proc_stat;

        fn stat_fixture(pid: u32, ppid: u32) -> ProcessStat {
            parse_session_stat(
                pid,
                &format!(
                    "{pid} (fixture) S {ppid} 10 10 0 -1 4194304 0 0 0 0 100 50 0 0 20 0 1 0 12345 1048576 256\n"
                ),
            )
            .unwrap()
        }

        #[test]
        fn session_stat_requires_actual_identity_and_session_fields() {
            let valid = "1234 (fixture) S 1000 1234 1234 34816 -1 4194304 0 0 0 0 100 50 0 0 20 0 1 0 12345 1048576 256\n";
            let stat = parse_session_stat(1234, valid).unwrap();
            assert_eq!(stat.session, 1234);
            assert_eq!(stat.tty_nr, 34816);
            assert_eq!(stat.tpgid, -1);
            assert_eq!(stat.starttime, 12345);
            assert!(parse_session_stat(1235, valid).is_err());
            assert!(parse_session_stat(1234, "1234 (fixture) S 1000").is_err());

            let fields: Vec<_> = valid
                .split(") ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .collect();
            for index in [0, 1, 2, 3, 4, 5, 19] {
                let mut corrupt = fields.clone();
                corrupt[index] = "invalid";
                let content = format!("1234 (fixture) {}\n", corrupt.join(" "));
                assert!(
                    matches!(
                        parse_session_stat(1234, &content),
                        Err(SessionError::StatParseError { .. })
                    ),
                    "field {index} must not silently become zero"
                );
            }
            for index in [2, 3] {
                let mut corrupt = fields.clone();
                corrupt[index] = "-1";
                let content = format!("1234 (fixture) {}\n", corrupt.join(" "));
                assert!(parse_session_stat(1234, &content).is_err());
            }
        }

        #[test]
        fn complete_ancestry_accepts_init_and_namespace_boundaries() {
            let mut analyzer = SessionAnalyzer::with_config(SessionConfig {
                max_ancestry_depth: 2,
                ..SessionConfig::default()
            });
            for (pid, ppid) in [(200, 100), (100, 1), (1, 0), (300, 0)] {
                analyzer.stat_cache.insert(pid, stat_fixture(pid, ppid));
            }
            assert_eq!(analyzer.get_ancestry(200).unwrap(), vec![200, 100, 1]);
            assert_eq!(analyzer.get_ancestry(300).unwrap(), vec![300]);
            analyzer.config.max_ancestry_depth = 0;
            assert_eq!(analyzer.get_ancestry(1).unwrap(), vec![1]);
        }

        #[test]
        fn incomplete_ancestry_never_returns_a_partial_success() {
            let mut analyzer = SessionAnalyzer::new();
            analyzer.stat_cache.insert(200, stat_fixture(200, u32::MAX));
            assert!(matches!(
                analyzer.get_ancestry(200),
                Err(SessionError::ProcessNotFound(u32::MAX))
            ));

            analyzer.stat_cache.insert(200, stat_fixture(200, 100));
            analyzer.stat_cache.insert(100, stat_fixture(100, 1));
            analyzer.config.max_ancestry_depth = 1;
            assert!(matches!(
                analyzer.get_ancestry(200),
                Err(SessionError::AncestryDepth { pid: 200, depth: 1 })
            ));
        }

        #[test]
        fn session_ancestry_rejects_self_parent_and_longer_cycles() {
            let mut analyzer = SessionAnalyzer::new();
            analyzer.stat_cache.insert(200, stat_fixture(200, 200));
            assert!(matches!(
                analyzer.get_ancestry(200),
                Err(SessionError::AncestryLoop(200))
            ));
            analyzer.stat_cache.insert(200, stat_fixture(200, 100));
            analyzer.stat_cache.insert(100, stat_fixture(100, 200));
            assert!(matches!(
                analyzer.get_ancestry(200),
                Err(SessionError::AncestryLoop(200))
            ));
        }

        #[test]
        fn convenience_session_checks_refuse_unknown_evidence() {
            let result = is_in_protected_session(u32::MAX, std::process::id());
            assert!(result.is_protected);
            assert!(result
                .reason
                .unwrap()
                .contains("session evidence unavailable"));
            assert!(result.protection_types.is_empty());
            assert!(result.evidence.is_empty());

            let (protected, reason) = check_session_protection(u32::MAX, std::process::id());
            assert!(protected);
            assert!(reason.unwrap().contains("session evidence unavailable"));
        }

        #[test]
        fn test_read_proc_stat_current_process() {
            let pid = std::process::id();
            let stat = parse_proc_stat(pid).expect("should read current process stat");

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
