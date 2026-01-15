//! Parsers for /proc filesystem entries (Linux-only).
//!
//! This module provides parsers for various /proc/<pid>/* files
//! to extract detailed process information.
//!
//! TODO: Full implementation pending.

/// Parse /proc/<pid>/stat file.
///
/// TODO: Full implementation pending.
pub fn parse_proc_stat(_content: &str) -> Option<ProcStat> {
    None
}

/// Parsed contents of /proc/<pid>/stat.
#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub tty_nr: u32,
    // TODO: Add more fields when implementing
}

/// Parse /proc/<pid>/status file.
///
/// TODO: Full implementation pending.
pub fn parse_proc_status(_content: &str) -> Option<ProcStatus> {
    None
}

/// Parsed contents of /proc/<pid>/status.
#[derive(Debug, Clone)]
pub struct ProcStatus {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    // TODO: Add more fields when implementing
}
