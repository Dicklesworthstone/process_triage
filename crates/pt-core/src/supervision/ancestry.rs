//! Process ancestry analysis for supervision detection.
//!
//! This module provides the core algorithm for walking the process tree
//! to detect supervisor processes in the ancestry chain.

use super::types::{
    AncestryEntry, EvidenceType, SupervisionEvidence, SupervisionResult, SupervisorDatabase,
};
use crate::collect::proc_parsers::ProcessStat;
#[cfg(target_os = "linux")]
use crate::collect::proc_parsers::{read_required_proc_stat, StatReadError};
use pt_common::ProcessId;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
use thiserror::Error;

/// Maximum depth to walk up the process tree.
const MAX_ANCESTRY_DEPTH: u32 = 20;

/// Errors that can occur during ancestry analysis.
#[derive(Debug, Error)]
pub enum AncestryError {
    #[error("I/O error reading {path} for PID {pid}: {source}")]
    IoError {
        pid: u32,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Parse error at {path} for PID {pid}: {message}")]
    ParseError {
        pid: u32,
        path: String,
        message: String,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Ancestry loop detected at PID {0}")]
    LoopDetected(u32),

    #[error("Ancestry for PID {pid} is incomplete at depth {depth}")]
    DepthLimit { pid: u32, depth: u32 },

    #[error("Process {0} changed while reading ancestry evidence")]
    ProcessChanged(u32),

    #[error("Ancestry evidence for PID {0} is unsupported on this platform")]
    Unsupported(u32),
}

/// Configuration for ancestry analysis.
#[derive(Debug, Clone)]
pub struct AncestryConfig {
    /// Maximum depth to walk.
    pub max_depth: u32,
    /// Whether to include full command line.
    pub include_cmdline: bool,
    /// Supervisor pattern database.
    pub database: SupervisorDatabase,
}

impl Default for AncestryConfig {
    fn default() -> Self {
        Self {
            max_depth: MAX_ANCESTRY_DEPTH,
            include_cmdline: true,
            database: SupervisorDatabase::with_defaults(),
        }
    }
}

/// Last observed process identities, refreshed before each safety decision.
#[derive(Debug, Default)]
pub struct ProcessTreeCache {
    /// Cached (pid -> ppid) mappings.
    ppid_map: HashMap<u32, u32>,
    /// Cached (pid -> comm) mappings.
    comm_map: HashMap<u32, String>,
    /// Birth ticks of the observed process incarnation.
    birth_map: HashMap<u32, u64>,
}

impl ProcessTreeCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate the cache by scanning /proc.
    ///
    /// These initial observations never authorize absence without a fresh read.
    #[cfg(target_os = "linux")]
    pub fn populate(&mut self) -> Result<(), AncestryError> {
        let proc = Path::new("/proc");
        let entries = fs::read_dir(proc).map_err(|e| AncestryError::IoError {
            pid: 0,
            path: "/proc".to_string(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|source| AncestryError::IoError {
                pid: 0,
                path: "/proc".to_string(),
                source,
            })?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process numeric directories (PIDs)
            if let Ok(pid) = name_str.parse::<u32>() {
                // Read stat for PPID and comm
                if let Ok(stat) = read_stat(pid) {
                    self.ppid_map.insert(pid, stat.ppid);
                    self.comm_map.insert(pid, stat.comm);
                    self.birth_map.insert(pid, stat.starttime);
                }
            }
        }

        Ok(())
    }

    /// Refresh before a safety decision: a cached absence is not live evidence.
    fn get_stat(&mut self, pid: u32) -> Result<ProcessStat, AncestryError> {
        let stat = read_stat(pid)?;
        self.ppid_map.insert(pid, stat.ppid);
        self.comm_map.insert(pid, stat.comm.clone());
        self.birth_map.insert(pid, stat.starttime);
        Ok(stat)
    }

    fn get_ppid(&mut self, pid: u32) -> Result<u32, AncestryError> {
        Ok(self.get_stat(pid)?.ppid)
    }
}

/// Read PPID and comm from /proc/<pid>/stat.
#[cfg(target_os = "linux")]
pub(super) fn read_stat(pid: u32) -> Result<ProcessStat, AncestryError> {
    read_required_proc_stat(pid).map_err(|error| match error {
        StatReadError::Read { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            AncestryError::ProcessNotFound(pid)
        }
        StatReadError::Read { source, .. } => AncestryError::IoError {
            pid,
            path: format!("/proc/{pid}/stat"),
            source,
        },
        StatReadError::Parse { reason, .. } => AncestryError::ParseError {
            pid,
            path: format!("/proc/{pid}/stat"),
            message: reason,
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn read_stat(pid: u32) -> Result<ProcessStat, AncestryError> {
    Err(AncestryError::Unsupported(pid))
}

/// Read cmdline from /proc/<pid>/cmdline.
#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Result<String, AncestryError> {
    let path = format!("/proc/{pid}/cmdline");
    let bytes = fs::read(&path).map_err(|source| AncestryError::IoError {
        pid,
        path: path.clone(),
        source,
    })?;
    let content = std::str::from_utf8(&bytes).map_err(|_| AncestryError::ParseError {
        pid,
        path,
        message: "invalid command-line UTF-8".to_string(),
    })?;
    Ok(content
        .split('\0')
        .filter(|arg| !arg.is_empty())
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(not(target_os = "linux"))]
fn read_cmdline(pid: u32) -> Result<String, AncestryError> {
    Err(AncestryError::Unsupported(pid))
}

/// Analyzer for process ancestry and supervision detection.
pub struct AncestryAnalyzer {
    config: AncestryConfig,
    cache: ProcessTreeCache,
}

impl AncestryAnalyzer {
    /// Create a new analyzer with default configuration.
    pub fn new() -> Self {
        Self {
            config: AncestryConfig::default(),
            cache: ProcessTreeCache::new(),
        }
    }

    /// Create an analyzer with custom configuration.
    pub fn with_config(config: AncestryConfig) -> Self {
        Self {
            config,
            cache: ProcessTreeCache::new(),
        }
    }

    /// Pre-populate the process tree cache.
    #[cfg(target_os = "linux")]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        self.cache.populate()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        Ok(())
    }

    /// Analyze a process for supervision by walking its ancestry.
    pub fn analyze(&mut self, pid: u32) -> Result<SupervisionResult, AncestryError> {
        if pid == 0 {
            return Err(AncestryError::ProcessNotFound(pid));
        }
        let mut ancestry_chain = Vec::new();
        let mut current_pid = pid;
        let mut visited = std::collections::HashSet::new();
        let mut depth = 0u32;

        // Walk up the process tree
        while current_pid != 0 && depth < self.config.max_depth {
            // Loop detection
            if !visited.insert(current_pid) {
                return Err(AncestryError::LoopDetected(current_pid));
            }

            // Get process info
            let stat = self.cache.get_stat(current_pid)?;
            let comm = stat.comm.clone();

            let cmdline = if self.config.include_cmdline {
                let command = read_cmdline(current_pid)?;
                let after = read_stat(current_pid)?;
                if after.starttime != stat.starttime
                    || after.ppid != stat.ppid
                    || after.comm != stat.comm
                {
                    return Err(AncestryError::ProcessChanged(current_pid));
                }
                Some(command)
            } else {
                None
            };

            // Add to ancestry chain
            ancestry_chain.push(AncestryEntry {
                pid: ProcessId(current_pid),
                comm: comm.clone(),
                cmdline,
            });

            // Check for supervisor match (skip the first entry - that's the process itself)
            if depth > 0 {
                let matches = self.config.database.find_matches(&comm);
                if let Some(pattern) = matches.first() {
                    // Found a supervisor in ancestry
                    let evidence = vec![SupervisionEvidence {
                        evidence_type: EvidenceType::Ancestry,
                        description: format!(
                            "Ancestor PID {} ({}) matches supervisor pattern '{}'",
                            current_pid, comm, pattern.name
                        ),
                        weight: pattern.confidence_weight,
                    }];

                    return Ok(SupervisionResult::supervised_by_ancestry(
                        pattern.category,
                        pattern.name.clone(),
                        ProcessId(current_pid),
                        depth,
                        pattern.confidence_weight,
                        evidence,
                        ancestry_chain,
                    ));
                }
            }

            // Move to parent
            let ppid = stat.ppid;
            if ppid == 0 {
                return Ok(SupervisionResult::not_supervised(ancestry_chain));
            }
            if ppid == current_pid {
                return Err(AncestryError::LoopDetected(current_pid));
            }

            current_pid = ppid;
            depth += 1;
        }

        Err(AncestryError::DepthLimit { pid, depth })
    }

    /// Check if a process is orphaned (parent is init).
    pub fn is_orphan(&mut self, pid: u32) -> Result<bool, AncestryError> {
        let ppid = self.cache.get_ppid(pid)?;
        Ok(ppid == 1)
    }

    /// Get the full ancestry chain for a process.
    pub fn get_ancestry(&mut self, pid: u32) -> Result<Vec<AncestryEntry>, AncestryError> {
        let result = self.analyze(pid)?;
        Ok(result.ancestry_chain)
    }
}

impl Default for AncestryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to analyze a single process.
pub fn analyze_supervision(pid: u32) -> Result<SupervisionResult, AncestryError> {
    let mut analyzer = AncestryAnalyzer::new();
    analyzer.analyze(pid)
}

/// Analyze multiple processes efficiently with cache sharing.
pub fn analyze_supervision_batch(
    pids: &[u32],
) -> Result<Vec<(u32, SupervisionResult)>, AncestryError> {
    let mut analyzer = AncestryAnalyzer::new();

    // Pre-populate cache for efficiency
    #[cfg(target_os = "linux")]
    analyzer.populate_cache()?;

    let mut results = Vec::with_capacity(pids.len());
    for &pid in pids {
        match analyzer.analyze(pid) {
            Ok(result) => results.push((pid, result)),
            Err(AncestryError::ProcessNotFound(missing)) if missing == pid => {
                // Process may have exited, skip it
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::proc_parsers::parse_proc_stat_content;

    #[test]
    fn test_parse_stat_simple() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "1234 (bash) S 1000 1234 1234 0 -1";
        let stat = parse_proc_stat_content(content).unwrap();
        assert_eq!(stat.ppid, 1000); // ppid is field 3 (index 1 after comm)
        assert_eq!(stat.comm, "bash");
    }

    #[test]
    fn test_parse_stat_with_parens_in_comm() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "5678 (my (weird) process) S 1234 5678 5678 0 -1";
        let stat = parse_proc_stat_content(content).unwrap();
        assert_eq!(stat.ppid, 1234); // ppid is 1234
        assert_eq!(stat.comm, "my (weird) process");
    }

    #[test]
    fn test_parse_stat_with_spaces() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "9999 (Web Content) S 1000 9999 9999 0 -1";
        let stat = parse_proc_stat_content(content).unwrap();
        assert_eq!(stat.ppid, 1000); // ppid is 1000
        assert_eq!(stat.comm, "Web Content");
    }

    #[test]
    fn test_ancestry_analyzer_default() {
        let analyzer = AncestryAnalyzer::new();
        assert_eq!(analyzer.config.max_depth, MAX_ANCESTRY_DEPTH);
        assert!(analyzer.config.include_cmdline);
    }

    #[test]
    fn test_ancestry_config_default() {
        let config = AncestryConfig::default();
        assert_eq!(config.max_depth, 20);
        assert!(config.include_cmdline);
        assert!(!config.database.patterns.is_empty());
    }

    #[test]
    fn test_process_tree_cache_new() {
        let cache = ProcessTreeCache::new();
        assert!(cache.ppid_map.is_empty());
        assert!(cache.comm_map.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cached_ancestry_cannot_supply_missing_or_stale_evidence() {
        let mut cache = ProcessTreeCache::new();
        cache.ppid_map.insert(u32::MAX, 0);
        cache
            .comm_map
            .insert(u32::MAX, "cached absence".to_string());
        cache.birth_map.insert(u32::MAX, 1);
        assert!(
            matches!(cache.get_stat(u32::MAX), Err(AncestryError::ProcessNotFound(pid)) if pid == u32::MAX)
        );
        let pid = std::process::id();
        let live = read_stat(pid).unwrap();
        cache.ppid_map.insert(pid, 0);
        cache.comm_map.insert(pid, "stale command".to_string());
        cache.birth_map.insert(pid, u64::MAX);
        let refreshed = cache.get_stat(pid).unwrap();
        assert_eq!(refreshed.ppid, live.ppid);
        assert_eq!(refreshed.starttime, live.starttime);
        assert_eq!(cache.birth_map[&pid], live.starttime);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ancestry_requires_an_observed_root_before_returning_absence() {
        let mut truncated = AncestryAnalyzer::with_config(AncestryConfig {
            max_depth: 1,
            include_cmdline: false,
            database: SupervisorDatabase::new(),
        });
        let pid = std::process::id();
        assert_ne!(read_stat(pid).unwrap().ppid, 0);
        assert!(
            matches!(truncated.analyze(pid), Err(AncestryError::DepthLimit { pid: failed, depth: 1 }) if failed == pid)
        );
        let mut root = AncestryAnalyzer::with_config(AncestryConfig {
            include_cmdline: false,
            database: SupervisorDatabase::new(),
            ..AncestryConfig::default()
        });
        let observed = read_stat(1).unwrap();
        assert_eq!(observed.ppid, 0);
        let result = root.analyze(1).unwrap();
        assert!(!result.is_supervised);
        assert_eq!(result.ancestry_chain.len(), 1);
        assert_eq!(result.ancestry_chain[0].pid.0, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_analyze_current_process() {
        let pid = std::process::id();
        let mut analyzer = AncestryAnalyzer::new();

        let result = analyzer
            .analyze(pid)
            .expect("should analyze current process");

        // Current process should have an ancestry chain
        assert!(!result.ancestry_chain.is_empty());

        // First entry should be this process
        assert_eq!(result.ancestry_chain[0].pid.0, pid);

        // Should be able to find comm
        let comm = &result.ancestry_chain[0].comm;
        assert!(!comm.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_analyze_init_process() {
        let mut analyzer = AncestryAnalyzer::new();

        // PID 1 might not be readable, so we just check it doesn't panic
        let _ = analyzer.analyze(1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_orphan_check() {
        let mut analyzer = AncestryAnalyzer::new();
        let pid = std::process::id();

        // Current process is probably not orphaned
        let is_orphan = analyzer.is_orphan(pid).expect("should check orphan status");
        // We can't assert the value, but it should complete without error
        let _ = is_orphan;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_batch_analysis() {
        let pid = std::process::id();
        let results = analyze_supervision_batch(&[pid]).expect("batch analysis should work");

        assert!(!results.is_empty());
        assert_eq!(results[0].0, pid);
    }
}
