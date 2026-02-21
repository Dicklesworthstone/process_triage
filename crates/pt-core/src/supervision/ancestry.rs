//! Process ancestry analysis for supervision detection.
//!
//! This module provides the core algorithm for walking the process tree
//! to detect supervisor processes in the ancestry chain.

use super::types::{
    AncestryEntry, EvidenceType, SupervisionEvidence, SupervisionResult, SupervisorDatabase,
};
use pt_common::ProcessId;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Maximum depth to walk up the process tree.
const MAX_ANCESTRY_DEPTH: u32 = 20;

/// Errors that can occur during ancestry analysis.
#[derive(Debug, Error)]
pub enum AncestryError {
    #[error("I/O error reading /proc/{pid}: {source}")]
    IoError {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Parse error for /proc/{pid}/stat: {message}")]
    ParseError { pid: u32, message: String },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Ancestry loop detected at PID {0}")]
    LoopDetected(u32),
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

/// Process tree cache for efficient batch analysis.
#[derive(Debug, Default)]
pub struct ProcessTreeCache {
    /// Cached (pid -> ppid) mappings.
    ppid_map: HashMap<u32, u32>,
    /// Cached (pid -> comm) mappings.
    comm_map: HashMap<u32, String>,
    /// Cached (pid -> cmdline) mappings.
    cmdline_map: HashMap<u32, String>,
}

impl ProcessTreeCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate the cache by scanning /proc.
    ///
    /// This is more efficient for batch analysis than reading on-demand.
    #[cfg(target_os = "linux")]
    pub fn populate(&mut self) -> Result<(), AncestryError> {
        let proc = Path::new("/proc");
        if !proc.exists() {
            return Ok(());
        }

        let entries =
            fs::read_dir(proc).map_err(|e| AncestryError::IoError { pid: 0, source: e })?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process numeric directories (PIDs)
            if let Ok(pid) = name_str.parse::<u32>() {
                // Read stat for PPID and comm
                if let Ok((ppid, comm)) = read_stat(pid) {
                    self.ppid_map.insert(pid, ppid);
                    self.comm_map.insert(pid, comm);
                }

                // Read cmdline
                if let Ok(cmdline) = read_cmdline(pid) {
                    self.cmdline_map.insert(pid, cmdline);
                }
            }
        }

        Ok(())
    }

    /// Get PPID from cache or read from /proc.
    fn get_ppid(&mut self, pid: u32) -> Result<u32, AncestryError> {
        if let Some(&ppid) = self.ppid_map.get(&pid) {
            return Ok(ppid);
        }

        let (ppid, comm) = read_stat(pid)?;
        self.ppid_map.insert(pid, ppid);
        self.comm_map.insert(pid, comm);
        Ok(ppid)
    }

    /// Get comm from cache or read from /proc.
    fn get_comm(&mut self, pid: u32) -> Result<String, AncestryError> {
        if let Some(comm) = self.comm_map.get(&pid) {
            return Ok(comm.clone());
        }

        let (ppid, comm) = read_stat(pid)?;
        self.ppid_map.insert(pid, ppid);
        self.comm_map.insert(pid, comm.clone());
        Ok(comm)
    }

    /// Get cmdline from cache or read from /proc.
    fn get_cmdline(&mut self, pid: u32) -> Option<String> {
        if let Some(cmdline) = self.cmdline_map.get(&pid) {
            return Some(cmdline.clone());
        }

        if let Ok(cmdline) = read_cmdline(pid) {
            self.cmdline_map.insert(pid, cmdline.clone());
            return Some(cmdline);
        }

        None
    }
}

/// Read PPID and comm from /proc/<pid>/stat.
#[cfg(target_os = "linux")]
fn read_stat(pid: u32) -> Result<(u32, String), AncestryError> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&stat_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AncestryError::ProcessNotFound(pid)
        } else {
            AncestryError::IoError { pid, source: e }
        }
    })?;

    parse_stat(&content, pid)
}

#[cfg(not(target_os = "linux"))]
fn read_stat(pid: u32) -> Result<(u32, String), AncestryError> {
    Err(AncestryError::ProcessNotFound(pid))
}

/// Parse /proc/<pid>/stat content to extract PPID and comm.
#[doc(hidden)]
pub(crate) fn parse_stat(content: &str, pid: u32) -> Result<(u32, String), AncestryError> {
    // Format: pid (comm) state ppid ...
    // The comm can contain spaces and parentheses, so find the last ')' first

    let open_paren = content.find('(').ok_or_else(|| AncestryError::ParseError {
        pid,
        message: "missing '(' in stat".to_string(),
    })?;

    let close_paren = content
        .rfind(')')
        .ok_or_else(|| AncestryError::ParseError {
            pid,
            message: "missing ')' in stat".to_string(),
        })?;

    let comm = content[open_paren + 1..close_paren].to_string();

    // Rest of the fields after the closing paren
    let rest = content.get(close_paren + 2..).ok_or_else(|| AncestryError::ParseError {
        pid,
        message: "content truncated after comm".to_string(),
    })?; // Skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // Field 0 after comm is state, field 1 is ppid
    if fields.len() < 2 {
        return Err(AncestryError::ParseError {
            pid,
            message: "too few fields after comm".to_string(),
        });
    }

    let ppid = fields[1]
        .parse::<u32>()
        .map_err(|_| AncestryError::ParseError {
            pid,
            message: format!("invalid ppid: {}", fields[1]),
        })?;

    Ok((ppid, comm))
}

/// Read cmdline from /proc/<pid>/cmdline.
#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Result<String, AncestryError> {
    let path = format!("/proc/{}/cmdline", pid);
    let content =
        fs::read_to_string(&path).map_err(|e| AncestryError::IoError { pid, source: e })?;

    // cmdline uses NUL as separator
    Ok(content.replace('\0', " ").trim().to_string())
}

#[cfg(not(target_os = "linux"))]
fn read_cmdline(_pid: u32) -> Result<String, AncestryError> {
    Ok(String::new())
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
            let comm = match self.cache.get_comm(current_pid) {
                Ok(c) => c,
                Err(AncestryError::ProcessNotFound(_)) if current_pid == 1 => {
                    // PID 1 may not be readable, that's OK
                    break;
                }
                Err(e) => return Err(e),
            };

            let cmdline = if self.config.include_cmdline {
                self.cache.get_cmdline(current_pid)
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
            let ppid = match self.cache.get_ppid(current_pid) {
                Ok(p) => p,
                Err(AncestryError::ProcessNotFound(_)) => break,
                Err(e) => return Err(e),
            };

            if ppid == current_pid || ppid == 0 {
                break; // Reached init or self-parented
            }

            current_pid = ppid;
            depth += 1;
        }

        // No supervisor found
        Ok(SupervisionResult::not_supervised(ancestry_chain))
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
            Err(AncestryError::ProcessNotFound(_)) => {
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

    #[test]
    fn test_parse_stat_simple() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "1234 (bash) S 1000 1234 1234 0 -1";
        let (ppid, comm) = parse_stat(content, 1234).unwrap();
        assert_eq!(ppid, 1000); // ppid is field 3 (index 1 after comm)
        assert_eq!(comm, "bash");
    }

    #[test]
    fn test_parse_stat_with_parens_in_comm() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "5678 (my (weird) process) S 1234 5678 5678 0 -1";
        let (ppid, comm) = parse_stat(content, 5678).unwrap();
        assert_eq!(ppid, 1234); // ppid is 1234
        assert_eq!(comm, "my (weird) process");
    }

    #[test]
    fn test_parse_stat_with_spaces() {
        // Format: pid (comm) state ppid pgrp session ...
        let content = "9999 (Web Content) S 1000 9999 9999 0 -1";
        let (ppid, comm) = parse_stat(content, 9999).unwrap();
        assert_eq!(ppid, 1000); // ppid is 1000
        assert_eq!(comm, "Web Content");
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
