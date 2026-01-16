//! Protected process filtering at scan phase.
//!
//! This module filters out protected processes early in the pipeline,
//! before inference scoring. This is more efficient than scoring first
//! and blocking later, and provides better UX by not showing protected
//! processes as candidates.
//!
//! # Architecture
//!
//! ```text
//! Quick/Deep Scan → ProtectedFilter → Inference → Decision
//!                         ↑
//!                   policy.json
//!                   (guardrails.protected_patterns)
//! ```
//!
//! # Pattern Matching
//!
//! Patterns are matched against multiple process fields for comprehensive protection:
//! - `comm`: Process basename (e.g., "sshd")
//! - `cmd`: Full command line (e.g., "/usr/sbin/sshd -D")
//! - `user`: Process owner username
//!
//! This ensures protection works whether the policy specifies a short name
//! or full path pattern.
//!
//! # Usage
//!
//! ```ignore
//! let filter = ProtectedFilter::new(&policy.guardrails)?;
//! let filtered_result = filter.filter_scan_result(&scan_result);
//! // Now inference only processes non-protected candidates
//! ```

use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, trace};

use super::types::{ProcessRecord, ScanResult};

/// Errors during protected filter setup.
#[derive(Debug, Error)]
pub enum ProtectedFilterError {
    #[error("invalid pattern at {path}: {message}")]
    InvalidPattern { path: String, message: String },
}

/// A compiled pattern for matching protected processes.
#[derive(Debug, Clone)]
pub struct CompiledProtectedPattern {
    /// Original pattern string.
    pub original: String,
    /// Pattern kind (regex, glob, literal).
    pub kind: PatternKind,
    /// Compiled regex (for regex and glob patterns).
    regex: Option<Regex>,
    /// Case insensitivity flag.
    case_insensitive: bool,
    /// Human-readable notes about why this is protected.
    pub notes: Option<String>,
}

/// Pattern matching type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Regex,
    Glob,
    Literal,
}

impl CompiledProtectedPattern {
    /// Compile a pattern entry from policy configuration.
    pub fn compile(
        pattern: &str,
        kind_str: &str,
        case_insensitive: bool,
        notes: Option<String>,
        path: &str,
    ) -> Result<Self, ProtectedFilterError> {
        let kind = match kind_str.to_lowercase().as_str() {
            "regex" => PatternKind::Regex,
            "glob" => PatternKind::Glob,
            "literal" => PatternKind::Literal,
            other => {
                return Err(ProtectedFilterError::InvalidPattern {
                    path: path.to_string(),
                    message: format!("unknown pattern kind: {other}"),
                })
            }
        };

        let regex = match kind {
            PatternKind::Regex => {
                let re_pattern = if case_insensitive {
                    format!("(?i){}", pattern)
                } else {
                    pattern.to_string()
                };
                Some(
                    Regex::new(&re_pattern).map_err(|e| ProtectedFilterError::InvalidPattern {
                        path: path.to_string(),
                        message: e.to_string(),
                    })?,
                )
            }
            PatternKind::Glob => {
                let regex_str = glob_to_regex(pattern);
                let full_pattern = if case_insensitive {
                    format!("(?i){}", regex_str)
                } else {
                    regex_str
                };
                Some(Regex::new(&full_pattern).map_err(|e| {
                    ProtectedFilterError::InvalidPattern {
                        path: path.to_string(),
                        message: e.to_string(),
                    }
                })?)
            }
            PatternKind::Literal => None, // Use string matching
        };

        Ok(Self {
            original: pattern.to_string(),
            kind,
            regex,
            case_insensitive,
            notes,
        })
    }

    /// Check if text matches this pattern.
    pub fn matches(&self, text: &str) -> bool {
        match self.kind {
            PatternKind::Regex | PatternKind::Glob => self
                .regex
                .as_ref()
                .map(|r| r.is_match(text))
                .unwrap_or(false),
            PatternKind::Literal => {
                if self.case_insensitive {
                    text.to_lowercase().contains(&self.original.to_lowercase())
                } else {
                    text.contains(&self.original)
                }
            }
        }
    }
}

/// Convert glob pattern to regex.
fn glob_to_regex(glob: &str) -> String {
    let mut regex_str = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                // Check for ** (recursive match)
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    // Check if followed by / (e.g., **/ means zero or more directories)
                    if i + 2 < chars.len() && chars[i + 2] == '/' {
                        // **/ should match zero or more path segments including trailing /
                        regex_str.push_str("(.*/)?");
                        i += 3; // Skip **, and /
                        continue;
                    }
                    // Plain ** matches anything (greedy)
                    regex_str.push_str(".*");
                    i += 2;
                    continue;
                }
                // Single * matches anything except /
                regex_str.push_str("[^/]*");
            }
            '?' => regex_str.push('.'),
            '[' => {
                // Character class - find matching ] and pass through
                let start = i;
                i += 1;
                // Handle negation and initial ]
                if i < chars.len() && (chars[i] == '!' || chars[i] == '^') {
                    i += 1;
                }
                if i < chars.len() && chars[i] == ']' {
                    i += 1;
                }
                // Find closing ]
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                if i < chars.len() {
                    // Valid character class - convert ! to ^ for negation
                    let class_content: String = chars[start..=i].iter().collect();
                    let converted = class_content.replace("[!", "[^");
                    regex_str.push_str(&converted);
                } else {
                    // No closing ] - escape the [
                    regex_str.push_str("\\[");
                    i = start; // Reset to just after [
                }
            }
            '.' | '+' | '(' | ')' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(c);
            }
            _ => regex_str.push(c),
        }
        i += 1;
    }
    regex_str.push('$');
    regex_str
}

/// Information about why a process was filtered as protected.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectedMatch {
    /// PID of the filtered process.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Full command line (truncated for logging).
    pub cmd_truncated: String,
    /// Which field matched the pattern.
    pub matched_field: MatchedField,
    /// The pattern that matched.
    pub pattern: String,
    /// Notes from the pattern (if any).
    pub notes: Option<String>,
}

/// Which field of the process matched the protected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedField {
    /// Matched against comm (process basename).
    Comm,
    /// Matched against cmd (full command line).
    Cmd,
    /// Matched against user.
    User,
    /// Matched against protected PID list.
    Pid,
    /// Matched against protected PPID list.
    Ppid,
}

/// Result of filtering protected processes.
#[derive(Debug, Clone, Serialize)]
pub struct FilterResult {
    /// Processes that passed the filter (not protected).
    pub passed: Vec<ProcessRecord>,
    /// Information about filtered processes.
    pub filtered: Vec<ProtectedMatch>,
    /// Number of processes before filtering.
    pub total_before: usize,
    /// Number of processes after filtering.
    pub total_after: usize,
}

/// Filter for protected processes.
///
/// Compiled patterns and lookup sets for efficient filtering at scan phase.
pub struct ProtectedFilter {
    /// Compiled protected patterns.
    patterns: Vec<CompiledProtectedPattern>,
    /// Protected users (lowercase for case-insensitive matching).
    protected_users: HashSet<String>,
    /// Protected PIDs.
    protected_pids: HashSet<u32>,
    /// Protected PPIDs (processes with these parents are protected).
    protected_ppids: HashSet<u32>,
}

impl ProtectedFilter {
    /// Create a new filter from guardrails configuration.
    ///
    /// # Arguments
    /// * `protected_patterns` - List of pattern entries from policy
    /// * `protected_users` - List of protected usernames
    /// * `never_kill_pid` - List of PIDs that are always protected
    /// * `never_kill_ppid` - List of PPIDs whose children are protected
    pub fn new(
        protected_patterns: &[(String, String, bool, Option<String>)],
        protected_users: &[String],
        never_kill_pid: &[u32],
        never_kill_ppid: &[u32],
    ) -> Result<Self, ProtectedFilterError> {
        let patterns = protected_patterns
            .iter()
            .enumerate()
            .map(|(i, (pattern, kind, case_insensitive, notes))| {
                CompiledProtectedPattern::compile(
                    pattern,
                    kind,
                    *case_insensitive,
                    notes.clone(),
                    &format!("protected_patterns[{i}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let protected_users: HashSet<String> =
            protected_users.iter().map(|u| u.to_lowercase()).collect();

        let protected_pids: HashSet<u32> = never_kill_pid.iter().copied().collect();
        let protected_ppids: HashSet<u32> = never_kill_ppid.iter().copied().collect();

        debug!(
            patterns = patterns.len(),
            users = protected_users.len(),
            pids = protected_pids.len(),
            ppids = protected_ppids.len(),
            "Protected filter initialized"
        );

        Ok(Self {
            patterns,
            protected_users,
            protected_pids,
            protected_ppids,
        })
    }

    /// Create a filter from policy guardrails struct.
    ///
    /// This is a convenience constructor that extracts fields from the policy types.
    pub fn from_guardrails(
        guardrails: &crate::config::policy::Guardrails,
    ) -> Result<Self, ProtectedFilterError> {
        let patterns: Vec<(String, String, bool, Option<String>)> = guardrails
            .protected_patterns
            .iter()
            .map(|p| {
                (
                    p.pattern.clone(),
                    p.kind.as_str().to_string(),
                    p.case_insensitive,
                    p.notes.clone(),
                )
            })
            .collect();

        Self::new(
            &patterns,
            &guardrails.protected_users,
            &guardrails
                .never_kill_pid
                .iter()
                .map(|&x| x as u32)
                .collect::<Vec<_>>(),
            &guardrails
                .never_kill_ppid
                .iter()
                .map(|&x| x as u32)
                .collect::<Vec<_>>(),
        )
    }

    /// Check if a process record is protected.
    ///
    /// Returns `Some(ProtectedMatch)` if protected, `None` if not.
    pub fn is_protected(&self, record: &ProcessRecord) -> Option<ProtectedMatch> {
        let pid = record.pid.0;
        let ppid = record.ppid.0;

        // Check protected PIDs first (fast lookup)
        if self.protected_pids.contains(&pid) {
            trace!(pid, "Process matches protected PID");
            return Some(ProtectedMatch {
                pid,
                comm: record.comm.clone(),
                cmd_truncated: truncate_cmd(&record.cmd, 80),
                matched_field: MatchedField::Pid,
                pattern: format!("never_kill_pid[{}]", pid),
                notes: Some("PID is in never_kill_pid list".to_string()),
            });
        }

        // Check protected PPIDs
        if self.protected_ppids.contains(&ppid) {
            trace!(pid, ppid, "Process matches protected PPID");
            return Some(ProtectedMatch {
                pid,
                comm: record.comm.clone(),
                cmd_truncated: truncate_cmd(&record.cmd, 80),
                matched_field: MatchedField::Ppid,
                pattern: format!("never_kill_ppid[{}]", ppid),
                notes: Some("Parent PID is in never_kill_ppid list".to_string()),
            });
        }

        // Check protected users
        if self.protected_users.contains(&record.user.to_lowercase()) {
            trace!(pid, user = %record.user, "Process matches protected user");
            return Some(ProtectedMatch {
                pid,
                comm: record.comm.clone(),
                cmd_truncated: truncate_cmd(&record.cmd, 80),
                matched_field: MatchedField::User,
                pattern: record.user.clone(),
                notes: Some("User is in protected_users list".to_string()),
            });
        }

        // Check patterns against comm (basename) first
        for pattern in &self.patterns {
            if pattern.matches(&record.comm) {
                trace!(
                    pid,
                    comm = %record.comm,
                    pattern = %pattern.original,
                    "Process comm matches protected pattern"
                );
                return Some(ProtectedMatch {
                    pid,
                    comm: record.comm.clone(),
                    cmd_truncated: truncate_cmd(&record.cmd, 80),
                    matched_field: MatchedField::Comm,
                    pattern: pattern.original.clone(),
                    notes: pattern.notes.clone(),
                });
            }
        }

        // Check patterns against full command line
        for pattern in &self.patterns {
            if pattern.matches(&record.cmd) {
                trace!(
                    pid,
                    cmd = %truncate_cmd(&record.cmd, 60),
                    pattern = %pattern.original,
                    "Process cmd matches protected pattern"
                );
                return Some(ProtectedMatch {
                    pid,
                    comm: record.comm.clone(),
                    cmd_truncated: truncate_cmd(&record.cmd, 80),
                    matched_field: MatchedField::Cmd,
                    pattern: pattern.original.clone(),
                    notes: pattern.notes.clone(),
                });
            }
        }

        None
    }

    /// Filter a scan result, removing protected processes.
    ///
    /// Returns a `FilterResult` containing passed processes and filtered info.
    pub fn filter_scan_result(&self, scan_result: &ScanResult) -> FilterResult {
        let total_before = scan_result.processes.len();
        let mut passed = Vec::with_capacity(total_before);
        let mut filtered = Vec::new();

        for record in &scan_result.processes {
            if let Some(match_info) = self.is_protected(record) {
                debug!(
                    pid = record.pid.0,
                    comm = %record.comm,
                    pattern = %match_info.pattern,
                    field = ?match_info.matched_field,
                    "Filtered protected process"
                );
                filtered.push(match_info);
            } else {
                passed.push(record.clone());
            }
        }

        let total_after = passed.len();

        if !filtered.is_empty() {
            debug!(
                filtered_count = filtered.len(),
                passed_count = total_after,
                "Protected filter completed"
            );
        }

        FilterResult {
            passed,
            filtered,
            total_before,
            total_after,
        }
    }

    /// Get the number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get the list of protected users.
    pub fn protected_users(&self) -> &HashSet<String> {
        &self.protected_users
    }

    /// Get the list of protected PIDs.
    pub fn protected_pids(&self) -> &HashSet<u32> {
        &self.protected_pids
    }

    /// Check if any pattern matches the given text.
    ///
    /// Returns the original pattern string if matched, None otherwise.
    /// This is useful for pre-check validation without a full ProcessRecord.
    pub fn matches_any_pattern(&self, text: &str) -> Option<&str> {
        for pattern in &self.patterns {
            if pattern.matches(text) {
                return Some(&pattern.original);
            }
        }
        None
    }
}

/// Truncate command line for logging (avoid huge logs).
fn truncate_cmd(cmd: &str, max_len: usize) -> String {
    if cmd.len() <= max_len {
        cmd.to_string()
    } else {
        format!("{}...", &cmd[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::{ProcessId, StartId};
    use std::time::Duration;

    fn make_test_record(pid: u32, ppid: u32, comm: &str, cmd: &str, user: &str) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(ppid),
            uid: 1000,
            user: user.to_string(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId::from_linux("test-boot-id", 1234567890, pid),
            comm: comm.to_string(),
            cmd: cmd.to_string(),
            state: super::super::types::ProcessState::Running,
            cpu_percent: 0.0,
            rss_bytes: 1024 * 1024,
            vsz_bytes: 2 * 1024 * 1024,
            tty: None,
            start_time_unix: 1234567890,
            elapsed: Duration::from_secs(3600),
            source: "test".to_string(),
        }
    }

    #[test]
    fn test_literal_pattern_matches_comm() {
        let patterns = vec![(
            "sshd".to_string(),
            "literal".to_string(),
            true,
            Some("SSH daemon".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();
        let record = make_test_record(1000, 1, "sshd", "/usr/sbin/sshd -D", "root");

        let result = filter.is_protected(&record);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.matched_field, MatchedField::Comm);
        assert_eq!(m.pattern, "sshd");
    }

    #[test]
    fn test_literal_pattern_matches_cmd() {
        let patterns = vec![(
            "/usr/sbin/sshd".to_string(),
            "literal".to_string(),
            false,
            None,
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();
        let record = make_test_record(1000, 1, "sshd", "/usr/sbin/sshd -D", "testuser");

        let result = filter.is_protected(&record);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.matched_field, MatchedField::Cmd);
    }

    #[test]
    fn test_regex_pattern_word_boundary() {
        let patterns = vec![(
            r"\bsystemd\b".to_string(),
            "regex".to_string(),
            true,
            Some("systemd".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        // Should match systemd
        let record = make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root");
        assert!(filter.is_protected(&record).is_some());

        // Should NOT match systemd-logind (due to word boundary)
        let record = make_test_record(
            100,
            1,
            "systemd-logind",
            "/usr/lib/systemd/systemd-logind",
            "root",
        );
        // Note: \b in regex matches word boundaries, so "systemd" in "systemd-logind" would still match
        // because there's a word boundary after systemd and before the hyphen
        assert!(filter.is_protected(&record).is_some());
    }

    #[test]
    fn test_glob_pattern_wildcard() {
        let patterns = vec![(
            "/usr/lib/systemd/*".to_string(),
            "glob".to_string(),
            false,
            None,
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        // Should match
        let record = make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root");
        assert!(filter.is_protected(&record).is_some());

        // Should NOT match
        let record = make_test_record(100, 1, "bash", "/bin/bash", "testuser");
        assert!(filter.is_protected(&record).is_none());
    }

    #[test]
    fn test_protected_user() {
        let filter = ProtectedFilter::new(&[], &["root".to_string()], &[], &[]).unwrap();

        let record = make_test_record(1000, 1, "bash", "/bin/bash", "root");
        let result = filter.is_protected(&record);
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_field, MatchedField::User);

        let record = make_test_record(1001, 1, "bash", "/bin/bash", "testuser");
        assert!(filter.is_protected(&record).is_none());
    }

    #[test]
    fn test_protected_user_case_insensitive() {
        let filter = ProtectedFilter::new(&[], &["ROOT".to_string()], &[], &[]).unwrap();

        let record = make_test_record(1000, 1, "bash", "/bin/bash", "root");
        assert!(filter.is_protected(&record).is_some());
    }

    #[test]
    fn test_protected_pid() {
        let filter = ProtectedFilter::new(&[], &[], &[1], &[]).unwrap();

        let record = make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root");
        let result = filter.is_protected(&record);
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_field, MatchedField::Pid);

        let record = make_test_record(100, 1, "bash", "/bin/bash", "testuser");
        assert!(filter.is_protected(&record).is_none());
    }

    #[test]
    fn test_protected_ppid() {
        let filter = ProtectedFilter::new(&[], &[], &[], &[1]).unwrap();

        // Direct child of PID 1 should be protected
        let record = make_test_record(100, 1, "bash", "/bin/bash", "testuser");
        let result = filter.is_protected(&record);
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_field, MatchedField::Ppid);

        // Grandchild of PID 1 should NOT be protected
        let record = make_test_record(200, 100, "vim", "/usr/bin/vim", "testuser");
        assert!(filter.is_protected(&record).is_none());
    }

    #[test]
    fn test_filter_scan_result() {
        let patterns = vec![("systemd".to_string(), "literal".to_string(), true, None)];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let scan_result = ScanResult {
            processes: vec![
                make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root"),
                make_test_record(100, 1, "bash", "/bin/bash", "testuser"),
                make_test_record(
                    101,
                    1,
                    "systemd-logind",
                    "/usr/lib/systemd/systemd-logind",
                    "root",
                ),
            ],
            metadata: super::super::types::ScanMetadata {
                scan_type: "quick".to_string(),
                platform: "linux".to_string(),
                boot_id: None,
                started_at: "2026-01-15T12:00:00Z".to_string(),
                duration_ms: 100,
                process_count: 3,
                warnings: vec![],
            },
        };

        let result = filter.filter_scan_result(&scan_result);

        assert_eq!(result.total_before, 3);
        assert_eq!(result.total_after, 1); // Only bash should pass
        assert_eq!(result.filtered.len(), 2); // systemd and systemd-logind filtered
        assert_eq!(result.passed.len(), 1);
        assert_eq!(result.passed[0].comm, "bash");
    }

    #[test]
    fn test_glob_to_regex_basic() {
        // Test * matches any characters
        let regex = glob_to_regex("*.txt");
        assert!(Regex::new(&regex).unwrap().is_match("file.txt"));
        assert!(Regex::new(&regex).unwrap().is_match("longfilename.txt"));
        assert!(!Regex::new(&regex).unwrap().is_match("file.md"));

        // Test ? matches single character
        let regex = glob_to_regex("file?.txt");
        assert!(Regex::new(&regex).unwrap().is_match("file1.txt"));
        assert!(!Regex::new(&regex).unwrap().is_match("file12.txt"));

        // Test ** matches anything (greedy)
        let regex = glob_to_regex("/usr/**/bin");
        assert!(Regex::new(&regex).unwrap().is_match("/usr/local/bin"));
        assert!(Regex::new(&regex).unwrap().is_match("/usr/bin"));
    }

    #[test]
    fn test_glob_to_regex_character_class() {
        let regex = glob_to_regex("file[0-9].txt");
        assert!(Regex::new(&regex).unwrap().is_match("file5.txt"));
        assert!(!Regex::new(&regex).unwrap().is_match("fileA.txt"));

        // Negated class
        let regex = glob_to_regex("file[!0-9].txt");
        assert!(Regex::new(&regex).unwrap().is_match("fileA.txt"));
        assert!(!Regex::new(&regex).unwrap().is_match("file5.txt"));
    }

    #[test]
    fn test_case_insensitive_literal() {
        let patterns = vec![(
            "SSHD".to_string(),
            "literal".to_string(),
            true, // case insensitive
            None,
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();
        let record = make_test_record(1000, 1, "sshd", "/usr/sbin/sshd -D", "testuser");
        assert!(filter.is_protected(&record).is_some());
    }

    #[test]
    fn test_case_sensitive_literal() {
        let patterns = vec![(
            "SSHD".to_string(),
            "literal".to_string(),
            false, // case sensitive
            None,
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();
        let record = make_test_record(1000, 1, "sshd", "/usr/sbin/sshd -D", "testuser");
        assert!(filter.is_protected(&record).is_none()); // Should NOT match
    }

    #[test]
    fn test_default_protected_services() {
        // Test the default protected patterns from policy.default.json
        let patterns = vec![
            (
                r"\b(systemd|journald|logind|dbus-daemon)\b".to_string(),
                "regex".to_string(),
                true,
                Some("core system services".to_string()),
            ),
            (
                r"\b(sshd|cron|crond)\b".to_string(),
                "regex".to_string(),
                true,
                Some("remote access and schedulers".to_string()),
            ),
            (
                r"\b(dockerd|containerd)\b".to_string(),
                "regex".to_string(),
                true,
                Some("containers".to_string()),
            ),
            (
                r"\b(postgres|redis|nginx|elasticsearch)\b".to_string(),
                "regex".to_string(),
                true,
                Some("databases and proxies".to_string()),
            ),
        ];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        // Test each protected service
        let test_cases = vec![
            ("systemd", "/usr/lib/systemd/systemd", true),
            ("journald", "/usr/lib/systemd/systemd-journald", true),
            ("sshd", "/usr/sbin/sshd -D", true),
            ("cron", "/usr/sbin/cron -f", true),
            ("dockerd", "/usr/bin/dockerd", true),
            ("containerd", "/usr/bin/containerd", true),
            ("postgres", "/usr/lib/postgresql/14/bin/postgres", true),
            ("redis-server", "/usr/bin/redis-server", true),
            ("nginx", "/usr/sbin/nginx -g daemon off;", true),
            ("bash", "/bin/bash", false),
            ("python", "/usr/bin/python3 script.py", false),
        ];

        for (comm, cmd, should_be_protected) in test_cases {
            let record = make_test_record(1000, 1, comm, cmd, "testuser");
            let result = filter.is_protected(&record);
            assert_eq!(
                result.is_some(),
                should_be_protected,
                "Expected '{}' to be protected={}, but got protected={}",
                comm,
                should_be_protected,
                result.is_some()
            );
        }
    }

    #[test]
    fn test_truncate_cmd() {
        assert_eq!(truncate_cmd("short", 80), "short");
        assert_eq!(
            truncate_cmd(
                "this is a very long command line that exceeds the maximum length limit",
                30
            ),
            "this is a very long command..."
        );
    }
}
